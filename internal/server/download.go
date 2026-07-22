package server

import (
	"context"
	"io"
	"os"

	"github.com/vitikevich-landau/go_fileshare/internal/proto"
	"github.com/vitikevich-landau/go_fileshare/internal/vfs"
)

// startDownload validates the request and, on success, streams the file from a
// dedicated goroutine so the reader stays free to handle PING/DOWNLOAD_CANCEL
// and events can be pushed mid-stream (docs/tz/09-go-port.md §5.5). Only one
// active transfer per session is allowed.
func (s *Server) startDownload(sess *Session, req proto.DownloadRequest) {
	if !sess.downloading.CompareAndSwap(false, true) {
		sess.sendMsg(proto.Error{Code: proto.ErrBadRequest, Message: "a transfer is already in progress"})
		return
	}
	f, info, err := s.vfs.Open(req.Path)
	if err != nil {
		sess.downloading.Store(false)
		s.sendErr(sess, vfs.CodeOf(err))
		return
	}
	total := uint64(info.Size())
	if req.Offset > total {
		f.Close()
		sess.downloading.Store(false)
		s.sendErr(sess, proto.ErrUnsupportedOffset)
		return
	}

	tid := s.nextTransfer.Add(1)
	cancel := make(chan struct{})
	sess.setCancel(tid, cancel)
	s.activeDownloads.Add(1)
	sess.wg.Add(1)
	go func() {
		defer sess.wg.Done()
		defer s.activeDownloads.Add(-1)
		defer f.Close()
		defer sess.touch() // refresh idle clock so post-download isn't reaped (RR-1)
		defer sess.downloading.Store(false)
		defer sess.clearCancel()  // a stale cancel must not touch a later transfer (R3-2)
		defer sess.clearCurPath() // clear even if checksum/read errors (bug #2)

		// A context that cancels when the transfer is cancelled or the session
		// is torn down, so a rate-limit wait cannot block on either.
		ctx, ctxCancel := context.WithCancel(context.Background())
		defer ctxCancel()
		go func() {
			// Cancel the rate-limit ctx on a client cancel OR teardown, so a
			// cancel that lands while the stream is blocked in limiter.Wait wakes
			// it promptly instead of stalling for minutes at a low bps (R3-1). The
			// stream loop distinguishes the two: on a client cancel it sends the
			// terminal CANCELLED error to keep the connection in sync (RR-3); on
			// teardown it just stops. ctx.Done() also lets this watcher exit on
			// normal completion, so it never leaks a goroutine.
			select {
			case <-sess.done:
			case <-cancel:
			case <-ctx.Done():
			}
			ctxCancel()
		}()

		sess.setCurPath(req.Path) // set before ACCEPT so drain sees an active transfer (bug #5)
		s.streamFile(ctx, sess, f, req, tid, total, cancel)
	}()
}

func (s *Server) streamFile(ctx context.Context, sess *Session, f *os.File, req proto.DownloadRequest, tid uint32, total uint64, cancel chan struct{}) {
	if req.Offset > 0 {
		if _, err := f.Seek(int64(req.Offset), io.SeekStart); err != nil {
			s.sendErr(sess, proto.ErrInternal)
			return
		}
	}
	if !sess.sendMsg(proto.DownloadAccept{TransferID: tid, TotalSize: total}) {
		return
	}

	clientKey := sess.Login()
	buf := make([]byte, proto.ChunkSize)
	sent := req.Offset
	for sent < total {
		select {
		case <-cancel:
			// Client asked to cancel: send a defined terminal frame after the
			// chunks already queued, so the client's loop ends in sync (RR-3).
			s.sendErr(sess, proto.ErrCancelled)
			return
		case <-sess.done:
			return
		default:
		}
		// Clamp the read to the announced remaining size so a file appended to
		// mid-transfer never makes us overshoot total_size (which the client
		// rejects); we deliver exactly the originally-announced prefix.
		toRead := buf
		if rem := total - sent; rem < uint64(len(buf)) {
			toRead = buf[:rem]
		}
		n, err := f.Read(toRead)
		if n > 0 {
			// Rate-limit against the CURRENT limits so a live config change
			// throttles this active transfer (docs/tz/09-go-port.md §5.6).
			lim := s.hub.Current().Limits
			if werr := s.limiter.Wait(ctx, clientKey, lim.PerClientBps, lim.GlobalBps, n); werr != nil {
				// The wait was interrupted. If the client asked to cancel, send the
				// terminal CANCELLED frame so its loop ends in sync (R3-1); on a
				// teardown, just stop (the connection is already closing).
				select {
				case <-cancel:
					s.sendErr(sess, proto.ErrCancelled)
				default:
				}
				return
			}
			// proto.Encode copies buf into a fresh frame, so reusing buf is safe.
			if !sess.sendMsg(proto.ChunkData{TransferID: tid, Data: buf[:n]}) {
				return
			}
			sess.bytes.Add(uint64(n))
			s.bytesSent.Add(uint64(n))
			sent += uint64(n)
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			// A read error mid-transfer: tell the client instead of leaving it
			// waiting, and never publish a partial file (CR-02).
			s.sendErr(sess, proto.ErrInternal)
			return
		}
	}

	// If the file shrank during the transfer we delivered fewer bytes than
	// announced; report an error rather than a success DONE the client would
	// (rightly) reject (CR-02).
	if sent != total {
		s.sendErr(sess, proto.ErrInternal)
		return
	}

	// The server always sends the checksum of the whole file; on a resumed
	// download the client verifies the reassembled file against it. If the
	// checksum cannot be computed we must NOT claim success — send an error so
	// the client never publishes an unverifiable file.
	_, algo, sum, cerr := s.vfs.Checksum(req.Path)
	if cerr != nil || algo != proto.AlgoSHA256 {
		s.sendErr(sess, proto.ErrInternal)
		return
	}
	if sess.sendMsg(proto.DownloadDone{TransferID: tid, Algo: algo, Checksum: sum}) {
		s.completed.Add(1)
	}
}
