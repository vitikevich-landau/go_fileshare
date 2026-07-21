package server

import (
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
	sess.setCancel(cancel)
	s.activeDownloads.Add(1)
	sess.wg.Add(1)
	go func() {
		defer sess.wg.Done()
		defer s.activeDownloads.Add(-1)
		defer f.Close()
		defer sess.downloading.Store(false)
		defer sess.clearCurPath() // clear even if checksum/read errors (bug #2)
		sess.setCurPath(req.Path) // set before ACCEPT so drain sees an active transfer (bug #5)
		s.streamFile(sess, f, req, tid, total, cancel)
	}()
}

func (s *Server) streamFile(sess *Session, f *os.File, req proto.DownloadRequest, tid uint32, total uint64, cancel chan struct{}) {
	if req.Offset > 0 {
		if _, err := f.Seek(int64(req.Offset), io.SeekStart); err != nil {
			s.sendErr(sess, proto.ErrInternal)
			return
		}
	}
	if !sess.sendMsg(proto.DownloadAccept{TransferID: tid, TotalSize: total}) {
		return
	}

	buf := make([]byte, proto.ChunkSize)
	sent := req.Offset
	for sent < total {
		select {
		case <-cancel:
			return
		case <-sess.done:
			return
		default:
		}
		n, err := f.Read(buf)
		if n > 0 {
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
			return
		}
	}

	// The server always sends the checksum of the whole file; on a resumed
	// download the client verifies the reassembled file against it.
	_, algo, sum, cerr := s.vfs.Checksum(req.Path)
	if cerr != nil {
		algo = proto.AlgoPending
		sum = [proto.ChecksumLen]byte{}
	}
	if sess.sendMsg(proto.DownloadDone{TransferID: tid, Algo: algo, Checksum: sum}) {
		s.completed.Add(1)
	}
}
