// Package client is a blocking transport for the fileshare v2 protocol used by
// the TUI and the --batch CLI. It handles the handshake, requests, downloads
// with resume, and transparently routes asynchronous EVENT_*/PONG frames to an
// event handler while awaiting a specific reply (docs/tz/09-go-port.md §5.8).
package client

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/vitikevich-landau/go_fileshare/internal/auth"
	"github.com/vitikevich-landau/go_fileshare/internal/proto"
)

// RemoteError is an ERROR frame returned by the server.
type RemoteError struct {
	Code    proto.ErrCode
	Message string
}

func (e *RemoteError) Error() string {
	if e.Message != "" {
		return fmt.Sprintf("%s: %s", e.Code, e.Message)
	}
	return e.Code.String()
}

// AuthError is an AUTH_FAIL from the server.
type AuthError struct {
	Reason  proto.AuthFailReason
	Message string
}

func (e *AuthError) Error() string { return fmt.Sprintf("authentication failed: %s", e.Message) }

// Options configures a Dial.
type Options struct {
	ClientName   string
	Login        string
	Password     string
	EventHandler func(proto.Message) // receives async EVENT_*/PONG frames
	DialTimeout  time.Duration
}

// Client is a connected protocol client. Its request methods are not safe for
// concurrent use with each other, but Ping/Interrupt/Close may be called from
// another goroutine.
type Client struct {
	conn net.Conn

	wmu          sync.Mutex // serializes writes
	eventHandler func(proto.Message)

	role       proto.Role
	sessionID  uint64
	serverName string
	motd       string
	authMode   proto.AuthMode
	iters      int
}

// Dial connects to addr, performs the handshake and authentication, and returns
// a ready client.
func Dial(addr string, opts Options) (*Client, error) {
	timeout := opts.DialTimeout
	if timeout == 0 {
		timeout = 10 * time.Second
	}
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return nil, err
	}
	return handshake(conn, opts)
}

// maxAuthIters bounds the PBKDF2 iteration count the client will run on a
// server-announced value, so a hostile/MITM server cannot pin a CPU (CR-04).
const maxAuthIters = 10_000_000

// handshake performs HELLO/AUTH over an already-connected socket and returns a
// ready client. On failure it closes conn.
func handshake(conn net.Conn, opts Options) (*Client, error) {
	c := &Client{conn: conn, eventHandler: opts.EventHandler}

	// Bound the whole handshake so a silent/MITM server cannot hang the client
	// indefinitely (CR-04); cleared once authenticated.
	hsTimeout := opts.DialTimeout
	if hsTimeout == 0 {
		hsTimeout = 10 * time.Second
	}
	_ = conn.SetReadDeadline(time.Now().Add(hsTimeout))

	name := opts.ClientName
	if name == "" {
		name = "go-fshare-client"
	}
	if err := c.writeMsg(proto.Hello{ProtoVer: proto.ProtoVersion, ClientName: name}); err != nil {
		conn.Close()
		return nil, err
	}

	m, err := c.readMsg()
	if err != nil {
		conn.Close()
		return nil, err
	}
	helloOk, ok := m.(proto.HelloOk)
	if !ok {
		conn.Close()
		if e, isErr := m.(proto.Error); isErr {
			return nil, &RemoteError{Code: e.Code, Message: e.Message}
		}
		return nil, fmt.Errorf("expected HELLO_OK, got %s", m.Type())
	}
	c.serverName = helloOk.ServerName
	c.authMode = helloOk.AuthMode
	c.iters = int(helloOk.PBKDF2Iters)

	// Validate the untrusted auth parameters before doing any expensive work.
	switch helloOk.AuthMode {
	case proto.AuthNone:
		// no proof; iters irrelevant
	case proto.AuthChallenge:
		if c.iters < 1 || c.iters > maxAuthIters {
			conn.Close()
			return nil, fmt.Errorf("server requested %d PBKDF2 iterations, outside [1,%d]", c.iters, maxAuthIters)
		}
	default:
		conn.Close()
		return nil, fmt.Errorf("unsupported auth mode %d", helloOk.AuthMode)
	}

	var proof [proto.ProofLen]byte
	if helloOk.AuthMode == proto.AuthChallenge {
		proof = auth.Proof(opts.Password, opts.Login, c.iters, helloOk.Challenge[:])
	}
	if err := c.writeMsg(proto.AuthRequest{Login: opts.Login, Proof: proof}); err != nil {
		conn.Close()
		return nil, err
	}

	m, err = c.readMsg()
	if err != nil {
		conn.Close()
		return nil, err
	}
	switch v := m.(type) {
	case proto.AuthOk:
		c.role = v.Role
		c.sessionID = v.SessionID
		c.motd = v.Motd
		_ = conn.SetReadDeadline(time.Time{}) // clear the handshake deadline
		return c, nil
	case proto.AuthFail:
		conn.Close()
		return nil, &AuthError{Reason: v.Reason, Message: v.Message}
	case proto.Error:
		conn.Close()
		return nil, &RemoteError{Code: v.Code, Message: v.Message}
	default:
		conn.Close()
		return nil, fmt.Errorf("expected AUTH_OK, got %s", m.Type())
	}
}

// Accessors.
func (c *Client) Role() proto.Role   { return c.role }
func (c *Client) SessionID() uint64  { return c.sessionID }
func (c *Client) ServerName() string { return c.serverName }
func (c *Client) Motd() string       { return c.motd }

func (c *Client) writeMsg(m proto.Message) error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	_, err := c.conn.Write(proto.Encode(m))
	return err
}

func (c *Client) readMsg() (proto.Message, error) {
	typ, payload, err := proto.ReadFrame(c.conn)
	if err != nil {
		return nil, err
	}
	return proto.Decode(typ, payload)
}

// isAsync reports whether m is an out-of-band frame that may arrive at any time
// and should be routed to the event handler rather than treated as a reply.
func isAsync(m proto.Message) bool {
	switch m.(type) {
	case proto.EventFs, proto.EventNotice, proto.EventConfig, proto.Pong:
		return true
	}
	return false
}

// recvExpect reads frames until one of type want arrives, dispatching async
// frames to the event handler and turning ERROR into a RemoteError.
func (c *Client) recvExpect(want proto.Msg) (proto.Message, error) {
	for {
		m, err := c.readMsg()
		if err != nil {
			return nil, err
		}
		if isAsync(m) {
			if c.eventHandler != nil {
				c.eventHandler(m)
			}
			continue
		}
		if e, ok := m.(proto.Error); ok {
			return nil, &RemoteError{Code: e.Code, Message: e.Message}
		}
		if m.Type() == want {
			return m, nil
		}
		return nil, fmt.Errorf("unexpected message %s, want %s", m.Type(), want)
	}
}

// ListDir lists a remote directory, returning the normalized path and entries.
func (c *Client) ListDir(path string) (string, []proto.DirEntry, error) {
	if err := c.writeMsg(proto.ListDirRequest{Path: path}); err != nil {
		return "", nil, err
	}
	m, err := c.recvExpect(proto.MsgListDirResponse)
	if err != nil {
		return "", nil, err
	}
	r := m.(proto.ListDirResponse)
	return r.Path, r.Entries, nil
}

// Stat returns metadata for a single remote path.
func (c *Client) Stat(path string) (string, proto.DirEntry, error) {
	if err := c.writeMsg(proto.StatRequest{Path: path}); err != nil {
		return "", proto.DirEntry{}, err
	}
	m, err := c.recvExpect(proto.MsgStatResponse)
	if err != nil {
		return "", proto.DirEntry{}, err
	}
	r := m.(proto.StatResponse)
	return r.Path, r.Entry, nil
}

// Checksum requests the checksum of a remote file.
func (c *Client) Checksum(path string) (proto.Algo, [proto.ChecksumLen]byte, error) {
	if err := c.writeMsg(proto.ChecksumRequest{Path: path}); err != nil {
		return proto.AlgoPending, [proto.ChecksumLen]byte{}, err
	}
	m, err := c.recvExpect(proto.MsgChecksumResp)
	if err != nil {
		return proto.AlgoPending, [proto.ChecksumLen]byte{}, err
	}
	r := m.(proto.ChecksumResponse)
	return r.Algo, r.Checksum, nil
}

// Subscribe sets the event subscription mask.
func (c *Client) Subscribe(mask uint32) error {
	return c.writeMsg(proto.Subscribe{Mask: mask})
}

// Ping sends a keepalive. The PONG is absorbed as an async frame by the next
// recvExpect or PollEvents.
func (c *Client) Ping() error { return c.writeMsg(proto.Ping{}) }

// frameReadTimeout bounds how long PollEvents will wait to finish a frame once
// its first byte has arrived. A well-behaved peer sends the small remainder of
// an event/pong frame in milliseconds; this only fires if a peer sends one byte
// then stalls without closing the socket, in which case PollEvents must not
// wedge the idle pump (and clientMu) forever (R4-1). It is a var so tests can
// shorten it.
var frameReadTimeout = 30 * time.Second

// PollEvents waits up to timeout for one asynchronous frame (EVENT_*/PONG),
// routing it to the event handler. It returns whether a frame was received. A
// timeout is reported as (false, nil). It must not run concurrently with a
// request method — a single goroutine owns all reads (docs/tz/09-go-port.md §5.8).
//
// The idle deadline applies only to the FIRST byte of the next frame, so a
// timeout before any byte arrives is a clean "no event" that consumes nothing
// and cannot desync the next poll (R3-7). Once a frame has started, the rest is
// read under a bounded frameReadTimeout instead of forever; if that fires the
// frame is partly consumed and the stream is desynced, so the connection is
// dropped rather than reused (R4-1).
func (c *Client) PollEvents(timeout time.Duration) (bool, error) {
	_ = c.conn.SetReadDeadline(time.Now().Add(timeout))
	var first [1]byte
	n, err := c.conn.Read(first[:])
	if n == 0 {
		_ = c.conn.SetReadDeadline(time.Time{})
		if err == nil || isTimeout(err) {
			return false, nil // idle: no byte of a frame arrived in time
		}
		return false, err
	}
	// A frame has begun; finish reading it under a bounded deadline.
	_ = c.conn.SetReadDeadline(time.Now().Add(frameReadTimeout))
	typ, payload, rerr := proto.ReadFrameContinue(first[0], c.conn, proto.MaxControlPayload)
	_ = c.conn.SetReadDeadline(time.Time{})
	if rerr != nil {
		// A stalled or broken mid-frame read leaves the stream desynced; drop the
		// connection so a later poll/request cannot read leftover bytes (R4-1).
		return false, c.abortConn(rerr)
	}
	m, derr := proto.Decode(typ, payload)
	if derr != nil {
		return false, derr
	}
	if isAsync(m) {
		if c.eventHandler != nil {
			c.eventHandler(m)
		}
		return true, nil
	}
	if e, ok := m.(proto.Error); ok {
		return false, &RemoteError{Code: e.Code, Message: e.Message}
	}
	return false, fmt.Errorf("unexpected frame while idle: %s", m.Type())
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// Progress is reported during a download.
type Progress struct {
	Received uint64
	Total    uint64
}

// Download is DownloadCtx with a background context (no cancellation).
func (c *Client) Download(remotePath, localPath string, progress func(Progress)) error {
	return c.DownloadCtx(context.Background(), remotePath, localPath, progress)
}

// DownloadCtx fetches remotePath into localPath, resuming from localPath+".part"
// if present. On completion it verifies the reassembled file against the
// server's whole-file checksum and atomically renames the .part into place.
// progress may be nil. Cancelling ctx aborts the transfer and returns ctx.Err():
// once the transfer id is known it sends DOWNLOAD_CANCEL and drains to the
// server's terminal frame so the connection stays usable (RR-3); before then it
// drops the connection, which cannot be resynced without a transfer id (R4-2).
func (c *Client) DownloadCtx(ctx context.Context, remotePath, localPath string, progress func(Progress)) error {
	err := c.downloadOnce(ctx, remotePath, localPath, progress)

	// A stale/oversized .part offset is rejected by the server: discard the .part
	// and retry ONCE from scratch. Removing it makes the retry's offset 0, which
	// the server can never reject as UNSUPPORTED_OFFSET, so this cannot loop; if
	// the .part cannot be removed we stop rather than recurse forever (R4-4).
	var re *RemoteError
	if errors.As(err, &re) && re.Code == proto.ErrUnsupportedOffset {
		partPath := localPath + ".part"
		if rmErr := os.Remove(partPath); rmErr != nil && !os.IsNotExist(rmErr) {
			return fmt.Errorf("cannot discard stale partial download %q: %w", partPath, rmErr)
		}
		return c.downloadOnce(ctx, remotePath, localPath, progress)
	}
	return err
}

// downloadOnce performs a single download attempt (no stale-offset retry). It
// observes ctx for the whole attempt, including the wait for ACCEPT (R4-2), and
// normalizes an error caused by cancellation to ctx.Err() via the named return.
func (c *Client) downloadOnce(ctx context.Context, remotePath, localPath string, progress func(Progress)) (rerr error) {
	if err := ctx.Err(); err != nil {
		return err // already cancelled: send nothing
	}

	partPath := localPath + ".part"
	var offset uint64
	if fi, err := os.Stat(partPath); err == nil && !fi.IsDir() {
		offset = uint64(fi.Size())
	}
	if err := os.MkdirAll(filepath.Dir(localPath), 0o755); err != nil {
		return err
	}

	// Watch ctx for the whole attempt, including the wait for ACCEPT. Until the
	// transfer id is known we cannot send a proper cancel or drain to a terminal
	// frame, so a cancel then closes the connection to unblock the wait and abort
	// (R4-2). Once ACCEPT arrives the watcher switches to the tid-aware
	// DOWNLOAD_CANCEL that keeps the connection in sync (RR-3, R3-2). We await the
	// watcher before returning so a cancel at the very end can never leak a
	// DOWNLOAD_CANCEL into the next transfer (R3-2).
	var tmu sync.Mutex
	var cancelTID uint32
	var haveTID bool
	watchDone := make(chan struct{})
	var watchWG sync.WaitGroup
	watchWG.Add(1)
	go func() {
		defer watchWG.Done()
		select {
		case <-ctx.Done():
			tmu.Lock()
			tid, have := cancelTID, haveTID
			tmu.Unlock()
			if have {
				_ = c.Cancel(tid)
			} else {
				c.conn.Close() // no transfer id yet: cannot resync, so drop it
			}
		case <-watchDone:
		}
	}()
	defer func() {
		close(watchDone)
		watchWG.Wait()
		// An error caused by the cancel (a closed conn, a CANCELLED terminal) is
		// reported as ctx.Err(); a completed download keeps its nil success even
		// if ctx was cancelled at the tail.
		if rerr != nil && ctx.Err() != nil {
			rerr = ctx.Err()
		}
	}()

	if err := c.writeMsg(proto.DownloadRequest{Path: remotePath, Offset: offset}); err != nil {
		return err
	}
	m, err := c.recvExpect(proto.MsgDownloadAccept)
	if err != nil {
		return err
	}
	accept := m.(proto.DownloadAccept)
	total := accept.TotalSize
	tid := accept.TransferID
	tmu.Lock()
	cancelTID = tid
	haveTID = true
	tmu.Unlock()

	flag := os.O_CREATE | os.O_WRONLY
	if offset > 0 {
		flag |= os.O_APPEND
	} else {
		flag |= os.O_TRUNC // discard any leftover .part when starting fresh
	}
	pf, err := os.OpenFile(partPath, flag, 0o644)
	if err != nil {
		// A local failure after ACCEPT: the server is about to stream the file,
		// so drop the connection rather than leave its chunks buffered for the
		// next request to misread (R3-3).
		return c.abortConn(err)
	}

	received := offset
	if progress != nil {
		progress(Progress{Received: received, Total: total})
	}

	for {
		typ, payload, rerr := proto.ReadFrame(c.conn)
		if rerr != nil {
			// Either the socket died, or the server sent a malformed/oversize
			// frame whose header was consumed but payload was not — which leaves
			// the stream desynced. Drop the connection in both cases so no later
			// request can read leftover bytes (R3-3).
			pf.Close()
			return c.abortConn(rerr)
		}
		msg, derr := proto.Decode(typ, payload)
		if derr != nil {
			// The server sent a malformed frame; the stream is still aligned but
			// its state is unknown and it keeps sending — drop the connection so
			// the next request cannot read leftover frames (R3-3).
			pf.Close()
			return c.abortConn(derr)
		}
		switch v := msg.(type) {
		case proto.ChunkData:
			if v.TransferID != tid {
				pf.Close()
				return c.abortConn(fmt.Errorf("chunk for unexpected transfer %d (want %d)", v.TransferID, tid))
			}
			if received+uint64(len(v.Data)) > total {
				pf.Close()
				return c.abortConn(fmt.Errorf("server sent more than total_size (%d > %d)", received+uint64(len(v.Data)), total))
			}
			if _, werr := pf.Write(v.Data); werr != nil {
				// A local write failure (e.g. disk full) while the server keeps
				// streaming: drop the connection to stay in sync (R3-3).
				pf.Close()
				return c.abortConn(werr)
			}
			received += uint64(len(v.Data))
			if progress != nil {
				progress(Progress{Received: received, Total: total})
			}
		case proto.DownloadDone:
			if cerr := pf.Close(); cerr != nil {
				return cerr
			}
			// Integrity gates before publishing (CR-02): the DONE must be for
			// this transfer, all announced bytes must have arrived, and it must
			// carry a supported checksum that matches the reassembled file. A
			// short read keeps the .part so it can be resumed; a checksum
			// mismatch discards it so we don't loop on a corrupt full-size .part.
			if v.TransferID != tid {
				return fmt.Errorf("DOWNLOAD_DONE for unexpected transfer %d (want %d)", v.TransferID, tid)
			}
			if received != total {
				return fmt.Errorf("incomplete download: got %d of %d bytes", received, total)
			}
			// Verify against whichever checksum the server used. SHA-256 fills
			// the whole 32-byte field; CRC-32 uses the first 4 bytes (big-endian,
			// the protocol's integer convention), the rest zero. This keeps
			// interop with a CRC32-configured C++ server (RR-2). The verify is
			// ctx-aware, so a cancel while hashing a large .part aborts promptly and
			// (via the deferred normalizer) returns ctx.Err() (R5-1); the DONE is
			// already fully read, so the connection stays in sync.
			if bad, herr := checksumMismatch(ctx, partPath, v.Algo, v.Checksum); herr != nil {
				return herr
			} else if bad {
				os.Remove(partPath)
				return errors.New("checksum mismatch after download")
			}
			// A cancel that lands at 100% (after DONE, during/after verify) must
			// not publish the file and report success. Keep the verified .part for
			// a later resume and report the cancellation (R5-1).
			if err := ctx.Err(); err != nil {
				return err
			}
			if err := os.Rename(partPath, localPath); err != nil {
				return err // bug #3: only report success if the file is in place
			}
			return nil
		case proto.Error:
			pf.Close()
			// If we asked to cancel, this ERROR is the server's terminal
			// acknowledgement; the connection is now in sync. Report the
			// cancellation, not a generic remote error.
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return &RemoteError{Code: v.Code, Message: v.Message}
		default:
			if isAsync(msg) {
				if c.eventHandler != nil {
					c.eventHandler(msg)
				}
				continue
			}
			// An unexpected in-band frame mid-download: the server's stream state
			// is out of sync with ours — drop the connection (R3-3).
			pf.Close()
			return c.abortConn(fmt.Errorf("unexpected message during download: %s", typ))
		}
	}
}

// abortConn closes the connection and returns err. It is used when a download
// fails locally or the server violates the protocol mid-stream: the server may
// still be sending CHUNK_DATA, so the only way to keep a later request from
// reading leftover frames is to drop the connection (R3-3). Terminal
// server frames (DOWNLOAD_DONE / ERROR) leave the connection in sync and do not
// go through here.
func (c *Client) abortConn(err error) error {
	c.conn.Close()
	return err
}

// Cancel asks the server to abort the active transfer without closing the
// connection.
func (c *Client) Cancel(transferID uint32) error {
	return c.writeMsg(proto.DownloadCancel{TransferID: transferID})
}

// ---- admin channel (role=admin) ----

// AdminGetConfig returns the effective config as JSON ([]config.KeyInfo).
func (c *Client) AdminGetConfig() ([]byte, error) {
	if err := c.writeMsg(proto.AdminGetConfig{}); err != nil {
		return nil, err
	}
	m, err := c.recvExpect(proto.MsgAdminConfig)
	if err != nil {
		return nil, err
	}
	return m.(proto.AdminConfig).JSON, nil
}

// AdminSet changes one hot config key. It returns the server's ok flag and message.
func (c *Client) AdminSet(key, value string) (bool, string, error) {
	if err := c.writeMsg(proto.AdminSet{Key: key, Value: value}); err != nil {
		return false, "", err
	}
	m, err := c.recvExpect(proto.MsgAdminSetResult)
	if err != nil {
		return false, "", err
	}
	r := m.(proto.AdminSetResult)
	return r.OK, r.Message, nil
}

// AdminListClients returns the connected sessions.
func (c *Client) AdminListClients() ([]proto.ClientInfo, error) {
	if err := c.writeMsg(proto.AdminListClients{}); err != nil {
		return nil, err
	}
	m, err := c.recvExpect(proto.MsgAdminClients)
	if err != nil {
		return nil, err
	}
	return m.(proto.AdminClients).Clients, nil
}

// AdminKick disconnects a session by id.
func (c *Client) AdminKick(sessionID uint64) (bool, string, error) {
	if err := c.writeMsg(proto.AdminKick{SessionID: sessionID}); err != nil {
		return false, "", err
	}
	m, err := c.recvExpect(proto.MsgAdminKickResult)
	if err != nil {
		return false, "", err
	}
	r := m.(proto.AdminKickResult)
	return r.OK, r.Message, nil
}

// AdminStats returns server statistics.
func (c *Client) AdminStats() (proto.AdminStatsResponse, error) {
	if err := c.writeMsg(proto.AdminStats{}); err != nil {
		return proto.AdminStatsResponse{}, err
	}
	m, err := c.recvExpect(proto.MsgAdminStatsResp)
	if err != nil {
		return proto.AdminStatsResponse{}, err
	}
	return m.(proto.AdminStatsResponse), nil
}

// AdminShutdown requests a graceful shutdown with the given grace period.
func (c *Client) AdminShutdown(graceSeconds uint32) (bool, string, error) {
	if err := c.writeMsg(proto.AdminShutdown{GraceSeconds: graceSeconds}); err != nil {
		return false, "", err
	}
	m, err := c.recvExpect(proto.MsgAdminShutdownResult)
	if err != nil {
		return false, "", err
	}
	r := m.(proto.AdminShutdownResult)
	return r.OK, r.Message, nil
}

// Interrupt unblocks a read in progress from another goroutine (e.g. to quit
// the TUI mid-download) by setting an immediate read deadline.
func (c *Client) Interrupt() {
	_ = c.conn.SetReadDeadline(time.Now())
}

// Close closes the connection.
func (c *Client) Close() error { return c.conn.Close() }

// checksumMismatch reports whether the file's checksum differs from want, using
// the algorithm the server declared. An unsupported/absent algorithm is an
// error. It is ctx-aware: verifying a large .part re-reads the whole file, so a
// cancel during it aborts promptly and returns ctx.Err() (R5-1).
func checksumMismatch(ctx context.Context, path string, algo proto.Algo, want [proto.ChecksumLen]byte) (bool, error) {
	switch algo {
	case proto.AlgoSHA256:
		got, err := sha256File(ctx, path)
		if err != nil {
			return false, err
		}
		return got != want, nil
	case proto.AlgoCRC32:
		got, err := crc32File(ctx, path)
		if err != nil {
			return false, err
		}
		return got != binary.BigEndian.Uint32(want[:4]), nil
	default:
		return false, fmt.Errorf("server did not provide a verifiable checksum (algo %d)", algo)
	}
}

func crc32File(ctx context.Context, path string) (uint32, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	h := crc32.NewIEEE()
	if err := copyCtx(ctx, h, f); err != nil {
		return 0, err
	}
	return h.Sum32(), nil
}

func sha256File(ctx context.Context, path string) ([proto.ChecksumLen]byte, error) {
	var out [proto.ChecksumLen]byte
	f, err := os.Open(path)
	if err != nil {
		return out, err
	}
	defer f.Close()
	h := sha256.New()
	if err := copyCtx(ctx, h, f); err != nil {
		return out, err
	}
	copy(out[:], h.Sum(nil))
	return out, nil
}

// copyCtx streams src into dst, checking ctx before each block so a long local
// hash aborts promptly on cancellation, returning ctx.Err() (R5-1).
func copyCtx(ctx context.Context, dst io.Writer, src io.Reader) error {
	buf := make([]byte, 128<<10)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		n, rerr := src.Read(buf)
		if n > 0 {
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return werr
			}
		}
		if rerr == io.EOF {
			return nil
		}
		if rerr != nil {
			return rerr
		}
	}
}
