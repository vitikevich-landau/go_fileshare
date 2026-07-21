// Package client is a blocking transport for the fileshare v2 protocol used by
// the TUI and the --batch CLI. It handles the handshake, requests, downloads
// with resume, and transparently routes asynchronous EVENT_*/PONG frames to an
// event handler while awaiting a specific reply (docs/tz/09-go-port.md §5.8).
package client

import (
	"crypto/sha256"
	"errors"
	"fmt"
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

// handshake performs HELLO/AUTH over an already-connected socket and returns a
// ready client. On failure it closes conn.
func handshake(conn net.Conn, opts Options) (*Client, error) {
	c := &Client{conn: conn, eventHandler: opts.EventHandler}

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

// PollEvents waits up to timeout for one asynchronous frame (EVENT_*/PONG),
// routing it to the event handler. It returns whether a frame was received. A
// timeout is reported as (false, nil). It must not run concurrently with a
// request method — a single goroutine owns all reads (docs/tz/09-go-port.md §5.8).
func (c *Client) PollEvents(timeout time.Duration) (bool, error) {
	_ = c.conn.SetReadDeadline(time.Now().Add(timeout))
	defer c.conn.SetReadDeadline(time.Time{})

	m, err := c.readMsg()
	if err != nil {
		if isTimeout(err) {
			return false, nil
		}
		return false, err
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

// Download fetches remotePath into localPath, resuming from localPath+".part"
// if present. On completion it verifies the reassembled file against the
// server's whole-file checksum and atomically renames the .part into place.
// progress may be nil.
func (c *Client) Download(remotePath, localPath string, progress func(Progress)) error {
	partPath := localPath + ".part"

	var offset uint64
	if fi, err := os.Stat(partPath); err == nil && !fi.IsDir() {
		offset = uint64(fi.Size())
	}
	if err := os.MkdirAll(filepath.Dir(localPath), 0o755); err != nil {
		return err
	}

	if err := c.writeMsg(proto.DownloadRequest{Path: remotePath, Offset: offset}); err != nil {
		return err
	}
	m, err := c.recvExpect(proto.MsgDownloadAccept)
	if err != nil {
		// A stale/oversized .part offset is rejected: discard it and restart
		// from scratch rather than looping forever (bug #6).
		var re *RemoteError
		if offset > 0 && errors.As(err, &re) && re.Code == proto.ErrUnsupportedOffset {
			os.Remove(partPath)
			return c.Download(remotePath, localPath, progress)
		}
		return err
	}
	accept := m.(proto.DownloadAccept)
	total := accept.TotalSize

	flag := os.O_CREATE | os.O_WRONLY
	if offset > 0 {
		flag |= os.O_APPEND
	} else {
		flag |= os.O_TRUNC // discard any leftover .part when starting fresh
	}
	pf, err := os.OpenFile(partPath, flag, 0o644)
	if err != nil {
		return err
	}

	received := offset
	if progress != nil {
		progress(Progress{Received: received, Total: total})
	}

	for {
		typ, payload, rerr := proto.ReadFrame(c.conn)
		if rerr != nil {
			pf.Close()
			return rerr
		}
		msg, derr := proto.Decode(typ, payload)
		if derr != nil {
			pf.Close()
			return derr
		}
		switch v := msg.(type) {
		case proto.ChunkData:
			if received+uint64(len(v.Data)) > total {
				pf.Close()
				return fmt.Errorf("server sent more than total_size (%d > %d)", received+uint64(len(v.Data)), total)
			}
			if _, werr := pf.Write(v.Data); werr != nil {
				pf.Close()
				return werr
			}
			received += uint64(len(v.Data))
			if progress != nil {
				progress(Progress{Received: received, Total: total})
			}
		case proto.DownloadDone:
			if cerr := pf.Close(); cerr != nil {
				return cerr
			}
			if v.Algo == proto.AlgoSHA256 {
				sum, herr := sha256File(partPath)
				if herr != nil {
					return herr
				}
				if sum != v.Checksum {
					os.Remove(partPath) // avoid looping on a corrupt full-size .part
					return errors.New("checksum mismatch after download")
				}
			}
			if err := os.Rename(partPath, localPath); err != nil {
				return err // bug #3: only report success if the file is in place
			}
			return nil
		case proto.Error:
			pf.Close()
			return &RemoteError{Code: v.Code, Message: v.Message}
		default:
			if isAsync(msg) {
				if c.eventHandler != nil {
					c.eventHandler(msg)
				}
				continue
			}
			pf.Close()
			return fmt.Errorf("unexpected message during download: %s", typ)
		}
	}
}

// Cancel asks the server to abort the active transfer without closing the
// connection.
func (c *Client) Cancel(transferID uint32) error {
	return c.writeMsg(proto.DownloadCancel{TransferID: transferID})
}

// Interrupt unblocks a read in progress from another goroutine (e.g. to quit
// the TUI mid-download) by setting an immediate read deadline.
func (c *Client) Interrupt() {
	_ = c.conn.SetReadDeadline(time.Now())
}

// Close closes the connection.
func (c *Client) Close() error { return c.conn.Close() }

func sha256File(path string) ([proto.ChecksumLen]byte, error) {
	var out [proto.ChecksumLen]byte
	f, err := os.Open(path)
	if err != nil {
		return out, err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return out, err
	}
	copy(out[:], h.Sum(nil))
	return out, nil
}
