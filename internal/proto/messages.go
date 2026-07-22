package proto

import "fmt"

// Message is a decoded protocol message. Encoders return a full frame via
// Encode; decoders are dispatched by Decode.
type Message interface {
	Type() Msg
	encode(w *writer)
}

// Encode marshals m into a complete wire frame.
func Encode(m Message) []byte {
	var w writer
	m.encode(&w)
	return Frame(m.Type(), w.buf)
}

// Decode parses a payload for the given message type. It enforces that the
// payload is fully consumed (no trailing bytes), matching require_end in the
// C++ reference (docs/tz/09-go-port.md §5.1).
func Decode(typ Msg, payload []byte) (Message, error) {
	r := newReader(payload)
	m, err := decodeBody(typ, r)
	if err != nil {
		return nil, err
	}
	if err := r.end(); err != nil {
		return nil, err
	}
	return m, nil
}

func decodeBody(typ Msg, r *reader) (Message, error) {
	switch typ {
	case MsgError:
		return decodeError(r)
	case MsgPing:
		return Ping{}, nil
	case MsgPong:
		return Pong{}, nil
	case MsgHello:
		return decodeHello(r)
	case MsgHelloOk:
		return decodeHelloOk(r)
	case MsgAuthRequest:
		return decodeAuthRequest(r)
	case MsgAuthOk:
		return decodeAuthOk(r)
	case MsgAuthFail:
		return decodeAuthFail(r)
	case MsgListDirRequest:
		return decodeListDirRequest(r)
	case MsgListDirResponse:
		return decodeListDirResponse(r)
	case MsgStatRequest:
		return decodeStatRequest(r)
	case MsgStatResponse:
		return decodeStatResponse(r)
	case MsgChecksumRequest:
		return decodeChecksumRequest(r)
	case MsgChecksumResp:
		return decodeChecksumResponse(r)
	case MsgDownloadRequest:
		return decodeDownloadRequest(r)
	case MsgDownloadAccept:
		return decodeDownloadAccept(r)
	case MsgChunkData:
		return decodeChunkData(r)
	case MsgDownloadDone:
		return decodeDownloadDone(r)
	case MsgDownloadCancel:
		return decodeDownloadCancel(r)
	case MsgSubscribe:
		return decodeSubscribe(r)
	case MsgEventFs:
		return decodeEventFs(r)
	case MsgEventNotice:
		return decodeEventNotice(r)
	case MsgEventConfig:
		return decodeEventConfig(r)
	case MsgAdminGetConfig:
		return AdminGetConfig{}, nil
	case MsgAdminConfig:
		return decodeAdminConfig(r)
	case MsgAdminSet:
		return decodeAdminSet(r)
	case MsgAdminSetResult:
		return decodeAdminSetResult(r)
	case MsgAdminListClients:
		return AdminListClients{}, nil
	case MsgAdminClients:
		return decodeAdminClients(r)
	case MsgAdminKick:
		return decodeAdminKick(r)
	case MsgAdminKickResult:
		return decodeAdminKickResult(r)
	case MsgAdminStats:
		return AdminStats{}, nil
	case MsgAdminStatsResp:
		return decodeAdminStatsResponse(r)
	case MsgAdminShutdown:
		return decodeAdminShutdown(r)
	case MsgAdminShutdownResult:
		return decodeAdminShutdownResult(r)
	}
	return nil, fmt.Errorf("proto: cannot decode msg type 0x%02x", byte(typ))
}

func boolU8(b bool) uint8 {
	if b {
		return 1
	}
	return 0
}

// ---- DirEntry (shared sub-structure) ----

// DirEntry describes one filesystem entry on the wire: name:str, kind:u8,
// size:u64, mtime:u64 (unix seconds), flags:u8 (docs/tz/09-go-port.md §4.4).
type DirEntry struct {
	Name  string
	Kind  Kind
	Size  uint64
	Mtime uint64
	Flags uint8
}

func (e DirEntry) encodeInto(w *writer) {
	w.str(e.Name)
	w.u8(uint8(e.Kind))
	w.u64(e.Size)
	w.u64(e.Mtime)
	w.u8(e.Flags)
}

func decodeDirEntry(r *reader) (DirEntry, error) {
	var e DirEntry
	var err error
	if e.Name, err = r.str(MaxNameLen); err != nil {
		return e, err
	}
	k, err := r.u8()
	if err != nil {
		return e, err
	}
	e.Kind = Kind(k)
	if e.Size, err = r.u64(); err != nil {
		return e, err
	}
	if e.Mtime, err = r.u64(); err != nil {
		return e, err
	}
	if e.Flags, err = r.u8(); err != nil {
		return e, err
	}
	return e, nil
}

// ---- ERROR / PING / PONG ----

type Error struct {
	Code    ErrCode
	Message string
}

func (Error) Type() Msg { return MsgError }
func (m Error) encode(w *writer) {
	w.u16(uint16(m.Code))
	w.str(m.Message)
}
func decodeError(r *reader) (Error, error) {
	var m Error
	code, err := r.u16()
	if err != nil {
		return m, err
	}
	m.Code = ErrCode(code)
	if m.Message, err = r.str(MaxStringLen); err != nil {
		return m, err
	}
	return m, nil
}

type Ping struct{}

func (Ping) Type() Msg        { return MsgPing }
func (Ping) encode(w *writer) {}

type Pong struct{}

func (Pong) Type() Msg        { return MsgPong }
func (Pong) encode(w *writer) {}

// ---- Handshake / auth ----

type Hello struct {
	ProtoVer   uint16
	ClientName string
}

func (Hello) Type() Msg { return MsgHello }
func (m Hello) encode(w *writer) {
	w.u16(m.ProtoVer)
	w.str(m.ClientName)
}
func decodeHello(r *reader) (Hello, error) {
	var m Hello
	var err error
	if m.ProtoVer, err = r.u16(); err != nil {
		return m, err
	}
	if m.ClientName, err = r.str(MaxStringLen); err != nil {
		return m, err
	}
	return m, nil
}

type HelloOk struct {
	ProtoVer    uint16
	ServerName  string
	AuthMode    AuthMode
	Challenge   [ChallengeLen]byte
	PBKDF2Iters uint32
}

func (HelloOk) Type() Msg { return MsgHelloOk }
func (m HelloOk) encode(w *writer) {
	w.u16(m.ProtoVer)
	w.str(m.ServerName)
	w.u8(uint8(m.AuthMode))
	w.fixed(m.Challenge[:], ChallengeLen)
	w.u32(m.PBKDF2Iters)
}
func decodeHelloOk(r *reader) (HelloOk, error) {
	var m HelloOk
	var err error
	if m.ProtoVer, err = r.u16(); err != nil {
		return m, err
	}
	if m.ServerName, err = r.str(MaxStringLen); err != nil {
		return m, err
	}
	mode, err := r.u8()
	if err != nil {
		return m, err
	}
	m.AuthMode = AuthMode(mode)
	if err = r.fixedInto(m.Challenge[:]); err != nil {
		return m, err
	}
	if m.PBKDF2Iters, err = r.u32(); err != nil {
		return m, err
	}
	return m, nil
}

type AuthRequest struct {
	Login string
	Proof [ProofLen]byte
}

func (AuthRequest) Type() Msg { return MsgAuthRequest }
func (m AuthRequest) encode(w *writer) {
	w.str(m.Login)
	w.fixed(m.Proof[:], ProofLen)
}
func decodeAuthRequest(r *reader) (AuthRequest, error) {
	var m AuthRequest
	var err error
	if m.Login, err = r.str(MaxStringLen); err != nil {
		return m, err
	}
	if err = r.fixedInto(m.Proof[:]); err != nil {
		return m, err
	}
	return m, nil
}

type AuthOk struct {
	Role      Role
	SessionID uint64
	Motd      string
}

func (AuthOk) Type() Msg { return MsgAuthOk }
func (m AuthOk) encode(w *writer) {
	w.u8(uint8(m.Role))
	w.u64(m.SessionID)
	w.str(m.Motd)
}
func decodeAuthOk(r *reader) (AuthOk, error) {
	var m AuthOk
	role, err := r.u8()
	if err != nil {
		return m, err
	}
	m.Role = Role(role)
	if m.SessionID, err = r.u64(); err != nil {
		return m, err
	}
	if m.Motd, err = r.str(MaxStringLen); err != nil {
		return m, err
	}
	return m, nil
}

type AuthFail struct {
	Reason  AuthFailReason
	Message string
}

func (AuthFail) Type() Msg { return MsgAuthFail }
func (m AuthFail) encode(w *writer) {
	w.u16(uint16(m.Reason))
	w.str(m.Message)
}
func decodeAuthFail(r *reader) (AuthFail, error) {
	var m AuthFail
	reason, err := r.u16()
	if err != nil {
		return m, err
	}
	m.Reason = AuthFailReason(reason)
	if m.Message, err = r.str(MaxStringLen); err != nil {
		return m, err
	}
	return m, nil
}

// ---- Filesystem ----

type ListDirRequest struct{ Path string }

func (ListDirRequest) Type() Msg          { return MsgListDirRequest }
func (m ListDirRequest) encode(w *writer) { w.str(m.Path) }
func decodeListDirRequest(r *reader) (ListDirRequest, error) {
	p, err := r.str(MaxPathLen)
	return ListDirRequest{Path: p}, err
}

type ListDirResponse struct {
	Path    string
	Entries []DirEntry
}

func (ListDirResponse) Type() Msg { return MsgListDirResponse }
func (m ListDirResponse) encode(w *writer) {
	w.str(m.Path)
	w.u32(uint32(len(m.Entries)))
	for _, e := range m.Entries {
		e.encodeInto(w)
	}
}
func decodeListDirResponse(r *reader) (ListDirResponse, error) {
	var m ListDirResponse
	var err error
	if m.Path, err = r.str(MaxPathLen); err != nil {
		return m, err
	}
	count, err := r.u32()
	if err != nil {
		return m, err
	}
	if count > MaxListEntries {
		return m, fmt.Errorf("proto: list count %d exceeds max %d", count, MaxListEntries)
	}
	m.Entries = make([]DirEntry, 0, count)
	for i := uint32(0); i < count; i++ {
		e, err := decodeDirEntry(r)
		if err != nil {
			return m, err
		}
		m.Entries = append(m.Entries, e)
	}
	return m, nil
}

type StatRequest struct{ Path string }

func (StatRequest) Type() Msg          { return MsgStatRequest }
func (m StatRequest) encode(w *writer) { w.str(m.Path) }
func decodeStatRequest(r *reader) (StatRequest, error) {
	p, err := r.str(MaxPathLen)
	return StatRequest{Path: p}, err
}

type StatResponse struct {
	Path  string
	Entry DirEntry
}

func (StatResponse) Type() Msg { return MsgStatResponse }
func (m StatResponse) encode(w *writer) {
	w.str(m.Path)
	m.Entry.encodeInto(w)
}
func decodeStatResponse(r *reader) (StatResponse, error) {
	var m StatResponse
	var err error
	if m.Path, err = r.str(MaxPathLen); err != nil {
		return m, err
	}
	if m.Entry, err = decodeDirEntry(r); err != nil {
		return m, err
	}
	return m, nil
}

type ChecksumRequest struct{ Path string }

func (ChecksumRequest) Type() Msg          { return MsgChecksumRequest }
func (m ChecksumRequest) encode(w *writer) { w.str(m.Path) }
func decodeChecksumRequest(r *reader) (ChecksumRequest, error) {
	p, err := r.str(MaxPathLen)
	return ChecksumRequest{Path: p}, err
}

type ChecksumResponse struct {
	Path     string
	Algo     Algo
	Checksum [ChecksumLen]byte
}

func (ChecksumResponse) Type() Msg { return MsgChecksumResp }
func (m ChecksumResponse) encode(w *writer) {
	w.str(m.Path)
	w.u8(uint8(m.Algo))
	w.fixed(m.Checksum[:], ChecksumLen)
}
func decodeChecksumResponse(r *reader) (ChecksumResponse, error) {
	var m ChecksumResponse
	var err error
	if m.Path, err = r.str(MaxPathLen); err != nil {
		return m, err
	}
	a, err := r.u8()
	if err != nil {
		return m, err
	}
	m.Algo = Algo(a)
	if err = r.fixedInto(m.Checksum[:]); err != nil {
		return m, err
	}
	return m, nil
}

// ---- Transfer ----

type DownloadRequest struct {
	Path   string
	Offset uint64
}

func (DownloadRequest) Type() Msg { return MsgDownloadRequest }
func (m DownloadRequest) encode(w *writer) {
	w.str(m.Path)
	w.u64(m.Offset)
}
func decodeDownloadRequest(r *reader) (DownloadRequest, error) {
	var m DownloadRequest
	var err error
	if m.Path, err = r.str(MaxPathLen); err != nil {
		return m, err
	}
	if m.Offset, err = r.u64(); err != nil {
		return m, err
	}
	return m, nil
}

type DownloadAccept struct {
	TransferID uint32
	TotalSize  uint64
}

func (DownloadAccept) Type() Msg { return MsgDownloadAccept }
func (m DownloadAccept) encode(w *writer) {
	w.u32(m.TransferID)
	w.u64(m.TotalSize)
}
func decodeDownloadAccept(r *reader) (DownloadAccept, error) {
	var m DownloadAccept
	var err error
	if m.TransferID, err = r.u32(); err != nil {
		return m, err
	}
	if m.TotalSize, err = r.u64(); err != nil {
		return m, err
	}
	return m, nil
}

// ChunkData carries a raw slice of file bytes (up to ChunkSize). The payload is
// transfer_id:u32 followed by the raw bytes with no length prefix; the frame
// length delimits the data.
type ChunkData struct {
	TransferID uint32
	Data       []byte
}

func (ChunkData) Type() Msg { return MsgChunkData }
func (m ChunkData) encode(w *writer) {
	w.u32(m.TransferID)
	w.raw(m.Data)
}
func decodeChunkData(r *reader) (ChunkData, error) {
	var m ChunkData
	var err error
	if m.TransferID, err = r.u32(); err != nil {
		return m, err
	}
	m.Data = r.rest()
	if len(m.Data) > ChunkSize {
		return m, fmt.Errorf("proto: chunk data %d exceeds ChunkSize %d", len(m.Data), ChunkSize)
	}
	return m, nil
}

type DownloadDone struct {
	TransferID uint32
	Algo       Algo
	Checksum   [ChecksumLen]byte
}

func (DownloadDone) Type() Msg { return MsgDownloadDone }
func (m DownloadDone) encode(w *writer) {
	w.u32(m.TransferID)
	w.u8(uint8(m.Algo))
	w.fixed(m.Checksum[:], ChecksumLen)
}
func decodeDownloadDone(r *reader) (DownloadDone, error) {
	var m DownloadDone
	var err error
	if m.TransferID, err = r.u32(); err != nil {
		return m, err
	}
	a, err := r.u8()
	if err != nil {
		return m, err
	}
	m.Algo = Algo(a)
	if err = r.fixedInto(m.Checksum[:]); err != nil {
		return m, err
	}
	return m, nil
}

type DownloadCancel struct{ TransferID uint32 }

func (DownloadCancel) Type() Msg          { return MsgDownloadCancel }
func (m DownloadCancel) encode(w *writer) { w.u32(m.TransferID) }
func decodeDownloadCancel(r *reader) (DownloadCancel, error) {
	id, err := r.u32()
	return DownloadCancel{TransferID: id}, err
}

// ---- Events ----

type Subscribe struct{ Mask uint32 }

func (Subscribe) Type() Msg          { return MsgSubscribe }
func (m Subscribe) encode(w *writer) { w.u32(m.Mask) }
func decodeSubscribe(r *reader) (Subscribe, error) {
	mask, err := r.u32()
	return Subscribe{Mask: mask}, err
}

type EventFs struct {
	Op    FsOp
	Kind  Kind
	Path  string
	Size  uint64
	Mtime uint64
}

func (EventFs) Type() Msg { return MsgEventFs }
func (m EventFs) encode(w *writer) {
	w.u8(uint8(m.Op))
	w.u8(uint8(m.Kind))
	w.str(m.Path)
	w.u64(m.Size)
	w.u64(m.Mtime)
}
func decodeEventFs(r *reader) (EventFs, error) {
	var m EventFs
	op, err := r.u8()
	if err != nil {
		return m, err
	}
	m.Op = FsOp(op)
	k, err := r.u8()
	if err != nil {
		return m, err
	}
	m.Kind = Kind(k)
	if m.Path, err = r.str(MaxPathLen); err != nil {
		return m, err
	}
	if m.Size, err = r.u64(); err != nil {
		return m, err
	}
	if m.Mtime, err = r.u64(); err != nil {
		return m, err
	}
	return m, nil
}

type EventNotice struct {
	Severity Severity
	Text     string
}

func (EventNotice) Type() Msg { return MsgEventNotice }
func (m EventNotice) encode(w *writer) {
	w.u8(uint8(m.Severity))
	w.str(m.Text)
}
func decodeEventNotice(r *reader) (EventNotice, error) {
	var m EventNotice
	sev, err := r.u8()
	if err != nil {
		return m, err
	}
	m.Severity = Severity(sev)
	if m.Text, err = r.str(MaxStringLen); err != nil {
		return m, err
	}
	return m, nil
}

type EventConfig struct {
	Key      string
	NewValue string
}

func (EventConfig) Type() Msg { return MsgEventConfig }
func (m EventConfig) encode(w *writer) {
	w.str(m.Key)
	w.str(m.NewValue)
}
func decodeEventConfig(r *reader) (EventConfig, error) {
	var m EventConfig
	var err error
	if m.Key, err = r.str(MaxStringLen); err != nil {
		return m, err
	}
	if m.NewValue, err = r.str(MaxStringLen); err != nil {
		return m, err
	}
	return m, nil
}

// ---- Admin ----

type AdminGetConfig struct{}

func (AdminGetConfig) Type() Msg        { return MsgAdminGetConfig }
func (AdminGetConfig) encode(w *writer) {}

// AdminConfig carries the effective config as JSON, prefixed with a u32 length
// (the one message that may exceed 64 KiB — docs/tz/09-go-port.md §4.2).
type AdminConfig struct{ JSON []byte }

func (AdminConfig) Type() Msg { return MsgAdminConfig }
func (m AdminConfig) encode(w *writer) {
	w.u32(uint32(len(m.JSON)))
	w.raw(m.JSON)
}
func decodeAdminConfig(r *reader) (AdminConfig, error) {
	n, err := r.u32()
	if err != nil {
		return AdminConfig{}, err
	}
	b, err := r.take(int(n))
	return AdminConfig{JSON: b}, err
}

type AdminSet struct {
	Key   string
	Value string
}

func (AdminSet) Type() Msg { return MsgAdminSet }
func (m AdminSet) encode(w *writer) {
	w.str(m.Key)
	w.str(m.Value)
}
func decodeAdminSet(r *reader) (AdminSet, error) {
	var m AdminSet
	var err error
	if m.Key, err = r.str(MaxStringLen); err != nil {
		return m, err
	}
	if m.Value, err = r.str(MaxStringLen); err != nil {
		return m, err
	}
	return m, nil
}

type AdminSetResult struct {
	OK      bool
	Message string
}

func (AdminSetResult) Type() Msg { return MsgAdminSetResult }
func (m AdminSetResult) encode(w *writer) {
	w.u8(boolU8(m.OK))
	w.str(m.Message)
}
func decodeAdminSetResult(r *reader) (AdminSetResult, error) {
	var m AdminSetResult
	ok, err := r.u8()
	if err != nil {
		return m, err
	}
	m.OK = ok != 0
	if m.Message, err = r.str(MaxStringLen); err != nil {
		return m, err
	}
	return m, nil
}

type AdminListClients struct{}

func (AdminListClients) Type() Msg        { return MsgAdminListClients }
func (AdminListClients) encode(w *writer) {}

// ClientInfo is one entry of ADMIN_CLIENTS.
type ClientInfo struct {
	SessionID   uint64
	Login       string
	IP          string
	Role        Role
	CurrentPath string
	BytesSent   uint64
	SpeedBps    uint64
}

type AdminClients struct{ Clients []ClientInfo }

func (AdminClients) Type() Msg { return MsgAdminClients }
func (m AdminClients) encode(w *writer) {
	w.u32(uint32(len(m.Clients)))
	for _, c := range m.Clients {
		w.u64(c.SessionID)
		w.str(c.Login)
		w.str(c.IP)
		w.u8(uint8(c.Role))
		w.str(c.CurrentPath)
		w.u64(c.BytesSent)
		w.u64(c.SpeedBps)
	}
}
func decodeAdminClients(r *reader) (AdminClients, error) {
	var m AdminClients
	count, err := r.u32()
	if err != nil {
		return m, err
	}
	if count > MaxListEntries {
		return m, fmt.Errorf("proto: client count %d exceeds max %d", count, MaxListEntries)
	}
	m.Clients = make([]ClientInfo, 0, count)
	for i := uint32(0); i < count; i++ {
		var c ClientInfo
		if c.SessionID, err = r.u64(); err != nil {
			return m, err
		}
		if c.Login, err = r.str(MaxStringLen); err != nil {
			return m, err
		}
		if c.IP, err = r.str(MaxStringLen); err != nil {
			return m, err
		}
		role, err := r.u8()
		if err != nil {
			return m, err
		}
		c.Role = Role(role)
		if c.CurrentPath, err = r.str(MaxPathLen); err != nil {
			return m, err
		}
		if c.BytesSent, err = r.u64(); err != nil {
			return m, err
		}
		if c.SpeedBps, err = r.u64(); err != nil {
			return m, err
		}
		m.Clients = append(m.Clients, c)
	}
	return m, nil
}

type AdminKick struct{ SessionID uint64 }

func (AdminKick) Type() Msg          { return MsgAdminKick }
func (m AdminKick) encode(w *writer) { w.u64(m.SessionID) }
func decodeAdminKick(r *reader) (AdminKick, error) {
	id, err := r.u64()
	return AdminKick{SessionID: id}, err
}

type AdminKickResult struct {
	OK      bool
	Message string
}

func (AdminKickResult) Type() Msg { return MsgAdminKickResult }
func (m AdminKickResult) encode(w *writer) {
	w.u8(boolU8(m.OK))
	w.str(m.Message)
}
func decodeAdminKickResult(r *reader) (AdminKickResult, error) {
	var m AdminKickResult
	ok, err := r.u8()
	if err != nil {
		return m, err
	}
	m.OK = ok != 0
	if m.Message, err = r.str(MaxStringLen); err != nil {
		return m, err
	}
	return m, nil
}

type AdminStats struct{}

func (AdminStats) Type() Msg        { return MsgAdminStats }
func (AdminStats) encode(w *writer) {}

type AdminStatsResponse struct {
	UptimeS         uint64
	BytesSent       uint64
	Completed       uint64
	ActiveConns     uint64
	ActiveDownloads uint64
	SharedFiles     uint64
	PerClientBps    uint64
	GlobalBps       uint64
	Version         string
}

func (AdminStatsResponse) Type() Msg { return MsgAdminStatsResp }
func (m AdminStatsResponse) encode(w *writer) {
	w.u64(m.UptimeS)
	w.u64(m.BytesSent)
	w.u64(m.Completed)
	w.u64(m.ActiveConns)
	w.u64(m.ActiveDownloads)
	w.u64(m.SharedFiles)
	w.u64(m.PerClientBps)
	w.u64(m.GlobalBps)
	w.str(m.Version)
}
func decodeAdminStatsResponse(r *reader) (AdminStatsResponse, error) {
	var m AdminStatsResponse
	var err error
	for _, p := range []*uint64{
		&m.UptimeS, &m.BytesSent, &m.Completed, &m.ActiveConns, &m.ActiveDownloads,
		&m.SharedFiles, &m.PerClientBps, &m.GlobalBps,
	} {
		if *p, err = r.u64(); err != nil {
			return m, err
		}
	}
	if m.Version, err = r.str(MaxStringLen); err != nil {
		return m, err
	}
	return m, nil
}

type AdminShutdown struct{ GraceSeconds uint32 }

func (AdminShutdown) Type() Msg          { return MsgAdminShutdown }
func (m AdminShutdown) encode(w *writer) { w.u32(m.GraceSeconds) }
func decodeAdminShutdown(r *reader) (AdminShutdown, error) {
	g, err := r.u32()
	return AdminShutdown{GraceSeconds: g}, err
}

type AdminShutdownResult struct {
	OK      bool
	Message string
}

func (AdminShutdownResult) Type() Msg { return MsgAdminShutdownResult }
func (m AdminShutdownResult) encode(w *writer) {
	w.u8(boolU8(m.OK))
	w.str(m.Message)
}
func decodeAdminShutdownResult(r *reader) (AdminShutdownResult, error) {
	var m AdminShutdownResult
	ok, err := r.u8()
	if err != nil {
		return m, err
	}
	m.OK = ok != 0
	if m.Message, err = r.str(MaxStringLen); err != nil {
		return m, err
	}
	return m, nil
}
