// Package proto implements the fileshare v2 wire protocol.
//
// The framing and message layout follow docs/tz/09-go-port.md §4 byte-for-byte,
// so a Go peer is interoperable with the reference C++ implementation. Every
// message is a 5-byte header (msg_type:u8, payload_length:u32 big-endian)
// followed by the payload. All integers are big-endian.
package proto

// Protocol-wide constants (docs/tz/09-go-port.md §4.3).
const (
	ProtoVersion      = 2
	MaxPathLen        = 4096
	MaxNameLen        = 255
	MaxStringLen      = 65535 // u16 length prefix ceiling
	MaxControlPayload = 4 << 20
	ChunkSize         = 64 << 10
	ChallengeLen      = 16
	ProofLen          = 32
	ChecksumLen       = 32
	MaxListEntries    = 1 << 20
	HeaderSize        = 5
)

// Msg is a one-byte message type code (docs/tz/09-go-port.md §4.4).
type Msg uint8

const (
	MsgError Msg = 0x06
	MsgPing  Msg = 0x07
	MsgPong  Msg = 0x08

	MsgHello       Msg = 0x10
	MsgHelloOk     Msg = 0x11
	MsgAuthRequest Msg = 0x12
	MsgAuthOk      Msg = 0x13
	MsgAuthFail    Msg = 0x14

	MsgListDirRequest  Msg = 0x20
	MsgListDirResponse Msg = 0x21
	MsgStatRequest     Msg = 0x22
	MsgStatResponse    Msg = 0x23
	MsgChecksumRequest Msg = 0x24
	MsgChecksumResp    Msg = 0x25

	MsgDownloadRequest Msg = 0x30
	MsgDownloadAccept  Msg = 0x31
	MsgChunkData       Msg = 0x32
	MsgDownloadDone    Msg = 0x33
	MsgDownloadCancel  Msg = 0x34

	MsgSubscribe   Msg = 0x40
	MsgEventFs     Msg = 0x41
	MsgEventNotice Msg = 0x42
	MsgEventConfig Msg = 0x43

	MsgAdminGetConfig      Msg = 0x50
	MsgAdminConfig         Msg = 0x51
	MsgAdminSet            Msg = 0x52
	MsgAdminSetResult      Msg = 0x53
	MsgAdminListClients    Msg = 0x54
	MsgAdminClients        Msg = 0x55
	MsgAdminKick           Msg = 0x56
	MsgAdminKickResult     Msg = 0x57
	MsgAdminStats          Msg = 0x58
	MsgAdminStatsResp      Msg = 0x59
	MsgAdminShutdown       Msg = 0x5A
	MsgAdminShutdownResult Msg = 0x5B
)

// Known reports whether m is a message type defined by the protocol. Framing
// rejects unknown types (docs/tz/09-go-port.md §4.1).
func (m Msg) Known() bool {
	switch m {
	case MsgError, MsgPing, MsgPong,
		MsgHello, MsgHelloOk, MsgAuthRequest, MsgAuthOk, MsgAuthFail,
		MsgListDirRequest, MsgListDirResponse, MsgStatRequest, MsgStatResponse,
		MsgChecksumRequest, MsgChecksumResp,
		MsgDownloadRequest, MsgDownloadAccept, MsgChunkData, MsgDownloadDone, MsgDownloadCancel,
		MsgSubscribe, MsgEventFs, MsgEventNotice, MsgEventConfig,
		MsgAdminGetConfig, MsgAdminConfig, MsgAdminSet, MsgAdminSetResult,
		MsgAdminListClients, MsgAdminClients, MsgAdminKick, MsgAdminKickResult,
		MsgAdminStats, MsgAdminStatsResp, MsgAdminShutdown, MsgAdminShutdownResult:
		return true
	}
	return false
}

func (m Msg) String() string {
	if s, ok := msgNames[m]; ok {
		return s
	}
	return "UNKNOWN"
}

var msgNames = map[Msg]string{
	MsgError: "ERROR", MsgPing: "PING", MsgPong: "PONG",
	MsgHello: "HELLO", MsgHelloOk: "HELLO_OK", MsgAuthRequest: "AUTH_REQUEST",
	MsgAuthOk: "AUTH_OK", MsgAuthFail: "AUTH_FAIL",
	MsgListDirRequest: "LIST_DIR_REQUEST", MsgListDirResponse: "LIST_DIR_RESPONSE",
	MsgStatRequest: "STAT_REQUEST", MsgStatResponse: "STAT_RESPONSE",
	MsgChecksumRequest: "CHECKSUM_REQUEST", MsgChecksumResp: "CHECKSUM_RESPONSE",
	MsgDownloadRequest: "DOWNLOAD_REQUEST", MsgDownloadAccept: "DOWNLOAD_ACCEPT",
	MsgChunkData: "CHUNK_DATA", MsgDownloadDone: "DOWNLOAD_DONE", MsgDownloadCancel: "DOWNLOAD_CANCEL",
	MsgSubscribe: "SUBSCRIBE", MsgEventFs: "EVENT_FS", MsgEventNotice: "EVENT_NOTICE", MsgEventConfig: "EVENT_CONFIG",
	MsgAdminGetConfig: "ADMIN_GET_CONFIG", MsgAdminConfig: "ADMIN_CONFIG",
	MsgAdminSet: "ADMIN_SET", MsgAdminSetResult: "ADMIN_SET_RESULT",
	MsgAdminListClients: "ADMIN_LIST_CLIENTS", MsgAdminClients: "ADMIN_CLIENTS",
	MsgAdminKick: "ADMIN_KICK", MsgAdminKickResult: "ADMIN_KICK_RESULT",
	MsgAdminStats: "ADMIN_STATS", MsgAdminStatsResp: "ADMIN_STATS_RESPONSE",
	MsgAdminShutdown: "ADMIN_SHUTDOWN", MsgAdminShutdownResult: "ADMIN_SHUTDOWN_RESULT",
}

// AuthMode is the server's authentication requirement, announced in HELLO_OK.
type AuthMode uint8

const (
	AuthNone      AuthMode = 0 // no-auth bootstrap: any login becomes ADMIN
	AuthChallenge AuthMode = 1
)

// Algo identifies a checksum algorithm.
type Algo uint8

const (
	AlgoPending Algo = 0
	AlgoCRC32   Algo = 1
	AlgoSHA256  Algo = 2
)

// Role is a session's authorization level.
type Role uint8

const (
	RoleAnonymous Role = 0
	RoleUser      Role = 1
	RoleAdmin     Role = 2
)

func (r Role) String() string {
	switch r {
	case RoleAnonymous:
		return "anonymous"
	case RoleUser:
		return "user"
	case RoleAdmin:
		return "admin"
	}
	return "unknown"
}

// Kind distinguishes files from directories in a DirEntry.
type Kind uint8

const (
	KindFile Kind = 0
	KindDir  Kind = 1
)

// FsOp is the operation reported by an EVENT_FS message.
type FsOp uint8

const (
	FsCreated  FsOp = 1
	FsModified FsOp = 2
	FsRemoved  FsOp = 3
)

// Severity classifies an EVENT_NOTICE.
type Severity uint8

const (
	SevInfo  Severity = 0
	SevWarn  Severity = 1
	SevError Severity = 2
)

// SUBSCRIBE mask bits (docs/tz/09-go-port.md §4.3).
const (
	SubFS     uint32 = 1
	SubNotice uint32 = 2
	SubConfig uint32 = 4
)

// DirEntry flag bits.
const (
	FlagNew uint8 = 1 // bit0: entry is "new" since the client's last visit
)

// ErrCode is an application-level error code carried by ERROR (docs/tz/02-protocol-v2.md §2.6).
type ErrCode uint16

const (
	ErrOK                 ErrCode = 0
	ErrFileNotFound       ErrCode = 1
	ErrUnsupportedOffset  ErrCode = 2
	ErrBadRequest         ErrCode = 3
	ErrInternal           ErrCode = 4
	ErrUnsupportedVersion ErrCode = 5
	ErrAuthRequired       ErrCode = 6
	ErrAuthFailed         ErrCode = 7
	ErrAccessDenied       ErrCode = 8
	ErrNotADirectory      ErrCode = 9
	ErrIsADirectory       ErrCode = 10
	ErrRateLimited        ErrCode = 11
	ErrServerShuttingDown ErrCode = 12
	ErrQuotaExceeded      ErrCode = 13
	// ErrCancelled terminates a transfer the client asked to cancel, keeping the
	// connection in sync (Go-port extension; see RR-3).
	ErrCancelled ErrCode = 14
)

func (c ErrCode) String() string {
	switch c {
	case ErrOK:
		return "OK"
	case ErrFileNotFound:
		return "FILE_NOT_FOUND"
	case ErrUnsupportedOffset:
		return "UNSUPPORTED_OFFSET"
	case ErrBadRequest:
		return "BAD_REQUEST"
	case ErrInternal:
		return "INTERNAL_ERROR"
	case ErrUnsupportedVersion:
		return "UNSUPPORTED_VERSION"
	case ErrAuthRequired:
		return "AUTH_REQUIRED"
	case ErrAuthFailed:
		return "AUTH_FAILED"
	case ErrAccessDenied:
		return "ACCESS_DENIED"
	case ErrNotADirectory:
		return "NOT_A_DIRECTORY"
	case ErrIsADirectory:
		return "IS_A_DIRECTORY"
	case ErrRateLimited:
		return "RATE_LIMITED"
	case ErrServerShuttingDown:
		return "SERVER_SHUTTING_DOWN"
	case ErrQuotaExceeded:
		return "QUOTA_EXCEEDED"
	case ErrCancelled:
		return "CANCELLED"
	}
	return "ERR_UNKNOWN"
}

// AuthFailReason codes carried by AUTH_FAIL. The wire spec leaves these to the
// implementation; these values are stable within this project.
type AuthFailReason uint16

const (
	AuthFailBadCredentials AuthFailReason = 1
	AuthFailUserDisabled   AuthFailReason = 2
	AuthFailBanned         AuthFailReason = 3
	AuthFailTooManySession AuthFailReason = 4
	AuthFailMalformed      AuthFailReason = 5
)
