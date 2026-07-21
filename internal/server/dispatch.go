package server

import "github.com/vitikevich-landau/go_fileshare/internal/proto"

// MinRole returns the minimum role a client must hold to send a message type
// (docs/tz/09-go-port.md §5.5). Handshake and keepalive are anonymous;
// filesystem/transfer/subscribe require a user; admin messages require admin.
// Server-only (response/event) codes default to admin so a client cannot send
// them; the dispatcher additionally rejects them as BAD_REQUEST.
func MinRole(m proto.Msg) proto.Role {
	switch m {
	case proto.MsgHello, proto.MsgAuthRequest, proto.MsgPing, proto.MsgPong, proto.MsgError:
		return proto.RoleAnonymous
	case proto.MsgListDirRequest, proto.MsgStatRequest, proto.MsgChecksumRequest,
		proto.MsgDownloadRequest, proto.MsgDownloadCancel, proto.MsgSubscribe:
		return proto.RoleUser
	default:
		return proto.RoleAdmin
	}
}

// roleAllows reports whether have satisfies the need level.
func roleAllows(have, need proto.Role) bool { return have >= need }
