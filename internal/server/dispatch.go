package server

import "github.com/vitikevich-landau/go_fileshare/internal/proto"

// MinRole возвращает МИНИМАЛЬНУЮ роль, которую должен иметь клиент, чтобы послать
// сообщение данного типа (docs/tz/09-go-port.md §5.5). Это единая точка
// авторизации: рукопожатие и keepalive — анонимны; файловая
// система/передача/подписка требуют роль user; админ-сообщения — admin.
// Коды «только для сервера» (ответы/события) по умолчанию требуют admin, чтобы
// клиент не мог их слать; диспетчер вдобавок отвергает их как BAD_REQUEST.
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

// roleAllows сообщает, удовлетворяет ли роль have минимально требуемой need.
// Роли упорядочены (anonymous < user < admin), поэтому достаточно сравнения.
func roleAllows(have, need proto.Role) bool { return have >= need }
