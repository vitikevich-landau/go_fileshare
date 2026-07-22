// Package proto реализует проводной протокол fileshare v2.
//
// ─────────────────────────────────────────────────────────────────────────────
// Как устроен протокол (в двух словах)
//
// Общение идёт КАДРАМИ. Каждый кадр — это 5-байтовый заголовок, за которым
// следует тело (payload):
//
//	┌────────────┬───────────────────────┬───────────────────────────┐
//	│ msg_type   │ payload_length         │ payload                   │
//	│ 1 байт u8  │ 4 байта u32, big-endian│ payload_length байт       │
//	└────────────┴───────────────────────┴───────────────────────────┘
//
// Все целые на проводе — big-endian. Раскладка кадров и тел повторяет
// docs/tz/09-go-port.md §4 БАЙТ-В-БАЙТ, поэтому Go-узел совместим с эталонной
// реализацией на C++: Go-сервер обслуживает C++-клиента и наоборот.
//
// Роли файлов пакета:
//   - proto.go     — константы протокола и ПЕРЕЧИСЛЕНИЯ (Msg, Role, ErrCode…);
//   - types.go     — словарь доменных величин (псевдонимы примитивов);
//   - messages.go  — структуры сообщений и их кодирование/декодирование;
//   - frame.go     — сборка и чтение кадра (заголовок + защита от переполнения);
//   - codec.go     — низкоуровневые чтение/запись big-endian с проверкой границ.
//
// ─────────────────────────────────────────────────────────────────────────────
package proto

// Общие константы протокола (docs/tz/09-go-port.md §4.3). Это «пределы и
// размеры», единые для обеих сторон; менять их — значит менять протокол.
const (
	ProtoVersion      = 2        // единственная поддерживаемая версия
	MaxPathLen        = 4096     // потолок длины пути в VFS
	MaxNameLen        = 255      // потолок длины имени одной записи каталога
	MaxStringLen      = 65535    // максимум для строки с префиксом длины u16
	MaxControlPayload = 4 << 20  // 4 МиБ — потолок тела для больших сообщений
	ChunkSize         = 64 << 10 // 64 КиБ — размер куска файла в CHUNK_DATA
	ChallengeLen      = 16       // длина challenge (nonce) в байтах
	ProofLen          = 32       // длина доказательства пароля (HMAC) в байтах
	ChecksumLen       = 32       // длина контрольной суммы (буфер под SHA-256)
	MaxListEntries    = 1 << 20  // потолок числа записей в списке (анти-DoS)
	HeaderSize        = 5        // размер заголовка кадра: u8 + u32
)

// Msg — однобайтовый код типа сообщения (docs/tz/09-go-port.md §4.4). Это
// defined-тип (не псевдоним): у него есть методы Known и String, а «семейство»
// сообщения читается по старшему полубайту кода — 0x1x рукопожатие, 0x2x
// файловая система, 0x3x передача, 0x4x события, 0x5x админ-канал.
type Msg uint8

const (
	// Служебные (0x0x): ошибка и heartbeat.
	MsgError Msg = 0x06
	MsgPing  Msg = 0x07
	MsgPong  Msg = 0x08

	// Рукопожатие и аутентификация (0x1x).
	MsgHello       Msg = 0x10
	MsgHelloOk     Msg = 0x11
	MsgAuthRequest Msg = 0x12
	MsgAuthOk      Msg = 0x13
	MsgAuthFail    Msg = 0x14

	// Файловая система: листинг, метаданные, контрольные суммы (0x2x).
	MsgListDirRequest  Msg = 0x20
	MsgListDirResponse Msg = 0x21
	MsgStatRequest     Msg = 0x22
	MsgStatResponse    Msg = 0x23
	MsgChecksumRequest Msg = 0x24
	MsgChecksumResp    Msg = 0x25

	// Передача файла: запрос, согласие, чанки, финиш, отмена (0x3x).
	MsgDownloadRequest Msg = 0x30
	MsgDownloadAccept  Msg = 0x31
	MsgChunkData       Msg = 0x32
	MsgDownloadDone    Msg = 0x33
	MsgDownloadCancel  Msg = 0x34

	// Подписка и push-события (0x4x).
	MsgSubscribe   Msg = 0x40
	MsgEventFs     Msg = 0x41
	MsgEventNotice Msg = 0x42
	MsgEventConfig Msg = 0x43

	// Админ-канал: конфиг, клиенты, kick, статистика, остановка, users (0x5x).
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
	MsgAdminReloadUsers    Msg = 0x5C
	MsgAdminReloadUsersRes Msg = 0x5D
)

// Known сообщает, определён ли код m протоколом. Слой кадрирования отвергает
// неизвестные типы ещё до чтения тела (docs/tz/09-go-port.md §4.1), поэтому
// «мусорный» первый байт не заставит сервер что-то выделять.
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
		MsgAdminStats, MsgAdminStatsResp, MsgAdminShutdown, MsgAdminShutdownResult,
		MsgAdminReloadUsers, MsgAdminReloadUsersRes:
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
	MsgAdminReloadUsers: "ADMIN_RELOAD_USERS", MsgAdminReloadUsersRes: "ADMIN_RELOAD_USERS_RESULT",
}

// AuthMode — требование сервера к аутентификации, объявляемое в HELLO_OK.
type AuthMode uint8

const (
	AuthNone      AuthMode = 0 // bootstrap без пароля: ЛЮБОЙ логин становится admin
	AuthChallenge AuthMode = 1 // обычный режим challenge–response
)

// Algo — какой алгоритм контрольной суммы использован.
type Algo uint8

const (
	AlgoPending Algo = 0 // сумма ещё не посчитана (ленивое вычисление в процессе)
	AlgoCRC32   Algo = 1 // быстрый CRC32 (первые 4 байта поля Checksum)
	AlgoSHA256  Algo = 2 // криптостойкий SHA-256 (все 32 байта)
)

// Role — уровень доступа сессии. Диспетчер сравнивает роль сессии с минимально
// требуемой для каждого типа сообщения, поэтому проверки прав не размазаны по
// обработчикам (docs/tz/01-architecture.md §3).
type Role uint8

const (
	RoleAnonymous Role = 0 // ещё не вошёл: можно только HELLO/AUTH/PING
	RoleUser      Role = 1 // обычный пользователь: листинг и скачивание
	RoleAdmin     Role = 2 // администратор: плюс весь админ-канал
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

// Kind — файл это или директория (поле DirEntry.Kind).
type Kind uint8

const (
	KindFile Kind = 0 // обычный файл
	KindDir  Kind = 1 // директория
)

// FsOp — какое изменение в файловой системе описывает EVENT_FS.
type FsOp uint8

const (
	FsCreated  FsOp = 1 // запись появилась
	FsModified FsOp = 2 // запись изменилась
	FsRemoved  FsOp = 3 // запись удалена
)

// Severity — важность (и цвет) уведомления EVENT_NOTICE.
type Severity uint8

const (
	SevInfo  Severity = 0 // информация
	SevWarn  Severity = 1 // предупреждение
	SevError Severity = 2 // ошибка
)

// Биты маски SUBSCRIBE (docs/tz/09-go-port.md §4.3). Клиент складывает нужные
// биты в SubscriptionMask и шлёт в SUBSCRIBE; сервер рассылает событие только
// тем, у кого установлен соответствующий бит.
const (
	SubFS     uint32 = 1 // события файловой системы (EVENT_FS)
	SubNotice uint32 = 2 // текстовые уведомления (EVENT_NOTICE)
	SubConfig uint32 = 4 // изменения конфигурации (EVENT_CONFIG)
)

// Биты флагов записи каталога (DirEntry.Flags).
const (
	FlagNew uint8 = 1 // бит 0: запись «новая» с момента прошлого визита клиента
)

// ErrCode — код ошибки уровня приложения, который несёт ERROR
// (docs/tz/02-protocol-v2.md §2.6). Отдельный от сетевых сбоев: соединение живо,
// просто конкретный запрос не выполнен.
type ErrCode uint16

const (
	ErrOK                 ErrCode = 0  // ошибки нет
	ErrFileNotFound       ErrCode = 1  // путь не существует
	ErrUnsupportedOffset  ErrCode = 2  // offset за пределами файла (докачка невозможна)
	ErrBadRequest         ErrCode = 3  // некорректный запрос (формат/параметры)
	ErrInternal           ErrCode = 4  // внутренняя ошибка сервера
	ErrUnsupportedVersion ErrCode = 5  // несовместимая версия протокола
	ErrAuthRequired       ErrCode = 6  // операция требует входа
	ErrAuthFailed         ErrCode = 7  // аутентификация не прошла
	ErrAccessDenied       ErrCode = 8  // нет прав на операцию
	ErrNotADirectory      ErrCode = 9  // ждали каталог, а это файл
	ErrIsADirectory       ErrCode = 10 // ждали файл, а это каталог
	ErrRateLimited        ErrCode = 11 // превышен лимит скорости/частоты
	ErrServerShuttingDown ErrCode = 12 // сервер останавливается
	ErrQuotaExceeded      ErrCode = 13 // превышена квота (перспектива M13)
	// ErrCancelled завершает передачу, которую сам клиент попросил отменить,
	// оставляя соединение в согласованном состоянии (расширение Go-порта; RR-3).
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

// AuthFailReason — код причины в AUTH_FAIL. Проводной формат оставляет эти
// значения на усмотрение реализации; в рамках проекта они стабильны.
type AuthFailReason uint16

const (
	AuthFailBadCredentials AuthFailReason = 1 // неверный логин или пароль
	AuthFailUserDisabled   AuthFailReason = 2 // учётка отключена
	AuthFailBanned         AuthFailReason = 3 // IP временно забанен гардом
	AuthFailTooManySession AuthFailReason = 4 // превышен лимит сессий на пользователя
	AuthFailMalformed      AuthFailReason = 5 // некорректный AUTH_REQUEST
)
