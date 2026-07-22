package proto

import "fmt"

// Message — разобранное сообщение протокола. Каждый тип сообщения умеет сказать
// свой Msg-код и сериализовать себя в тело кадра (encode); обратное
// преобразование делает Decode. encode неэкспортируемый: собирать кадр нужно
// через Encode, чтобы к телу всегда добавлялся корректный заголовок.
type Message interface {
	Type() Msg
	encode(w *writer)
}

// Encode превращает сообщение m в готовый кадр (5-байтовый заголовок + тело).
func Encode(m Message) []byte {
	var w writer
	m.encode(&w)
	return Frame(m.Type(), w.buf)
}

// Decode разбирает тело кадра заданного типа в сообщение. Обязательно требует,
// чтобы тело было ИЗРАСХОДОВАНО ПОЛНОСТЬЮ (без «хвоста»): лишние байты означают
// рассинхрон формата — это зеркалит require_end из эталона на C++
// (docs/tz/09-go-port.md §5.1).
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
	case MsgAdminReloadUsers:
		return AdminReloadUsers{}, nil
	case MsgAdminReloadUsersRes:
		return decodeAdminReloadUsersResult(r)
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

// DirEntry — одна запись каталога на проводе: имя, тип (файл/папка), размер,
// время модификации и флаги. Формат: name:str, kind:u8, size:u64,
// mtime:u64 (unix-секунды), flags:u8 (docs/tz/09-go-port.md §4.4). Одна и та же
// структура переиспользуется в LIST_DIR_RESPONSE и STAT_RESPONSE.
type DirEntry struct {
	Name  FileName    // имя записи без пути, напр. «report.pdf»
	Kind  Kind        // файл или директория
	Size  FileSize    // размер в байтах (для директории — 0)
	Mtime UnixSeconds // время последней модификации, unix-секунды
	Flags EntryFlags  // битовые флаги (FlagNew — «новая» с прошлого визита)
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

// Error — сообщение ERROR: код ошибки уровня приложения плюс человекочитаемое
// пояснение. Сервер шлёт его, когда не может выполнить запрос (файл не найден,
// нет прав, требуется аутентификация и т.п.); клиент показывает Message
// пользователю, а по Code принимает решение (например, ErrCancelled завершает
// передачу штатно, не как сбой).
type Error struct {
	Code    ErrCode // машиночитаемый код (см. перечисление ErrCode)
	Message string  // текст для человека
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

// Ping — heartbeat-запрос «ты жив?». Пустое тело: важен сам факт кадра. Любая
// сторона может слать PING, чтобы вовремя заметить обрыв «молчащего» TCP.
type Ping struct{}

func (Ping) Type() Msg        { return MsgPing }
func (Ping) encode(w *writer) {}

// Pong — ответ на Ping, тоже с пустым телом.
type Pong struct{}

func (Pong) Type() Msg        { return MsgPong }
func (Pong) encode(w *writer) {}

// ---- Handshake / auth ----

// Hello — самое первое сообщение клиента после установки TCP: объявляет версию
// протокола и представляется. Сервер по ProtoVer сразу решает, говорить ли
// дальше (v2 отказывает v1 и наоборот).
type Hello struct {
	ProtoVer   ProtocolVersion // версия протокола, которую предлагает клиент
	ClientName string          // самоназвание, напр. «commander/2.0»
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

// HelloOk — ответ сервера на Hello: подтверждает версию, представляется,
// объявляет режим аутентификации и передаёт параметры challenge–response
// (случайный вызов и число итераций PBKDF2). По ним клиент считает
// доказательство, не пересылая пароль по сети.
type HelloOk struct {
	ProtoVer    ProtocolVersion  // согласованная версия протокола
	ServerName  string           // самоназвание сервера
	AuthMode    AuthMode         // AuthNone (любой логин = admin) или AuthChallenge
	Challenge   Challenge        // случайный вызов для этого рукопожатия
	PBKDF2Iters PBKDF2Iterations // сколько итераций PBKDF2 применить к паролю
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

// AuthRequest — клиент присылает логин и доказательство знания пароля (SCRAM
// ClientProof, см. тип Proof). Сам пароль на проводе не появляется никогда.
type AuthRequest struct {
	Login string // учётная запись
	Proof Proof  // ClientProof = ClientKey XOR HMAC(StoredKey, challenge||login)
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

// AuthOk — сервер принял вход: сообщает выданную роль, номер сессии и
// приветствие (motd). После этого соединение переходит из HANDSHAKE в рабочее
// состояние и принимает все разрешённые роли сообщения.
type AuthOk struct {
	Role      Role      // выданный уровень доступа (user/admin)
	SessionID SessionID // номер сессии (для админского kick и списка клиентов)
	Motd      string    // «message of the day», приветствие
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

// AuthFail — сервер отклонил вход: код причины (неверный пароль, учётка
// отключена, IP забанен и т.п.) плюс текст. Провальные попытки и баны при этом
// ещё и аудируются на сервере.
type AuthFail struct {
	Reason  AuthFailReason // почему отказано (см. перечисление)
	Message string         // пояснение для человека
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

// ListDirRequest — клиент просит содержимое каталога Path (в терминах VFS,
// от корня раздачи).
type ListDirRequest struct{ Path Path }

func (ListDirRequest) Type() Msg          { return MsgListDirRequest }
func (m ListDirRequest) encode(w *writer) { w.str(m.Path) }
func decodeListDirRequest(r *reader) (ListDirRequest, error) {
	p, err := r.str(MaxPathLen)
	return ListDirRequest{Path: p}, err
}

// ListDirResponse — ответ на LIST_DIR: путь и список его записей. Это одно из
// немногих сообщений, которое может быть большим, поэтому у него отдельный
// лимит на число записей (MaxListEntries).
type ListDirResponse struct {
	Path    Path       // каталог, содержимое которого перечислено
	Entries []DirEntry // его записи (файлы и подкаталоги)
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

// StatRequest — клиент просит метаданные одной записи (файла или каталога).
type StatRequest struct{ Path Path }

func (StatRequest) Type() Msg          { return MsgStatRequest }
func (m StatRequest) encode(w *writer) { w.str(m.Path) }
func decodeStatRequest(r *reader) (StatRequest, error) {
	p, err := r.str(MaxPathLen)
	return StatRequest{Path: p}, err
}

// StatResponse — ответ на STAT: путь и одна DirEntry с его метаданными.
type StatResponse struct {
	Path  Path     // запрошенный путь
	Entry DirEntry // метаданные этой записи
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

// ChecksumRequest — клиент просит контрольную сумму файла. Сервер считает её
// ЛЕНИВО и кэширует по (path, size, mtime), поэтому первый запрос может быть
// дороже последующих.
type ChecksumRequest struct{ Path Path }

func (ChecksumRequest) Type() Msg          { return MsgChecksumRequest }
func (m ChecksumRequest) encode(w *writer) { w.str(m.Path) }
func decodeChecksumRequest(r *reader) (ChecksumRequest, error) {
	p, err := r.str(MaxPathLen)
	return ChecksumRequest{Path: p}, err
}

// ChecksumResponse — ответ на CHECKSUM: путь, алгоритм и сама сумма. Если сумма
// ещё считается, Algo может быть AlgoPending.
type ChecksumResponse struct {
	Path     Path     // файл, для которого посчитана сумма
	Algo     Algo     // алгоритм (CRC32 / SHA-256 / ещё считается)
	Checksum Checksum // значение суммы (для CRC32 значимы первые 4 байта)
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

// DownloadRequest — клиент просит скачать файл, начиная с Offset. Offset > 0 —
// это ДОКАЧКА: клиент уже имеет «<имя>.part» и хочет продолжить с места обрыва.
type DownloadRequest struct {
	Path   Path       // какой файл качать
	Offset ByteOffset // с какого байта начать (0 — сначала)
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

// DownloadAccept — сервер согласился отдать файл: назначает номер передачи и
// сообщает полный размер файла. Дальше идут CHUNK_DATA с этим же TransferID.
type DownloadAccept struct {
	TransferID TransferID // номер этой передачи (им же помечаются чанки и отмена)
	TotalSize  FileSize   // полный размер файла в байтах
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

// ChunkData несёт очередной кусок файла (до ChunkSize байт). Формат тела:
// transfer_id:u32, за ним СЫРЫЕ байты БЕЗ префикса длины — границу данных задаёт
// длина самого кадра. Это единственное сообщение, где полезная нагрузка не
// самоописываема по длине внутри тела.
type ChunkData struct {
	TransferID TransferID // к какой передаче относится кусок
	Data       []byte     // сырые байты файла (длину задаёт кадр)
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

// DownloadDone — сервер отдал файл целиком и прислал его контрольную сумму.
// Клиент сверяет её со своей: совпало — переименовывает «.part» в файл; нет —
// оставляет «.part» для повторной докачки.
type DownloadDone struct {
	TransferID TransferID // какая передача завершена
	Algo       Algo       // алгоритм контрольной суммы
	Checksum   Checksum   // сумма для сверки
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

// DownloadCancel — клиент просит прервать текущую передачу. Сервер отменит её,
// только если TransferID совпадает с активной, иначе отмена игнорируется, чтобы
// «поздняя» отмена не убила уже следующую передачу (R3-2).
type DownloadCancel struct{ TransferID TransferID }

func (DownloadCancel) Type() Msg          { return MsgDownloadCancel }
func (m DownloadCancel) encode(w *writer) { w.u32(m.TransferID) }
func decodeDownloadCancel(r *reader) (DownloadCancel, error) {
	id, err := r.u32()
	return DownloadCancel{TransferID: id}, err
}

// ---- Events ----

// Subscribe — клиент подписывается на push-события. Mask — комбинация битов
// SubFS / SubNotice / SubConfig: сервер будет слать только те события, чьи биты
// установлены.
type Subscribe struct{ Mask SubscriptionMask }

func (Subscribe) Type() Msg          { return MsgSubscribe }
func (m Subscribe) encode(w *writer) { w.u32(m.Mask) }
func decodeSubscribe(r *reader) (Subscribe, error) {
	mask, err := r.u32()
	return Subscribe{Mask: mask}, err
}

// EventFs — push-уведомление об изменении в раздаче: файл появился, изменился
// или удалён. Сервер рассылает его подписчикам (SubFS), чтобы TUI подсветил
// новое и обновил панель без ручного обновления.
type EventFs struct {
	Op    FsOp        // что произошло: создан / изменён / удалён
	Kind  Kind        // файл это был или директория
	Path  Path        // путь изменившейся записи
	Size  FileSize    // новый размер (для удаления не значим)
	Mtime UnixSeconds // новое время модификации
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

// EventNotice — произвольное текстовое уведомление сервера клиенту (SubNotice):
// например, предупреждение об скорой остановке. Severity задаёт цвет/важность.
type EventNotice struct {
	Severity Severity // info / warn / error
	Text     string   // текст уведомления
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

// EventConfig — push-уведомление о том, что админ поменял настройку (SubConfig).
// Клиенты узнают об изменении лимитов и т.п. без опроса.
type EventConfig struct {
	Key      string // какой параметр изменился, напр. «limits.per_client_bps»
	NewValue string // его новое значение (строкой)
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

// AdminGetConfig — админ запрашивает текущий эффективный конфиг. Тело пустое.
type AdminGetConfig struct{}

func (AdminGetConfig) Type() Msg        { return MsgAdminGetConfig }
func (AdminGetConfig) encode(w *writer) {}

// AdminConfig несёт действующий конфиг как JSON с префиксом длины u32 —
// единственное сообщение, которому разрешено превышать 64 КиБ
// (docs/tz/09-go-port.md §4.2).
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

// AdminSet — админ меняет одну настройку на лету. Сервер валидирует, атомарно
// подменяет снапшот настроек, пишет конфиг на диск и рассылает EventConfig.
type AdminSet struct {
	Key   string // имя параметра
	Value string // новое значение (строкой; сервер разберёт по типу параметра)
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

// AdminSetResult — результат ADMIN_SET: применилось ли изменение и пояснение
// (например, почему значение отвергнуто валидацией).
type AdminSetResult struct {
	OK      bool   // применилось ли
	Message string // пояснение
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

// AdminListClients — админ запрашивает список подключённых клиентов. Тело пустое;
// ответ — AdminClients.
type AdminListClients struct{}

func (AdminListClients) Type() Msg        { return MsgAdminListClients }
func (AdminListClients) encode(w *writer) {}

// ClientInfo — одна строка списка ADMIN_CLIENTS: сводка по подключённому
// клиенту, которую видит админ в панели (F9).
type ClientInfo struct {
	SessionID   SessionID      // номер сессии (по нему делают kick)
	Login       Login          // под какой учёткой вошёл
	IP          ClientAddr     // сетевой адрес
	Role        Role           // уровень доступа
	CurrentPath Path           // где сейчас «находится» (последний LIST_DIR)
	BytesSent   ByteCount      // сколько всего байт ему отдано
	SpeedBps    BytesPerSecond // текущая измеренная скорость
}

// AdminClients — ответ на ADMIN_LIST_CLIENTS: список сводок по всем сессиям.
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

// AdminKick — админ принудительно отключает сессию по её номеру.
type AdminKick struct{ SessionID SessionID }

func (AdminKick) Type() Msg          { return MsgAdminKick }
func (m AdminKick) encode(w *writer) { w.u64(m.SessionID) }
func decodeAdminKick(r *reader) (AdminKick, error) {
	id, err := r.u64()
	return AdminKick{SessionID: id}, err
}

// AdminKickResult — результат ADMIN_KICK: нашлась ли такая сессия и была ли
// отключена.
type AdminKickResult struct {
	OK      bool   // была ли сессия найдена и отключена
	Message string // пояснение
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

// AdminStats — админ запрашивает сводную статистику. Тело пустое; ответ —
// AdminStatsResponse.
type AdminStats struct{}

func (AdminStats) Type() Msg        { return MsgAdminStats }
func (AdminStats) encode(w *writer) {}

// AdminStatsResponse — сводная статистика сервера для админ-панели: время
// работы, суммарный трафик, число завершённых передач, активные соединения и
// закачки, сколько файлов раздаётся, текущие лимиты скорости и версия сервера.
type AdminStatsResponse struct {
	UptimeS         DurationSeconds // время работы демона, секунды
	BytesSent       ByteCount       // всего отдано байт с момента старта
	Completed       Count           // сколько передач завершено успешно
	ActiveConns     Count           // сейчас открытых сессий
	ActiveDownloads Count           // сейчас идущих закачек
	SharedFiles     Count           // сколько файлов в раздаче (обычных, не папок)
	PerClientBps    BytesPerSecond  // текущий лимит на одного клиента (0 — без лимита)
	GlobalBps       BytesPerSecond  // текущий общий лимит (0 — без лимита)
	Version         string          // версия сервера
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

// AdminShutdown — админ инициирует остановку сервера. GraceSeconds — сколько
// дать активным передачам доиграть перед принудительным закрытием сокетов.
type AdminShutdown struct{ GraceSeconds GracePeriodSeconds }

func (AdminShutdown) Type() Msg          { return MsgAdminShutdown }
func (m AdminShutdown) encode(w *writer) { w.u32(m.GraceSeconds) }
func decodeAdminShutdown(r *reader) (AdminShutdown, error) {
	g, err := r.u32()
	return AdminShutdown{GraceSeconds: g}, err
}

// AdminShutdownResult — подтверждение приёма ADMIN_SHUTDOWN: сервер начал
// graceful-остановку.
type AdminShutdownResult struct {
	OK      bool   // принята ли команда
	Message string // пояснение
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

// AdminReloadUsers — админ просит перечитать users.json без перезапуска. Сессии
// пользователей, ставших отключёнными/удалёнными, при этом сбрасываются.
type AdminReloadUsers struct{}

func (AdminReloadUsers) Type() Msg        { return MsgAdminReloadUsers }
func (AdminReloadUsers) encode(w *writer) {}

// AdminReloadUsersResult — результат ADMIN_RELOAD_USERS.
type AdminReloadUsersResult struct {
	OK      bool   // успешно ли перечитано
	Message string // пояснение (например, сколько учёток загружено)
}

func (AdminReloadUsersResult) Type() Msg { return MsgAdminReloadUsersRes }
func (m AdminReloadUsersResult) encode(w *writer) {
	w.u8(boolU8(m.OK))
	w.str(m.Message)
}
func decodeAdminReloadUsersResult(r *reader) (AdminReloadUsersResult, error) {
	var m AdminReloadUsersResult
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
