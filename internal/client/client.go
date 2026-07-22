// Package client — блокирующий транспорт протокола fileshare v2 для TUI и режима
// --batch. Он проводит рукопожатие, шлёт запросы, качает файлы с докачкой и
// прозрачно переправляет асинхронные кадры EVENT_*/PONG в обработчик событий,
// пока ждёт конкретный ответ (docs/tz/09-go-port.md §5.8).
//
// Правила конкурентности и словарь типов описаны в types.go.
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

// RemoteError — кадр ERROR, полученный от сервера (ошибка уровня приложения:
// файл не найден, нет прав и т.п.). Отдельно от сетевых ошибок Go.
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

// AuthError — кадр AUTH_FAIL от сервера (вход отклонён).
type AuthError struct {
	Reason  proto.AuthFailReason
	Message string
}

func (e *AuthError) Error() string { return fmt.Sprintf("authentication failed: %s", e.Message) }

// Options — параметры для Dial.
type Options struct {
	ClientName   ClientName
	Login        Login
	Password     Password
	EventHandler func(proto.Message) // принимает асинхронные кадры EVENT_*/PONG
	DialTimeout  DialTimeout
}

// Client — подключённый клиент протокола. Его ЗАПРОСНЫЕ методы нельзя вызывать
// конкурентно друг с другом (они по очереди пишут запрос и читают ответ из
// одного сокета), но Ping/Interrupt/Close можно звать из другой горутины.
type Client struct {
	conn net.Conn

	wmu          sync.Mutex // сериализует записи в сокет
	eventHandler func(proto.Message)

	role       proto.Role
	sessionID  SessionID
	serverName string
	motd       string
	authMode   proto.AuthMode
	iters      Iterations
}

// Dial соединяется с addr, проводит рукопожатие и аутентификацию и возвращает
// готовый клиент.
func Dial(addr ServerAddr, opts Options) (*Client, error) {
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

// maxAuthIters ограничивает число итераций PBKDF2, которое клиент выполнит по
// объявленному сервером значению, чтобы враждебный/MITM-сервер не загрузил CPU
// (CR-04).
const maxAuthIters = 10_000_000

// handshake проводит HELLO/AUTH поверх уже установленного сокета и возвращает
// готовый клиент. При сбое закрывает conn.
func handshake(conn net.Conn, opts Options) (*Client, error) {
	c := &Client{conn: conn, eventHandler: opts.EventHandler}

	// Ограничиваем всё рукопожатие по времени, чтобы молчащий/MITM-сервер не
	// подвесил клиента навсегда (CR-04); снимается после аутентификации.
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

	// Проверяем недоверенные параметры аутентификации ДО любой дорогой работы.
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

// isAsync сообщает, является ли m «внеполосным» кадром, который может прийти в
// любой момент (push-событие или PONG) и должен уйти в обработчик событий, а не
// быть принят за ответ на запрос.
func isAsync(m proto.Message) bool {
	switch m.(type) {
	case proto.EventFs, proto.EventNotice, proto.EventConfig, proto.Pong:
		return true
	}
	return false
}

// recvExpect читает кадры, пока не придёт кадр типа want, попутно отправляя
// async-кадры в обработчик событий и превращая ERROR в RemoteError. Это и есть
// «прозрачная маршрутизация»: события, пришедшие посреди ожидания ответа, не
// теряются и не путаются с ответом.
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

// ListDir перечисляет удалённый каталог, возвращая нормализованный путь и записи.
func (c *Client) ListDir(path Path) (string, []proto.DirEntry, error) {
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

// Stat возвращает метаданные одного удалённого пути.
func (c *Client) Stat(path Path) (string, proto.DirEntry, error) {
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

// Checksum запрашивает контрольную сумму удалённого файла (сервер считает её
// лениво с кэшем, поэтому первый запрос может быть дороже).
func (c *Client) Checksum(path Path) (proto.Algo, [proto.ChecksumLen]byte, error) {
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

// Subscribe задаёт маску подписки на события (какие push-события слать).
func (c *Client) Subscribe(mask uint32) error {
	return c.writeMsg(proto.Subscribe{Mask: mask})
}

// Ping шлёт keepalive. Ответный PONG будет поглощён как async-кадр ближайшим
// recvExpect или PollEvents.
func (c *Client) Ping() error { return c.writeMsg(proto.Ping{}) }

// frameReadTimeout bounds how long PollEvents will wait to finish a frame once
// its first byte has arrived. A well-behaved peer sends the small remainder of
// an event/pong frame in milliseconds; this only fires if a peer sends one byte
// then stalls without closing the socket, in which case PollEvents must not
// wedge the idle pump (and clientMu) forever (R4-1). It is a var so tests can
// shorten it.
var frameReadTimeout = 30 * time.Second

// PollEvents ждёт до timeout один асинхронный кадр (EVENT_*/PONG) и отправляет
// его в обработчик событий. Возвращает, был ли получен кадр; тайм-аут — это
// (false, nil). НЕ должен работать одновременно с запросным методом — все чтения
// принадлежат одной горутине (docs/tz/09-go-port.md §5.8).
//
// Тонкость десинхронизации: idle-дедлайн применяется только к ПЕРВОМУ байту
// следующего кадра, поэтому тайм-аут до прихода любого байта — это чистое «нет
// события», которое ничего не съедает и не рассинхронизирует следующий опрос
// (R3-7). Как только кадр начался, остаток читается под ограниченным
// frameReadTimeout, а не вечно; если он сработал — кадр прочитан частично, поток
// рассинхронизирован, поэтому соединение сбрасывается, а не переиспользуется (R4-1).
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

// Progress — прогресс скачивания (сколько получено из скольки всего), которым
// клиент кормит индикатор в UI.
type Progress struct {
	Received uint64
	Total    uint64
}

// Download — это DownloadCtx с фоновым контекстом (без отмены).
func (c *Client) Download(remotePath Path, localPath LocalPath, progress func(Progress)) error {
	return c.DownloadCtx(context.Background(), remotePath, localPath, progress)
}

// DownloadCtx качает remotePath в localPath, продолжая с localPath+".part", если
// такой есть (докачка). По завершении сверяет пересобранный файл с контрольной
// суммой всего файла от сервера и АТОМАРНО переименовывает «.part» на место.
// progress может быть nil. Отмена ctx прерывает передачу и возвращает ctx.Err():
// как только известен id передачи, шлётся DOWNLOAD_CANCEL с дочитыванием до
// терминального кадра сервера, чтобы соединение осталось пригодным (RR-3); до
// этого соединение сбрасывается — без id передачи его не ресинхронизировать (R4-2).
func (c *Client) DownloadCtx(ctx context.Context, remotePath Path, localPath LocalPath, progress func(Progress)) error {
	err := c.downloadOnce(ctx, remotePath, localPath, progress)

	// Устаревший/слишком большой offset у «.part» сервер отвергает: выбрасываем
	// «.part» и повторяем ОДИН раз с нуля. Удаление делает offset повтора равным 0,
	// который сервер уже не отвергнет как UNSUPPORTED_OFFSET, поэтому зацикливания
	// нет; если «.part» удалить не удалось — останавливаемся, а не рекурсируем вечно
	// (R4-4).
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

// downloadOnce выполняет ОДНУ попытку скачивания (без повтора по устаревшему
// offset). Следит за ctx на протяжении всей попытки, включая ожидание ACCEPT
// (R4-2), и через именованный возврат нормализует ошибку, вызванную отменой, к
// ctx.Err().
func (c *Client) downloadOnce(ctx context.Context, remotePath Path, localPath LocalPath, progress func(Progress)) (rerr error) {
	if err := ctx.Err(); err != nil {
		return err // уже отменено: ничего не шлём
	}

	partPath := localPath + ".part"
	var offset uint64
	if fi, err := os.Stat(partPath); err == nil && !fi.IsDir() {
		offset = uint64(fi.Size())
	}
	if err := os.MkdirAll(filepath.Dir(localPath), 0o755); err != nil {
		return err
	}

	// Следим за ctx всю попытку, включая ожидание ACCEPT. Пока id передачи
	// неизвестен, нельзя ни послать корректную отмену, ни дочитать до терминального
	// кадра, поэтому отмена тогда закрывает соединение, чтобы разблокировать
	// ожидание и прерваться (R4-2). Как только пришёл ACCEPT, наблюдатель
	// переключается на DOWNLOAD_CANCEL с id, который держит соединение в согласии
	// (RR-3, R3-2). Дожидаемся наблюдателя перед возвратом, чтобы отмена в самом
	// конце не «утекла» DOWNLOAD_CANCEL-ом в следующую передачу (R3-2).
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
			// Проверки целостности ПЕРЕД публикацией (CR-02): DONE должен быть для
			// этой передачи, все объявленные байты должны прийти, и он должен нести
			// поддерживаемую сумму, совпадающую с пересобранным файлом. Недобор байт
			// оставляет «.part» для докачки; несовпадение суммы удаляет его, чтобы не
			// зациклиться на битом «.part» полного размера.
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

// abortConn закрывает соединение и возвращает err. Используется, когда скачивание
// сбоит локально или сервер нарушает протокол посреди стрима: сервер может всё
// ещё слать CHUNK_DATA, поэтому единственный способ не дать следующему запросу
// прочитать чужие кадры — сбросить соединение (R3-3). Терминальные кадры сервера
// (DOWNLOAD_DONE / ERROR) оставляют соединение в согласии и сюда НЕ идут.
func (c *Client) abortConn(err error) error {
	c.conn.Close()
	return err
}

// Cancel просит сервер прервать активную передачу, НЕ закрывая соединение.
func (c *Client) Cancel(transferID proto.TransferID) error {
	return c.writeMsg(proto.DownloadCancel{TransferID: transferID})
}

// ---- админ-канал (role=admin) ----

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

// AdminReloadUsers asks the server to re-read users.json and drop the sessions
// of any now-disabled/removed user.
func (c *Client) AdminReloadUsers() (bool, string, error) {
	if err := c.writeMsg(proto.AdminReloadUsers{}); err != nil {
		return false, "", err
	}
	m, err := c.recvExpect(proto.MsgAdminReloadUsersRes)
	if err != nil {
		return false, "", err
	}
	r := m.(proto.AdminReloadUsersResult)
	return r.OK, r.Message, nil
}

// Interrupt из другой горутины разблокирует идущее чтение (например, чтобы выйти
// из TUI посреди скачивания), выставляя немедленный дедлайн чтения.
func (c *Client) Interrupt() {
	_ = c.conn.SetReadDeadline(time.Now())
}

// Close закрывает соединение.
func (c *Client) Close() error { return c.conn.Close() }

// checksumMismatch сообщает, отличается ли сумма файла от want, используя
// объявленный сервером алгоритм. Неподдерживаемый/отсутствующий алгоритм — ошибка.
// Учитывает ctx: сверка большого «.part» перечитывает весь файл, поэтому отмена во
// время неё прерывается сразу и возвращает ctx.Err() (R5-1). CRC-32 занимает
// первые 4 байта поля (big-endian), SHA-256 — все 32 — так держится совместимость
// с C++-сервером, настроенным на CRC32 (RR-2).
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
