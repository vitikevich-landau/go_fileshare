package server

import (
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/vitikevich-landau/go_fileshare/internal/proto"
)

// writeDeadline ограничивает одну запись в сокет, чтобы застрявший клиент не
// заклинил горутину-писателя навсегда.
const writeDeadline = 30 * time.Second

// flushTimeout ограничивает, сколько teardown ждёт, пока писатель дошлёт
// накопленные кадры, перед принудительным закрытием сокета.
const flushTimeout = 2 * time.Second

// idleCheckInterval — как часто «сторож простоя» переоценивает соединение.
const idleCheckInterval = time.Second

// outBuffer — глубина исходящей очереди на сессию.
const outBuffer = 64

var emptyPath = ""

// Session — один подключённый клиент. Исходящие кадры идут через канал out,
// который вычитывает ЕДИНСТВЕННАЯ горутина-писатель: поэтому записи
// сериализованы (кадры атомарны на проводе), а медленный клиент создаёт
// backpressure только собственным передачам — рассылки шлются НЕблокирующе и
// отбрасываются, а не тормозят остальных (docs/tz/09-go-port.md §5.5).
//
// Часть полей защищена мьютексом mu (login/role/authed/cancel*), часть —
// атомарные (subMask/bytes/curPath/downloading/inFlight/lastActivity), чтобы
// читаться на горячем пути без блокировок.
type Session struct {
	ID   SessionID
	IP   ClientIP
	conn net.Conn

	out  chan []byte     // очередь исходящих кадров (читает writeLoop)
	done chan struct{}   // закрывается при teardown — сигнал всем горутинам сессии
	wg   *sync.WaitGroup // фоновые горутины (писатель + активная закачка)

	challenge []byte // выдан во время рукопожатия

	mu        sync.Mutex
	login     string
	role      proto.Role
	authed    bool
	cancelDL  chan struct{} // закрытие отменяет активную закачку
	cancelTID TransferID    // id передачи, которой принадлежит канал отмены (R3-2)

	subMask      atomic.Uint32          // маска подписки на события
	bytes        atomic.Uint64          // отдано байт этому клиенту
	curPath      atomic.Pointer[string] // где клиент «находится» (последний LIST_DIR)
	downloading  atomic.Bool            // идёт ли сейчас закачка
	inFlight     atomic.Bool            // выполняется ли обработчик запроса (R3-6)
	lastActivity atomic.Int64           // unix-нс последней активности (для сторожа простоя)
	startedAt    time.Time
}

func newSession(id SessionID, conn net.Conn, ip ClientIP, wg *sync.WaitGroup) *Session {
	s := &Session{
		ID:        id,
		IP:        ip,
		conn:      conn,
		out:       make(chan []byte, outBuffer),
		done:      make(chan struct{}),
		wg:        wg,
		startedAt: time.Now(),
	}
	s.curPath.Store(&emptyPath)
	s.lastActivity.Store(time.Now().UnixNano())
	return s
}

// touch отмечает активность для сторожа простоя.
func (s *Session) touch() { s.lastActivity.Store(time.Now().UnixNano()) }

// idleFor сообщает, как долго сессия была без активности.
func (s *Session) idleFor() time.Duration {
	return time.Since(time.Unix(0, s.lastActivity.Load()))
}

// send кладёт кадр в очередь, БЛОКИРУЯСЬ для backpressure, пока кадр не примут
// или пока сессию не начнут закрывать (тогда возвращает false). Так медленный
// клиент притормаживает свои же передачи, а не теряет кадры.
func (s *Session) send(frame []byte) bool {
	select {
	case s.out <- frame:
		return true
	case <-s.done:
		return false
	}
}

// trySend кладёт кадр в очередь БЕЗ блокировки, отбрасывая его, если очередь
// полна. Используется для рассылок, чтобы один медленный клиент не задержал
// доставку остальным.
func (s *Session) trySend(frame []byte) bool {
	select {
	case s.out <- frame:
		return true
	default:
		return false
	}
}

func (s *Session) sendMsg(m proto.Message) bool    { return s.send(proto.Encode(m)) }
func (s *Session) trySendMsg(m proto.Message) bool { return s.trySend(proto.Encode(m)) }

// writeLoop сливает очередь out в сокет, пока сессию не начнут закрывать, затем
// по мере сил дошлёт всё, что ещё осталось в очереди (например, финальный
// AUTH_FAIL/ERROR). Это единственное место, которое пишет в сокет.
func (s *Session) writeLoop() {
	for {
		select {
		case frame := <-s.out:
			if !s.writeFrame(frame) {
				return
			}
		case <-s.done:
			for {
				select {
				case frame := <-s.out:
					if !s.writeFrame(frame) {
						return
					}
				default:
					return
				}
			}
		}
	}
}

func (s *Session) writeFrame(frame []byte) bool {
	_ = s.conn.SetWriteDeadline(time.Now().Add(writeDeadline))
	if _, err := s.conn.Write(frame); err != nil {
		s.conn.Close() // на мёртвом сокете закрываем, чтобы разблокировать читателя
		return false
	}
	return true
}

func (s *Session) setAuthed(login string, role proto.Role) {
	s.mu.Lock()
	s.login = login
	s.role = role
	s.authed = true
	s.mu.Unlock()
}

func (s *Session) Login() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.login
}

func (s *Session) Role() proto.Role {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.role
}

func (s *Session) Authed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.authed
}

// setCancel устанавливает канал отмены для активной закачки и запоминает id
// передачи, которому он принадлежит, чтобы запрос отмены можно было сопоставить
// именно с ней (R3-2).
func (s *Session) setCancel(tid TransferID, c chan struct{}) {
	s.mu.Lock()
	s.cancelDL = c
	s.cancelTID = tid
	s.mu.Unlock()
}

// clearCancel сбрасывает канал отмены после завершения передачи, чтобы
// «запоздавший» DOWNLOAD_CANCEL не задел следующую передачу (R3-2).
func (s *Session) clearCancel() {
	s.mu.Lock()
	s.cancelDL = nil
	s.cancelTID = 0
	s.mu.Unlock()
}

// cancelDownload закрывает канал отмены активной закачки, но ТОЛЬКО если tid
// совпадает с активной передачей. Случайная или запоздавшая отмена для другой
// (например, уже завершённой) передачи игнорируется, чтобы не оборвать не ту
// (R3-2). Возвращает, была ли отмена действительно доставлена.
func (s *Session) cancelDownload(tid TransferID) bool {
	s.mu.Lock()
	c := s.cancelDL
	if c == nil || s.cancelTID != tid {
		s.mu.Unlock()
		return false
	}
	s.cancelDL = nil
	s.mu.Unlock()
	close(c)
	return true
}

func (s *Session) setCurPath(p string) { s.curPath.Store(&p) }
func (s *Session) clearCurPath()       { s.curPath.Store(&emptyPath) }
func (s *Session) CurPath() string {
	if p := s.curPath.Load(); p != nil {
		return *p
	}
	return ""
}

// Registry отслеживает живые сессии (по SessionID). Безопасен для конкурентного
// доступа: диспетчер, рассылки, админ-kick и сторож простоя обращаются к нему из
// разных горутин.
type Registry struct {
	mu       sync.Mutex
	sessions map[uint64]*Session
}

func NewRegistry() *Registry { return &Registry{sessions: map[uint64]*Session{}} }

func (r *Registry) add(s *Session) {
	r.mu.Lock()
	r.sessions[s.ID] = s
	r.mu.Unlock()
}

func (r *Registry) remove(id uint64) {
	r.mu.Lock()
	delete(r.sessions, id)
	r.mu.Unlock()
}

func (r *Registry) get(id uint64) (*Session, bool) {
	r.mu.Lock()
	s, ok := r.sessions[id]
	r.mu.Unlock()
	return s, ok
}

func (r *Registry) list() []*Session {
	r.mu.Lock()
	out := make([]*Session, 0, len(r.sessions))
	for _, s := range r.sessions {
		out = append(out, s)
	}
	r.mu.Unlock()
	return out
}

func (r *Registry) count() int {
	r.mu.Lock()
	n := len(r.sessions)
	r.mu.Unlock()
	return n
}

// reserveUserSlot АТОМАРНО проверяет лимит сессий на пользователя и, если место
// есть, помечает sess аутентифицированной — так параллельные рукопожатия одного
// пользователя не смогут все проскочить проверку до того, как хоть одно
// зафиксируется (CR-06). max <= 0 означает «без лимита». Возвращает, выдан ли слот.
func (r *Registry) reserveUserSlot(sess *Session, login string, role proto.Role, max int) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if max > 0 {
		n := 0
		for _, s := range r.sessions {
			if s != sess && s.Authed() && s.Login() == login {
				n++
			}
		}
		if n >= max {
			return false
		}
	}
	sess.setAuthed(login, role)
	return true
}

// closeAll принудительно закрывает сокеты всех сессий (используется при остановке
// после истечения grace-периода).
func (r *Registry) closeAll() {
	for _, s := range r.list() {
		s.conn.Close()
	}
}

// broadcast кладёт frame в очередь каждой сессии, подписанной на любой бит в mask,
// НЕблокирующей отправкой — так тормозящий клиент не задержит доставку остальным
// (docs/tz/09-go-port.md §5.5).
func (r *Registry) broadcast(mask uint32, frame []byte) {
	for _, s := range r.list() {
		if s.subMask.Load()&mask != 0 {
			s.trySend(frame)
		}
	}
}
