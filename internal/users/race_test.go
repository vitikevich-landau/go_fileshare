package users_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/vitikevich-landau/go_fileshare/internal/domain"
	"github.com/vitikevich-landau/go_fileshare/internal/metadata"
	"github.com/vitikevich-landau/go_fileshare/internal/users"
)

// gatedShares — порт §7.4, который умеет ЗАДЕРЖАТЬ ровно одну фазу отзыва.
//
// Задержка по таймеру для этой проверки не годится: обе команды спали бы
// одинаково, порядок отзыва почти всегда повторял бы порядок commit'а, и тест
// проходил бы даже на сломанном коде. Поэтому первая же попытка перевести ссылки
// в hold сообщает о своём входе и ждёт разрешения — окно между commit'ом и
// отзывом открывается на столько, на сколько нужно тесту.
type gatedShares struct {
	hold    users.ShareState
	entered chan struct{}
	release chan struct{}

	once sync.Once
	mu   sync.Mutex
	last users.ShareState
}

func newGatedShares(hold users.ShareState) *gatedShares {
	return &gatedShares{
		hold:    hold,
		entered: make(chan struct{}),
		release: make(chan struct{}),
	}
}

func (g *gatedShares) SetUserShares(_ context.Context, _ domain.UserID, st users.ShareState) (int, error) {
	if st == g.hold {
		g.once.Do(func() {
			close(g.entered)
			<-g.release
		})
	}
	g.mu.Lock()
	g.last = st
	g.mu.Unlock()
	return 1, nil
}

func (g *gatedShares) lastState() users.ShareState {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.last
}

func (g *gatedShares) CloseUser(context.Context, domain.UserID) int  { return 0 }
func (g *gatedShares) Recompute(context.Context, domain.UserID) int  { return 0 }
func (g *gatedShares) RevokeUser(context.Context, domain.UserID) int { return 0 }

// rebuildWithShares собирает второй сервис поверх той же базы, но с другим
// портом §7.4: newEnv фиксирует spy, а этому тесту нужен порт, умеющий ждать.
func rebuildWithShares(t *testing.T, e *env, sh *gatedShares) *users.Service {
	t.Helper()
	svc, err := users.New(context.Background(), users.Config{
		DB:        e.db,
		Users:     e.repo,
		Resources: e.res,
		Layout:    e.layout,
		AuthIters: testAuthIters,
		Sessions:  sh,
		Tokens:    sh,
		Shares:    sh,
	})
	if err != nil {
		t.Fatalf("users.New: %v", err)
	}
	return svc
}

// TestConcurrentStateChangesDoNotReorderRevocation закрывает гонку §7.4: команда
// состоит из транзакции и следующей за ней фазы отзыва, а SQLite упорядочивает
// только первые половины.
//
// Сценарий подстроен так, чтобы сломанный код падал ДЕТЕРМИНИРОВАННО: `enable`
// коммитит active и застревает внутри отзыва; пока он стоит, стартует `disable`.
// Без per-user замка `disable` успевает закоммитить disabled и перевести ссылки в
// suspended, после чего отпущенный `enable` возвращает их в active — БД говорит
// «отключён», обе команды вернули успех, а публичные ссылки продолжают работать.
// С замком `disable` ждёт на входе, и порядок отзыва повторяет порядок commit'а.
func TestConcurrentStateChangesDoNotReorderRevocation(t *testing.T) {
	t.Parallel()

	e := newEnv(t)
	sh := newGatedShares(users.ShareActive)
	svc := rebuildWithShares(t, e, sh)

	// Инвариант 13 (§2.2, §7.4) проверяется В транзакции SetState, а миграция
	// заводит только системный аккаунт, и тот disabled. Без живого администратора
	// обе команды откатились бы по LAST_ADMIN_REQUIRED, и гонка осталась бы
	// непроверенной при зелёном тесте.
	e.seed(t, metadata.NewUser{
		Login:  "root",
		Role:   domain.RoleAdmin,
		State:  domain.UserActive,
		Secret: secretFor("root", "pw"),
	})
	u := e.seed(t, metadata.NewUser{
		Login:  "racer",
		Role:   domain.RoleUser,
		State:  domain.UserActive,
		Secret: secretFor("racer", "pw"),
	})

	ctx := context.Background()
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := svc.SetState(ctx, u.ID, domain.UserActive); err != nil {
			t.Errorf("SetState(active): %v", err)
		}
	}()

	// enable закоммитил active и стоит внутри фазы отзыва.
	<-sh.entered

	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := svc.SetState(ctx, u.ID, domain.UserDisabled); err != nil {
			t.Errorf("SetState(disabled): %v", err)
		}
	}()

	// Форы достаточно, чтобы disable дошёл до конца, если его никто не держит.
	// С замком он стоит на acquire, и фора ничего не меняет.
	time.Sleep(100 * time.Millisecond)
	close(sh.release)
	wg.Wait()

	got, err := svc.ByID(ctx, u.ID)
	if err != nil {
		t.Fatalf("ByID: %v", err)
	}
	want := users.ShareActive
	if got.State == domain.UserDisabled {
		want = users.ShareSuspended
	}
	if last := sh.lastState(); last != want {
		t.Fatalf("пользователь в состоянии %q, ссылки оставлены в %q, ожидалось %q — "+
			"фаза отзыва разошлась с порядком commit'а (§7.4)", got.State, last, want)
	}
}
