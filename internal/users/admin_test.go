package users_test

import (
	"bytes"
	"context"
	"errors"
	"math"
	"slices"
	"testing"

	"github.com/vitikevich-landau/go_fileshare/internal/domain"
	"github.com/vitikevich-landau/go_fileshare/internal/users"
)

// admin создаёт активного администратора. Без него инвариант 13 (§2.2 п. 13)
// отклоняет почти каждую операцию — и правильно: установка без активного
// администратора работать не имеет права (§7.5).
func (e *env) admin(t *testing.T, login string) users.User {
	t.Helper()
	u, err := e.svc.Create(context.Background(), users.CreateUser{
		Login:  login,
		Role:   domain.RoleAdmin,
		Secret: users.NewSecret{Password: "admin-password"},
	})
	if err != nil {
		t.Fatalf("Create(%q admin): %v", login, err)
	}
	e.spy.reset()
	return u
}

func (e *env) member(t *testing.T, login, password string) users.User {
	t.Helper()
	u, err := e.svc.Create(context.Background(), users.CreateUser{
		Login:  login,
		Role:   domain.RoleUser,
		Secret: users.NewSecret{Password: password},
	})
	if err != nil {
		t.Fatalf("Create(%q): %v", login, err)
	}
	e.spy.reset()
	return u
}

// state читает состояние пользователя мимо сервиса: тесты обязаны проверять
// зафиксированную строку, а не то, что вернул метод.
func (e *env) state(t *testing.T, id domain.UserID) domain.UserState {
	t.Helper()
	u, err := e.repo.ByID(context.Background(), id)
	if err != nil {
		t.Fatalf("ByID(%d): %v", id, err)
	}
	return u.State
}

// TestCreateStoresLegacySalt — долг PR2 закрыт: соль вычисляет сервис и она
// детерминирована (§6.2 п. 1–2). Проверяется не только значение в колонке, но и
// главное следствие: клиент, выводящий соль САМ из логина, входит этим паролем.
func TestCreateStoresLegacySalt(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	const password = "s3cret"

	u := e.admin(t, "root")
	row, err := e.repo.ByID(ctx, u.ID)
	if err != nil {
		t.Fatalf("ByID: %v", err)
	}
	if !bytes.Equal(row.Secret.Salt, domain.LegacySalt("root")) {
		t.Errorf("salt = %q, want %q (§6.2 п. 2)", row.Secret.Salt, domain.LegacySalt("root"))
	}
	if row.Secret.AuthIters != testAuthIters {
		t.Errorf("auth_iters = %d, want %d (§6.2 п. 3)", row.Secret.AuthIters, testAuthIters)
	}
	if row.Secret.KDFAlgo != domain.KDFPBKDF2SHA256 || row.Secret.KDFParams != "" {
		t.Errorf("kdf = %q/%q, want pbkdf2-sha256 и NULL (§6.2 п. 4)",
			row.Secret.KDFAlgo, row.Secret.KDFParams)
	}

	m := e.member(t, "alice", password)
	challenge := []byte("0123456789abcdef")
	got, err := e.svc.Authenticate(ctx, users.AuthAttempt{
		Login: "alice", Challenge: challenge, Proof: proofFor("alice", password, challenge)})
	if err != nil {
		t.Fatalf("созданный пользователь не может войти своим паролем: %v", err)
	}
	if got.ID != m.ID {
		t.Errorf("Authenticate вернул id %d, ожидался %d", got.ID, m.ID)
	}
}

// TestCreateRejects — таблица отказов `user add`. Каждая строка нарушает ровно
// одно правило и обязана дать класс, который граница server переводит в
// BAD_REQUEST или в собственный код.
func TestCreateRejects(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	e.admin(t, "root")
	e.member(t, "alice", "pw")

	tests := []struct {
		name string
		in   users.CreateUser
		want error
	}{
		{
			name: "пустой пароль",
			in:   users.CreateUser{Login: "bob", Role: domain.RoleUser},
			want: users.ErrBadRequest,
		},
		{
			name: "чужое auth_iters",
			in: users.CreateUser{Login: "bob", Role: domain.RoleUser,
				Secret: users.NewSecret{Password: "pw", AuthIters: testAuthIters * 2}},
			want: users.ErrBadRequest,
		},
		{
			name: "argon2id без верификатора",
			in: users.CreateUser{Login: "bob", Role: domain.RoleUser,
				Secret: users.NewSecret{Password: "pw", KDFAlgo: domain.KDFArgon2id}},
			want: users.ErrBadRequest,
		},
		{
			name: "роль вне словаря",
			in: users.CreateUser{Login: "bob", Role: domain.Role("root"),
				Secret: users.NewSecret{Password: "pw"}},
			want: users.ErrBadRequest,
		},
		{
			name: "создание сразу в pending_delete",
			in: users.CreateUser{Login: "bob", Role: domain.RoleUser, State: domain.UserPendingDelete,
				Secret: users.NewSecret{Password: "pw"}},
			want: users.ErrBadRequest,
		},
		{
			name: "квота выше вместимости колонки",
			in: users.CreateUser{Login: "bob", Role: domain.RoleUser, QuotaBytes: math.MaxUint64,
				Secret: users.NewSecret{Password: "pw"}},
			want: users.ErrBadRequest,
		},
		{
			name: "занятый логин",
			in: users.CreateUser{Login: "alice", Role: domain.RoleUser,
				Secret: users.NewSecret{Password: "pw"}},
			want: users.ErrLoginExists,
		},
		{
			name: "логин системного аккаунта",
			in: users.CreateUser{Login: domain.SystemLogin, Role: domain.RoleUser,
				Secret: users.NewSecret{Password: "pw"}},
			want: users.ErrLoginExists,
		},
		{
			name: "пустой логин",
			in: users.CreateUser{Login: "", Role: domain.RoleUser,
				Secret: users.NewSecret{Password: "pw"}},
			want: users.ErrInvalidLogin,
		},
		{
			name: "логин с переводом строки",
			in: users.CreateUser{Login: "a\nb", Role: domain.RoleUser,
				Secret: users.NewSecret{Password: "pw"}},
			want: users.ErrInvalidLogin,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := e.svc.Create(ctx, tt.in); !errors.Is(err, tt.want) {
				t.Fatalf("Create вернул %v, ожидалась %v", err, tt.want)
			}
		})
	}
}

// TestRevocationTablePerOperation — наблюдаемое поведение таблицы §7.4: для
// каждой операции проверяется, что сервис вызвал ровно те реестры, которые
// перечисляет документ, и в том порядке, в котором живой доступ отнимается
// раньше остального.
func TestRevocationTablePerOperation(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name string
		// run выполняет операцию над пользователем u (не администратором).
		run  func(t *testing.T, e *env, u users.User)
		want []string
	}{
		{
			name: "user disable",
			run: func(t *testing.T, e *env, u users.User) {
				if err := e.svc.SetState(ctx, u.ID, domain.UserDisabled); err != nil {
					t.Fatalf("SetState(disabled): %v", err)
				}
			},
			want: []string{"sessions.close", "tokens.revoke", "shares.suspended"},
		},
		{
			name: "user enable",
			run: func(t *testing.T, e *env, u users.User) {
				if err := e.svc.SetState(ctx, u.ID, domain.UserDisabled); err != nil {
					t.Fatalf("SetState(disabled): %v", err)
				}
				e.spy.reset()
				if err := e.svc.SetState(ctx, u.ID, domain.UserActive); err != nil {
					t.Fatalf("SetState(active): %v", err)
				}
			},
			want: []string{"shares.active"},
		},
		{
			name: "user passwd",
			run: func(t *testing.T, e *env, u users.User) {
				if err := e.svc.SetPassword(ctx, u.ID, users.NewSecret{Password: "new-password"}); err != nil {
					t.Fatalf("SetPassword: %v", err)
				}
			},
			want: []string{"sessions.close", "tokens.revoke"},
		},
		{
			name: "user role",
			run: func(t *testing.T, e *env, u users.User) {
				if err := e.svc.SetRole(ctx, u.ID, domain.RoleAdmin); err != nil {
					t.Fatalf("SetRole: %v", err)
				}
			},
			want: []string{"sessions.recompute", "tokens.revoke"},
		},
		{
			name: "user quota",
			run: func(t *testing.T, e *env, u users.User) {
				if err := e.svc.SetQuota(ctx, u.ID, 20<<30); err != nil {
					t.Fatalf("SetQuota: %v", err)
				}
			},
			want: []string{"sessions.recompute"},
		},
		{
			name: "user delete",
			run: func(t *testing.T, e *env, u users.User) {
				if err := e.svc.SetState(ctx, u.ID, domain.UserPendingDelete); err != nil {
					t.Fatalf("SetState(pending_delete): %v", err)
				}
			},
			want: []string{"sessions.close", "tokens.revoke", "shares.revoked"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := newEnv(t)
			e.admin(t, "root")
			u := e.member(t, "alice", "pw")

			tt.run(t, e, u)

			if got := e.spy.log(); !slices.Equal(got, tt.want) {
				t.Fatalf("вызовы реестров = %v, таблица §7.4 требует %v", got, tt.want)
			}
		})
	}
}

// TestFailedOperationRevokesNothing — §7.4: отклонённая операция «состояние не
// меняет и сессии не рвёт». Проверяется на инварианте последнего администратора:
// именно он отклоняет операцию ПОСЛЕ того, как строка уже изменена в транзакции,
// поэтому это же и проверка того, что откат случился до отзыва.
func TestFailedOperationRevokesNothing(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	root := e.admin(t, "root")

	if err := e.svc.SetState(ctx, root.ID, domain.UserDisabled); !errors.Is(err, users.ErrLastAdminRequired) {
		t.Fatalf("SetState вернул %v, ожидалась ErrLastAdminRequired", err)
	}
	if got := e.state(t, root.ID); got != domain.UserActive {
		t.Errorf("состояние изменилось на %q, хотя операция отклонена", got)
	}
	if got := e.spy.log(); len(got) != 0 {
		t.Errorf("отклонённая операция обратилась к реестрам: %v", got)
	}
}

// TestLastAdminInvariant — инвариант 13 (§2.2 п. 13, §7.4): операции disable,
// delete и понижение роли отклоняются кодом LAST_ADMIN_REQUIRED, если опустошили
// бы множество активных администраторов.
func TestLastAdminInvariant(t *testing.T) {
	ctx := context.Background()

	tests := map[string]func(e *env, root users.User) error{
		"disable последнего администратора": func(e *env, root users.User) error {
			return e.svc.SetState(ctx, root.ID, domain.UserDisabled)
		},
		"delete последнего администратора": func(e *env, root users.User) error {
			return e.svc.SetState(ctx, root.ID, domain.UserPendingDelete)
		},
		"понижение роли последнего администратора": func(e *env, root users.User) error {
			return e.svc.SetRole(ctx, root.ID, domain.RoleUser)
		},
	}
	for name, op := range tests {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			root := e.admin(t, "root")
			// Обычный пользователь администратором не считается: множество
			// проверяется по паре (role = admin, state = active).
			e.member(t, "alice", "pw")

			if err := op(e, root); !errors.Is(err, users.ErrLastAdminRequired) {
				t.Fatalf("операция вернула %v, ожидалась ErrLastAdminRequired", err)
			}
		})
	}
}

// TestSecondAdminLiftsTheInvariant — инвариант запрещает опустошить множество, а
// не менять администраторов: при двух активных администраторах те же операции
// проходят.
func TestSecondAdminLiftsTheInvariant(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	first := e.admin(t, "root")
	e.admin(t, "second")

	if err := e.svc.SetRole(ctx, first.ID, domain.RoleUser); err != nil {
		t.Fatalf("SetRole при двух администраторах: %v", err)
	}
	if err := e.svc.SetState(ctx, first.ID, domain.UserDisabled); err != nil {
		t.Fatalf("SetState при живом втором администраторе: %v", err)
	}
}

// TestDisabledAdminDoesNotCount — §7.5: администратора в состоянии disabled или
// pending_delete для старта недостаточно, значит, и в множество инварианта 13 он
// не входит.
func TestDisabledAdminDoesNotCount(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	root := e.admin(t, "root")
	spare := e.admin(t, "spare")

	if err := e.svc.SetState(ctx, spare.ID, domain.UserDisabled); err != nil {
		t.Fatalf("SetState(spare, disabled): %v", err)
	}
	if err := e.svc.SetState(ctx, root.ID, domain.UserDisabled); !errors.Is(err, users.ErrLastAdminRequired) {
		t.Fatalf("отключённый администратор зачтён как активный: %v", err)
	}
}

// TestStateTransitions — §24.1 п. 6 для users.state: каждый недопустимый переход
// отвергается, терминальное состояние необратимо.
func TestStateTransitions(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name string
		from domain.UserState
		to   domain.UserState
		ok   bool
	}{
		{"active -> disabled", domain.UserActive, domain.UserDisabled, true},
		{"active -> pending_delete", domain.UserActive, domain.UserPendingDelete, true},
		{"disabled -> active", domain.UserDisabled, domain.UserActive, true},
		{"disabled -> pending_delete", domain.UserDisabled, domain.UserPendingDelete, true},
		{"pending_delete -> active", domain.UserPendingDelete, domain.UserActive, false},
		{"pending_delete -> disabled", domain.UserPendingDelete, domain.UserDisabled, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := newEnv(t)
			e.admin(t, "root")
			u := e.member(t, "alice", "pw")

			if tt.from != domain.UserActive {
				if err := e.svc.SetState(ctx, u.ID, tt.from); err != nil {
					t.Fatalf("подготовка состояния %q: %v", tt.from, err)
				}
			}
			err := e.svc.SetState(ctx, u.ID, tt.to)
			switch {
			case tt.ok && err != nil:
				t.Fatalf("переход %q -> %q отвергнут: %v", tt.from, tt.to, err)
			case !tt.ok && !errors.Is(err, users.ErrBadRequest):
				t.Fatalf("переход %q -> %q дал %v, ожидалась ErrBadRequest", tt.from, tt.to, err)
			}
			if !tt.ok && e.state(t, u.ID) != tt.from {
				t.Errorf("недопустимый переход изменил состояние")
			}
		})
	}
}

// TestRepeatedDisableReappliesRevocation — перевод в то же состояние разрешён и
// заново применяет таблицу §7.4. Так операция, прерванная между commit и отзывом
// (падение процесса), доводится повторным запуском команды.
func TestRepeatedDisableReappliesRevocation(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	e.admin(t, "root")
	u := e.member(t, "alice", "pw")

	if err := e.svc.SetState(ctx, u.ID, domain.UserDisabled); err != nil {
		t.Fatalf("первый disable: %v", err)
	}
	e.spy.reset()
	if err := e.svc.SetState(ctx, u.ID, domain.UserDisabled); err != nil {
		t.Fatalf("повторный disable: %v", err)
	}
	want := []string{"sessions.close", "tokens.revoke", "shares.suspended"}
	if got := e.spy.log(); !slices.Equal(got, want) {
		t.Errorf("повторный disable вызвал %v, ожидалось %v", got, want)
	}
}

// TestSetPasswordChangesTheVerifier — новый пароль работает, прежний перестаёт, а
// соль остаётся производной от логина (§6.2 п. 2): её смена обесценила бы
// stored_key для клиента, который выводит соль сам.
func TestSetPasswordChangesTheVerifier(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	e.admin(t, "root")
	u := e.member(t, "alice", "old-password")
	challenge := []byte("0123456789abcdef")

	if err := e.svc.SetPassword(ctx, u.ID, users.NewSecret{Password: "new-password"}); err != nil {
		t.Fatalf("SetPassword: %v", err)
	}

	if _, err := e.svc.Authenticate(ctx, users.AuthAttempt{
		Login: "alice", Challenge: challenge, Proof: proofFor("alice", "new-password", challenge),
	}); err != nil {
		t.Errorf("новый пароль не подошёл: %v", err)
	}
	if _, err := e.svc.Authenticate(ctx, users.AuthAttempt{
		Login: "alice", Challenge: challenge, Proof: proofFor("alice", "old-password", challenge),
	}); !errors.Is(err, users.ErrBadCredentials) {
		t.Errorf("прежний пароль всё ещё подходит: %v", err)
	}

	row, err := e.repo.ByID(ctx, u.ID)
	if err != nil {
		t.Fatalf("ByID: %v", err)
	}
	if !bytes.Equal(row.Secret.Salt, domain.LegacySalt("alice")) {
		t.Errorf("salt = %q, want %q (§6.2 п. 2)", row.Secret.Salt, domain.LegacySalt("alice"))
	}
	if row.Secret.AuthIters != testAuthIters {
		t.Errorf("auth_iters = %d, want %d (§6.2 п. 3)", row.Secret.AuthIters, testAuthIters)
	}
}

// TestSetPasswordRejectsForeignParameters — §3.3: `user passwd` не вправе задать
// иное auth_iters, пока нет канала доставки параметров, и обязан ответить
// BAD_REQUEST, а не применить значение молча.
func TestSetPasswordRejectsForeignParameters(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	e.admin(t, "root")
	u := e.member(t, "alice", "pw")

	tests := map[string]users.NewSecret{
		"чужое auth_iters": {Password: "new", AuthIters: testAuthIters * 2},
		"argon2id":         {Password: "new", KDFAlgo: domain.KDFArgon2id},
		"пустой пароль":    {Password: ""},
	}
	for name, in := range tests {
		t.Run(name, func(t *testing.T) {
			if err := e.svc.SetPassword(ctx, u.ID, in); !errors.Is(err, users.ErrBadRequest) {
				t.Fatalf("SetPassword вернул %v, ожидалась ErrBadRequest", err)
			}
			if got := e.spy.log(); len(got) != 0 {
				t.Errorf("отклонённый passwd обратился к реестрам: %v", got)
			}
		})
	}

	// Прежний пароль обязан продолжать работать: отклонённая операция ничего не
	// меняет.
	challenge := []byte("0123456789abcdef")
	if _, err := e.svc.Authenticate(ctx, users.AuthAttempt{
		Login: "alice", Challenge: challenge, Proof: proofFor("alice", "pw", challenge),
	}); err != nil {
		t.Errorf("прежний пароль перестал работать после отклонённого passwd: %v", err)
	}
}

// TestQuota — SetQuota записывает значение, Quota его читает, ноль означает
// unlimited (§6.2), значение выше вместимости колонки отвергается.
func TestQuota(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	e.admin(t, "root")
	u := e.member(t, "alice", "pw")

	if err := e.svc.SetQuota(ctx, u.ID, 20<<30); err != nil {
		t.Fatalf("SetQuota: %v", err)
	}
	q, err := e.svc.Quota(ctx, u.ID)
	if err != nil {
		t.Fatalf("Quota: %v", err)
	}
	if q.QuotaBytes != 20<<30 || q.Unlimited() {
		t.Errorf("Quota = %+v", q)
	}
	if q.UsedBytes != 0 || q.ReservedBytes != 0 {
		t.Errorf("счётчики нового пользователя = %+v, ожидались нули (§11.4)", q)
	}

	if err := e.svc.SetQuota(ctx, u.ID, 0); err != nil {
		t.Fatalf("SetQuota(0): %v", err)
	}
	if q, err := e.svc.Quota(ctx, u.ID); err != nil || !q.Unlimited() {
		t.Errorf("Quota после обнуления = %+v, err = %v", q, err)
	}

	if err := e.svc.SetQuota(ctx, u.ID, math.MaxUint64); !errors.Is(err, users.ErrBadRequest) {
		t.Errorf("SetQuota(MaxUint64) вернул %v, ожидалась ErrBadRequest", err)
	}
}

// TestSystemAccountIsNotAdministrable — §6.2: системный аккаунт не
// администрируется командами §7.4. Он владеет public-ресурсами, переданными при
// purge их прежних владельцев, и его состояние, роль и квота заданы схемой.
func TestSystemAccountIsNotAdministrable(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	e.admin(t, "root")

	tests := map[string]func() error{
		"SetState":    func() error { return e.svc.SetState(ctx, domain.SystemUserID, domain.UserActive) },
		"SetRole":     func() error { return e.svc.SetRole(ctx, domain.SystemUserID, domain.RoleUser) },
		"SetPassword": func() error { return e.svc.SetPassword(ctx, domain.SystemUserID, users.NewSecret{Password: "pw"}) },
		"SetQuota":    func() error { return e.svc.SetQuota(ctx, domain.SystemUserID, 1<<30) },
	}
	for name, op := range tests {
		t.Run(name, func(t *testing.T) {
			if err := op(); !errors.Is(err, users.ErrSystemAccount) {
				t.Fatalf("%s вернул %v, ожидалась ErrSystemAccount", name, err)
			}
			if got := e.spy.log(); len(got) != 0 {
				t.Errorf("операция над системным аккаунтом обратилась к реестрам: %v", got)
			}
		})
	}

	// Состояние системной записи не изменилось ни одной из попыток.
	if got := e.state(t, domain.SystemUserID); got != domain.UserDisabled {
		t.Errorf("состояние системного аккаунта = %q, want disabled (§6.2)", got)
	}
}

// TestOperationsOnMissingUser — операции над несуществующим идентификатором дают
// ErrNotFound, а не молчаливый успех: UPDATE, не затронувший строк, иначе
// выглядел бы как выполненная команда.
func TestOperationsOnMissingUser(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	e.admin(t, "root")
	const missing = domain.UserID(4242)

	tests := map[string]func() error{
		"SetState":    func() error { return e.svc.SetState(ctx, missing, domain.UserDisabled) },
		"SetRole":     func() error { return e.svc.SetRole(ctx, missing, domain.RoleAdmin) },
		"SetPassword": func() error { return e.svc.SetPassword(ctx, missing, users.NewSecret{Password: "pw"}) },
		"SetQuota":    func() error { return e.svc.SetQuota(ctx, missing, 1<<30) },
		"Quota":       func() error { _, err := e.svc.Quota(ctx, missing); return err },
	}
	for name, op := range tests {
		t.Run(name, func(t *testing.T) {
			if err := op(); !errors.Is(err, users.ErrNotFound) {
				t.Fatalf("%s вернул %v, ожидалась ErrNotFound", name, err)
			}
		})
	}
}

// TestListIncludesSystemAccount — `user list` (§7.4) отдаёт всех, включая
// системную запись: скрывать её или нет — решение слоя команды, а не сервиса.
func TestListIncludesSystemAccount(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	e.admin(t, "root")
	e.member(t, "alice", "pw")

	list, err := e.svc.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	logins := make([]string, 0, len(list))
	for _, u := range list {
		logins = append(logins, u.Login)
	}
	for _, want := range []string{domain.SystemLogin, "root", "alice"} {
		if !slices.Contains(logins, want) {
			t.Errorf("List не содержит %q: %v", want, logins)
		}
	}
}
