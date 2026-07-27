package users_test

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"testing"

	"github.com/vitikevich-landau/go_fileshare/internal/domain"
	"github.com/vitikevich-landau/go_fileshare/internal/metadata"
	"github.com/vitikevich-landau/go_fileshare/internal/scram"
	"github.com/vitikevich-landau/go_fileshare/internal/users"
)

// TestAuthParamsUniformIterations — §27 п. 2 и §3.3: до M14 AuthIters одинаков
// для ВСЕХ логинов, включая несуществующий и системный. Иначе клиент,
// получивший чужое значение, вывел бы ключ с другим числом итераций, и вход
// перестал бы работать без единой ошибки на сервере.
func TestAuthParamsUniformIterations(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	e.seed(t, metadata.NewUser{Login: "alice", Role: domain.RoleUser, Secret: secretFor("alice", "pw")})

	for _, login := range []string{"alice", domain.SystemLogin, "no-such-user", ""} {
		p, err := e.svc.AuthParams(ctx, login)
		if err != nil {
			t.Fatalf("AuthParams(%q): %v", login, err)
		}
		if p.AuthIters != uint32(testAuthIters) {
			t.Errorf("AuthParams(%q).AuthIters = %d, want %d", login, p.AuthIters, testAuthIters)
		}
		if p.KdfAlgo != domain.KDFPBKDF2SHA256 {
			t.Errorf("AuthParams(%q).KdfAlgo = %q", login, p.KdfAlgo)
		}
		if p.KdfParams != "" {
			t.Errorf("AuthParams(%q).KdfParams = %q, при pbkdf2-sha256 ожидалась пустая строка (§6.2 п. 4)",
				login, p.KdfParams)
		}
		if len(p.Challenge) != domain.ChallengeLen {
			t.Errorf("AuthParams(%q).Challenge = %d байт, want %d", login, len(p.Challenge), domain.ChallengeLen)
		}
	}
}

// TestAuthParamsIgnoresRowIterations — значение берётся из конфигурации, а не из
// колонки. Расхождение между записями §6.2 п. 3 объявляет ошибкой конфигурации,
// отклоняемой при старте, поэтому обслуживать такую базу сервис не обязан — а
// вернув колонку, он бы её обслуживал, выдавая разным логинам разные параметры.
func TestAuthParamsIgnoresRowIterations(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)

	odd := secretFor("odd", "pw")
	odd.AuthIters = testAuthIters * 2
	e.seed(t, metadata.NewUser{Login: "odd", Role: domain.RoleUser, Secret: odd})

	p, err := e.svc.AuthParams(ctx, "odd")
	if err != nil {
		t.Fatalf("AuthParams: %v", err)
	}
	if p.AuthIters != uint32(testAuthIters) {
		t.Errorf("AuthParams.AuthIters = %d, want действующее значение конфигурации %d",
			p.AuthIters, testAuthIters)
	}
}

// TestAuthParamsChallengeIsFresh — challenge выдаётся на рукопожатие: повторное
// значение позволило бы переиграть перехваченное доказательство.
func TestAuthParamsChallengeIsFresh(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	e.seed(t, metadata.NewUser{Login: "alice", Role: domain.RoleUser, Secret: secretFor("alice", "pw")})

	first, err := e.svc.AuthParams(ctx, "alice")
	if err != nil {
		t.Fatalf("AuthParams: %v", err)
	}
	second, err := e.svc.AuthParams(ctx, "alice")
	if err != nil {
		t.Fatalf("AuthParams: %v", err)
	}
	if bytes.Equal(first.Challenge, second.Challenge) {
		t.Error("challenge повторился между рукопожатиями")
	}
}

// TestAuthParamsRealSaltIsDeterministic — §6.2 п. 2: до M14 соль существующего
// пользователя равна "fileshare-v2:" || login. Клиент выводит её сам, поэтому
// любое другое значение сделало бы вход невозможным.
func TestAuthParamsRealSaltIsDeterministic(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	e.seed(t, metadata.NewUser{Login: "alice", Role: domain.RoleUser, Secret: secretFor("alice", "pw")})

	p, err := e.svc.AuthParams(ctx, "alice")
	if err != nil {
		t.Fatalf("AuthParams: %v", err)
	}
	if !bytes.Equal(p.Salt, domain.LegacySalt("alice")) {
		t.Errorf("Salt = %q, want %q (§6.2 п. 2)", p.Salt, domain.LegacySalt("alice"))
	}
}

// TestAuthParamsFakeSaltIsIndistinguishable — правило перехода §3.3 п. 1: пока
// установка хранит детерминированные соли, фиктивная соль обязана иметь ТУ ЖЕ
// форму.
//
// Проверяется не форма ради формы, а свойство: ответ на несуществующий логин
// побайтово таков, каким был бы ответ на существующий с тем же логином, — значит,
// по ответу нельзя узнать, есть ли учётная запись. Формула §3.3 п. 1
// (HMAC от server_secret) дала бы здесь 16 случайных байт против производной от
// логина и сама отвечала бы на этот вопрос; она вводится вместе со случайными
// солями в M14.
func TestAuthParamsFakeSaltIsIndistinguishable(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	e.seed(t, metadata.NewUser{Login: "alice", Role: domain.RoleUser, Secret: secretFor("alice", "pw")})

	real, err := e.svc.AuthParams(ctx, "alice")
	if err != nil {
		t.Fatalf("AuthParams(alice): %v", err)
	}
	fake, err := e.svc.AuthParams(ctx, "ghost")
	if err != nil {
		t.Fatalf("AuthParams(ghost): %v", err)
	}

	if !bytes.Equal(fake.Salt, domain.LegacySalt("ghost")) {
		t.Errorf("фиктивная соль = %q, want %q (§3.3 п. 1, §6.2 п. 2)",
			fake.Salt, domain.LegacySalt("ghost"))
	}
	if !bytes.Equal(real.Salt, domain.LegacySalt("alice")) {
		t.Errorf("настоящая соль = %q, want %q (§6.2 п. 2)", real.Salt, domain.LegacySalt("alice"))
	}
	// Всё, кроме соли и challenge, обязано совпадать: иначе различие переезжает в
	// другое поле того же ответа.
	if real.KdfAlgo != fake.KdfAlgo || real.AuthIters != fake.AuthIters || real.KdfParams != fake.KdfParams {
		t.Errorf("ответы различимы вне соли: %+v против %+v", real, fake)
	}
	// Длина соли — тоже наблюдаемая величина, и на логинах одной длины она обязана
	// совпадать.
	if len(real.Salt) != len(fake.Salt) {
		t.Errorf("длина соли выдаёт существование записи: %d против %d", len(real.Salt), len(fake.Salt))
	}
}

// TestAuthParamsFakeSaltIsDeterministicAndPerLogin — соль несуществующего логина
// детерминирована (иначе повторный запрос выдал бы отсутствие записи) и зависит
// от логина (иначе одна соль на всех выдала бы то же самое). После M14 это
// обеспечивает server_secret; до M14 — производная от логина.
func TestAuthParamsFakeSaltIsDeterministicAndPerLogin(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)

	first, err := e.svc.AuthParams(ctx, "ghost")
	if err != nil {
		t.Fatalf("AuthParams: %v", err)
	}
	second, err := e.svc.AuthParams(ctx, "ghost")
	if err != nil {
		t.Fatalf("AuthParams: %v", err)
	}
	if !bytes.Equal(first.Salt, second.Salt) {
		t.Error("фиктивная соль не детерминирована: повторный запрос выдаёт отсутствие пользователя")
	}

	other, err := e.svc.AuthParams(ctx, "ghost2")
	if err != nil {
		t.Fatalf("AuthParams: %v", err)
	}
	if bytes.Equal(first.Salt, other.Salt) {
		t.Error("фиктивная соль одинакова для разных логинов")
	}
}

// TestAuthenticate — успешный вход и таблица отказов. Доказательство считается
// так, как его считает клиент: соль он выводит сам из логина.
func TestAuthenticate(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	const password = "correct horse battery staple"
	e.seed(t, metadata.NewUser{Login: "alice", Role: domain.RoleUser, Secret: secretFor("alice", password)})

	challenge := []byte("0123456789abcdef")

	u, err := e.svc.Authenticate(ctx, users.AuthAttempt{
		Login:     "alice",
		Challenge: challenge,
		Proof:     proofFor("alice", password, challenge),
		RemoteIP:  "192.0.2.10",
	})
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if u.Login != "alice" || u.Role != domain.RoleUser || u.State != domain.UserActive {
		t.Errorf("Authenticate вернул %+v", u)
	}
	if u.ID == domain.SystemUserID {
		t.Error("новому пользователю выдан идентификатор системного аккаунта")
	}

	tests := []struct {
		name string
		att  users.AuthAttempt
		want error
	}{
		{
			name: "неверный пароль",
			att: users.AuthAttempt{Login: "alice", Challenge: challenge,
				Proof: proofFor("alice", "wrong", challenge)},
			want: users.ErrBadCredentials,
		},
		{
			name: "несуществующий логин",
			att: users.AuthAttempt{Login: "ghost", Challenge: challenge,
				Proof: proofFor("ghost", password, challenge)},
			want: users.ErrBadCredentials,
		},
		{
			name: "повтор доказательства на новом challenge",
			att: users.AuthAttempt{Login: "alice", Challenge: []byte("ffffffffffffffff"),
				Proof: proofFor("alice", password, challenge)},
			want: users.ErrBadCredentials,
		},
		{
			name: "пустое доказательство",
			att:  users.AuthAttempt{Login: "alice", Challenge: challenge},
			want: users.ErrBadCredentials,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := e.svc.Authenticate(ctx, tt.att); !errors.Is(err, tt.want) {
				t.Fatalf("Authenticate вернул %v, ожидалась %v", err, tt.want)
			}
		})
	}
}

// TestAuthenticateHidesUserExistence — «логина нет» и «пароль не тот» обязаны
// давать ОДИН класс ошибки: §3.3 п. 1 разрешает отличать существование учётной
// записи только по AUTH_FAIL, а раздельные классы на границе server немедленно
// стали бы перечислителем логинов.
func TestAuthenticateHidesUserExistence(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	e.seed(t, metadata.NewUser{Login: "alice", Role: domain.RoleUser, Secret: secretFor("alice", "pw")})
	challenge := []byte("0123456789abcdef")

	_, missing := e.svc.Authenticate(ctx, users.AuthAttempt{
		Login: "ghost", Challenge: challenge, Proof: proofFor("ghost", "pw", challenge)})
	_, wrong := e.svc.Authenticate(ctx, users.AuthAttempt{
		Login: "alice", Challenge: challenge, Proof: proofFor("alice", "nope", challenge)})

	if !errors.Is(missing, users.ErrBadCredentials) || !errors.Is(wrong, users.ErrBadCredentials) {
		t.Fatalf("классы ошибок разошлись: нет пользователя = %v, неверный пароль = %v", missing, wrong)
	}
	if errors.Is(missing, users.ErrUserDisabled) || errors.Is(wrong, users.ErrUserDisabled) {
		t.Error("неудача входа отнесена к ErrUserDisabled")
	}
}

// TestAuthenticateRejectsNonActiveStates — §6.2: вход разрешён только в
// состоянии active. Проверяется, что причина отличается от ErrBadCredentials:
// v2 уже различает эти ответы (proto.AuthFailUserDisabled), и инвариант 12 не
// позволяет менять смысл существующего кода.
func TestAuthenticateRejectsNonActiveStates(t *testing.T) {
	ctx := context.Background()
	challenge := []byte("0123456789abcdef")

	for _, state := range []domain.UserState{domain.UserDisabled, domain.UserPendingDelete} {
		t.Run(string(state), func(t *testing.T) {
			e := newEnv(t)
			u := e.seed(t, metadata.NewUser{
				Login: "alice", Role: domain.RoleUser, Secret: secretFor("alice", "pw"),
			})
			err := e.db.Write(ctx, func(tx *sql.Tx) error {
				return e.repo.SetState(ctx, tx, u.ID, state)
			})
			if err != nil {
				t.Fatalf("SetState: %v", err)
			}

			_, err = e.svc.Authenticate(ctx, users.AuthAttempt{
				Login: "alice", Challenge: challenge, Proof: proofFor("alice", "pw", challenge)})
			if !errors.Is(err, users.ErrUserDisabled) {
				t.Fatalf("Authenticate вернул %v, ожидалась ErrUserDisabled", err)
			}
		})
	}
}

// TestAuthenticateRejectsSystemAccount — §6.2: системный аккаунт не может пройти
// аутентификацию ни при каких данных, и проверка выполняется ДО сравнения proof.
//
// Тест подменяет верификатор системной записи на известный и предъявляет
// ПРАВИЛЬНОЕ доказательство. Именно так и проверяется порядок: если бы сравнение
// шло первым, вход бы удался.
func TestAuthenticateRejectsSystemAccount(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	const password = "system-password"
	challenge := []byte("0123456789abcdef")

	err := e.db.Write(ctx, func(tx *sql.Tx) error {
		return e.repo.SetSecret(ctx, tx, domain.SystemUserID,
			secretFor(domain.SystemLogin, password))
	})
	if err != nil {
		t.Fatalf("SetSecret: %v", err)
	}

	_, err = e.svc.Authenticate(ctx, users.AuthAttempt{
		Login:     domain.SystemLogin,
		Challenge: challenge,
		Proof:     proofFor(domain.SystemLogin, password, challenge),
	})
	if err == nil {
		t.Fatal("системный аккаунт прошёл аутентификацию")
	}
	if !errors.Is(err, users.ErrBadCredentials) {
		t.Errorf("err = %v: граница server обязана увидеть ErrBadCredentials", err)
	}
	if !errors.Is(err, users.ErrSystemAccount) {
		t.Errorf("err = %v: audit §20.2 обязан различать попытку входа под системным аккаунтом", err)
	}
}

// TestAuthenticateRejectsUnverifiableKDF — запись с argon2id завести нельзя, но
// она может приехать из испорченной БД. Сравнить её proof «как будто pbkdf2»
// значило бы проверить не тот ключ, поэтому вход отклоняется явной ошибкой
// (§6.2 п. 5).
func TestAuthenticateRejectsUnverifiableKDF(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)

	key := scram.StoredKey("pw", domain.LegacySalt("argon"), testAuthIters)
	e.seed(t, metadata.NewUser{
		Login: "argon", Role: domain.RoleUser,
		Secret: metadata.Secret{
			KDFAlgo:   domain.KDFArgon2id,
			Salt:      domain.LegacySalt("argon"),
			StoredKey: key[:],
			AuthIters: 0,
			KDFParams: "m=65536,t=3,p=1",
		},
	})

	challenge := []byte("0123456789abcdef")
	_, err := e.svc.Authenticate(ctx, users.AuthAttempt{
		Login: "argon", Challenge: challenge, Proof: proofFor("argon", "pw", challenge)})
	if err == nil {
		t.Fatal("вход по записи с argon2id удался, хотя проверять её нечем")
	}
}
