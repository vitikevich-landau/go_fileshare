package users

import (
	"context"
	"crypto/hmac"
	crand "crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/vitikevich-landau/go_fileshare/internal/domain"
	"github.com/vitikevich-landau/go_fileshare/internal/metadata"
	"github.com/vitikevich-landau/go_fileshare/internal/scram"
)

// fakeSaltLabel — метка вывода фиктивной соли несуществующего логина: §3.3 п. 1
// задаёт её нормативно, `Salt = HMAC-SHA256(server_secret, "auth-params-v1" ||
// Login)[:16]`. Менять строку нельзя: она входит в вычисление, и другое значение
// сделало бы соли других версий сервера различными для одного логина.
const fakeSaltLabel = "auth-params-v1"

// AuthParams — параметры, с которыми клиент выводит ключ (§27, §3.3).
//
// Отличия от предварительного объявления §27 два, и оба сужают тип: KdfAlgo —
// domain.KDFAlgo вместо string (словарь §6.2 закрыт, и строка позволяла бы
// вернуть значение вне него), AuthIters — uint32 как на проводе.
type AuthParams struct {
	KdfAlgo domain.KDFAlgo
	// AuthIters — число итераций PBKDF2; 0 при argon2id (§6.2 п. 4).
	AuthIters uint32
	// KdfParams непуст только при argon2id: m=<KiB>,t=<iters>,p=<lanes>.
	KdfParams string
	// Salt — соль, с которой посчитан текущий stored_key (§6.2). До M14
	// детерминирована и равна "fileshare-v2:" || login.
	Salt []byte
	// Challenge — вызов этого рукопожатия, ChallengeLen байт из crypto/rand.
	Challenge []byte
}

// AuthAttempt — попытка входа (§27).
//
// Proof — массив, а не []byte из предварительного объявления §27: длина
// доказательства фиксирована (scram.KeyLen = proto.ProofLen), и массив делает
// «доказательство не той длины» невыразимым вместо того, чтобы проверять его в
// начале каждой реализации.
type AuthAttempt struct {
	Login     string
	Challenge []byte
	Proof     scram.Proof
	// RemoteIP — адрес клиента. Сервису он нужен не для решения о доступе (бан по
	// IP остаётся в auth.Guard, §19), а для записи audit §20.2, которая
	// добавляется в PR7 вместе с таблицей audit_events.
	RemoteIP string
}

// AuthParams возвращает параметры рукопожатия для логина и свежий challenge.
//
// Раунд AUTH_PARAMS появляется на проводе в M14 (§3.3), но метод существует уже
// сейчас, потому что правило, которое он обязан соблюдать, относится к M12–M13:
//
//  1. AuthIters ОДИНАКОВ для всех логинов (§27 п. 2, §3.3). Возвращается
//     действующее значение конфигурации, а не колонка строки: §6.2 п. 3
//     запрещает расхождение между записями, оно проверяется при старте
//     (metadata.VerifyInvariants), и брать значение из строки означало бы
//     готовность обслуживать базу, которую старт обязан отвергнуть.
//  2. Для НЕСУЩЕСТВУЮЩЕГО логина возвращаются детерминированные фиктивные
//     параметры, выведенные от логина и server_secret (§3.3 п. 1). Значение
//     детерминировано между рестартами, потому что секрет создаётся миграцией и
//     не регенерируется (§6.12).
//
// Работа выполняется одинаковая в обоих случаях: фиктивная соль считается ВСЕГДА,
// до того как известно, есть ли пользователь. Иначе ветка «пользователя нет»
// стоила бы одним HMAC меньше, а §3.3 п. 1 требует не отличаться по времени.
//
// Ограничение, которое переживёт этот PR и обязано быть снято в M14. Пока соль
// существующего пользователя детерминирована (§6.2 п. 2), она имеет вид
// "fileshare-v2:" || login, а фиктивная — RandomSaltLen случайных байт, то есть
// ФОРМА соли сама отвечает на вопрос «есть ли такой пользователь». На M12–M13
// это никому не видно: раунда на проводе нет, метод обслуживает только
// внутренние вызовы. Но M14 включает раунд, а соли существующих записей
// становятся случайными лишь при смене пароля — учётка, не менявшая пароль,
// останется различимой. Закрыть это обязан PR, вводящий раунд: либо принудительной
// пересолкой, либо фиктивной солью в детерминированной форме. §3.3 п. 1 сам по
// себе этого не закрывает.
func (s *Service) AuthParams(ctx context.Context, login string) (AuthParams, error) {
	challenge := make([]byte, domain.ChallengeLen)
	if _, err := crand.Read(challenge); err != nil {
		return AuthParams{}, fmt.Errorf("users: auth params for %q: challenge: %w", login, err)
	}
	fake := s.fakeSalt(login)

	u, err := s.users.ByLogin(ctx, login)
	switch {
	case errors.Is(err, metadata.ErrNotFound):
		return AuthParams{
			KdfAlgo:   domain.KDFPBKDF2SHA256,
			AuthIters: uint32(s.authIters),
			Salt:      fake,
			Challenge: challenge,
		}, nil
	case err != nil:
		return AuthParams{}, translate(err)
	}

	// Системный аккаунт не скрывается: его соль — производная от общеизвестного
	// логина 'system' (§6.2 п. 2), а сам он есть в каждой установке, так что
	// скрывать нечего. Войти он всё равно не может — это проверяет Authenticate
	// ДО сравнения proof.
	return AuthParams{
		KdfAlgo:   u.Secret.KDFAlgo,
		AuthIters: uint32(s.authIters),
		KdfParams: u.Secret.KDFParams,
		Salt:      u.Secret.Salt,
		Challenge: challenge,
	}, nil
}

// fakeSalt выводит соль несуществующего логина по формуле §3.3 п. 1.
func (s *Service) fakeSalt(login string) []byte {
	m := hmac.New(sha256.New, s.serverSecret)
	m.Write([]byte(fakeSaltLabel))
	m.Write([]byte(login))
	return m.Sum(nil)[:domain.RandomSaltLen]
}

// Authenticate проверяет доказательство и возвращает пользователя (§27).
//
// Порядок проверок нормативен, а не удобен:
//
//  1. системный аккаунт отвергается ДО сравнения proof (§6.2). Причина не в
//     экономии: stored_key системной записи взят из crypto/rand, то есть
//     теоретически подделываем не более, чем любой другой, — но правило «он не
//     может войти ни при каких данных» обязано держаться и на базе, куда
//     верификатор записали руками;
//  2. состояние проверяется до сравнения proof: disabled и pending_delete не
//     пускают (§6.2), и знание пароля этого не меняет;
//  3. сравнение доказательства — последним, константным временем (scram.Verify).
//
// «Логина нет» и «доказательство не то» дают ОДНУ ошибку ErrBadCredentials:
// §3.3 п. 1 разрешает отличать существование учётной записи только по AUTH_FAIL
// после полного proof, и раздельные ошибки на границе server немедленно стали бы
// перечислителем логинов. Отдельный dummy-verify для выравнивания времени не
// вводится: цена ветки «нет пользователя» — один HMAC и один SHA256, тогда как
// PBKDF2 считает КЛИЕНТ, и на фоне запроса к БД и сетевого джиттера эта разница
// не наблюдаема. Грубое выравнивание обеспечивает auth.fail_delay_ms сервера.
//
// Бан по IP, лимит сессий и задержка на неудачу остаются на границе server: они
// свойства СОЕДИНЕНИЯ, а не пользователя, и сервису для решения не нужны.
func (s *Service) Authenticate(ctx context.Context, att AuthAttempt) (User, error) {
	u, err := s.users.ByLogin(ctx, att.Login)
	switch {
	case errors.Is(err, metadata.ErrNotFound):
		return User{}, fmt.Errorf("%w: login %q", ErrBadCredentials, att.Login)
	case err != nil:
		return User{}, translate(err)
	}

	if u.IsSystem() {
		// Две обёртки: границе server нужен ErrBadCredentials (иначе ответ выдал
		// бы, что запись существует), а audit §20.2 обязан различать попытку
		// входа под системным аккаунтом от обычной неудачи.
		return User{}, fmt.Errorf("%w: %w cannot authenticate (§6.2)", ErrBadCredentials, ErrSystemAccount)
	}
	if !u.State.CanAuthenticate() {
		return User{}, fmt.Errorf("%w: login %q is in state %q", ErrUserDisabled, u.Login, u.State)
	}
	if u.Secret.KDFAlgo != domain.KDFPBKDF2SHA256 {
		// Проверить argon2id пока нечем (§6.2 п. 5): доказательство считается по
		// PBKDF2-цепочке. Запись с argon2id завести нельзя (см. Create), но она
		// может приехать из испорченной БД, и молча сравнить proof «как будто
		// pbkdf2» значило бы проверить не тот ключ.
		return User{}, fmt.Errorf("users: login %q uses kdf_algo %q, which has no verifier before M14 (§6.2 п. 5)",
			u.Login, u.Secret.KDFAlgo)
	}

	var stored scram.Key
	if len(u.Secret.StoredKey) != len(stored) {
		return User{}, fmt.Errorf("users: login %q has stored_key of %d bytes, want %d (§6.2)",
			u.Login, len(u.Secret.StoredKey), len(stored))
	}
	copy(stored[:], u.Secret.StoredKey)

	if !scram.Verify(stored, att.Challenge, att.Login, att.Proof) {
		return User{}, fmt.Errorf("%w: login %q", ErrBadCredentials, att.Login)
	}
	return view(u), nil
}
