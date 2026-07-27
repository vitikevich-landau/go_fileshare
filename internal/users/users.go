// Package users — UserService (§27): единственный слой, которому разрешено
// менять таблицу users, и единственный, кто знает правила, схемой не выразимые.
//
// Граница с репозиторием проведена так. metadata.Users меняет СТРОКУ и проверяет
// то, что верно всегда (словари §6.2, связи kdf_algo/auth_iters/kdf_params).
// Здесь живёт всё остальное:
//
//   - таблица «операция → сессии → токены → shares» §7.4: живые сессии и выданные
//     токены приводятся в соответствие с новым состоянием ДО того, как команда
//     вернёт успех;
//   - инвариант последнего администратора (§2.2 п. 13, §7.4) — проверка в ТОЙ ЖЕ
//     транзакции, что и операция;
//   - временные правила этапа, которых репозиторий держать не должен: соль
//     §6.2 п. 1–2 детерминирована до M14, auth_iters §6.2 п. 3 и §3.3 одинаков у
//     всех и не задаётся операцией, argon2id недоступен, пока его нечем
//     проверять.
//
// Последний пункт — прямой долг PR2, где репозиторий сознательно отказался
// проверять соль: правило действует до M14 и там отменяется, а знать логин и
// этап обязан сервис. Отсюда форма API: NewSecret не имеет поля Salt вовсе.
// Неправильную соль здесь нельзя не «проверить» — её невозможно выразить.
//
// Чего этот пакет не делает:
//
//   - не знает wire layout. §4.3 п. 1 запрещает сервису импортировать proto;
//     доменные ошибки в коды §22 переводит граница server (§4.3 п. 2). Поэтому
//     пакет объявляет собственные sentinel-ошибки: server не вправе импортировать
//     metadata, и без них ему нечего было бы отображать в код;
//   - не считает арифметику квот. §11.4 — единственный источник формул
//     used_bytes и reserved_bytes, и владеет ими QuotaService (M13). Quota здесь
//     только читает счётчики;
//   - не пишет audit. Таблица audit_events и запись §20.2 по каждой операции
//     §7.4 п. 7 сдаются PR7 этого же этапа; порты Sessions/Tokens/Shares
//     оставлены расширяемыми ровно для того, чтобы audit добавлялся не правкой
//     каждой операции.
package users

import (
	"context"
	"errors"
	"fmt"

	"github.com/vitikevich-landau/go_fileshare/internal/db"
	"github.com/vitikevich-landau/go_fileshare/internal/domain"
	"github.com/vitikevich-landau/go_fileshare/internal/metadata"
	"github.com/vitikevich-landau/go_fileshare/internal/storage"
)

// Sentinel-ошибки сервиса. Их читает граница server и переводит в коды §22
// (§4.3 п. 2); внутри они оборачивают ошибки репозитория, чтобы диагностика не
// терялась.
var (
	// ErrNotFound — пользователя с таким идентификатором или логином нет.
	ErrNotFound = errors.New("users: no such user")

	// ErrLoginExists — логин занят. Занятым он остаётся и у пользователя в
	// состоянии pending_delete: §6.2 не освобождает логин до purge, иначе новый
	// пользователь унаследовал бы audit-историю старого.
	ErrLoginExists = errors.New("users: login already exists")

	// ErrInvalidLogin — логин не проходит проверку §6.2.
	ErrInvalidLogin = errors.New("users: invalid login")

	// ErrBadCredentials — доказательство не подтверждает знание пароля ЛИБО
	// такого логина нет. Один класс на два случая сознательно: §3.3 п. 1
	// разрешает отличать существование учётной записи только по AUTH_FAIL, и
	// расщепление этой ошибки на границе server немедленно превратило бы её в
	// перечислитель логинов.
	ErrBadCredentials = errors.New("users: bad credentials")

	// ErrUserDisabled — состояние учётной записи не допускает входа: disabled или
	// pending_delete (§6.2). Отдельно от ErrBadCredentials, потому что v2 уже
	// различает эти ответы (proto.AuthFailUserDisabled), и инвариант 12 не
	// позволяет менять смысл существующего кода.
	ErrUserDisabled = errors.New("users: user state does not allow authentication")

	// ErrSystemAccount — операция обращена к системному аккаунту id = 0 (§6.2).
	// Он не может пройти аутентификацию ни при каких данных, не имеет /home и не
	// администрируется командами §7.4.
	ErrSystemAccount = errors.New("users: system account")

	// ErrLastAdminRequired — операция опустошила бы множество пользователей с
	// ролью admin и состоянием active (§2.2 п. 13, §7.4). На границе server —
	// код LAST_ADMIN_REQUIRED.
	ErrLastAdminRequired = errors.New("users: at least one active administrator is required")

	// ErrBadRequest — запрос противоречит правилам этапа: попытка задать
	// собственное auth_iters (§3.3), запросить argon2id до появления его
	// проверки (§6.2 п. 5), передать пустой пароль. На границе server — код
	// BAD_REQUEST, как прямо требует §3.3.
	ErrBadRequest = errors.New("users: bad request")

	// ErrPurgeNotPending — purge вызван для пользователя, которого не переводили
	// в pending_delete. §7.4 делает удаление двухфазным именно для того, чтобы
	// физическое удаление данных требовало отдельного подтверждённого шага.
	ErrPurgeNotPending = errors.New("users: purge requires state pending_delete")

	// ErrPurgeBlocked — у пользователя остались объекты, которые §6.11 требует
	// удалить ДО строки users, и удалить их этот этап ещё не умеет.
	ErrPurgeBlocked = errors.New("users: purge blocked by remaining references")
)

// User — идентичность пользователя в том виде, в каком её видят другие сервисы
// (§27: UploadService, FileService и прочие принимают именно User).
//
// KDF-материала здесь нет и быть не может: §6.2 хранит верификатор, а не
// показывает его. Квоты здесь тоже нет — она меняется независимо от идентичности
// (§7.4 п. 5) и читается методом Quota, чтобы значение нельзя было закэшировать
// на время сессии (§27 п. 5).
type User struct {
	ID    domain.UserID
	Login string
	Role  domain.Role
	State domain.UserState
}

// IsAdmin сообщает, что у пользователя роль admin. Роль admin даёт
// user-возможности плюс админ-канал (§7.1), и права на чужой home она НЕ даёт:
// инвариант изоляции (§2.2 п. 2) исключений по роли не имеет.
func (u User) IsAdmin() bool { return u.Role == domain.RoleAdmin }

// Quota — счётчики квоты пользователя (§6.2, §11.4). Формулы принадлежат §11.4 и
// QuotaService; здесь значения только читаются.
type Quota struct {
	// QuotaBytes = 0 означает unlimited (§6.2).
	QuotaBytes int64
	// UsedBytes и ReservedBytes определены §11.4 исчерпывающе.
	UsedBytes     int64
	ReservedBytes int64
}

// Unlimited сообщает, что квота не ограничена (§6.2). При этом счётчики ведутся
// как обычно: инвариант 8 просто не проверяется (§24.1 п. 5).
func (q Quota) Unlimited() bool { return q.QuotaBytes == 0 }

// Sessions — реестр живых сессий с точки зрения §7.4. Реализует его слой server,
// у которого есть сокеты; сервису достаточно этих двух действий, потому что
// таблица §7.4 других не содержит.
//
// Порт объявлен здесь, а не в server, по правилу зависимостей: интерфейс нужен
// потребителю (§4.3 запрещает сервису знать про server), а реализация живёт у
// того, кто владеет соединениями.
type Sessions interface {
	// CloseUser закрывает ВСЕ сессии пользователя, включая v2-сессии и активные
	// передачи, и возвращает их число. «Закрываются» в §7.4 означает немедленно:
	// disable, passwd и delete — реакция на инцидент, и ждать завершения
	// передачи они не обязаны (§7.4 п. 2).
	CloseUser(ctx context.Context, userID domain.UserID) int

	// Recompute требует перечитать UserContext пользователя до выполнения
	// следующей операции каждой его сессии и возвращает число затронутых сессий.
	//
	// Сессия при этом СОХРАНЯЕТСЯ (§7.4 п. 3): role и quota не рвут активную
	// передачу файла. Кэширование роли на время сессии запрещено, поэтому
	// реализация обязана не «обновить копию», а сделать так, чтобы следующая
	// операция прочитала роль заново. Понижение роли, кроме того, немедленно
	// снимает подписки на админские события: любое последующее ADMIN_*
	// получает ACCESS_DENIED (§7.4 п. 4).
	Recompute(ctx context.Context, userID domain.UserID) int
}

// Tokens — отзыв transfer session tokens (§16.3). Токены появляются в M14, и DoD
// M12 их отзыв прямо исключает, но вызов стоит в тех и только тех операциях,
// которые перечисляет таблица §7.4: иначе к M14 придётся заново выяснять, где он
// должен быть, по документу, а не по коду.
type Tokens interface {
	// RevokeUser отзывает все токены пользователя и возвращает их число.
	RevokeUser(ctx context.Context, userID domain.UserID) int
}

// ShareState — что таблица §7.4 предписывает сделать со ссылками пользователя.
// Значения соответствуют состояниям shares.state (§6.8, §17.4).
type ShareState string

const (
	// ShareSuspended — ссылки приостановлены: disable (§17.4). Восстановимо.
	ShareSuspended ShareState = "suspended"
	// ShareActive — ссылки возвращаются в работу: enable.
	ShareActive ShareState = "active"
	// ShareRevoked — ссылки отозваны окончательно: delete. Терминально.
	ShareRevoked ShareState = "revoked"
)

// Shares — перевод публичных ссылок пользователя в новое состояние (§17.4).
// Ссылки появляются в M16; порт существует по той же причине, что и Tokens.
type Shares interface {
	// SetUserShares переводит все ссылки пользователя в state и возвращает их
	// число.
	SetUserShares(ctx context.Context, userID domain.UserID, state ShareState) int
}

// Config — зависимости сервиса. Одна структура вместо восьми позиционных
// аргументов: набор будет расти (audit в PR7, quota в M13), а порядок аргументов
// у конструктора с восемью параметрами одного вида — приглашение перепутать их
// молча.
type Config struct {
	DB        *db.DB
	Users     *metadata.Users
	Resources *metadata.Resources
	Layout    storage.Layout

	// AuthIters — действующее auth.pbkdf2_iters (§19.3). Значение ОДНО на всю
	// установку: §6.2 п. 3 и §3.3 требуют одинакового auth_iters у всех записей
	// до появления раунда AUTH_PARAMS в M14, а расхождение между записями
	// считается ошибкой конфигурации и отклоняется при старте
	// (metadata.VerifyInvariants).
	AuthIters int

	// Sessions, Tokens и Shares — порты §7.4. nil означает «этой подсистемы в
	// сборке нет»: сервис подставит заглушку. Заглушка допустима не везде —
	// Sessions без реализации означала бы, что «сессии закрываются» из таблицы
	// §7.4 не выполняется, поэтому её отсутствие обязан осознанно выбрать
	// вызывающий (см. AllowNoSessions).
	Sessions Sessions
	Tokens   Tokens
	Shares   Shares

	// AllowNoSessions разрешает собрать сервис без реестра сессий. Нужно
	// локальным командам остановленного daemon (--init-admin, --promote,
	// --migrate-users, §7.5, §21.4): живых сессий там нет по определению, и
	// требовать реестр значило бы заставить их поднимать половину сервера.
	//
	// Отдельный флаг, а не молчаливая заглушка при nil: у работающего daemon
	// забытый реестр — это тихо неисполняемая таблица §7.4, то есть отключённый
	// отзыв привилегий. Такое обязано быть заявлено, а не получиться.
	AllowNoSessions bool
}

// Service — реализация UserService (§27).
type Service struct {
	db     *db.DB
	users  *metadata.Users
	res    *metadata.Resources
	layout storage.Layout

	sessions Sessions
	tokens   Tokens
	shares   Shares

	authIters int
}

// New собирает сервис и проверяет, что собран он полностью.
func New(ctx context.Context, cfg Config) (*Service, error) {
	switch {
	case cfg.DB == nil:
		return nil, errors.New("users: Config.DB is nil")
	case cfg.Users == nil:
		return nil, errors.New("users: Config.Users is nil")
	case cfg.Resources == nil:
		return nil, errors.New("users: Config.Resources is nil")
	case cfg.Layout.Root() == "":
		return nil, errors.New("users: Config.Layout is not initialized")
	case cfg.AuthIters <= 0:
		return nil, fmt.Errorf("users: Config.AuthIters = %d, must be > 0 (auth.pbkdf2_iters, §19.3)",
			cfg.AuthIters)
	case cfg.Sessions == nil && !cfg.AllowNoSessions:
		return nil, errors.New("users: Config.Sessions is nil: таблица §7.4 требует закрывать сессии; " +
			"для локальных команд остановленного daemon задайте AllowNoSessions")
	}

	// §6.2 п. 3 и §19.4 п. 19: действующее auth.pbkdf2_iters обязано совпадать с
	// колонкой всех записей. Разошлись — не входит никто, а ответ сервера при этом
	// не отличается от ответа на неверный пароль, поэтому сбой обязан случиться
	// здесь, на сборке, а не на первом входе.
	if err := cfg.Users.VerifyAuthIters(ctx, cfg.AuthIters); err != nil {
		return nil, fmt.Errorf("users: %w", err)
	}

	s := &Service{
		db:        cfg.DB,
		users:     cfg.Users,
		res:       cfg.Resources,
		layout:    cfg.Layout,
		sessions:  cfg.Sessions,
		tokens:    cfg.Tokens,
		shares:    cfg.Shares,
		authIters: cfg.AuthIters,
	}
	if s.sessions == nil {
		s.sessions = noSessions{}
	}
	if s.tokens == nil {
		s.tokens = noTokens{}
	}
	if s.shares == nil {
		s.shares = noShares{}
	}
	return s, nil
}

// AuthIters возвращает действующее число итераций PBKDF2. Сервер объявляет его в
// HELLO_OK до того, как узнал логин (§3.3), поэтому значение обязано быть
// доступно вне контекста конкретного пользователя.
func (s *Service) AuthIters() int { return s.authIters }

// Заглушки портов. Возвращают 0 «затронутых», и это правда: подсистемы в сборке
// нет, значит, отзывать нечего.
type noSessions struct{}

func (noSessions) CloseUser(context.Context, domain.UserID) int { return 0 }
func (noSessions) Recompute(context.Context, domain.UserID) int { return 0 }

type noTokens struct{}

func (noTokens) RevokeUser(context.Context, domain.UserID) int { return 0 }

type noShares struct{}

func (noShares) SetUserShares(context.Context, domain.UserID, ShareState) int { return 0 }

// view переводит строку репозитория в идентичность, которую видят другие
// сервисы. Отдельная функция, а не метод metadata.User: слой metadata не должен
// знать про сервисные типы (§4.3).
func view(u metadata.User) User {
	return User{ID: u.ID, Login: u.Login, Role: u.Role, State: u.State}
}

// translate переводит ошибку репозитория в sentinel сервиса, сохраняя исходный
// текст. Граница server не вправе импортировать metadata (§4.3), поэтому без
// перевода ей нечего было бы отображать в код §22.
func translate(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, metadata.ErrNotFound):
		return fmt.Errorf("%w: %v", ErrNotFound, err)
	case errors.Is(err, metadata.ErrLoginExists), errors.Is(err, metadata.ErrReservedLogin):
		return fmt.Errorf("%w: %v", ErrLoginExists, err)
	case errors.Is(err, metadata.ErrInvalidLogin):
		return fmt.Errorf("%w: %v", ErrInvalidLogin, err)
	case errors.Is(err, metadata.ErrLastAdminRequired):
		return fmt.Errorf("%w: %v", ErrLastAdminRequired, err)
	default:
		return err
	}
}
