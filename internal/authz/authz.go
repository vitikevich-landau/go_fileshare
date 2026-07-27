// Package authz — AuthorizationService (§27): единственный источник решения о
// доступе в системе.
//
// «Единственный» — нормативное требование, а не пожелание. §7.3: любое EVENT,
// любой journal query и любой запрос через HTTPS gateway используют один и тот же
// authorization service, и другого источника решения о доступе нет; gateway не
// имеет собственной модели прав и обращается сюда от имени owner_user_id ссылки
// (§17.3). Отсюда и то, чего в пакете нет: он не знает ни версии протокола, ни
// формата кадра. §7.2 прямо запрещает считать версию протокола частью границы
// изоляции — она влияет только на набор доступных операций и на адресацию путей.
//
// Правила доступа этого этапа (§7.1, §7.3):
//
//   - namespace home: ресурс виден и доступен ТОЛЬКО своему владельцу. Роль admin
//     исключением не является — DoD M12 требует, чтобы два пользователя не видели
//     home друг друга «листингом, stat, checksum, прямым путём, событием или
//     journal», и роль в этом перечне не упомянута. Админ-канал (§7.1) даёт права
//     на управление, а не на чужие файлы;
//   - namespace public: чтение доступно всем аутентифицированным, запись — роли
//     admin (§7.3). ACL появляется в M16 и заменяет это правило, не меняя того,
//     кто его применяет.
//
// UserContext создаётся для ЛЮБОЙ аутентифицированной сессии независимо от версии
// протокола (§7.2). Анонимного UserContext не существует: даже в режиме
// --insecure-no-auth сервер обязан использовать обычную запись пользователя с
// ролью admin и обслуживать все сессии её UserContext (§7.2), а «общий» корень не
// вводится ни при каких настройках.
package authz

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/vitikevich-landau/go_fileshare/internal/domain"
	"github.com/vitikevich-landau/go_fileshare/internal/metadata"
	"github.com/vitikevich-landau/go_fileshare/internal/storage"
)

// Sentinel-ошибки. Их читает граница server и переводит в коды §22 (§4.3 п. 2):
// ErrAccessDenied — в ACCESS_DENIED, ErrNotFound — в NOT_FOUND, ErrInvalidPath —
// в INVALID_NAME (§5.3).
var (
	// ErrAccessDenied — доступ запрещён. Один класс и на «не твоё», и на «нет
	// прав» сознательно: различать их значило бы сообщать, что чужой ресурс
	// существует.
	ErrAccessDenied = errors.New("authz: access denied")

	// ErrNotFound — ресурса по этому пути нет. Для чужого home недостижимость
	// обеспечена конструкцией: другого home не выразить в адресации вовсе.
	ErrNotFound = errors.New("authz: no such resource")

	// ErrInvalidPath — путь не проходит правила §5.3 п. 1–9.
	ErrInvalidPath = errors.New("authz: invalid path")
)

// UserContext — идентичность и файловая граница сессии (§7.2).
//
// Отличие от предварительного объявления §7.2 одно: Role имеет тип domain.Role, а
// не proto.Role, — §4.3 п. 1 запрещает сервисному пакету зависеть от wire layout,
// и роль как решение о правах живёт в domain.
//
// Квоты в структуре нет: она меняется независимо от идентичности (§7.4 п. 5), а
// §27 п. 5 запрещает кэшировать её на время сессии. Читать квоту следует у
// UserService на каждое резервирование.
type UserContext struct {
	UserID domain.UserID
	Login  string
	Role   domain.Role

	// HomeRoot — запертый корень files/users/<UserID>/live. Открывается ДО первой
	// файловой операции сессии, и все её запросы обслуживаются только через него
	// (§7.2): обслуживание аутентифицированной сессии поверх единого глобального
	// VFS запрещено. Границу удерживает сам os.Root, а не проверки в
	// обработчиках.
	HomeRoot *os.Root
}

// IsAdmin сообщает, что роль сессии — admin (§7.1). На доступ к чужому home не
// влияет: см. докстринг пакета.
func (uc UserContext) IsAdmin() bool { return uc.Role == domain.RoleAdmin }

// Close закрывает корень сессии. Вызывается ровно один раз владельцем сессии при
// её завершении. Значение UserContext копируемо, и копии разделяют один корень
// (см. Refresh), поэтому закрывать его дважды нельзя.
func (uc UserContext) Close() error {
	if uc.HomeRoot == nil {
		return nil
	}
	return uc.HomeRoot.Close()
}

// Config — зависимости сервиса.
type Config struct {
	Users     *metadata.Users
	Resources *metadata.Resources
	Layout    storage.Layout
}

// Service — реализация AuthorizationService (§27).
type Service struct {
	users  *metadata.Users
	res    *metadata.Resources
	layout storage.Layout
}

// New собирает сервис.
func New(cfg Config) (*Service, error) {
	switch {
	case cfg.Users == nil:
		return nil, errors.New("authz: Config.Users is nil")
	case cfg.Resources == nil:
		return nil, errors.New("authz: Config.Resources is nil")
	case cfg.Layout.Root() == "":
		return nil, errors.New("authz: Config.Layout is not initialized")
	}
	return &Service{users: cfg.Users, res: cfg.Resources, layout: cfg.Layout}, nil
}

// Context собирает UserContext сессии и открывает её home root (§7.2, §27).
//
// Состояние проверяется здесь, хотя вход уже проверил его: между аутентификацией и
// открытием корня пользователь может быть отключён административной командой, а
// §7.4 требует, чтобы disabled не получил новой сессии. Проверка стоит на
// последнем шаге, после которого сессия становится обслуживаемой.
//
// Системный аккаунт отвергается: §6.2 объявляет, что /home у него нет, и открыть
// его значило бы создать дерево записи, которая не может пройти аутентификацию.
//
// Возвращённый корень закрывает вызывающий (UserContext.Close): время жизни
// корня — время жизни сессии, и знать о нём сервис не может.
func (s *Service) Context(ctx context.Context, userID domain.UserID) (UserContext, error) {
	if userID == domain.SystemUserID {
		return UserContext{}, fmt.Errorf("%w: the system account has no home (§6.2)", ErrAccessDenied)
	}
	u, err := s.users.ByID(ctx, userID)
	if err != nil {
		return UserContext{}, translate(err)
	}
	if !u.State.CanAuthenticate() {
		return UserContext{}, fmt.Errorf("%w: user %d is in state %q (§6.2, §7.4)",
			ErrAccessDenied, userID, u.State)
	}

	root, err := s.layout.OpenUserHome(userID)
	if err != nil {
		return UserContext{}, fmt.Errorf("authz: home root of user %d: %w", userID, err)
	}
	return UserContext{UserID: u.ID, Login: u.Login, Role: u.Role, HomeRoot: root}, nil
}

// Refresh перечитывает роль сессии, СОХРАНЯЯ уже открытый корень.
//
// Это и есть «пересчёт UserContext» из таблицы §7.4: операции role и quota не
// рвут сессию, но её роль обязана быть перечитана до выполнения следующей
// операции, а кэширование роли на время сессии запрещено (§7.4 п. 3, §27 п. 5).
//
// Корень не переоткрывается намеренно: домашний каталог — функция от UserID
// (§5.1), от роли и квоты он не зависит, а переоткрытие на каждом пересчёте
// означало бы новый дескриптор при каждой административной команде. Возвращённое
// значение разделяет корень с исходным, поэтому закрывать его следует ровно один
// раз — тем UserContext, который сессия хранит у себя.
//
// Если к моменту пересчёта пользователь удалён или больше не активен, метод
// возвращает ошибку: сессия обязана быть закрыта, и решение об этом принимает
// вызывающий (для disable и delete её уже закрыл отзыв §7.4 — здесь остаётся
// гонка порядка, а не второй путь).
func (s *Service) Refresh(ctx context.Context, uc UserContext) (UserContext, error) {
	u, err := s.users.ByID(ctx, uc.UserID)
	if err != nil {
		return UserContext{}, translate(err)
	}
	if !u.State.CanAuthenticate() {
		return UserContext{}, fmt.Errorf("%w: user %d is in state %q (§7.4)",
			ErrAccessDenied, uc.UserID, u.State)
	}
	return UserContext{UserID: u.ID, Login: u.Login, Role: u.Role, HomeRoot: uc.HomeRoot}, nil
}

// Resolve разрешает VirtualPath в ресурс (§27).
//
// namespace принимается вторым аргументом, как объявлено в §27, хотя §5.3 п. 9
// требует, чтобы путь начинался с /home или /public и, значит, уже содержал его.
// Аргумент не игнорируется и не переопределяет путь: пустое значение означает
// «взять из пути», непустое обязано СОВПАСТЬ. Расхождение — ошибка, а не выбор
// одного из двух: вызывающий, у которого namespace и путь разошлись, ошибся, и
// молча предпочесть любой из них значило бы обслужить не тот запрос.
//
// Изоляция здесь обеспечена конструкцией, а не проверкой: корнем для namespace
// home служит home ВЫЗЫВАЮЩЕГО (uc.UserID), и никакая последовательность
// компонентов не выведет обход в чужое дерево, потому что чужой home в адресации
// не выразим вовсе. Именно это требование DoD M12 «пользователь A не видит home
// пользователя B прямым путём» — и оно не зависит от версии протокола, потому что
// v3-путь /home/a.bin и v2-путь /a.bin разрешаются одним и тем же способом
// (§7.2).
//
// Обход идёт по ЖИВЫМ детям: удалённый в корзину ресурс из дерева уходит (§10.1),
// и путь к нему не ведёт. Восстановление из корзины работает с TrashID, а не с
// путём (§10.2).
func (s *Service) Resolve(
	ctx context.Context, uc UserContext, namespace domain.Namespace, virtualPath string,
) (metadata.Resource, error) {
	path, err := metadata.ParsePath(virtualPath)
	if err != nil {
		return metadata.Resource{}, fmt.Errorf("%w: %v", ErrInvalidPath, err)
	}
	if namespace != "" && namespace != path.Namespace {
		return metadata.Resource{}, fmt.Errorf(
			"%w: namespace %q contradicts path %q, which addresses %q",
			ErrInvalidPath, namespace, virtualPath, path.Namespace)
	}

	cur, err := s.namespaceRoot(ctx, uc, path.Namespace)
	if err != nil {
		return metadata.Resource{}, err
	}
	for i, name := range path.Components {
		if cur.Kind != domain.KindDir {
			// Путь идёт сквозь файл: /home/a.bin/b. Это «не найдено», а не
			// «неверный путь», — форма пути безупречна, такого ресурса нет.
			return metadata.Resource{}, fmt.Errorf("%w: %q is not a directory in %q",
				ErrNotFound, cur.Name, virtualPath)
		}
		child, err := s.res.ChildByName(ctx, path.Namespace, cur.ID, name)
		if err != nil {
			if errors.Is(err, metadata.ErrNotFound) {
				return metadata.Resource{}, fmt.Errorf("%w: %q has no component %d (%q)",
					ErrNotFound, virtualPath, i+1, name)
			}
			return metadata.Resource{}, translate(err)
		}
		cur = child
	}
	return cur, nil
}

// namespaceRoot возвращает корень namespace для этой сессии.
func (s *Service) namespaceRoot(
	ctx context.Context, uc UserContext, ns domain.Namespace,
) (metadata.Resource, error) {
	switch ns {
	case domain.NamespaceHome:
		// Корень — home ВЫЗЫВАЮЩЕГО. Другого home адресация не выражает.
		root, err := s.res.HomeRoot(ctx, uc.UserID)
		if err != nil {
			return metadata.Resource{}, translate(err)
		}
		return root, nil
	case domain.NamespacePublic:
		root, err := s.res.PublicRoot(ctx)
		if err != nil {
			return metadata.Resource{}, translate(err)
		}
		return root, nil
	default:
		return metadata.Resource{}, fmt.Errorf("%w: namespace %q is not in the §6.3 dictionary",
			ErrInvalidPath, ns)
	}
}

// Visible сообщает, видим ли ресурс этой сессии (§27).
//
// Метод отвечает на вопрос «имеет ли право знать, что этот ресурс изменился»,
// поэтому вызывается на каждое событие для каждого получателя (§7.3): рассылка
// обязана быть per-recipient, событие, невидимое получателю, не отправляется
// вовсе, а событие с обрезанным или замаскированным путём запрещено — сам факт
// изменения тоже информация.
//
// Решение принимается по строке ресурса: namespace и owner_user_id. Поддерево не
// обходится, и это не срезанный угол — согласованность namespace вдоль цепочки
// parent_id обеспечивает metadata.Resources.Create (родитель и ребёнок обязаны
// быть в одном namespace), а расхождение в уже существующих строках — это
// расхождение метаданных, которое разбирает fsck (§21.3), а не решение о доступе.
// Обход же стоил бы до MaxTreeDepth запросов на КАЖДОГО получателя КАЖДОГО
// события.
//
// Удалённый в корзину ресурс виден только владельцу: его trash-запись лежит под
// его user-id (§7.3, §10), и остальным о содержимом чужой корзины знать нечего —
// в том числе о содержимом корзины в namespace public.
func (s *Service) Visible(ctx context.Context, uc UserContext, resourceID domain.ResourceID) (bool, error) {
	res, err := s.res.ByID(ctx, resourceID)
	if err != nil {
		if errors.Is(err, metadata.ErrNotFound) {
			// Несуществующий ресурс не «невидим», а отсутствует, и вызывающий
			// обязан различать: событие о неизвестном ресурсе — дефект, а не
			// отказ в доступе.
			return false, fmt.Errorf("%w: resource %s", ErrNotFound, resourceID)
		}
		return false, translate(err)
	}
	return s.visibleResource(uc, res), nil
}

// VisibleResource — та же проверка над уже прочитанной строкой. Нужна на горячем
// пути: рендеринг события под получателя уже держит ресурс в руках (§7.3), и
// второе чтение той же строки на каждого получателя было бы чистой платой за
// форму вызова.
func (s *Service) VisibleResource(uc UserContext, res metadata.Resource) bool {
	return s.visibleResource(uc, res)
}

func (s *Service) visibleResource(uc UserContext, res metadata.Resource) bool {
	own := res.OwnerUserID == uc.UserID
	switch res.Namespace {
	case domain.NamespaceHome:
		// Только владельцу. Роль admin исключением не является: DoD M12 требует
		// изоляции home без оговорок по роли.
		return own
	case domain.NamespacePublic:
		// Чтение public доступно всем аутентифицированным (§7.3); содержимое
		// корзины — только владельцу.
		return own || !res.Deleted()
	default:
		// Namespace вне словаря §6.3 — испорченная строка. Отказ, а не догадка.
		return false
	}
}

// translate переводит ошибку репозитория в sentinel сервиса: граница server не
// вправе импортировать metadata (§4.3), и без перевода ей нечего было бы
// отображать в код §22.
func translate(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, metadata.ErrNotFound):
		return fmt.Errorf("%w: %v", ErrNotFound, err)
	case errors.Is(err, metadata.ErrInvalidName):
		return fmt.Errorf("%w: %v", ErrInvalidPath, err)
	default:
		return err
	}
}
