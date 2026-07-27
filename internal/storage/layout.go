// Package storage — раскладка data root §5.1 docs/tz/10-cloud-drive-spec.md и
// per-user корни, через которые обслуживается файловая часть сессии.
//
// Пакет отвечает на один вопрос: «где на диске лежит то, что метаданные назвали
// по идентификатору». Он не знает ни таблицы resources, ни виртуальных путей:
// разрешение VirtualPath → ResourceID выполняет `resources` — единственный
// источник истины о структуре дерева (§5.1, инвариант 14), а storage открывает
// blob уже по ID.
//
// Правила §5.2, которым подчинён каждый путь этого пакета:
//
//   - компоненты строятся ТОЛЬКО из серверных ID;
//   - логин никогда не становится физическим именем каталога;
//   - никакие пользовательские строки не конкатенируются с data root.
//
// Отсюда и форма API: наружу выставлены методы от domain.UserID, а не от строк,
// и ни один из них не принимает пользовательское имя. Каталог пользовательского
// дерева представления на диске не имеет вовсе — каталог существует как строка в
// `resources` (§5.1, §6.3), и в live/ лежат только blob файлов.
//
// Что этот пакет НЕ делает, хотя §5.1 этого требует, и почему:
//
//  1. Проверка единства устройства для files/, staging/, versions/, recovery/ и
//     quarantine/ (одинаковый device id) — стартовая проверка daemon, а не
//     свойство раскладки. Она требует ключа storage.data_root (§19.3), которого
//     ещё нет, и платформенного чтения device id, тогда как §5.6 ограничивает
//     daemon POSIX. Обязательство остаётся за PR, вводящим ключ конфигурации.
//  2. Физический путь blob (`live/<aa>/<bb>/<resource-id>` с двухуровневым
//     шардом от первых четырёх hex-символов ID и обязательной проверкой
//     `^[0-9a-f]{32}$` до конкатенации) появится вместе со своим потребителем —
//     download и upload. Вводить его раньше значило бы зафиксировать раскладку
//     blob, не имея ни одного файла, который по ней ищут.
//  3. fsync родителя после создания каталога (§5.1) относится к каталогам,
//     создаваемым ЛЕНИВО во время публикации загрузки: там от него зависит
//     durability атомарного rename. Стартовый скелет к этому классу не
//     относится — потерянный при сбое питания пустой каталог создаётся заново
//     при следующем старте.
package storage

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"github.com/vitikevich-landau/go_fileshare/internal/domain"
)

// dirPerm — режим создаваемых каталогов. 0700, а не 0755: в files/ лежит
// содержимое пользовательских файлов, и мировое чтение data root означало бы
// раздачу этого содержимого локальным пользователям хоста, а в Docker — ещё и
// через bind-mount каталога /data. То же решение и по той же причине принято для
// самого файла БД (internal/db, §6.12).
const dirPerm os.FileMode = 0o700

// ErrNoHome — у пользователя нет и не может быть каталога /home. Единственный
// такой пользователь — системный аккаунт id = 0: §6.2 объявляет, что он не имеет
// /home и служит только владельцем public-ресурсов и строки journal_state потока
// /public.
var ErrNoHome = errors.New("storage: user has no home root")

// Layout — раскладка data root (§5.1). Значение неизменяемо после New, поэтому
// безопасно для конкурентного использования и передаётся по значению.
type Layout struct {
	root string
}

// New проверяет data root и возвращает раскладку.
//
// Путь обязан быть абсолютным. Относительный data root означал бы, что
// физическое расположение данных зависит от рабочего каталога процесса: тот же
// daemon, перезапущенный из другого каталога (systemd, docker exec, ручной
// запуск оператором), обслуживал бы ПУСТОЕ дерево, не сообщив ни об одной
// ошибке, — а метабаза при этом осталась бы полной, и расхождение выглядело бы
// как потеря всех файлов.
//
// Существование каталога здесь НЕ проверяется: New — разбор конфигурации,
// а создание и проверка скелета — EnsureSkeleton, отдельный шаг с правом
// изменить файловую систему.
func New(dataRoot string) (Layout, error) {
	if dataRoot == "" {
		return Layout{}, errors.New("storage: data root is empty")
	}
	if !filepath.IsAbs(dataRoot) {
		return Layout{}, fmt.Errorf("storage: data root %q is not absolute", dataRoot)
	}
	return Layout{root: filepath.Clean(dataRoot)}, nil
}

// Root возвращает data root.
func (l Layout) Root() string { return l.root }

// Files — каталог files/ (§5.1).
func (l Layout) Files() string { return filepath.Join(l.root, "files") }

// UserDir — files/users/<user-id> (§5.1). Имя каталога — десятичный UserID:
// стабильный серверный идентификатор, а не логин (§5.2), поэтому переименование
// пользователя, когда оно появится, не тронет ни одного пути на диске.
func (l Layout) UserDir(id domain.UserID) string {
	return filepath.Join(l.root, "files", "users", strconv.FormatInt(int64(id), 10))
}

// UserLive — files/users/<user-id>/live: корень namespace home этого
// пользователя (§5.1, §7.2). Именно он открывается как os.Root, и именно на него
// монтируется v2-сессия того же пользователя read-only.
func (l Layout) UserLive(id domain.UserID) string {
	return filepath.Join(l.UserDir(id), "live")
}

// PublicLive — files/public/live: единственный корень namespace public (§5.1).
func (l Layout) PublicLive() string {
	return filepath.Join(l.root, "files", "public", "live")
}

// StagingUploads — staging/uploads (§5.1): каталог `.upart`-файлов
// незавершённых загрузок. Состояние загрузки хранится только в SQLite (§6.4),
// файла с состоянием рядом с `.upart` не существует.
func (l Layout) StagingUploads() string {
	return filepath.Join(l.root, "staging", "uploads")
}

// VersionsDir — versions/<user-id> (§5.1). Version blob public-ресурса лежит под
// его ВЛАДЕЛЬЦЕМ (§6.3), отдельного каталога versions/public не вводится.
func (l Layout) VersionsDir(id domain.UserID) string {
	return filepath.Join(l.root, "versions", strconv.FormatInt(int64(id), 10))
}

// Recovery — recovery/ (§5.1): маркеры незавершённых операций.
func (l Layout) Recovery() string { return filepath.Join(l.root, "recovery") }

// Quarantine — quarantine/ (§5.1).
func (l Layout) Quarantine() string { return filepath.Join(l.root, "quarantine") }

// Certs — certs/ (§5.1). Может находиться где угодно относительно files/:
// требование единства устройства на него не распространяется.
func (l Layout) Certs() string { return filepath.Join(l.root, "certs") }

// Backups — backups/ (§5.1), к единству устройства тоже не относится.
func (l Layout) Backups() string { return filepath.Join(l.root, "backups") }

// EnsureSkeleton создаёт каталоги data root, которые §5.1 объявляет
// обязательными.
//
// files/users создаётся пустым: каталог конкретного пользователя появляется
// вместе с его первой сессией (OpenUserHome). Каталог quarantine/ создаётся
// заранее, хотя наполняется редко: место, куда переносят повреждённые данные,
// должно существовать до того, как оно понадобится.
func (l Layout) EnsureSkeleton() error {
	for _, dir := range []string{
		filepath.Join(l.root, "files", "users"),
		l.PublicLive(),
		l.StagingUploads(),
		filepath.Join(l.root, "versions"),
		l.Recovery(),
		l.Quarantine(),
	} {
		if err := os.MkdirAll(dir, dirPerm); err != nil {
			return fmt.Errorf("storage: create %s: %w", dir, err)
		}
	}
	return nil
}

// OpenUserHome открывает files/users/<user-id>/live как запертый корень.
//
// §7.2 требует открыть per-user os.Root ДО первой файловой операции сессии и
// обслуживать все её запросы только через него: обслуживание аутентифицированной
// сессии поверх единого глобального VFS запрещено независимо от версии
// протокола. os.Root удерживает границу сам — ни «..», ни симлинк наружу не
// выводят операцию за корень, — и именно поэтому изоляция не зависит от того, не
// забыл ли обработчик проверить путь.
//
// Каталог создаётся, если его нет. Это не молчаливое исправление чужой ошибки, а
// единственный корректный порядок: строку пользователя создаёт транзакция БД, а
// файловая система транзакции не имеет, так что каталог, созданный до commit,
// остался бы мусором при откате. Отсюда же следует, что «каталога нет» — обычное
// состояние нового пользователя, а не признак поломки.
//
// Скрыть неподключённый диск это не может: отсутствие самого data root — ошибка
// старта daemon (EnsureSkeleton и проверка §5.1), и до открытия корней сессии
// дело не доходит.
//
// Системный аккаунт отвергается: у него нет /home (§6.2). Возвращённый корень
// закрывает вызывающий — он же владеет временем жизни сессии.
func (l Layout) OpenUserHome(id domain.UserID) (*os.Root, error) {
	if id == domain.SystemUserID {
		return nil, fmt.Errorf("%w: system account (§6.2)", ErrNoHome)
	}
	if id < 0 {
		return nil, fmt.Errorf("%w: user id %d is negative", ErrNoHome, id)
	}
	return openRoot(l.UserLive(id))
}

// OpenPublic открывает files/public/live как запертый корень. Он один на всю
// установку: namespace public — общее дерево, а разграничение доступа к нему
// выполняет authorization service (§7.3), а не отдельный корень на каждого.
func (l Layout) OpenPublic() (*os.Root, error) { return openRoot(l.PublicLive()) }

func openRoot(dir string) (*os.Root, error) {
	if err := os.MkdirAll(dir, dirPerm); err != nil {
		return nil, fmt.Errorf("storage: create %s: %w", dir, err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, fmt.Errorf("storage: open root %s: %w", dir, err)
	}
	return root, nil
}

// RemoveUserData удаляет физические данные пользователя: files/users/<id> и
// versions/<id>.
//
// Вызывается `user purge` ПОСЛЕ commit транзакции (§7.4). Отсутствие каталогов
// ошибкой не является: у пользователя, ни разу не открывшего сессию, их нет, а
// повторный purge обязан быть безвредным.
//
// Метод не удаляет ни public-ресурсы (при purge они передаются системному
// аккаунту, а не удаляются, — §7.3, §7.4), ни staging: и то и другое живёт вне
// каталогов пользователя. В общем случае §6.11 шаг 7 поручает удаление файлов
// worker'у blob_gc; здесь удаляются именно КАТАЛОГИ пользователя, которых у
// blob_gc в очереди нет и быть не может — он ведёт учёт blob, а не каталогов.
func (l Layout) RemoveUserData(id domain.UserID) error {
	if id == domain.SystemUserID {
		return fmt.Errorf("storage: refusing to remove data of the system account (§6.2)")
	}
	var errs []error
	for _, dir := range []string{l.UserDir(id), l.VersionsDir(id)} {
		if err := os.RemoveAll(dir); err != nil {
			errs = append(errs, fmt.Errorf("storage: remove %s: %w", dir, err))
		}
	}
	return errors.Join(errs...)
}
