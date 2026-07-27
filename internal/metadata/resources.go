package metadata

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/vitikevich-landau/go_fileshare/internal/db"
	"github.com/vitikevich-landau/go_fileshare/internal/domain"
)

// ErrNotFound — запрошенной строки нет. Общий для всех репозиториев пакета.
var ErrNotFound = errors.New("metadata: not found")

// ErrNameExists — в каталоге уже живёт ресурс с ПОБАЙТОВО тем же именем.
// Отображается в RESOURCE_EXISTS всегда, при любой конфигурации (§5.3).
var ErrNameExists = errors.New("metadata: name already exists")

// ErrNameConflict — в каталоге уже живёт ресурс, чьё имя отличается только
// регистром или формой нормализации Unicode (совпадение по name_fold).
// Отображается в тот же RESOURCE_EXISTS, но ТОЛЬКО при
// storage.case_conflict_detect = true; отдельная ошибка нужна, чтобы сервис мог
// отличить настоящий дубликат от конфликта по политике — в логе и в аудите это
// разные события (§5.3).
var ErrNameConflict = errors.New("metadata: case or normalization conflict")

// Resource — строка таблицы resources (§6.3).
//
// Колонки storage_relpath здесь нет, как нет её и в схеме: физический путь
// current content вычисляется функцией от (owner_user_id, id) по правилам §5.1,
// поэтому rename и move каталога — операция над ОДНОЙ строкой метаданных.
type Resource struct {
	ID          domain.ResourceID
	OwnerUserID domain.UserID
	// ParentID равен ID у отсоединённых строк: корня namespace и корня
	// удалённого поддерева (§6.3).
	ParentID  domain.ResourceID
	Namespace domain.Namespace
	// Name хранится байт-в-байт таким, каким его прислал клиент (§5.3).
	Name string
	// NameFold — производная от Name величина для детекта коллизий и имён
	// keyed locks. Клиенту не отдаётся никогда (§6.3).
	NameFold     string
	Kind         domain.Kind
	Revision     domain.Revision
	SizeBytes    int64
	ChecksumAlgo domain.ChecksumAlgo
	Checksum     []byte
	CreatedAt    domain.UnixMillis
	UpdatedAt    domain.UnixMillis
	// DeletedAt равен нулю, когда ресурс жив (в БД — NULL).
	DeletedAt domain.UnixMillis
	// TrashedRootID нулевой, когда ресурс жив (в БД — NULL). Схема требует,
	// чтобы он был заполнен ровно тогда, когда заполнен DeletedAt.
	TrashedRootID domain.ResourceID
}

// Deleted сообщает, что ресурс удалён логически и лежит в корзине (§10.1).
func (r Resource) Deleted() bool { return r.DeletedAt != 0 }

// IsRoot сообщает, что строка не подключена к дереву (§6.3). У живого ресурса
// это означает корень namespace, у удалённого — корень удалённого поддерева.
func (r Resource) IsRoot() bool { return r.ID == r.ParentID }

// NewResource — данные для создания строки resources. Идентификатор не
// принимается: его выдаёт репозиторий, потому что ResourceID задаёт физический
// путь (§5.1), и принимать его снаружи значило бы позволить вызывающему выбрать
// путь на диске.
type NewResource struct {
	OwnerUserID domain.UserID
	ParentID    domain.ResourceID
	Namespace   domain.Namespace
	Name        string
	Kind        domain.Kind
	// Revision у создаваемого каталога равен NoRevision; у файла его задаёт
	// commit загрузки (§8.4).
	Revision     domain.Revision
	SizeBytes    int64
	ChecksumAlgo domain.ChecksumAlgo
	Checksum     []byte
}

// Resources — репозиторий таблицы resources (§6.3).
//
// Читающие методы ходят в читающий handle, пишущие принимают открытую
// транзакцию: §23.2 требует, чтобы мутация и проверки её предусловий выполнялись
// в ОДНОЙ транзакции, а репозиторий, открывающий транзакцию сам, такую
// композицию делает невозможной.
type Resources struct {
	r *sql.DB
}

// NewResources строит репозиторий поверх открытой пары handle'ов.
func NewResources(d *db.DB) *Resources { return &Resources{r: d.Reader} }

const resourceColumns = `id, owner_user_id, parent_id, namespace, name, name_fold, kind,
	current_revision, size_bytes, checksum_algo, checksum,
	created_at_ms, updated_at_ms, deleted_at_ms, trashed_root_id`

// ByID возвращает ресурс по идентификатору НЕЗАВИСИМО от того, жив он или
// удалён: вызывающему нужны обе ситуации — восстановление из корзины (§10.2)
// работает именно с удалёнными строками. Проверять Resource.Deleted обязан он.
func (rs *Resources) ByID(ctx context.Context, id domain.ResourceID) (Resource, error) {
	row := rs.r.QueryRowContext(ctx,
		`SELECT `+resourceColumns+` FROM resources WHERE id = ?`, id.String())
	res, err := scanResource(row)
	if errors.Is(err, sql.ErrNoRows) {
		return Resource{}, fmt.Errorf("%w: resource %s", ErrNotFound, id)
	}
	return res, err
}

// HomeRoot возвращает корень /home пользователя (§6.3, §7.2). Корень создаётся
// вместе с пользователем и принадлежит ему.
func (rs *Resources) HomeRoot(ctx context.Context, userID domain.UserID) (Resource, error) {
	return rs.root(ctx, domain.NamespaceHome, userID)
}

// PublicRoot возвращает корень /public (§6.3). Он создан миграцией 0001 и
// принадлежит системному аккаунту.
func (rs *Resources) PublicRoot(ctx context.Context) (Resource, error) {
	return rs.root(ctx, domain.NamespacePublic, domain.SystemUserID)
}

func (rs *Resources) root(ctx context.Context, ns domain.Namespace, owner domain.UserID) (Resource, error) {
	row := rs.r.QueryRowContext(ctx, `SELECT `+resourceColumns+` FROM resources
WHERE namespace = ? AND owner_user_id = ? AND id = parent_id AND deleted_at_ms IS NULL`,
		string(ns), int64(owner))
	res, err := scanResource(row)
	if errors.Is(err, sql.ErrNoRows) {
		return Resource{}, fmt.Errorf("%w: %s root of user %d", ErrNotFound, ns, owner)
	}
	return res, err
}

// ChildByName ищет ЖИВОГО ребёнка каталога по побайтовому имени. Запрос ложится
// на resources_uniq_name, поэтому namespace передаётся явно, хотя и выводится из
// родителя: без него частичный индекс не используется.
func (rs *Resources) ChildByName(ctx context.Context, ns domain.Namespace, parent domain.ResourceID, name string) (Resource, error) {
	row := rs.r.QueryRowContext(ctx, `SELECT `+resourceColumns+` FROM resources
WHERE namespace = ? AND parent_id = ? AND name = ? AND deleted_at_ms IS NULL`,
		string(ns), parent.String(), name)
	res, err := scanResource(row)
	if errors.Is(err, sql.ErrNoRows) {
		return Resource{}, fmt.Errorf("%w: %q in %s", ErrNotFound, name, parent)
	}
	return res, err
}

// ChildByFold ищет ЖИВОГО ребёнка каталога, имя которого совпадает с fold —
// то есть отличается от искомого только регистром или формой нормализации
// (§5.3). Индекс resources_fold не уникален (политика переключаема конфигом),
// поэтому совпасть могут несколько строк; возвращается любая из них, потому что
// вызывающему нужен факт конфликта, а не полный список.
func (rs *Resources) ChildByFold(ctx context.Context, ns domain.Namespace, parent domain.ResourceID, fold string) (Resource, error) {
	row := rs.r.QueryRowContext(ctx, `SELECT `+resourceColumns+` FROM resources
WHERE namespace = ? AND parent_id = ? AND name_fold = ? AND deleted_at_ms IS NULL
LIMIT 1`, string(ns), parent.String(), fold)
	res, err := scanResource(row)
	if errors.Is(err, sql.ErrNoRows) {
		return Resource{}, fmt.Errorf("%w: nothing folds to %q in %s", ErrNotFound, fold, parent)
	}
	return res, err
}

// Children возвращает ЖИВЫХ детей каталога, упорядоченных по имени.
//
// Это не листинг §13: страниц, режимов сортировки и page token здесь нет, и
// каталог выдаётся целиком. Пагинация приезжает вместе с LIST_REQUEST_V3 (§13.2)
// и опирается на те же частичные индексы; до неё метод обслуживает внутренние
// обходы, где каталог заведомо мал.
func (rs *Resources) Children(ctx context.Context, ns domain.Namespace, parent domain.ResourceID) ([]Resource, error) {
	rows, err := rs.r.QueryContext(ctx, `SELECT `+resourceColumns+` FROM resources
WHERE namespace = ? AND parent_id = ? AND id <> parent_id AND deleted_at_ms IS NULL
ORDER BY name`, string(ns), parent.String())
	if err != nil {
		return nil, fmt.Errorf("metadata: list children of %s: %w", parent, err)
	}
	defer rows.Close()

	var out []Resource
	for rows.Next() {
		res, err := scanResource(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("metadata: list children of %s: %w", parent, err)
	}
	return out, nil
}

// CreateRoot создаёт корень namespace: id = parent_id, пустое имя, kind = dir
// (§6.3). Корень /public создаёт миграция 0001, корень /home — создание
// пользователя, поэтому метод вызывается только оттуда.
//
// ValidateName к пустому имени корня не применяется намеренно: правило §5.3 п. 1
// запрещает пустое имя пользовательской операции, а корень пользовательской
// операцией не создаётся. Ровно это и выражает CHECK (name <> ” OR id =
// parent_id) в схеме.
func (rs *Resources) CreateRoot(ctx context.Context, tx *sql.Tx, ns domain.Namespace, owner domain.UserID) (Resource, error) {
	if !ns.Valid() {
		return Resource{}, fmt.Errorf("metadata: create root: namespace %q is not in the §6.3 dictionary", ns)
	}
	id, err := domain.NewResourceID()
	if err != nil {
		return Resource{}, fmt.Errorf("metadata: create %s root: %w", ns, err)
	}
	now := domain.NowMillis()
	res := Resource{
		ID:          id,
		OwnerUserID: owner,
		ParentID:    id,
		Namespace:   ns,
		Kind:        domain.KindDir,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	if err := insertResource(ctx, tx, res); err != nil {
		return Resource{}, fmt.Errorf("metadata: create %s root of user %d: %w", ns, owner, err)
	}
	return res, nil
}

// Create вставляет ресурс в каталог, проверив предусловия §5.3 в той же
// транзакции, что и саму вставку.
//
// caseConflictDetect — значение storage.case_conflict_detect (§5.3). Оно
// приходит параметром, а не читается репозиторием из конфига: репозиторий не
// знает про конфиг-хаб, а решение политики принимает вызывающий сервис.
//
// Проверка байтового имени выполняется ЗАПРОСОМ, а не разбором ошибки
// UNIQUE-индекса: коды ошибок драйвера видны только в internal/db, где драйвер и
// импортируется (ADR 0001 §4.6). Гонки это не создаёт — пишущий handle держит
// ровно одно соединение и открывает каждую транзакцию как BEGIN IMMEDIATE, то
// есть другой писатель не может вклиниться между проверкой и вставкой. Сам
// уникальный индекс остаётся последней линией обороны и обязан её пережить.
func (rs *Resources) Create(ctx context.Context, tx *sql.Tx, in NewResource, caseConflictDetect bool) (Resource, error) {
	if err := ValidateName(in.Name); err != nil {
		return Resource{}, err
	}
	if !in.Namespace.Valid() {
		return Resource{}, fmt.Errorf("metadata: create %q: namespace %q is not in the §6.3 dictionary",
			in.Name, in.Namespace)
	}
	if !in.Kind.Valid() {
		return Resource{}, fmt.Errorf("metadata: create %q: kind %q is not in the §6.3 dictionary",
			in.Name, in.Kind)
	}
	if in.SizeBytes < 0 {
		return Resource{}, fmt.Errorf("metadata: create %q: size_bytes = %d, must be >= 0",
			in.Name, in.SizeBytes)
	}
	if err := validateChecksum(in.ChecksumAlgo, in.Checksum); err != nil {
		return Resource{}, fmt.Errorf("metadata: create %q: %w", in.Name, err)
	}
	// Каталог создаётся ПУСТЫМ во всех трёх смыслах, относящихся к содержимому:
	// без размера, без ревизии и без контрольной суммы.
	//
	// Схема ловит только первое: CHECK (kind = 'file' OR size_bytes = 0). Два
	// других поля она с видом ресурса не связывает, и каталог с ревизией 7 и
	// суммой SHA256 лёг бы в таблицу молча. Врал бы он ровно тому, кто обязан
	// верить `resources` без оглядки: stat отдал бы клиенту сумму содержимого,
	// которого нет, а проверка ExpectedRevision (§9.6 — она про мутации ФАЙЛА)
	// получила бы величину, которую никто не увеличивает.
	//
	// Запрет относится к СОЗДАНИЮ. Что делать с ревизией каталога дальше —
	// вопрос мутаций §9, и здесь он не решается.
	if in.Kind == domain.KindDir {
		switch {
		case in.SizeBytes != 0:
			return Resource{}, fmt.Errorf("metadata: create dir %q: size_bytes = %d, must be 0 (§6.3)",
				in.Name, in.SizeBytes)
		case in.Revision != domain.NoRevision:
			return Resource{}, fmt.Errorf("metadata: create dir %q: current_revision = %d, must be %d: "+
				"a directory has no content to revise", in.Name, in.Revision, domain.NoRevision)
		case in.ChecksumAlgo != domain.ChecksumPending || len(in.Checksum) != 0:
			return Resource{}, fmt.Errorf("metadata: create dir %q: checksum_algo = %q with %d byte(s) of "+
				"checksum, both must be unset: a directory has no content to sum",
				in.Name, in.ChecksumAlgo, len(in.Checksum))
		}
	}

	parent, err := childrenParent(ctx, tx, in.ParentID)
	if err != nil {
		return Resource{}, err
	}
	if parent.Kind != domain.KindDir {
		return Resource{}, fmt.Errorf("metadata: create %q: parent %s is a file", in.Name, in.ParentID)
	}
	if parent.Deleted() {
		return Resource{}, fmt.Errorf("metadata: create %q: parent %s is deleted", in.Name, in.ParentID)
	}
	if parent.Namespace != in.Namespace {
		return Resource{}, fmt.Errorf("metadata: create %q: parent %s is in namespace %q, not %q",
			in.Name, in.ParentID, parent.Namespace, in.Namespace)
	}
	// §6.3: «Для namespace = 'home' владелец — хозяин корня». Внешний ключ этого
	// не ловит — он проверяет лишь существование пользователя.
	//
	// Последствие подмены владельца не косметическое. Физический путь blob —
	// функция от (owner_user_id, id) по §5.1, а квота списывается с владельца
	// (§11.4). Строка в home пользователя A, помеченная владельцем B, положила бы
	// содержимое под root пользователя B и списала бы его квоту, оставаясь видимой
	// в дереве A: это разом и пробой изоляции home (DoD M12), и порча учёта.
	//
	// Проверка против НЕПОСРЕДСТВЕННОГО родителя достаточна по индукции: корень
	// создаётся с владельцем-пользователем, а каждая вставка ниже сверяется с уже
	// проверенным родителем.
	//
	// Для namespace = 'public' ограничения нет сознательно: там владельцем
	// становится создавший ресурс пользователь (§6.3), и его квота за
	// public-контент и списывается.
	if in.Namespace == domain.NamespaceHome && in.OwnerUserID != parent.OwnerUserID {
		return Resource{}, fmt.Errorf(
			"metadata: create %q: owner_user_id = %d, but the home tree of %s belongs to user %d; "+
				"in the home namespace the owner is the owner of the root (§6.3)",
			in.Name, in.OwnerUserID, in.ParentID, parent.OwnerUserID)
	}

	var exists int
	err = tx.QueryRowContext(ctx, `SELECT 1 FROM resources
WHERE namespace = ? AND parent_id = ? AND name = ? AND deleted_at_ms IS NULL`,
		string(in.Namespace), in.ParentID.String(), in.Name).Scan(&exists)
	switch {
	case err == nil:
		return Resource{}, fmt.Errorf("%w: %q in %s", ErrNameExists, in.Name, in.ParentID)
	case !errors.Is(err, sql.ErrNoRows):
		return Resource{}, fmt.Errorf("metadata: check name %q: %w", in.Name, err)
	}

	fold := FoldName(in.Name)
	if caseConflictDetect {
		var other string
		err := tx.QueryRowContext(ctx, `SELECT name FROM resources
WHERE namespace = ? AND parent_id = ? AND name_fold = ? AND deleted_at_ms IS NULL
LIMIT 1`, string(in.Namespace), in.ParentID.String(), fold).Scan(&other)
		switch {
		case err == nil:
			return Resource{}, fmt.Errorf("%w: %q collides with existing %q in %s",
				ErrNameConflict, in.Name, other, in.ParentID)
		case !errors.Is(err, sql.ErrNoRows):
			return Resource{}, fmt.Errorf("metadata: check fold of %q: %w", in.Name, err)
		}
	}

	id, err := domain.NewResourceID()
	if err != nil {
		return Resource{}, fmt.Errorf("metadata: create %q: %w", in.Name, err)
	}
	now := domain.NowMillis()
	res := Resource{
		ID:           id,
		OwnerUserID:  in.OwnerUserID,
		ParentID:     in.ParentID,
		Namespace:    in.Namespace,
		Name:         in.Name,
		NameFold:     fold,
		Kind:         in.Kind,
		Revision:     in.Revision,
		SizeBytes:    in.SizeBytes,
		ChecksumAlgo: in.ChecksumAlgo,
		Checksum:     in.Checksum,
		CreatedAt:    now,
		UpdatedAt:    now,
	}
	if err := insertResource(ctx, tx, res); err != nil {
		return Resource{}, fmt.Errorf("metadata: create %q in %s: %w", in.Name, in.ParentID, err)
	}
	return res, nil
}

// childrenParent читает родителя ВНУТРИ транзакции: проверка предусловия,
// выполненная читающим handle'ом, относилась бы к другому снапшоту.
func childrenParent(ctx context.Context, tx *sql.Tx, id domain.ResourceID) (Resource, error) {
	row := tx.QueryRowContext(ctx, `SELECT `+resourceColumns+` FROM resources WHERE id = ?`, id.String())
	res, err := scanResource(row)
	if errors.Is(err, sql.ErrNoRows) {
		return Resource{}, fmt.Errorf("%w: parent %s", ErrNotFound, id)
	}
	return res, err
}

func insertResource(ctx context.Context, tx *sql.Tx, r Resource) error {
	_, err := tx.ExecContext(ctx, `
INSERT INTO resources (id, owner_user_id, parent_id, namespace, name, name_fold, kind,
                       current_revision, size_bytes, checksum_algo, checksum,
                       created_at_ms, updated_at_ms, deleted_at_ms, trashed_root_id)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL)`,
		r.ID.String(), int64(r.OwnerUserID), r.ParentID.String(), string(r.Namespace),
		r.Name, r.NameFold, string(r.Kind), int64(r.Revision), r.SizeBytes,
		nullableAlgo(r.ChecksumAlgo), nullableBlob(r.Checksum),
		int64(r.CreatedAt), int64(r.UpdatedAt))
	return err
}

// validateChecksum сверяет пару (algo, checksum) с §6.1: у ChecksumPending в БД
// обе колонки NULL, у остальных длина суммы задана алгоритмом. Проверка нужна
// здесь потому, что схема её выразить не может: CHECK видит колонки по
// отдельности, а не их согласованность с длиной BLOB.
func validateChecksum(algo domain.ChecksumAlgo, sum []byte) error {
	if !algo.Valid() {
		return fmt.Errorf("checksum algo %q is not in the §6.1 dictionary", algo)
	}
	if algo == domain.ChecksumPending {
		if len(sum) != 0 {
			return fmt.Errorf("checksum is %d bytes while algo is unset (§6.1)", len(sum))
		}
		return nil
	}
	if want := algo.SignificantBytes(); len(sum) != want {
		return fmt.Errorf("checksum for %s is %d bytes, want %d (§6.1)", algo, len(sum), want)
	}
	return nil
}

type scanner interface {
	Scan(dest ...any) error
}

func scanResource(s scanner) (Resource, error) {
	var (
		r          Resource
		id         string
		parentID   string
		namespace  string
		kind       string
		revision   int64
		algo       sql.NullString
		sum        []byte
		deletedAt  sql.NullInt64
		trashedRID sql.NullString
		owner      int64
		created    int64
		updated    int64
	)
	err := s.Scan(&id, &owner, &parentID, &namespace, &r.Name, &r.NameFold, &kind,
		&revision, &r.SizeBytes, &algo, &sum, &created, &updated, &deletedAt, &trashedRID)
	if err != nil {
		return Resource{}, err
	}

	if r.ID, err = domain.ParseResourceID(id); err != nil {
		return Resource{}, fmt.Errorf("metadata: resources.id: %w", err)
	}
	if r.ParentID, err = domain.ParseResourceID(parentID); err != nil {
		return Resource{}, fmt.Errorf("metadata: resources.parent_id of %s: %w", id, err)
	}
	if r.Namespace, err = domain.ParseNamespace(namespace); err != nil {
		return Resource{}, fmt.Errorf("metadata: resources.namespace of %s: %w", id, err)
	}
	if r.Kind, err = domain.ParseKind(kind); err != nil {
		return Resource{}, fmt.Errorf("metadata: resources.kind of %s: %w", id, err)
	}
	if algo.Valid {
		if r.ChecksumAlgo, err = domain.ParseChecksumAlgo(algo.String); err != nil {
			return Resource{}, fmt.Errorf("metadata: resources.checksum_algo of %s: %w", id, err)
		}
	}
	if trashedRID.Valid {
		if r.TrashedRootID, err = domain.ParseResourceID(trashedRID.String); err != nil {
			return Resource{}, fmt.Errorf("metadata: resources.trashed_root_id of %s: %w", id, err)
		}
	}
	r.OwnerUserID = domain.UserID(owner)
	r.Revision = domain.Revision(revision)
	r.Checksum = sum
	r.CreatedAt = domain.UnixMillis(created)
	r.UpdatedAt = domain.UnixMillis(updated)
	if deletedAt.Valid {
		r.DeletedAt = domain.UnixMillis(deletedAt.Int64)
	}
	return r, nil
}

// nullableAlgo отображает ChecksumPending в NULL: §6.1 объявляет «сумма не
// посчитана» отсутствием строки в колонке, а не пустой строкой, и CHECK в схеме
// пустую строку отверг бы.
func nullableAlgo(a domain.ChecksumAlgo) any {
	if a == domain.ChecksumPending {
		return nil
	}
	return string(a)
}

func nullableBlob(b []byte) any {
	if len(b) == 0 {
		return nil
	}
	return b
}
