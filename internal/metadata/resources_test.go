package metadata_test

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	"github.com/vitikevich-landau/go_fileshare/internal/db"
	"github.com/vitikevich-landau/go_fileshare/internal/domain"
	"github.com/vitikevich-landau/go_fileshare/internal/metadata"
)

// create — обёртка «одна вставка в одной транзакции»: в тестах репозитория
// композиция операций не проверяется, а шум от db.Write вокруг каждой строки
// делает нечитаемым то, что проверяется.
func create(t *testing.T, d *db.DB, rs *metadata.Resources, in metadata.NewResource, detect bool) (metadata.Resource, error) {
	t.Helper()
	var (
		out metadata.Resource
		err error
	)
	txErr := d.Write(context.Background(), func(tx *sql.Tx) error {
		out, err = rs.Create(context.Background(), tx, in, detect)
		return err
	})
	if err == nil && txErr != nil {
		t.Fatalf("commit: %v", txErr)
	}
	return out, err
}

// TestPublicRootFromMigration — корень /public существует с первой секунды и
// имеет ту форму, которую §6.3 требует от корня namespace: id = parent_id,
// пустое имя, каталог, владелец — системный аккаунт.
func TestPublicRootFromMigration(t *testing.T) {
	ctx := context.Background()
	d := open(t, t.TempDir())
	rs := metadata.NewResources(d)

	root, err := rs.PublicRoot(ctx)
	if err != nil {
		t.Fatalf("PublicRoot: %v", err)
	}
	if !root.IsRoot() {
		t.Errorf("PublicRoot: id = %s, parent_id = %s, ожидалось равенство", root.ID, root.ParentID)
	}
	if root.Name != "" || root.NameFold != "" {
		t.Errorf("PublicRoot: name = %q, name_fold = %q, ожидались пустые", root.Name, root.NameFold)
	}
	if root.Kind != domain.KindDir {
		t.Errorf("PublicRoot: kind = %q, want %q", root.Kind, domain.KindDir)
	}
	if root.OwnerUserID != domain.SystemUserID {
		t.Errorf("PublicRoot: owner = %d, want %d", root.OwnerUserID, domain.SystemUserID)
	}
	if root.Deleted() {
		t.Error("PublicRoot: корень помечен удалённым")
	}

	// Корень /home системного аккаунта не создаётся: §6.2 прямо говорит, что у
	// него нет /home.
	if _, err := rs.HomeRoot(ctx, domain.SystemUserID); !errors.Is(err, metadata.ErrNotFound) {
		t.Errorf("HomeRoot(system) = %v, want ErrNotFound: §6.2 не даёт системному аккаунту /home", err)
	}
}

// TestCreateAndLookup — созданный ресурс находится всеми тремя способами, а его
// поля переживают круг «записали → прочитали» без потерь.
func TestCreateAndLookup(t *testing.T) {
	ctx := context.Background()
	d := open(t, t.TempDir())
	rs := metadata.NewResources(d)
	root, err := rs.PublicRoot(ctx)
	if err != nil {
		t.Fatalf("PublicRoot: %v", err)
	}

	sum := make([]byte, 32)
	for i := range sum {
		sum[i] = byte(i)
	}
	file, err := create(t, d, rs, metadata.NewResource{
		OwnerUserID:  domain.SystemUserID,
		ParentID:     root.ID,
		Namespace:    domain.NamespacePublic,
		Name:         "отчёт.pdf",
		Kind:         domain.KindFile,
		Revision:     7,
		SizeBytes:    1234,
		ChecksumAlgo: domain.ChecksumSHA256,
		Checksum:     sum,
	}, true)
	if err != nil {
		t.Fatalf("Create file: %v", err)
	}
	dir, err := create(t, d, rs, metadata.NewResource{
		OwnerUserID: domain.SystemUserID,
		ParentID:    root.ID,
		Namespace:   domain.NamespacePublic,
		Name:        "архив",
		Kind:        domain.KindDir,
	}, true)
	if err != nil {
		t.Fatalf("Create dir: %v", err)
	}

	got, err := rs.ByID(ctx, file.ID)
	if err != nil {
		t.Fatalf("ByID: %v", err)
	}
	if got.Name != "отчёт.pdf" || got.SizeBytes != 1234 || got.Revision != 7 {
		t.Errorf("ByID: name = %q, size = %d, revision = %d; want «отчёт.pdf», 1234, 7",
			got.Name, got.SizeBytes, got.Revision)
	}
	if got.ChecksumAlgo != domain.ChecksumSHA256 || len(got.Checksum) != 32 {
		t.Errorf("ByID: algo = %q, len(checksum) = %d; want sha256, 32", got.ChecksumAlgo, len(got.Checksum))
	}
	if got.NameFold != metadata.FoldName("отчёт.pdf") {
		t.Errorf("ByID: name_fold = %q, want %q", got.NameFold, metadata.FoldName("отчёт.pdf"))
	}
	if got.IsRoot() {
		t.Error("ByID: обычный ресурс считает себя корнем")
	}

	byName, err := rs.ChildByName(ctx, domain.NamespacePublic, root.ID, "отчёт.pdf")
	if err != nil {
		t.Fatalf("ChildByName: %v", err)
	}
	if byName.ID != file.ID {
		t.Errorf("ChildByName вернул %s, want %s", byName.ID, file.ID)
	}

	// Каталог отдаётся целиком и упорядочен по имени; сам корень в детей не
	// попадает, хотя формально parent_id у него указывает на себя.
	children, err := rs.Children(ctx, domain.NamespacePublic, root.ID)
	if err != nil {
		t.Fatalf("Children: %v", err)
	}
	if len(children) != 2 {
		t.Fatalf("Children вернул %d записей, want 2", len(children))
	}
	if children[0].ID != dir.ID || children[1].ID != file.ID {
		t.Errorf("Children: порядок %q, %q; ожидался по имени: «архив», «отчёт.pdf»",
			children[0].Name, children[1].Name)
	}
}

// TestCreateByteDuplicate — побайтовое совпадение имени в живом каталоге даёт
// ErrNameExists при ЛЮБОЙ конфигурации (§5.3).
func TestCreateByteDuplicate(t *testing.T) {
	ctx := context.Background()
	d := open(t, t.TempDir())
	rs := metadata.NewResources(d)
	root, err := rs.PublicRoot(ctx)
	if err != nil {
		t.Fatalf("PublicRoot: %v", err)
	}

	in := metadata.NewResource{
		OwnerUserID: domain.SystemUserID, ParentID: root.ID,
		Namespace: domain.NamespacePublic, Name: "a.txt", Kind: domain.KindFile,
	}
	if _, err := create(t, d, rs, in, true); err != nil {
		t.Fatalf("первое создание: %v", err)
	}
	for _, detect := range []bool{true, false} {
		if _, err := create(t, d, rs, in, detect); !errors.Is(err, metadata.ErrNameExists) {
			t.Errorf("повтор при case_conflict_detect = %v: %v, want ErrNameExists", detect, err)
		}
	}
}

// TestCreateCaseConflict — совпадение ТОЛЬКО по name_fold: конфликт при
// storage.case_conflict_detect = true и законное соседство при false (§5.3).
func TestCreateCaseConflict(t *testing.T) {
	ctx := context.Background()

	t.Run("detect=true", func(t *testing.T) {
		d := open(t, t.TempDir())
		rs := metadata.NewResources(d)
		root, err := rs.PublicRoot(ctx)
		if err != nil {
			t.Fatalf("PublicRoot: %v", err)
		}
		base := metadata.NewResource{
			OwnerUserID: domain.SystemUserID, ParentID: root.ID,
			Namespace: domain.NamespacePublic, Kind: domain.KindFile,
		}
		base.Name = "a.txt"
		if _, err := create(t, d, rs, base, true); err != nil {
			t.Fatalf("создание a.txt: %v", err)
		}
		// Отличается регистром.
		base.Name = "A.TXT"
		if _, err := create(t, d, rs, base, true); !errors.Is(err, metadata.ErrNameConflict) {
			t.Errorf("создание A.TXT = %v, want ErrNameConflict", err)
		}
		// Отличается формой нормализации: NFD против NFC.
		base.Name = aRingNFC + ".bin"
		if _, err := create(t, d, rs, base, true); err != nil {
			t.Fatalf("создание NFC-имени: %v", err)
		}
		base.Name = aRingNFD + ".bin"
		if _, err := create(t, d, rs, base, true); !errors.Is(err, metadata.ErrNameConflict) {
			t.Errorf("создание того же имени в NFD = %v, want ErrNameConflict", err)
		}
	})

	t.Run("detect=false", func(t *testing.T) {
		d := open(t, t.TempDir())
		rs := metadata.NewResources(d)
		root, err := rs.PublicRoot(ctx)
		if err != nil {
			t.Fatalf("PublicRoot: %v", err)
		}
		base := metadata.NewResource{
			OwnerUserID: domain.SystemUserID, ParentID: root.ID,
			Namespace: domain.NamespacePublic, Kind: domain.KindFile,
		}
		base.Name = "a.txt"
		if _, err := create(t, d, rs, base, false); err != nil {
			t.Fatalf("создание a.txt: %v", err)
		}
		base.Name = "A.TXT"
		if _, err := create(t, d, rs, base, false); err != nil {
			t.Fatalf("создание A.TXT при выключенном детекте: %v", err)
		}
		children, err := rs.Children(ctx, domain.NamespacePublic, root.ID)
		if err != nil {
			t.Fatalf("Children: %v", err)
		}
		if len(children) != 2 {
			t.Fatalf("при выключенном детекте ожидались оба файла, получено %d", len(children))
		}
	})
}

// TestCreateAfterDelete — сценарий «удалил и залил заново» обязан работать без
// ошибки (§10.1). Держится он на предикате WHERE deleted_at_ms IS NULL у
// resources_uniq_name: без него удалённая строка навсегда занимала бы имя.
func TestCreateAfterDelete(t *testing.T) {
	ctx := context.Background()
	d := open(t, t.TempDir())
	rs := metadata.NewResources(d)
	root, err := rs.PublicRoot(ctx)
	if err != nil {
		t.Fatalf("PublicRoot: %v", err)
	}

	in := metadata.NewResource{
		OwnerUserID: domain.SystemUserID, ParentID: root.ID,
		Namespace: domain.NamespacePublic, Name: "a.txt", Kind: domain.KindFile,
	}
	first, err := create(t, d, rs, in, true)
	if err != nil {
		t.Fatalf("первое создание: %v", err)
	}

	// Удаление выполняется прямым UPDATE, а не методом репозитория: логическое
	// удаление — это операция §9.5 вместе с записью корзины и журналом, она
	// приезжает на своём этапе. Здесь проверяется схема, а не будущий API.
	// trashed_root_id указывает на саму строку: она и есть корень удалённого
	// поддерева (§6.3), и CHECK требует заполнить обе колонки вместе.
	if err := d.Write(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx,
			`UPDATE resources SET deleted_at_ms = ?, trashed_root_id = id WHERE id = ?`,
			int64(domain.NowMillis()), first.ID.String())
		return err
	}); err != nil {
		t.Fatalf("пометить удалённым: %v", err)
	}

	second, err := create(t, d, rs, in, true)
	if err != nil {
		t.Fatalf("повторное создание после удаления: %v", err)
	}
	if second.ID == first.ID {
		t.Error("новый ресурс переиспользовал ResourceID удалённого")
	}
	if _, err := rs.ChildByName(ctx, domain.NamespacePublic, root.ID, "a.txt"); err != nil {
		t.Errorf("ChildByName после пересоздания: %v", err)
	}
	// Удалённая строка по-прежнему доступна по идентификатору: на ней держится
	// восстановление из корзины.
	old, err := rs.ByID(ctx, first.ID)
	if err != nil {
		t.Fatalf("ByID удалённой строки: %v", err)
	}
	if !old.Deleted() {
		t.Error("ByID вернул удалённую строку как живую")
	}
}

// TestCreateRejects — предусловия, которые Create обязан проверить сам, потому
// что схема их не выражает или выражает непонятной для клиента ошибкой.
func TestCreateRejects(t *testing.T) {
	ctx := context.Background()
	d := open(t, t.TempDir())
	rs := metadata.NewResources(d)
	root, err := rs.PublicRoot(ctx)
	if err != nil {
		t.Fatalf("PublicRoot: %v", err)
	}
	file, err := create(t, d, rs, metadata.NewResource{
		OwnerUserID: domain.SystemUserID, ParentID: root.ID,
		Namespace: domain.NamespacePublic, Name: "file.bin", Kind: domain.KindFile,
	}, true)
	if err != nil {
		t.Fatalf("подготовка: %v", err)
	}
	missing, err := domain.NewResourceID()
	if err != nil {
		t.Fatalf("NewResourceID: %v", err)
	}

	good := metadata.NewResource{
		OwnerUserID: domain.SystemUserID, ParentID: root.ID,
		Namespace: domain.NamespacePublic, Name: "ok.txt", Kind: domain.KindFile,
	}
	cases := []struct {
		why    string
		mutate func(*metadata.NewResource)
		want   error
	}{
		{"имя нарушает §5.3", func(n *metadata.NewResource) { n.Name = "CON.txt" }, metadata.ErrInvalidName},
		{"пустое имя не корня", func(n *metadata.NewResource) { n.Name = "" }, metadata.ErrInvalidName},
		{"родителя нет", func(n *metadata.NewResource) { n.ParentID = missing }, metadata.ErrNotFound},
		{"родитель — файл", func(n *metadata.NewResource) { n.ParentID = file.ID }, nil},
		{"namespace не совпадает с родителем", func(n *metadata.NewResource) { n.Namespace = domain.NamespaceHome }, nil},
		{"каталог с размером", func(n *metadata.NewResource) { n.Kind = domain.KindDir; n.SizeBytes = 10 }, nil},
		{"отрицательный размер", func(n *metadata.NewResource) { n.SizeBytes = -1 }, nil},
		{"kind вне словаря", func(n *metadata.NewResource) { n.Kind = "symlink" }, nil},
		{"namespace вне словаря", func(n *metadata.NewResource) { n.Namespace = "shared" }, nil},
		{"сумма без алгоритма", func(n *metadata.NewResource) { n.Checksum = []byte{1, 2, 3, 4} }, nil},
		{"длина суммы не по алгоритму", func(n *metadata.NewResource) {
			n.ChecksumAlgo = domain.ChecksumCRC32
			n.Checksum = make([]byte, 32)
		}, nil},
	}
	for _, tc := range cases {
		in := good
		tc.mutate(&in)
		_, err := create(t, d, rs, in, true)
		if err == nil {
			t.Errorf("%s: Create вернул nil, ожидалась ошибка", tc.why)
			continue
		}
		if tc.want != nil && !errors.Is(err, tc.want) {
			t.Errorf("%s: Create = %v, ожидалась обёртка %v", tc.why, err, tc.want)
		}
	}
}

// TestChildByFold — поиск по свёрнутому имени находит ресурс, записанный в
// другом регистре и другой форме нормализации. На этом запросе держится детект
// конфликтов, поэтому он проверяется отдельно от самого детекта.
func TestChildByFold(t *testing.T) {
	ctx := context.Background()
	d := open(t, t.TempDir())
	rs := metadata.NewResources(d)
	root, err := rs.PublicRoot(ctx)
	if err != nil {
		t.Fatalf("PublicRoot: %v", err)
	}
	if _, err := create(t, d, rs, metadata.NewResource{
		OwnerUserID: domain.SystemUserID, ParentID: root.ID,
		Namespace: domain.NamespacePublic, Name: "Отчёт" + aRingNFC + ".TXT", Kind: domain.KindFile,
	}, true); err != nil {
		t.Fatalf("подготовка: %v", err)
	}

	// Ищем по свёртке имени, записанного иначе: нижний регистр и NFD.
	fold := metadata.FoldName("отчёт" + aRingNFD + ".txt")
	got, err := rs.ChildByFold(ctx, domain.NamespacePublic, root.ID, fold)
	if err != nil {
		t.Fatalf("ChildByFold: %v", err)
	}
	if got.Name != "Отчёт"+aRingNFC+".TXT" {
		t.Errorf("ChildByFold вернул %q", got.Name)
	}

	if _, err := rs.ChildByFold(ctx, domain.NamespacePublic, root.ID, metadata.FoldName("другое")); !errors.Is(err, metadata.ErrNotFound) {
		t.Errorf("ChildByFold(несуществующее) = %v, want ErrNotFound", err)
	}
}

// TestCreateHomeOwnerMustMatchRoot — §6.3 требует, чтобы в namespace home
// владельцем ресурса был хозяин корня. Внешний ключ этого не ловит: он
// проверяет лишь существование пользователя.
//
// Последствие подмены не косметическое. Физический путь blob — функция от
// (owner_user_id, id) по §5.1, а квота списывается с владельца (§11.4). Строка
// в home пользователя A с владельцем B положила бы содержимое под root
// пользователя B и списала бы его квоту, оставаясь видимой в дереве A.
func TestCreateHomeOwnerMustMatchRoot(t *testing.T) {
	ctx := context.Background()
	d, us, rs := repos(t)

	mk := func(login string) metadata.User {
		t.Helper()
		u, err := createUser(t, d, us, newUser(login, domain.RoleUser))
		if err != nil {
			t.Fatalf("создать %q: %v", login, err)
		}
		return u
	}
	alice, bob := mk("alice"), mk("bob")

	aliceHome, err := rs.HomeRoot(ctx, alice.ID)
	if err != nil {
		t.Fatalf("HomeRoot(alice): %v", err)
	}

	if _, err := create(t, d, rs, metadata.NewResource{
		OwnerUserID: bob.ID, ParentID: aliceHome.ID,
		Namespace: domain.NamespaceHome, Name: "steal.bin", Kind: domain.KindFile,
	}, true); err == nil {
		t.Error("ресурс с чужим owner_user_id принят в home другого пользователя")
	}

	own, err := create(t, d, rs, metadata.NewResource{
		OwnerUserID: alice.ID, ParentID: aliceHome.ID,
		Namespace: domain.NamespaceHome, Name: "own.bin", Kind: domain.KindFile,
	}, true)
	if err != nil {
		t.Fatalf("собственный ресурс отвергнут: %v", err)
	}
	if own.OwnerUserID != alice.ID {
		t.Errorf("owner = %d, want %d", own.OwnerUserID, alice.ID)
	}

	// Проверка индуктивна: подкаталог наследует то же ограничение.
	dir, err := create(t, d, rs, metadata.NewResource{
		OwnerUserID: alice.ID, ParentID: aliceHome.ID,
		Namespace: domain.NamespaceHome, Name: "sub", Kind: domain.KindDir,
	}, true)
	if err != nil {
		t.Fatalf("подкаталог: %v", err)
	}
	if _, err := create(t, d, rs, metadata.NewResource{
		OwnerUserID: bob.ID, ParentID: dir.ID,
		Namespace: domain.NamespaceHome, Name: "deep.bin", Kind: domain.KindFile,
	}, true); err == nil {
		t.Error("чужой владелец принят на второй уровень home")
	}

	// В public ограничения нет: владельцем становится создавший ресурс (§6.3).
	public, err := rs.PublicRoot(ctx)
	if err != nil {
		t.Fatalf("PublicRoot: %v", err)
	}
	if _, err := create(t, d, rs, metadata.NewResource{
		OwnerUserID: bob.ID, ParentID: public.ID,
		Namespace: domain.NamespacePublic, Name: "shared.bin", Kind: domain.KindFile,
	}, true); err != nil {
		t.Errorf("ресурс в public с владельцем-создателем отвергнут: %v", err)
	}
}
