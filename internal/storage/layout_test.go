package storage_test

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"

	"github.com/vitikevich-landau/go_fileshare/internal/domain"
	"github.com/vitikevich-landau/go_fileshare/internal/storage"
)

func layout(t *testing.T) storage.Layout {
	t.Helper()
	l, err := storage.New(t.TempDir())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return l
}

// TestNewRejectsRelativeRoot — относительный data root означал бы, что
// физическое расположение данных зависит от рабочего каталога процесса: тот же
// daemon, перезапущенный из другого каталога, обслуживал бы пустое дерево при
// полной метабазе.
func TestNewRejectsRelativeRoot(t *testing.T) {
	for _, root := range []string{"", "data", "./data", filepath.Join("..", "data")} {
		if _, err := storage.New(root); err == nil {
			t.Errorf("New(%q) прошёл, ожидалась ошибка", root)
		}
	}
}

// TestLayoutMatchesSpec — раскладка §5.1 дословно. Тест сверяет ОТНОСИТЕЛЬНЫЕ
// пути: абсолютные зависят от временного каталога, а нормативен именно набор
// компонентов.
func TestLayoutMatchesSpec(t *testing.T) {
	l := layout(t)
	const uid = domain.UserID(42)

	tests := []struct {
		name string
		got  string
		want string
	}{
		{"files", l.Files(), "files"},
		{"каталог пользователя", l.UserDir(uid), "files/users/42"},
		{"home пользователя", l.UserLive(uid), "files/users/42/live"},
		{"public", l.PublicLive(), "files/public/live"},
		{"staging", l.StagingUploads(), "staging/uploads"},
		{"версии пользователя", l.VersionsDir(uid), "versions/42"},
		{"recovery", l.Recovery(), "recovery"},
		{"quarantine", l.Quarantine(), "quarantine"},
		{"certs", l.Certs(), "certs"},
		{"backups", l.Backups(), "backups"},
	}
	for _, tt := range tests {
		rel, err := filepath.Rel(l.Root(), tt.got)
		if err != nil {
			t.Fatalf("%s: Rel(%q): %v", tt.name, tt.got, err)
		}
		if got := filepath.ToSlash(rel); got != tt.want {
			t.Errorf("%s = %q, want %q (§5.1)", tt.name, got, tt.want)
		}
	}
}

// TestUserComponentIsTheNumericID — §5.2: компонент пути, отвечающий за
// пользователя, — это десятичный UserID и только он. Проверяется не отсутствием
// логина в строке (его туда и передать некуда), а тем, что компонент разбирается
// обратно в тот же идентификатор: именно из этого следует, что переименование
// пользователя, когда оно появится, не тронет ни одного пути на диске.
func TestUserComponentIsTheNumericID(t *testing.T) {
	l := layout(t)
	for _, id := range []domain.UserID{1, 7, 1024, 9007199254740993} {
		for name, dir := range map[string]string{
			"UserDir":     l.UserDir(id),
			"UserLive":    filepath.Dir(l.UserLive(id)),
			"VersionsDir": l.VersionsDir(id),
		} {
			got, err := strconv.ParseInt(filepath.Base(dir), 10, 64)
			if err != nil || domain.UserID(got) != id {
				t.Errorf("%s(%d): компонент %q не является десятичным UserID (§5.2)",
					name, id, filepath.Base(dir))
			}
		}
	}
}

// TestEnsureSkeleton — §5.1 объявляет каталоги обязательными, значит, они
// существуют после подготовки data root, а не появляются в момент первой ошибки.
func TestEnsureSkeleton(t *testing.T) {
	l := layout(t)
	if err := l.EnsureSkeleton(); err != nil {
		t.Fatalf("EnsureSkeleton: %v", err)
	}
	for _, dir := range []string{
		filepath.Join(l.Files(), "users"),
		l.PublicLive(),
		l.StagingUploads(),
		l.Recovery(),
		l.Quarantine(),
	} {
		st, err := os.Stat(dir)
		if err != nil {
			t.Errorf("Stat(%s): %v", dir, err)
			continue
		}
		if !st.IsDir() {
			t.Errorf("%s не каталог", dir)
		}
	}
	// Повторный вызов безвреден: подготовка выполняется на каждом старте.
	if err := l.EnsureSkeleton(); err != nil {
		t.Fatalf("повторный EnsureSkeleton: %v", err)
	}
}

// TestEnsureSkeletonKeepsDataRootPrivate — в files/ лежит содержимое
// пользовательских файлов, поэтому мировое чтение data root означало бы раздачу
// его локальным пользователям хоста (в Docker — через bind-mount /data).
func TestEnsureSkeletonKeepsDataRootPrivate(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("режим каталога в POSIX-смысле на Windows не выражается: доступ задаётся ACL")
	}
	l := layout(t)
	if err := l.EnsureSkeleton(); err != nil {
		t.Fatalf("EnsureSkeleton: %v", err)
	}
	st, err := os.Stat(l.PublicLive())
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if perm := st.Mode().Perm(); perm&0o077 != 0 {
		t.Errorf("режим %v открывает каталог группе или всем", perm)
	}
}

// TestOpenUserHomeCreatesAndLocks — корень открывается до первой файловой
// операции сессии (§7.2) и удерживает границу сам: «..» наружу не выводит.
func TestOpenUserHomeCreatesAndLocks(t *testing.T) {
	l := layout(t)

	root, err := l.OpenUserHome(1)
	if err != nil {
		t.Fatalf("OpenUserHome: %v", err)
	}
	defer root.Close()

	if got, want := root.Name(), l.UserLive(1); got != want {
		t.Errorf("корень открыт на %q, want %q", got, want)
	}
	if st, err := os.Stat(l.UserLive(1)); err != nil || !st.IsDir() {
		t.Fatalf("каталог home не создан: %v", err)
	}

	// Побег из корня. os.Root обязан отвергнуть путь, покидающий корень, даже
	// если целевой файл существует: на этом держится изоляция §7.2, а не на
	// проверках в обработчиках.
	outside := filepath.Join(l.Root(), "outside.txt")
	if err := os.WriteFile(outside, []byte("secret"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	for _, escape := range []string{
		"../../../outside.txt",
		filepath.Join("..", "..", "..", "outside.txt"),
	} {
		if _, err := root.Open(escape); err == nil {
			t.Errorf("os.Root открыл %q за пределами корня", escape)
		}
	}
}

// TestOpenUserHomeIsIdempotent — второй вызов не пересоздаёт каталог и не теряет
// содержимое: сессии одного пользователя открывают один и тот же home.
func TestOpenUserHomeIsIdempotent(t *testing.T) {
	l := layout(t)
	first, err := l.OpenUserHome(3)
	if err != nil {
		t.Fatalf("OpenUserHome: %v", err)
	}
	defer first.Close()
	if err := os.WriteFile(filepath.Join(l.UserLive(3), "blob"), []byte("x"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	second, err := l.OpenUserHome(3)
	if err != nil {
		t.Fatalf("повторный OpenUserHome: %v", err)
	}
	defer second.Close()
	if _, err := second.Stat("blob"); err != nil {
		t.Errorf("содержимое home потеряно: %v", err)
	}
}

// TestOpenUserHomeRejectsSystemAccount — §6.2: системный аккаунт не имеет /home.
// Открыть ему корень значило бы создать files/users/0/live, то есть дерево,
// принадлежащее записи, которая не может пройти аутентификацию.
func TestOpenUserHomeRejectsSystemAccount(t *testing.T) {
	l := layout(t)
	root, err := l.OpenUserHome(domain.SystemUserID)
	if err == nil {
		root.Close()
		t.Fatal("системному аккаунту открыт home")
	}
	if !errors.Is(err, storage.ErrNoHome) {
		t.Errorf("err = %v, ожидалась ErrNoHome", err)
	}
	if _, err := os.Stat(l.UserDir(domain.SystemUserID)); !os.IsNotExist(err) {
		t.Errorf("каталог системного аккаунта создан: %v", err)
	}
}

// TestOpenPublicIsShared — namespace public — общее дерево: корень один на
// установку, разграничение доступа выполняет authorization service (§7.3).
func TestOpenPublicIsShared(t *testing.T) {
	l := layout(t)
	root, err := l.OpenPublic()
	if err != nil {
		t.Fatalf("OpenPublic: %v", err)
	}
	defer root.Close()
	if got, want := root.Name(), l.PublicLive(); got != want {
		t.Errorf("public открыт на %q, want %q", got, want)
	}
}

// TestRemoveUserData — `user purge` (§7.4) уносит и содержимое home, и версии
// пользователя; повторный вызов безвреден, потому что purge обязан быть
// повторяемым.
func TestRemoveUserData(t *testing.T) {
	l := layout(t)
	root, err := l.OpenUserHome(5)
	if err != nil {
		t.Fatalf("OpenUserHome: %v", err)
	}
	if err := os.WriteFile(filepath.Join(l.UserLive(5), "blob"), []byte("x"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := os.MkdirAll(l.VersionsDir(5), 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	// Windows не удаляет каталог с открытым дескриптором внутри, а сессии
	// пользователя к моменту purge закрыты по §7.4.
	root.Close()

	if err := l.RemoveUserData(5); err != nil {
		t.Fatalf("RemoveUserData: %v", err)
	}
	for _, dir := range []string{l.UserDir(5), l.VersionsDir(5)} {
		if _, err := os.Stat(dir); !os.IsNotExist(err) {
			t.Errorf("%s не удалён: %v", dir, err)
		}
	}
	if err := l.RemoveUserData(5); err != nil {
		t.Errorf("повторный RemoveUserData: %v", err)
	}
}

// TestRemoveUserDataRefusesSystemAccount — системный аккаунт владеет
// public-ресурсами, переданными при purge их прежних владельцев (§7.3, §7.4).
// Снести его данные значило бы удалить public-контент всей установки.
func TestRemoveUserDataRefusesSystemAccount(t *testing.T) {
	l := layout(t)
	if err := l.RemoveUserData(domain.SystemUserID); err == nil {
		t.Fatal("RemoveUserData(system) прошёл")
	}
}
