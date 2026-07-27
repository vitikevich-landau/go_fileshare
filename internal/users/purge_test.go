package users_test

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/vitikevich-landau/go_fileshare/internal/domain"
	"github.com/vitikevich-landau/go_fileshare/internal/metadata"
	"github.com/vitikevich-landau/go_fileshare/internal/users"
)

// delete переводит пользователя в pending_delete — первую фазу §7.4.
func (e *env) delete(t *testing.T, id domain.UserID) {
	t.Helper()
	if err := e.svc.SetState(context.Background(), id, domain.UserPendingDelete); err != nil {
		t.Fatalf("SetState(pending_delete): %v", err)
	}
	e.spy.reset()
}

// TestPurgeRemovesUserAndItsTree — вторая фаза §7.4: строка users, её home-дерево
// и строка journal_state исчезают.
//
// journal_state проверяется отдельно и придирчиво: она уходит каскадом (§6.11), а
// каскад — единственный шаг, который никто не выполняет явно, поэтому его отказ
// заметить труднее всего.
func TestPurgeRemovesUserAndItsTree(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	e.admin(t, "root")
	u := e.member(t, "alice", "pw")

	// Каталог home появляется при первой сессии; создаём его, чтобы проверить,
	// что purge уносит и физические данные.
	root, err := e.layout.OpenUserHome(u.ID)
	if err != nil {
		t.Fatalf("OpenUserHome: %v", err)
	}
	if err := os.WriteFile(filepath.Join(e.layout.UserLive(u.ID), "blob"), []byte("x"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	root.Close()

	e.delete(t, u.ID)
	if err := e.svc.Purge(ctx, u.ID); err != nil {
		t.Fatalf("Purge: %v", err)
	}

	if _, err := e.repo.ByID(ctx, u.ID); !errors.Is(err, metadata.ErrNotFound) {
		t.Errorf("строка users осталась: %v", err)
	}
	if _, err := e.res.HomeRoot(ctx, u.ID); !errors.Is(err, metadata.ErrNotFound) {
		t.Errorf("корень /home остался: %v", err)
	}
	if n := countJournalState(t, e, u.ID); n != 0 {
		t.Errorf("journal_state пользователя осталась (%d строк): каскад §6.11 не сработал", n)
	}
	if _, err := os.Stat(e.layout.UserDir(u.ID)); !os.IsNotExist(err) {
		t.Errorf("каталог пользователя остался: %v", err)
	}
	// Логин освобождается только purge: до него он занят (§6.2).
	if _, err := e.svc.Create(ctx, users.CreateUser{
		Login: "alice", Role: domain.RoleUser, Secret: users.NewSecret{Password: "pw2"},
	}); err != nil {
		t.Errorf("логин не освободился после purge: %v", err)
	}
}

// TestPurgeRequiresPendingDelete — §7.4 делает удаление двухфазным: purge
// активного пользователя означал бы, что одна команда уничтожает данные без
// предшествующего отзыва доступа.
func TestPurgeRequiresPendingDelete(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	e.admin(t, "root")
	u := e.member(t, "alice", "pw")

	for _, state := range []domain.UserState{domain.UserActive, domain.UserDisabled} {
		if err := e.svc.SetState(ctx, u.ID, state); err != nil {
			t.Fatalf("подготовка состояния %q: %v", state, err)
		}
		e.spy.reset()
		if err := e.svc.Purge(ctx, u.ID); !errors.Is(err, users.ErrPurgeNotPending) {
			t.Errorf("Purge в состоянии %q вернул %v, ожидалась ErrPurgeNotPending", state, err)
		}
		if _, err := e.repo.ByID(ctx, u.ID); err != nil {
			t.Errorf("отклонённый purge удалил строку: %v", err)
		}
	}
}

// TestPurgeTransfersPublicResources — §7.3 и §7.4: public-ресурсы удаляемого
// пользователя передаются системному аккаунту, а не удаляются. Владелец
// public-контента — тот, кто его загрузил, и удаление учётки не должно уносить
// файл, которым пользуется вся установка.
func TestPurgeTransfersPublicResources(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	e.admin(t, "root")
	u := e.member(t, "alice", "pw")

	publicRoot, err := e.res.PublicRoot(ctx)
	if err != nil {
		t.Fatalf("PublicRoot: %v", err)
	}
	var shared metadata.Resource
	err = e.db.Write(ctx, func(tx *sql.Tx) error {
		shared, err = e.res.Create(ctx, tx, metadata.NewResource{
			OwnerUserID: u.ID,
			ParentID:    publicRoot.ID,
			Namespace:   domain.NamespacePublic,
			Name:        "shared.txt",
			Kind:        domain.KindDir,
		}, true)
		return err
	})
	if err != nil {
		t.Fatalf("создание public-ресурса: %v", err)
	}

	e.delete(t, u.ID)
	if err := e.svc.Purge(ctx, u.ID); err != nil {
		t.Fatalf("Purge: %v", err)
	}

	got, err := e.res.ByID(ctx, shared.ID)
	if err != nil {
		t.Fatalf("public-ресурс удалён вместе с пользователем: %v", err)
	}
	if got.OwnerUserID != domain.SystemUserID {
		t.Errorf("владелец public-ресурса = %d, ожидался системный аккаунт %d (§7.3, §7.4)",
			got.OwnerUserID, domain.SystemUserID)
	}
}

// TestPurgeDeletesTreeBottomUp — RESTRICT на resources.parent_id требует удалять
// метаданные снизу вверх (§6.11). Дерево строится глубже одного уровня, потому
// что однопроходное удаление на плоском дереве прошло бы и при неверном порядке.
func TestPurgeDeletesTreeBottomUp(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	e.admin(t, "root")
	u := e.member(t, "alice", "pw")

	home, err := e.res.HomeRoot(ctx, u.ID)
	if err != nil {
		t.Fatalf("HomeRoot: %v", err)
	}
	parent := home.ID
	err = e.db.Write(ctx, func(tx *sql.Tx) error {
		for _, name := range []string{"a", "b", "c", "d"} {
			dir, err := e.res.Create(ctx, tx, metadata.NewResource{
				OwnerUserID: u.ID,
				ParentID:    parent,
				Namespace:   domain.NamespaceHome,
				Name:        name,
				Kind:        domain.KindDir,
			}, true)
			if err != nil {
				return err
			}
			parent = dir.ID
		}
		return nil
	})
	if err != nil {
		t.Fatalf("построение дерева: %v", err)
	}

	e.delete(t, u.ID)
	if err := e.svc.Purge(ctx, u.ID); err != nil {
		t.Fatalf("Purge вложенного дерева: %v", err)
	}
	if n := countResources(t, e, u.ID); n != 0 {
		t.Errorf("после purge осталось %d ресурсов пользователя", n)
	}
}

// TestPurgeBlockedByUnimplementedSteps — §6.11 требует убрать загрузки, версии,
// trash-записи и ссылки ДО строки users, а это шаги, принадлежащие M13, M15 и
// M16. Пока их нет, таблицы пусты; появятся раньше своей реализации purge —
// команда обязана отказаться, назвав таблицу, а не упереться в безымянное
// «FOREIGN KEY constraint failed».
//
// Строка uploads вставляется напрямую: репозитория загрузок не существует, и
// именно поэтому проверка нужна.
func TestPurgeBlockedByUnimplementedSteps(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	e.admin(t, "root")
	u := e.member(t, "alice", "pw")

	home, err := e.res.HomeRoot(ctx, u.ID)
	if err != nil {
		t.Fatalf("HomeRoot: %v", err)
	}
	uploadID, err := domain.NewUploadID()
	if err != nil {
		t.Fatalf("NewUploadID: %v", err)
	}
	err = e.db.Write(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `
INSERT INTO uploads (id, user_id, client_upload_key, target_parent_id, target_name,
                     target_name_fold, expected_size_bytes, expected_checksum_algo,
                     expected_checksum, received_bytes, synced_bytes, reserved_bytes,
                     overwrite_mode, state, staging_relpath,
                     created_at_ms, updated_at_ms, expires_at_ms)
VALUES (?, ?, ?, ?, 'x.bin', 'x.bin', 10, 'sha256', ?, 0, 0, 10,
        'fail', 'created', ?, ?, ?, ?)`,
			uploadID.String(), int64(u.ID), []byte("client-key"), home.ID.String(),
			make([]byte, 32), "uploads/"+uploadID.String()+".upart",
			int64(domain.NowMillis()), int64(domain.NowMillis()), int64(domain.NowMillis())+3600_000)
		return err
	})
	if err != nil {
		t.Fatalf("вставка строки uploads: %v", err)
	}

	e.delete(t, u.ID)
	err = e.svc.Purge(ctx, u.ID)
	if !errors.Is(err, users.ErrPurgeBlocked) {
		t.Fatalf("Purge вернул %v, ожидалась ErrPurgeBlocked", err)
	}
	if _, err := e.repo.ByID(ctx, u.ID); err != nil {
		t.Errorf("отклонённый purge удалил строку users: %v", err)
	}
	if _, err := e.res.HomeRoot(ctx, u.ID); err != nil {
		t.Errorf("отклонённый purge удалил корень /home: %v", err)
	}
}

// TestPurgeRefusesSystemAccount — §6.2: системная запись создаётся миграцией в
// любой инсталляции и владеет public-ресурсами, переданными при purge их прежних
// владельцев (§7.3). Её удаление снесло бы public-контент всей установки.
func TestPurgeRefusesSystemAccount(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	e.admin(t, "root")

	if err := e.svc.Purge(ctx, domain.SystemUserID); !errors.Is(err, users.ErrSystemAccount) {
		t.Fatalf("Purge(system) вернул %v, ожидалась ErrSystemAccount", err)
	}
	if _, err := e.repo.ByID(ctx, domain.SystemUserID); err != nil {
		t.Errorf("системная запись пострадала: %v", err)
	}
}

// TestPurgeRevokesNothing — у `user purge` в таблице §7.4 три прочерка: сессии
// закрыты, токены отозваны, а ссылки отозваны окончательно ещё операцией delete.
func TestPurgeRevokesNothing(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	e.admin(t, "root")
	u := e.member(t, "alice", "pw")

	e.delete(t, u.ID)
	if err := e.svc.Purge(ctx, u.ID); err != nil {
		t.Fatalf("Purge: %v", err)
	}
	if got := e.spy.log(); len(got) != 0 {
		t.Errorf("purge обратился к реестрам: %v", got)
	}
}

// TestPurgeOfLastAdminIsRejected — §7.4 перечисляет `user purge` среди операций,
// которые отклоняются кодом LAST_ADMIN_REQUIRED. Достижимо это только на базе, где
// администратор уже неактивен, — то есть проверка страхует не типичный сценарий,
// а инвариант 13 как таковой.
func TestPurgeOfLastAdminIsRejected(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	root := e.admin(t, "root")
	spare := e.admin(t, "spare")

	// root уходит в pending_delete, пока spare активен, — это разрешено.
	e.delete(t, root.ID)
	// Теперь spare отключается: активных администраторов не остаётся вовсе.
	if err := e.svc.SetState(ctx, spare.ID, domain.UserDisabled); !errors.Is(err, users.ErrLastAdminRequired) {
		t.Fatalf("отключение единственного активного администратора прошло: %v", err)
	}

	// purge root по-прежнему возможен: он не сокращает множество активных
	// администраторов, потому что root в нём уже не состоит.
	if err := e.svc.Purge(ctx, root.ID); err != nil {
		t.Fatalf("Purge неактивного администратора: %v", err)
	}
	if _, err := e.repo.ByLogin(ctx, "spare"); err != nil {
		t.Errorf("живой администратор пострадал: %v", err)
	}
}

func countJournalState(t *testing.T, e *env, id domain.UserID) int {
	t.Helper()
	return countRows(t, e, `SELECT count(*) FROM journal_state WHERE user_id = ?`, int64(id))
}

func countResources(t *testing.T, e *env, id domain.UserID) int {
	t.Helper()
	return countRows(t, e, `SELECT count(*) FROM resources WHERE owner_user_id = ?`, int64(id))
}

func countRows(t *testing.T, e *env, query string, args ...any) int {
	t.Helper()
	var n int
	err := e.db.Write(context.Background(), func(tx *sql.Tx) error {
		return tx.QueryRowContext(context.Background(), query, args...).Scan(&n)
	})
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	return n
}
