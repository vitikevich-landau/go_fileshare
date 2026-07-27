package metadata_test

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"

	"github.com/vitikevich-landau/go_fileshare/internal/domain"
	"github.com/vitikevich-landau/go_fileshare/internal/metadata"
)

// TestUserReferencesNamesTheBlockingTable — RESTRICT сообщает только «FOREIGN KEY
// constraint failed», без имени таблицы, а §6.11 требует от purge выполнить
// работу явно и по шагам. Значит, вызывающему нужно имя.
func TestUserReferencesNamesTheBlockingTable(t *testing.T) {
	ctx := context.Background()
	d, us, _ := repos(t)

	u, err := createUser(t, d, us, newUser("alice", domain.RoleUser))
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	var refs []metadata.UserReference
	err = d.Write(ctx, func(tx *sql.Tx) error {
		refs, err = us.UserReferences(ctx, tx, u.ID)
		return err
	})
	if err != nil {
		t.Fatalf("UserReferences: %v", err)
	}

	// У свежего пользователя ровно одна ссылка — корень /home, созданный вместе с
	// ним (§6.3). Пустых таблиц в перечне быть не должно: иначе purge отказывался
	// бы всегда.
	if len(refs) != 1 || refs[0].Table != "resources" || refs[0].Rows != 1 {
		t.Fatalf("UserReferences = %v, ожидалась одна ссылка resources: 1", refs)
	}
}

// TestDeleteOwnedRefusesParentCycle — цикл parent_id схема выразить может, а
// удаление снизу вверх на нём не работает: листьев у цикла нет, поэтому первый же
// проход удалит ноль строк.
//
// Проверяется, что метод отвечает ошибкой, а не успехом. Успех здесь опаснее
// ошибки: он выглядел бы как выполненное удаление, а следом падало бы удаление
// строки users с безымянным «FOREIGN KEY constraint failed».
func TestDeleteOwnedRefusesParentCycle(t *testing.T) {
	ctx := context.Background()
	d, us, res := repos(t)

	u, err := createUser(t, d, us, newUser("alice", domain.RoleUser))
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	home, err := res.HomeRoot(ctx, u.ID)
	if err != nil {
		t.Fatalf("HomeRoot: %v", err)
	}

	// Два каталога, ссылающиеся друг на друга. Репозиторий такого не создаёт —
	// цикл вносится напрямую, как его внесла бы ручная правка базы.
	var a, b metadata.Resource
	err = d.Write(ctx, func(tx *sql.Tx) error {
		if a, err = res.Create(ctx, tx, metadata.NewResource{
			OwnerUserID: u.ID, ParentID: home.ID, Namespace: domain.NamespaceHome,
			Name: "a", Kind: domain.KindDir,
		}, true); err != nil {
			return err
		}
		if b, err = res.Create(ctx, tx, metadata.NewResource{
			OwnerUserID: u.ID, ParentID: a.ID, Namespace: domain.NamespaceHome,
			Name: "b", Kind: domain.KindDir,
		}, true); err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `UPDATE resources SET parent_id = ? WHERE id = ?`,
			b.ID.String(), a.ID.String())
		return err
	})
	if err != nil {
		t.Fatalf("подготовка цикла: %v", err)
	}

	err = d.Write(ctx, func(tx *sql.Tx) error {
		_, err := res.DeleteOwned(ctx, tx, u.ID)
		return err
	})
	if err == nil {
		t.Fatal("DeleteOwned вернул успех на цикле parent_id")
	}
	if !strings.Contains(err.Error(), "cycle") {
		t.Errorf("ошибка не называет причину: %v", err)
	}
}

// TestTransferOwnershipIsScopedToNamespace — ограничение namespace обязательно:
// тот же UPDATE без него унёс бы и home пользователя, то есть отдал бы его личное
// дерево системному аккаунту вместо удаления.
func TestTransferOwnershipIsScopedToNamespace(t *testing.T) {
	ctx := context.Background()
	d, us, res := repos(t)

	u, err := createUser(t, d, us, newUser("alice", domain.RoleUser))
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	home, err := res.HomeRoot(ctx, u.ID)
	if err != nil {
		t.Fatalf("HomeRoot: %v", err)
	}

	var moved int
	err = d.Write(ctx, func(tx *sql.Tx) error {
		moved, err = res.TransferOwnership(ctx, tx, domain.NamespacePublic, u.ID, domain.SystemUserID)
		return err
	})
	if err != nil {
		t.Fatalf("TransferOwnership: %v", err)
	}
	if moved != 0 {
		t.Errorf("перенесено %d строк, а public-ресурсов у пользователя нет", moved)
	}

	after, err := res.ByID(ctx, home.ID)
	if err != nil {
		t.Fatalf("ByID: %v", err)
	}
	if after.OwnerUserID != u.ID {
		t.Errorf("владелец /home сменился на %d: перенос вышел за namespace", after.OwnerUserID)
	}
}

// TestDeleteUserRefusesSystemAccount — §6.2: системная запись создаётся миграцией
// в любой инсталляции и удалению не подлежит.
func TestDeleteUserRefusesSystemAccount(t *testing.T) {
	ctx := context.Background()
	d, us, _ := repos(t)

	err := d.Write(ctx, func(tx *sql.Tx) error {
		return us.Delete(ctx, tx, domain.SystemUserID)
	})
	if !errors.Is(err, metadata.ErrReservedLogin) {
		t.Fatalf("Delete(system) вернул %v, ожидалась ErrReservedLogin", err)
	}
	if _, err := us.ByID(ctx, domain.SystemUserID); err != nil {
		t.Errorf("системная запись пострадала: %v", err)
	}
}
