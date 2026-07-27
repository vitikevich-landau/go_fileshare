package users

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/vitikevich-landau/go_fileshare/internal/domain"
)

// Purge физически удаляет пользователя (`user purge <login> --yes`, §7.4).
//
// Вторая и последняя фаза удаления. §7.4 делает его двухфазным намеренно:
// `user delete` только помечает (state = pending_delete), а данные уносит
// отдельная подтверждённая команда. Поэтому метод ТРЕБУЕТ состояния
// pending_delete: purge активного пользователя означал бы, что одна команда
// уничтожает данные без предшествующего отзыва доступа.
//
// Порядок шагов задан §6.11 и выполняется в одной транзакции:
//
//  1. public-ресурсы передаются системному аккаунту (§7.3, §7.4): владелец
//     public-контента — тот, кто его загрузил, и при удалении пользователя
//     контент не исчезает, а меняет владельца;
//  2. проверяется, что не осталось ссылок, которые §6.11 требует убрать ДО
//     строки users, — активных загрузок, версий, trash-записей и shares. Убрать
//     их — шаги 1–4 §6.11, и они принадлежат операциям, которых на этом этапе
//     ещё нет: загрузки сдаются в M13, версии и корзина в M15, ссылки в M16.
//     Пока их нет, эти таблицы пусты, и проверка молчит; появятся раньше своей
//     реализации purge — команда откажется, назвав таблицу, вместо того чтобы
//     упереться в безымянное «FOREIGN KEY constraint failed» или, хуже, снести
//     метаданные, оставив файлы на диске;
//  3. удаляются оставшиеся ресурсы пользователя — снизу вверх, как требует
//     RESTRICT на parent_id;
//  4. удаляется строка users; journal_state уходит каскадом (§6.11).
//
// used_bytes обнуляется вместе со строкой (§11.4), отдельного вычитания не
// требуя.
//
// После commit удаляются каталоги пользователя. Именно после: файловая система
// транзакции не имеет, и удалив файлы первыми, откат оставил бы метаданные,
// ссылающиеся в пустоту. Обратный порядок оставляет мусор на диске, который
// находит и убирает fsck (§21.3), — это несравнимо дешевле.
//
// Строки в таблице отзыва §7.4 у purge три прочерка, и это не упущение: к этому
// моменту пользователь уже в pending_delete, его сессии закрыты, токены
// отозваны, а ссылки отозваны окончательно операцией delete.
func (s *Service) Purge(ctx context.Context, userID domain.UserID) error {
	if userID == domain.SystemUserID {
		// Системный аккаунт владеет public-ресурсами, переданными при purge их
		// прежних владельцев (§7.3), и создаётся миграцией в любой инсталляции
		// (§6.2). Его удаление снесло бы public-контент всей установки.
		return fmt.Errorf("%w: the system account is created by migration 0001 and owns transferred "+
			"public resources (§6.2, §7.3)", ErrSystemAccount)
	}

	err := s.db.Write(ctx, func(tx *sql.Tx) error {
		u, err := s.users.ByIDTx(ctx, tx, userID)
		if err != nil {
			return err
		}
		if u.State != domain.UserPendingDelete {
			return fmt.Errorf("%w: login %q is in state %q; run `user delete` first (§7.4)",
				ErrPurgeNotPending, u.Login, u.State)
		}

		// §7.3, §7.4: public-ресурсы передаются системному аккаунту, а не
		// удаляются. Шаг обязан быть первым: после него DeleteOwned видит только
		// home пользователя.
		if _, err := s.res.TransferOwnership(ctx, tx, domain.NamespacePublic,
			userID, domain.SystemUserID); err != nil {
			return err
		}

		if err := s.assertPurgeable(ctx, tx, userID, u.Login); err != nil {
			return err
		}
		if _, err := s.res.DeleteOwned(ctx, tx, userID); err != nil {
			return err
		}
		if err := s.users.Delete(ctx, tx, userID); err != nil {
			return err
		}
		return s.assertActiveAdminRemains(ctx, tx)
	})
	if err != nil {
		return translate(err)
	}

	// Каталоги — после commit. Ошибка удаления не отменяет purge: строки уже
	// нет, и возвращать «не удалось» без возможности повторить транзакцию значило
	// бы соврать. Она сообщается вызывающему как есть, а оставшиеся каталоги
	// найдёт fsck.
	if err := s.layout.RemoveUserData(userID); err != nil {
		return fmt.Errorf("users: purge of user %d committed, but its directories remain: %w", userID, err)
	}
	s.applyRevocation(ctx, opPurge, userID)
	return nil
}

// assertPurgeable проверяет, что у пользователя не осталось объектов, которые
// §6.11 требует удалить ДО его строки и которые этот этап удалять не умеет
// (шаги 1–4 §6.11: отмена активных загрузок с возвратом резервирования, постановка
// blob версий и current content в blob_gc, уменьшение used_bytes).
//
// Ресурсы из перечня исключены: их удаляет сам purge шагом 3.
func (s *Service) assertPurgeable(ctx context.Context, tx *sql.Tx, userID domain.UserID, login string) error {
	refs, err := s.users.UserReferences(ctx, tx, userID)
	if err != nil {
		return err
	}
	var blocking []string
	for _, ref := range refs {
		if ref.Table == "resources" {
			continue
		}
		blocking = append(blocking, ref.String())
	}
	if len(blocking) == 0 {
		return nil
	}
	return fmt.Errorf("%w: login %q still has %s; §6.11 requires removing these before the users row, "+
		"which belongs to uploads (M13), versions and trash (M15) and shares (M16)",
		ErrPurgeBlocked, login, strings.Join(blocking, ", "))
}
