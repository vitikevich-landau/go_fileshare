package metadata_test

import (
	"context"
	"encoding/hex"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/vitikevich-landau/go_fileshare/internal/domain"
	"github.com/vitikevich-landau/go_fileshare/internal/metadata"
)

// keyHex — правдоподобный stored_key: 64 hex-символа, то есть SHA256(ClientKey).
func keyHex(seed byte) string {
	raw := make([]byte, 32)
	for i := range raw {
		raw[i] = seed + byte(i)
	}
	return hex.EncodeToString(raw)
}

func usersJSON(body string) []byte { return []byte(`{"users":[` + body + `]}`) }

func rec(login, role, key string, enabled bool) string {
	e := "false"
	if enabled {
		e = "true"
	}
	return `{"login":"` + login + `","role":"` + role + `","stored_key":"` + key + `","enabled":` + e + `}`
}

func importOpts() metadata.ImportOptions {
	return metadata.ImportOptions{AuthIters: testAuthIters}
}

// TestImportUsers — основной перенос §21.4: enabled отображается в state, соль
// заполняется литералом "fileshare-v2:"+login, kdf_algo — pbkdf2-sha256,
// auth_iters берётся из старого конфига.
func TestImportUsers(t *testing.T) {
	ctx := context.Background()
	d, us, res := repos(t)

	data := usersJSON(rec("alice", "admin", keyHex(1), true) + "," + rec("bob", "user", keyHex(2), false))
	report, err := metadata.ImportUsers(ctx, d, us, data, importOpts())
	if err != nil {
		t.Fatalf("ImportUsers: %v", err)
	}
	if len(report.Created) != 2 || report.Created[0] != "alice" || report.Created[1] != "bob" {
		t.Fatalf("Created = %v, want [alice bob]", report.Created)
	}

	alice, err := us.ByLogin(ctx, "alice")
	if err != nil {
		t.Fatalf("ByLogin(alice): %v", err)
	}
	if alice.Role != domain.RoleAdmin {
		t.Errorf("alice.role = %q, want admin", alice.Role)
	}
	if alice.State != domain.UserActive {
		t.Errorf(`alice.state = %q, want active: "enabled": true отображается в active (§21.4)`, alice.State)
	}
	if hex.EncodeToString(alice.Secret.StoredKey) != keyHex(1) {
		t.Error("stored_key не перенесён из JSON")
	}
	if string(alice.Secret.Salt) != string(domain.LegacySalt("alice")) {
		t.Errorf("salt = %q, want %q: иначе миграция ломает аутентификацию (§21.4)",
			alice.Secret.Salt, domain.LegacySalt("alice"))
	}
	if alice.Secret.KDFAlgo != domain.KDFPBKDF2SHA256 {
		t.Errorf("kdf_algo = %q, want pbkdf2-sha256", alice.Secret.KDFAlgo)
	}
	if alice.Secret.AuthIters != testAuthIters {
		t.Errorf("auth_iters = %d, want %d из старого конфига", alice.Secret.AuthIters, testAuthIters)
	}

	bob, err := us.ByLogin(ctx, "bob")
	if err != nil {
		t.Fatalf("ByLogin(bob): %v", err)
	}
	if bob.State != domain.UserDisabled {
		t.Errorf(`bob.state = %q, want disabled: "enabled": false отображается в disabled (§21.4)`, bob.State)
	}

	// Импортированный пользователь получает те же сопутствующие строки, что и
	// заведённый командой: корень /home и строку журнала.
	for _, u := range []metadata.User{alice, bob} {
		if _, err := res.HomeRoot(ctx, u.ID); err != nil {
			t.Errorf("у импортированного %q нет корня /home: %v", u.Login, err)
		}
	}

	// И база остаётся пригодной к старту.
	if err := metadata.VerifyInvariants(ctx, d.Reader); err != nil {
		t.Errorf("после импорта база не проходит собственные инварианты: %v", err)
	}
}

// TestImportIdempotent — повторный запуск не меняет БД (DoD M12). Логин, уже
// импортированный с идентичными данными, пропускается.
func TestImportIdempotent(t *testing.T) {
	ctx := context.Background()
	d, us, _ := repos(t)
	data := usersJSON(rec("alice", "admin", keyHex(1), true) + "," + rec("bob", "user", keyHex(2), false))

	first, err := metadata.ImportUsers(ctx, d, us, data, importOpts())
	if err != nil {
		t.Fatalf("первый импорт: %v", err)
	}
	before, err := us.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}

	second, err := metadata.ImportUsers(ctx, d, us, data, importOpts())
	if err != nil {
		t.Fatalf("повторный импорт: %v", err)
	}
	if len(second.Created) != 0 || len(second.Updated) != 0 {
		t.Errorf("повтор создал %v и обновил %v, ожидалось ничего", second.Created, second.Updated)
	}
	if len(second.Skipped) != len(first.Created) {
		t.Errorf("Skipped = %v, ожидались все %v", second.Skipped, first.Created)
	}

	after, err := us.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(before) != len(after) {
		t.Fatalf("после повтора пользователей %d, было %d", len(after), len(before))
	}
	for i := range before {
		if !reflect.DeepEqual(before[i], after[i]) {
			t.Errorf("запись %q изменилась при повторном запуске:\nбыло  %+v\nстало %+v",
				before[i].Login, before[i], after[i])
		}
	}
}

// TestImportIdempotentIgnoresAuthIters — auth_iters НЕ входит в перечень полей
// сверки §21.4, и это не упущение: значение существующей записи — то число, с
// которым посчитан её stored_key, а конфиг с тех пор мог смениться. Взяв конфиг
// за истину, повторный запуск сломал бы вход тем, кого он не менял.
func TestImportIdempotentIgnoresAuthIters(t *testing.T) {
	ctx := context.Background()
	d, us, _ := repos(t)
	data := usersJSON(rec("alice", "admin", keyHex(1), true))

	if _, err := metadata.ImportUsers(ctx, d, us, data, importOpts()); err != nil {
		t.Fatalf("первый импорт: %v", err)
	}
	raised := metadata.ImportOptions{AuthIters: testAuthIters * 2}
	report, err := metadata.ImportUsers(ctx, d, us, data, raised)
	if err != nil {
		t.Fatalf("повтор с другим auth_iters: %v", err)
	}
	if len(report.Skipped) != 1 {
		t.Errorf("Skipped = %v, ожидался пропуск alice", report.Skipped)
	}
	alice, err := us.ByLogin(ctx, "alice")
	if err != nil {
		t.Fatalf("ByLogin: %v", err)
	}
	if alice.Secret.AuthIters != testAuthIters {
		t.Errorf("auth_iters = %d, ожидалось прежнее %d: оно соответствует stored_key записи",
			alice.Secret.AuthIters, testAuthIters)
	}
}

// TestImportConflict — логин, существующий в БД с иными данными, прерывает
// миграцию понятной ошибкой с указанием логина и различающихся полей (§21.4).
func TestImportConflict(t *testing.T) {
	ctx := context.Background()
	d, us, _ := repos(t)

	if _, err := metadata.ImportUsers(ctx, d, us,
		usersJSON(rec("alice", "user", keyHex(1), true)), importOpts()); err != nil {
		t.Fatalf("подготовка: %v", err)
	}

	// Роль и stored_key в файле другие.
	changed := usersJSON(rec("alice", "admin", keyHex(9), true))
	_, err := metadata.ImportUsers(ctx, d, us, changed, importOpts())
	if err == nil {
		t.Fatal("конфликт не прерывает миграцию")
	}
	for _, want := range []string{"alice", "role", "stored_key", "--overwrite-existing"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("в сообщении нет %q: %v", want, err)
		}
	}
	// Верификатор пароля в сообщение попасть не должен.
	if strings.Contains(err.Error(), keyHex(9)) || strings.Contains(err.Error(), keyHex(1)) {
		t.Errorf("сообщение содержит stored_key: %v", err)
	}

	got, err := us.ByLogin(ctx, "alice")
	if err != nil {
		t.Fatalf("ByLogin: %v", err)
	}
	if got.Role != domain.RoleUser {
		t.Errorf("запись изменена несмотря на прерывание: role = %q", got.Role)
	}
}

// TestImportOverwriteExisting — с флагом запись перезаписывается значениями из
// JSON (§21.4).
func TestImportOverwriteExisting(t *testing.T) {
	ctx := context.Background()
	d, us, _ := repos(t)

	if _, err := metadata.ImportUsers(ctx, d, us,
		usersJSON(rec("alice", "user", keyHex(1), true)), importOpts()); err != nil {
		t.Fatalf("подготовка: %v", err)
	}
	before, err := us.ByLogin(ctx, "alice")
	if err != nil {
		t.Fatalf("ByLogin: %v", err)
	}

	opts := importOpts()
	opts.OverwriteExisting = true
	report, err := metadata.ImportUsers(ctx, d, us,
		usersJSON(rec("alice", "admin", keyHex(9), false)), opts)
	if err != nil {
		t.Fatalf("импорт с --overwrite-existing: %v", err)
	}
	if len(report.Updated) != 1 || report.Updated[0] != "alice" {
		t.Errorf("Updated = %v, want [alice]", report.Updated)
	}

	after, err := us.ByLogin(ctx, "alice")
	if err != nil {
		t.Fatalf("ByLogin: %v", err)
	}
	if after.ID != before.ID {
		t.Errorf("перезапись сменила UserID с %d на %d: идентификатор стабилен (§2.1)", before.ID, after.ID)
	}
	if after.Role != domain.RoleAdmin || after.State != domain.UserDisabled {
		t.Errorf("после перезаписи role = %q, state = %q; ожидались admin и disabled", after.Role, after.State)
	}
	if hex.EncodeToString(after.Secret.StoredKey) != keyHex(9) {
		t.Error("stored_key не перезаписан")
	}
}

// TestImportAllOrNothing — конфликт на второй записи не оставляет
// импортированной первую. Частичный результат не позволил бы ни повторить
// миграцию, ни откатить её, не разбираясь вручную, где она остановилась.
func TestImportAllOrNothing(t *testing.T) {
	ctx := context.Background()
	d, us, _ := repos(t)

	if _, err := metadata.ImportUsers(ctx, d, us,
		usersJSON(rec("bob", "user", keyHex(2), true)), importOpts()); err != nil {
		t.Fatalf("подготовка: %v", err)
	}

	// alice новая, bob конфликтует.
	data := usersJSON(rec("alice", "user", keyHex(1), true) + "," + rec("bob", "admin", keyHex(7), true))
	if _, err := metadata.ImportUsers(ctx, d, us, data, importOpts()); err == nil {
		t.Fatal("конфликт не прервал миграцию")
	}
	if _, err := us.ByLogin(ctx, "alice"); err == nil {
		t.Error("alice импортирована, хотя миграция прервана: транзакция не откатилась")
	}
}

// TestImportParseRejects — §24.1 п. 12: разбор users.json отвергает всё, что
// нельзя перенести без молчаливой подмены смысла.
func TestImportParseRejects(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		why  string
		data []byte
		want string
	}{
		{"не JSON", []byte("{"), "parse users.json"},
		{
			"дубликат логина внутри файла",
			usersJSON(rec("alice", "user", keyHex(1), true) + "," + rec("alice", "admin", keyHex(2), true)),
			"twice",
		},
		{"пустой логин", usersJSON(rec("", "user", keyHex(1), true)), "login is empty"},
		{"роль вне словаря", usersJSON(rec("alice", "root", keyHex(1), true)), "role"},
		{"stored_key не hex", usersJSON(rec("alice", "user", "zz", true)), "not hex"},
		{"stored_key не той длины", usersJSON(rec("alice", "user", "aabb", true)), "bytes"},
	}
	for _, tc := range cases {
		d, us, _ := repos(t)
		_, err := metadata.ImportUsers(ctx, d, us, tc.data, importOpts())
		if err == nil {
			t.Errorf("%s: ошибки нет", tc.why)
			continue
		}
		if !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: в сообщении нет %q: %v", tc.why, tc.want, err)
		}
	}
}

// TestImportDuplicateRejectedEvenWithOverwrite — конфликт логинов ВНУТРИ файла
// остаётся ошибкой всегда (§21.4): --overwrite-existing разрешает спор файла с
// базой, а не файла с самим собой.
func TestImportDuplicateRejectedEvenWithOverwrite(t *testing.T) {
	ctx := context.Background()
	d, us, _ := repos(t)
	opts := importOpts()
	opts.OverwriteExisting = true

	data := usersJSON(rec("alice", "user", keyHex(1), true) + "," + rec("alice", "admin", keyHex(2), true))
	if _, err := metadata.ImportUsers(ctx, d, us, data, opts); err == nil {
		t.Fatal("дубликат внутри файла принят при --overwrite-existing")
	}
}

// TestImportRequiresAuthIters — auth_iters из старого конфига обязателен: он
// уходит в каждую запись, и ноль означал бы stored_key, посчитанный неизвестно с
// чем.
func TestImportRequiresAuthIters(t *testing.T) {
	ctx := context.Background()
	d, us, _ := repos(t)
	if _, err := metadata.ImportUsers(ctx, d, us,
		usersJSON(rec("alice", "user", keyHex(1), true)), metadata.ImportOptions{}); err == nil {
		t.Fatal("импорт с auth_iters = 0 принят")
	}
}

// TestImportOverwriteKeepsAuthItersWhenSecretUnchanged — перезапись роли или
// состояния НЕ трогает auth_iters, если сам секрет не изменился.
//
// Иначе перезапись протащила бы в запись значение из сегодняшнего конфига,
// оставив прежний stored_key: пользователь не вошёл бы вовсе, а следующий старт
// демона упёрся бы в сверку §6.2 п. 3. Это ровно то расхождение, ради
// недопущения которого auth_iters исключён из перечня полей сверки.
func TestImportOverwriteKeepsAuthItersWhenSecretUnchanged(t *testing.T) {
	ctx := context.Background()
	d, us, _ := repos(t)

	if _, err := metadata.ImportUsers(ctx, d, us,
		usersJSON(rec("alice", "user", keyHex(1), true)), importOpts()); err != nil {
		t.Fatalf("подготовка: %v", err)
	}

	// Конфиг сменился, а в файле у alice поменялась только роль.
	opts := metadata.ImportOptions{AuthIters: testAuthIters * 2, OverwriteExisting: true}
	report, err := metadata.ImportUsers(ctx, d, us,
		usersJSON(rec("alice", "admin", keyHex(1), true)), opts)
	if err != nil {
		t.Fatalf("перезапись роли: %v", err)
	}
	if len(report.Updated) != 1 {
		t.Fatalf("Updated = %v, ожидалась alice", report.Updated)
	}

	alice, err := us.ByLogin(ctx, "alice")
	if err != nil {
		t.Fatalf("ByLogin: %v", err)
	}
	if alice.Role != domain.RoleAdmin {
		t.Errorf("role = %q, want admin: перезапись не применилась", alice.Role)
	}
	if alice.Secret.AuthIters != testAuthIters {
		t.Errorf("auth_iters = %d, ожидалось прежнее %d: stored_key не менялся",
			alice.Secret.AuthIters, testAuthIters)
	}
	// И база остаётся пригодной к старту: сверка §6.2 п. 3 не должна сработать.
	if err := metadata.VerifyInvariants(ctx, d.Reader); err != nil {
		t.Errorf("после перезаписи база не проходит инварианты: %v", err)
	}
}

// TestImportOverwriteUpdatesAuthItersWithSecret — а когда меняется сам секрет,
// auth_iters берётся из конфига: новый stored_key посчитан именно с ним.
func TestImportOverwriteUpdatesAuthItersWithSecret(t *testing.T) {
	ctx := context.Background()
	d, us, _ := repos(t)

	if _, err := metadata.ImportUsers(ctx, d, us,
		usersJSON(rec("alice", "user", keyHex(1), true)), importOpts()); err != nil {
		t.Fatalf("подготовка: %v", err)
	}

	const raised = testAuthIters * 2
	opts := metadata.ImportOptions{AuthIters: raised, OverwriteExisting: true}
	if _, err := metadata.ImportUsers(ctx, d, us,
		usersJSON(rec("alice", "user", keyHex(9), true)), opts); err != nil {
		t.Fatalf("перезапись секрета: %v", err)
	}

	alice, err := us.ByLogin(ctx, "alice")
	if err != nil {
		t.Fatalf("ByLogin: %v", err)
	}
	if hex.EncodeToString(alice.Secret.StoredKey) != keyHex(9) {
		t.Error("stored_key не перезаписан")
	}
	if alice.Secret.AuthIters != raised {
		t.Errorf("auth_iters = %d, want %d: новый stored_key посчитан с ним",
			alice.Secret.AuthIters, raised)
	}
}

// TestImportRequiresUsersArray — отсутствие ключа users прерывает миграцию.
//
// Опечатка в имени ключа разбирается без единой жалобы и даёт ноль записей:
// одноразовая миграция отрапортовала бы об успехе и оставила базу пустой.
func TestImportRequiresUsersArray(t *testing.T) {
	ctx := context.Background()

	for _, tc := range []struct{ why, body string }{
		{"опечатка в имени ключа", `{"user":[]}`},
		{"ключа нет вовсе", `{}`},
		{"users равен null", `{"users":null}`},
	} {
		d, us, _ := repos(t)
		_, err := metadata.ImportUsers(ctx, d, us, []byte(tc.body), importOpts())
		if err == nil {
			t.Errorf("%s: импорт принят молча", tc.why)
			continue
		}
		if !strings.Contains(err.Error(), "users") {
			t.Errorf("%s: в сообщении нет упоминания ключа: %v", tc.why, err)
		}
	}

	// Осознанно пустой массив остаётся законным: именно так auth.Save пишет
	// файл, когда пользователей не осталось.
	d, us, _ := repos(t)
	report, err := metadata.ImportUsers(ctx, d, us, []byte(`{"users":[]}`), importOpts())
	if err != nil {
		t.Fatalf("пустой массив отклонён: %v", err)
	}
	if len(report.Created)+len(report.Skipped)+len(report.Updated) != 0 {
		t.Errorf("пустой массив что-то изменил: %+v", report)
	}
}

// TestImportRejectsDemotingLastAdmin — §7.4: отклоняются операции, которые
// СДЕЛАЛИ БЫ множество активных администраторов пустым. Импорт, снимающий
// последнего админа, — это оно и есть.
func TestImportRejectsDemotingLastAdmin(t *testing.T) {
	ctx := context.Background()
	d, us, _ := repos(t)

	if _, err := metadata.ImportUsers(ctx, d, us,
		usersJSON(rec("root", "admin", keyHex(1), true)), importOpts()); err != nil {
		t.Fatalf("подготовка: %v", err)
	}

	opts := importOpts()
	opts.OverwriteExisting = true
	for _, tc := range []struct{ why, body string }{
		{"понижение роли", rec("root", "user", keyHex(1), true)},
		{"отключение", rec("root", "admin", keyHex(1), false)},
	} {
		_, err := metadata.ImportUsers(ctx, d, us, usersJSON(tc.body), opts)
		if !errors.Is(err, metadata.ErrLastAdminRequired) {
			t.Errorf("%s: %v, want ErrLastAdminRequired", tc.why, err)
		}
	}

	// Транзакция откатилась целиком: админ на месте.
	root, err := us.ByLogin(ctx, "root")
	if err != nil {
		t.Fatalf("ByLogin: %v", err)
	}
	if root.Role != domain.RoleAdmin || root.State != domain.UserActive {
		t.Errorf("админ изменён несмотря на отказ: role = %q, state = %q", root.Role, root.State)
	}

	// А замена одного админа другим в том же файле проходит: множество не
	// пустеет.
	body := rec("root", "user", keyHex(1), true) + "," + rec("root2", "admin", keyHex(2), true)
	if _, err := metadata.ImportUsers(ctx, d, us, usersJSON(body), opts); err != nil {
		t.Errorf("замена админа отклонена: %v", err)
	}
}

// TestImportWithoutAdminsIsAllowed — импорт в базу, где активных админов не
// было И ДО него, проходит и лишь помечается флагом.
//
// Отказ здесь был бы прямо вреден: восстановительный путь §7.5 — это
// `--promote <login>`, повышение УЖЕ ИМПОРТИРОВАННОГО пользователя. Запретив
// импорт, мы оставили бы оператора с файлом, который некуда залить, и базой,
// которую некем починить.
func TestImportWithoutAdminsIsAllowed(t *testing.T) {
	ctx := context.Background()
	d, us, _ := repos(t)

	report, err := metadata.ImportUsers(ctx, d, us,
		usersJSON(rec("alice", "user", keyHex(1), true)+","+rec("bob", "admin", keyHex(2), false)),
		importOpts())
	if err != nil {
		t.Fatalf("импорт без активных админов отклонён: %v", err)
	}
	if !report.NoActiveAdmin {
		t.Error("NoActiveAdmin не поднят: команда промолчит о непригодной к старту базе")
	}
	if _, err := us.ByLogin(ctx, "alice"); err != nil {
		t.Errorf("пользователи не импортированы: %v", err)
	}

	// А когда админ есть, флаг не поднимается.
	d2, us2, _ := repos(t)
	report, err = metadata.ImportUsers(ctx, d2, us2,
		usersJSON(rec("root", "admin", keyHex(1), true)), importOpts())
	if err != nil {
		t.Fatalf("импорт: %v", err)
	}
	if report.NoActiveAdmin {
		t.Error("NoActiveAdmin поднят при живом администраторе")
	}
}

// TestImportRejectsSystemLogin — логин системного аккаунта отвергается всегда.
//
// В старом файле он совершенно легален: резервирует его §6.2, которого во
// времена users.json не было. Но в новой схеме он принадлежит предсозданной
// записи id = 0, и импорт поверх неё ломает установку необратимо: обычная
// (enabled) учётка перевела бы системный аккаунт в active, после чего
// verifySystemAccount не пускает daemon стартовать.
func TestImportRejectsSystemLogin(t *testing.T) {
	ctx := context.Background()

	for _, tc := range []struct {
		why       string
		overwrite bool
	}{{"без флага", false}, {"с --overwrite-existing", true}} {
		d, us, _ := repos(t)
		opts := importOpts()
		opts.OverwriteExisting = tc.overwrite

		body := rec("alice", "admin", keyHex(1), true) + "," +
			rec(domain.SystemLogin, "admin", keyHex(2), true)
		_, err := metadata.ImportUsers(ctx, d, us, usersJSON(body), opts)
		if !errors.Is(err, metadata.ErrReservedLogin) {
			t.Errorf("%s: %v, want ErrReservedLogin", tc.why, err)
		}

		// Системный аккаунт нетронут и база по-прежнему стартует.
		if err := metadata.VerifyInvariants(ctx, d.Reader); err != nil {
			t.Errorf("%s: системный аккаунт повреждён: %v", tc.why, err)
		}
		// И весь импорт отменён: alice не появилась.
		if _, err := us.ByLogin(ctx, "alice"); !errors.Is(err, metadata.ErrNotFound) {
			t.Errorf("%s: импорт применился частично", tc.why)
		}
	}
}

// TestImportRejectsMixedAuthIters — импорт не оставляет в базе два разных
// auth_iters (§6.2 п. 3).
//
// Сценарий будничный: пользователи посчитаны со старым auth.pbkdf2_iters,
// конфиг подняли, тот же файл перезалили с новой записью. Старые пропускаются
// как идентичные (auth_iters не входит в сверку §21.4), новая создаётся с новым
// значением. Без этой проверки команда рапортует об успехе, демон не поднимается,
// а повторный импорт уже ничего не чинит — пропуск остаётся пропуском.
func TestImportRejectsMixedAuthIters(t *testing.T) {
	ctx := context.Background()
	d, us, _ := repos(t)

	if _, err := metadata.ImportUsers(ctx, d, us,
		usersJSON(rec("root", "admin", keyHex(1), true)), importOpts()); err != nil {
		t.Fatalf("подготовка: %v", err)
	}

	// Конфиг подняли, в файле появился новый пользователь.
	raised := metadata.ImportOptions{AuthIters: testAuthIters * 2}
	body := rec("root", "admin", keyHex(1), true) + "," + rec("bob", "user", keyHex(2), true)
	_, err := metadata.ImportUsers(ctx, d, us, usersJSON(body), raised)
	if err == nil {
		t.Fatal("импорт со смешанными auth_iters принят: демон с такой базой не стартует")
	}
	// Сообщение обязано назвать оба значения и текущий конфиг.
	for _, want := range []string{"600000", "1200000", "auth.pbkdf2_iters"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("в сообщении нет %q: %v", want, err)
		}
	}

	// Откат целиком: bob не появился, база по-прежнему стартует.
	if _, err := us.ByLogin(ctx, "bob"); !errors.Is(err, metadata.ErrNotFound) {
		t.Error("bob импортирован несмотря на отказ")
	}
	if err := metadata.VerifyInvariants(ctx, d.Reader); err != nil {
		t.Errorf("база испорчена отклонённым импортом: %v", err)
	}

	// С правильным конфигом тот же файл проходит.
	if _, err := metadata.ImportUsers(ctx, d, us, usersJSON(body), importOpts()); err != nil {
		t.Fatalf("импорт с исходным auth.pbkdf2_iters: %v", err)
	}
	if err := metadata.VerifyInvariants(ctx, d.Reader); err != nil {
		t.Errorf("после корректного импорта база не стартует: %v", err)
	}
}

// TestImportRepairsMixedAuthIters — а перезапись ВСЕХ секретов остаётся
// работающим путём: после неё значение снова одно, и проверка пропускает.
func TestImportRepairsMixedAuthIters(t *testing.T) {
	ctx := context.Background()
	d, us, _ := repos(t)

	body := rec("root", "admin", keyHex(1), true) + "," + rec("bob", "user", keyHex(2), true)
	if _, err := metadata.ImportUsers(ctx, d, us, usersJSON(body), importOpts()); err != nil {
		t.Fatalf("подготовка: %v", err)
	}

	// Все секреты в файле новые, конфиг новый — значит, все записи получают его.
	const raised = testAuthIters * 2
	opts := metadata.ImportOptions{AuthIters: raised, OverwriteExisting: true}
	fresh := rec("root", "admin", keyHex(5), true) + "," + rec("bob", "user", keyHex(6), true)
	if _, err := metadata.ImportUsers(ctx, d, us, usersJSON(fresh), opts); err != nil {
		t.Fatalf("перезапись всех секретов отклонена: %v", err)
	}
	for _, login := range []string{"root", "bob"} {
		u, err := us.ByLogin(ctx, login)
		if err != nil {
			t.Fatalf("ByLogin(%s): %v", login, err)
		}
		if u.Secret.AuthIters != raised {
			t.Errorf("%s: auth_iters = %d, want %d", login, u.Secret.AuthIters, raised)
		}
	}
	if err := metadata.VerifyInvariants(ctx, d.Reader); err != nil {
		t.Errorf("после перезаписи всех секретов база не стартует: %v", err)
	}
}
