// Package arch объявляет правило зависимостей §4.3 docs/tz/10-cloud-drive-spec.md
// как ДАННЫЕ и проверяет его на графе импортов модуля.
//
// §4.3 п. 4 требует теста, который строит граф импортов пакетов и падает при
// появлении запрещённого ребра, и объявляет его обязательным с M12 (§24.1 п. 17).
// Момент выбран не произвольно: M12 вводит первые сервисные пакеты, а вместе с
// ними — единственное правило §4.3, которое ничем, кроме теста, не удержать.
// Компилятор ловит только циклы; «сервис знает wire layout» компилируется
// прекрасно и обнаруживается через полгода, когда обратный путь уже дорог.
//
// Почему таблица живёт в коде, а не только в тесте: правило §4.3 адресовано
// автору нового пакета, а не только CI. Ошибка «пакет не классифицирован»
// заставляет объявить слой явно ДО первого импорта, а не выяснять его из
// сообщения упавшего теста.
//
// Проверяются НЕ-тестовые файлы. Внешние тестовые пакеты (`_test`) сознательно
// исключены: сверка объявлений, разнесённых по слоям, выполняется именно ими и
// является санкционированным исключением. Так устроен, например,
// `TestMaxNameLenMatchesProto` (§5.3 п. 6): `domain.MaxNameLen` и
// `proto.MaxNameLen` обязаны совпадать, проверить это может только код, видящий
// оба пакета, и запрет такого ребра означал бы запрет самой проверки.
package arch

// ModulePath — путь модуля. Импорты с этим префиксом и составляют граф; всё
// остальное (stdlib, внешние зависимости) правилом §4.3 не ограничено.
const ModulePath = "github.com/vitikevich-landau/go_fileshare"

// Rules — для каждого пакета модуля множество внутренних пакетов, которые ему
// разрешено импортировать НАПРЯМУЮ. Ключ и значения — путь пакета без префикса
// ModulePath.
//
// Таблица заполнена по §4.3 и НЕ шире её: пустое множество означает «только
// stdlib и внешние зависимости». Пакет, отсутствующий в таблице, — ошибка, а не
// разрешение: см. докстринг пакета.
var Rules = map[string][]string{
	// domain -> stdlib only. Пустое множество здесь — не формальность: это
	// свойство, из которого следует, что доменный словарь может импортировать
	// любой слой, не создавая цикла.
	"internal/domain": {},

	// SCRAM-математика: чистые функции над [32]byte, ни слова о проводе и о
	// хранилище. Пакет выделен ровно для того, чтобы сервисный слой мог
	// проверять доказательство, не импортируя ни proto, ни internal/auth
	// (§4.3 п. 1).
	"internal/scram": {},

	// Конфигурация и инфраструктурные листья.
	"internal/config":    {},
	"internal/ratelimit": {},

	// proto -> domain + stdlib. Ребро объявлено разрешённым, хотя сегодня его
	// нет: §4.3 предписывает proto брать числовые значения кодов §22 из domain
	// (§4.3 п. 2), и это работа этапа, вводящего ERROR_V3.
	"internal/proto": {"internal/domain"},

	// Слой персистентности. §4.3 называет его `metadata`; в этой кодовой базе он
	// состоит из двух пакетов, потому что ADR 0001 §4.2 выделил пару handle'ов в
	// отдельный пакет: db отвечает за СОЕДИНЕНИЕ (PRAGMA, пул, BEGIN IMMEDIATE),
	// metadata — за СХЕМУ и данные. Драйвер SQLite виден только внутри db.
	"internal/db":       {"internal/domain"},
	"internal/metadata": {"internal/db", "internal/domain"},

	// storage -> domain + stdlib (§4.3): раскладка §5.1 и per-user os.Root.
	"internal/storage": {"internal/domain"},

	// Сервисные пакеты. Их главное ограничение — не в этой таблице, а в
	// ServicePackages: proto не должен быть достижим НИ НА КАКОЙ глубине.
	"internal/users": {
		"internal/db", "internal/domain", "internal/metadata",
		"internal/scram", "internal/storage",
	},
	"internal/authz": {"internal/domain", "internal/metadata", "internal/storage"},

	// Поверхности. server -> services + proto + domain + config (§4.3);
	// internal/auth, internal/vfs, internal/ratelimit и internal/watcher — его
	// сегодняшняя инфраструктура (см. LegacyEdges).
	"internal/server": {
		"internal/auth", "internal/authz", "internal/config", "internal/domain",
		"internal/proto", "internal/ratelimit", "internal/users",
		"internal/vfs", "internal/watcher",
	},
	"internal/client": {"internal/auth", "internal/domain", "internal/proto"},
	"internal/tui":    {"internal/client", "internal/domain"},

	// Пакеты, которым §4.3 слоя не назначала.
	"internal/auth":    {"internal/domain", "internal/scram"},
	"internal/vfs":     {},
	"internal/watcher": {},
	"internal/arch":    {},
}

// CompositionRoots — пакеты, которым разрешён импорт любого внутреннего пакета.
//
// §4.3 пишет `cmd -> server/client/tui/gateway/syncer/config`, перечисляя
// ПОВЕРХНОСТИ, которые запускает команда. Но собрать сервис из репозиториев,
// раскладки и портов должен кто-то, кто видит и то и другое, и этот кто-то —
// main: композиционный корень по определению знает все слои, и вынос сборки в
// один из слоёв как раз и создал бы запрещённое ребро.
var CompositionRoots = []string{
	"cmd/fshare-daemon",
	"cmd/fshare-commander",
}

// ServicePackages — сервисные пакеты §4.3 п. 1. Для них проверяется сильное
// правило: internal/proto не достижим по графу импортов ни на какой глубине.
//
// Ограничение не косметическое. Сервис, знающий wire layout, начинает возвращать
// наружу proto-типы, и тогда единственным местом, где живёт формат кадра,
// перестаёт быть proto: gateway (§4.3 п. 5) и v2-совместимость (инвариант 12)
// держатся именно на том, что решение сервиса от версии протокола не зависит.
// Доменные ошибки в wire-коды переводит граница server (§4.3 п. 2).
//
// Список пополняется по мере появления сервисов: upload, mutations, trash,
// versions, transfer, changes, events, shares (§4.3). Имя, которого ещё нет в
// графе, проверку не нарушает.
var ServicePackages = []string{
	"internal/users",
	"internal/authz",
}

// LegacyEdges — рёбра, которые существуют сегодня и §4.3 п. 3 назначил к
// снятию: `internal/auth` и `internal/vfs` импортируют proto ради proto.Role,
// proto.ErrCode, proto.Algo, proto.ChecksumLen и proto.DirEntry, а перевод обоих
// пакетов на internal/domain — работа M12, неизбежная хотя бы потому, что по
// инварианту 14 vfs.List перестаёт быть источником листинга.
//
// Список — храповик, а не оправдание: тест требует, чтобы каждое объявленное
// здесь ребро всё ещё существовало. Убрали импорт — обязаны убрать строку,
// поэтому множество может только сокращаться и не превращается в свалку
// разрешений, про которую никто не помнит, актуальна ли она.
var LegacyEdges = map[string][]string{
	// internal/auth: proto.Role в users.json-совместимом Lookup/SetUser,
	// proto.ProofLen и proto.ChecksumLen в словаре типов.
	"internal/auth": {"internal/proto"},
	// internal/vfs: proto.DirEntry, proto.Algo, proto.ErrCode, proto.ChecksumLen.
	"internal/vfs": {"internal/proto"},
	// internal/watcher: proto.Path и коды событий файловой системы.
	"internal/watcher": {"internal/proto"},
	// internal/tui: §4.3 объявляет `tui -> client + domain`, но сегодня TUI
	// читает proto-типы напрямую (proto.Role, proto.DirEntry, proto.ClientInfo).
	// Снимается тогда же, когда client перестаёт отдавать наружу proto-типы.
	"internal/tui": {"internal/proto"},
}

// Violation — одно нарушение правила §4.3.
type Violation struct {
	// From — пакет-нарушитель, To — пакет, который он импортирует. Для
	// нарушения «пакет не классифицирован» To пусто.
	From, To string
	// Reason — человеко-читаемая причина с отсылкой к §4.3.
	Reason string
}

func (v Violation) String() string {
	if v.To == "" {
		return v.From + ": " + v.Reason
	}
	return v.From + " -> " + v.To + ": " + v.Reason
}

// Check проверяет граф импортов (пакет → его прямые внутренние импорты, пути без
// префикса ModulePath) и возвращает все нарушения сразу.
//
// Все, а не первое: правило слоёв нарушают пачками — один неверный импорт в
// сервисе обычно тянет за собой два-три в соседних файлах, и по одному
// нарушению за прогон это чинится вслепую.
func Check(graph map[string][]string) []Violation {
	var out []Violation

	roots := make(map[string]bool, len(CompositionRoots))
	for _, p := range CompositionRoots {
		roots[p] = true
	}

	for pkg, imports := range graph {
		if roots[pkg] {
			continue
		}
		allowed, classified := Rules[pkg]
		if !classified {
			out = append(out, Violation{
				From:   pkg,
				Reason: "пакет не классифицирован: объявите его слой в arch.Rules по таблице §4.3",
			})
			continue
		}
		set := make(map[string]bool, len(allowed)+2)
		for _, a := range allowed {
			set[a] = true
		}
		for _, l := range LegacyEdges[pkg] {
			set[l] = true
		}
		for _, imp := range imports {
			if !set[imp] {
				out = append(out, Violation{From: pkg, To: imp, Reason: "ребро не разрешено таблицей §4.3"})
			}
		}
	}

	out = append(out, checkServices(graph)...)
	return append(out, checkLegacyStale(graph)...)
}

// checkServices проверяет §4.3 п. 1 в сильной форме: proto не достижим из
// сервисного пакета ни на какой глубине. Прямого ребра недостаточно —
// транзитная зависимость даёт сервису тот же доступ к wire layout, только через
// посредника.
func checkServices(graph map[string][]string) []Violation {
	var out []Violation
	for _, svc := range ServicePackages {
		if _, ok := graph[svc]; !ok {
			continue // сервис ещё не создан
		}
		if path := pathTo(graph, svc, "internal/proto"); path != nil {
			out = append(out, Violation{
				From:   svc,
				To:     "internal/proto",
				Reason: "сервисный пакет достигает proto: " + join(path, " -> ") + " (§4.3 п. 1)",
			})
		}
	}
	return out
}

// checkLegacyStale требует, чтобы каждое объявленное legacy-ребро существовало.
// Исчезло ребро — строка обязана исчезнуть вместе с ним: иначе список разрешений
// живёт дольше долга, который он описывает.
func checkLegacyStale(graph map[string][]string) []Violation {
	var out []Violation
	for pkg, edges := range LegacyEdges {
		imports, ok := graph[pkg]
		if !ok {
			out = append(out, Violation{
				From:   pkg,
				Reason: "пакет из arch.LegacyEdges не существует: удалите строку",
			})
			continue
		}
		have := make(map[string]bool, len(imports))
		for _, imp := range imports {
			have[imp] = true
		}
		for _, e := range edges {
			if !have[e] {
				out = append(out, Violation{
					From:   pkg,
					To:     e,
					Reason: "legacy-ребро снято: удалите строку из arch.LegacyEdges (§4.3 п. 3)",
				})
			}
		}
	}
	return out
}

// pathTo возвращает путь от from до target по графу или nil, если target
// недостижим. Путь, а не признак: сообщение «users достигает proto» без цепочки
// посредников не подсказывает, какое ребро убирать.
func pathTo(graph map[string][]string, from, target string) []string {
	type step struct {
		pkg  string
		path []string
	}
	seen := map[string]bool{from: true}
	queue := []step{{pkg: from, path: []string{from}}}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		for _, imp := range graph[cur.pkg] {
			if imp == target {
				return append(append([]string{}, cur.path...), target)
			}
			if seen[imp] {
				continue
			}
			seen[imp] = true
			next := append(append([]string{}, cur.path...), imp)
			queue = append(queue, step{pkg: imp, path: next})
		}
	}
	return nil
}

func join(parts []string, sep string) string {
	out := ""
	for i, p := range parts {
		if i > 0 {
			out += sep
		}
		out += p
	}
	return out
}
