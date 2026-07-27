package arch_test

import (
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/vitikevich-landau/go_fileshare/internal/arch"
)

// TestDependencyRule — обязательный с M12 тест графа импортов (§4.3 п. 4,
// §24.1 п. 17).
func TestDependencyRule(t *testing.T) {
	graph := buildGraph(t)
	if len(graph) == 0 {
		t.Fatal("граф импортов пуст: тест ничего не проверил")
	}
	for _, v := range arch.Check(graph) {
		t.Errorf("нарушение правила зависимостей §4.3: %s", v)
	}
}

// TestGraphSeesEveryPackage — страховка от молчаливо пустого графа: обход
// каталогов легко сломать так, что он перестанет находить файлы и тест начнёт
// «проходить» ни на чём. Проверяется наличие пакетов всех слоёв таблицы §4.3.
func TestGraphSeesEveryPackage(t *testing.T) {
	graph := buildGraph(t)
	for _, pkg := range []string{
		"internal/domain", "internal/db", "internal/metadata",
		"internal/proto", "internal/server", "internal/client", "cmd/fshare-daemon",
	} {
		if _, ok := graph[pkg]; !ok {
			t.Errorf("пакет %s не попал в граф", pkg)
		}
	}
}

// TestLegacyEdgesAreNotEmpty фиксирует смысл храповика LegacyEdges: пока §4.3
// п. 3 не выполнен, список непуст, и его сокращение — наблюдаемый прогресс.
// Опустеет — строку теста удалять вместе с самим списком.
func TestLegacyEdgesAreNotEmpty(t *testing.T) {
	if len(arch.LegacyEdges) == 0 {
		t.Fatal("LegacyEdges пуст: §4.3 п. 3 выполнен, удалите список и этот тест")
	}
}

// TestCheckCatchesForbiddenEdge — негативный случай, без которого предыдущие
// ничего не стоят: проверка обязана падать на запрещённом ребре, а не молча
// одобрять любой граф.
func TestCheckCatchesForbiddenEdge(t *testing.T) {
	cases := map[string]map[string][]string{
		"прямое запрещённое ребро": {
			"internal/domain": {"internal/proto"},
		},
		"неклассифицированный пакет": {
			"internal/newthing": {},
		},
		"сервис достигает proto транзитом": {
			"internal/users":    {"internal/metadata"},
			"internal/metadata": {"internal/db"},
			"internal/db":       {"internal/proto"},
		},
	}
	for name, graph := range cases {
		t.Run(name, func(t *testing.T) {
			// LegacyEdges описывают реальный модуль, а не игрушечный граф,
			// поэтому в этих случаях они дают «ребро снято» — их отбрасываем и
			// смотрим ровно на то нарушение, которое проверяем.
			if got := violationsExcludingLegacy(arch.Check(graph)); len(got) == 0 {
				t.Fatalf("Check одобрил граф %v", graph)
			}
		})
	}
}

func violationsExcludingLegacy(vs []arch.Violation) []arch.Violation {
	var out []arch.Violation
	for _, v := range vs {
		if strings.Contains(v.Reason, "arch.LegacyEdges") {
			continue
		}
		out = append(out, v)
	}
	return out
}

// buildGraph строит граф прямых внутренних импортов по ИСХОДНИКАМ, а не через
// go/build: правило §4.3 обязано держаться на любой целевой платформе, а
// go/build отдал бы только файлы текущей GOOS и молча пропустил бы запрещённый
// импорт в changetime_darwin.go при прогоне на linux.
//
// Тестовые файлы исключены сознательно — причина в докстринге пакета arch.
func buildGraph(t *testing.T) map[string][]string {
	t.Helper()
	root := moduleRoot(t)
	graph := map[string][]string{}
	fset := token.NewFileSet()

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "docs", "testdata":
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(d.Name(), ".go") || strings.HasSuffix(d.Name(), "_test.go") {
			return nil
		}
		rel, err := filepath.Rel(root, filepath.Dir(path))
		if err != nil {
			return err
		}
		pkg := filepath.ToSlash(rel)
		if _, ok := graph[pkg]; !ok {
			graph[pkg] = nil
		}
		f, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if err != nil {
			return err
		}
		for _, spec := range f.Imports {
			imp, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				return err
			}
			inner, ok := strings.CutPrefix(imp, arch.ModulePath+"/")
			if !ok {
				continue
			}
			if !contains(graph[pkg], inner) {
				graph[pkg] = append(graph[pkg], inner)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("обход модуля: %v", err)
	}
	return graph
}

func contains(haystack []string, needle string) bool {
	for _, h := range haystack {
		if h == needle {
			return true
		}
	}
	return false
}

// moduleRoot поднимается от рабочего каталога теста до go.mod. Путь не зашит
// («../..»), чтобы перемещение пакета не превратило тест в проверку пустого
// графа: он бы прошёл.
func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("go.mod не найден вверх от %s", dir)
		}
		dir = parent
	}
}
