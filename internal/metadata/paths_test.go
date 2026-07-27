package metadata_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/vitikevich-landau/go_fileshare/internal/domain"
	"github.com/vitikevich-landau/go_fileshare/internal/metadata"
)

// TestParsePathAccepts — формы, которые §5.3 п. 9 объявляет допустимыми, включая
// сами корни namespace.
func TestParsePathAccepts(t *testing.T) {
	tests := []struct {
		path       string
		ns         domain.Namespace
		components []string
	}{
		{"/home", domain.NamespaceHome, nil},
		{"/public", domain.NamespacePublic, nil},
		{"/home/a.bin", domain.NamespaceHome, []string{"a.bin"}},
		{"/home/dir/sub/file.txt", domain.NamespaceHome, []string{"dir", "sub", "file.txt"}},
		{"/public/shared.pdf", domain.NamespacePublic, []string{"shared.pdf"}},
		// Имя из символов, которые сервер разрешает сознательно (§5.3): daemon
		// работает только на POSIX, переносом занимается клиент.
		{"/home/что? да!*", domain.NamespaceHome, []string{"что? да!*"}},
		// Точка внутри имени — не «.» и не «..».
		{"/home/..a", domain.NamespaceHome, []string{"..a"}},
	}
	for _, tt := range tests {
		got, err := metadata.ParsePath(tt.path)
		if err != nil {
			t.Errorf("ParsePath(%q): %v", tt.path, err)
			continue
		}
		if got.Namespace != tt.ns {
			t.Errorf("ParsePath(%q).Namespace = %q, want %q", tt.path, got.Namespace, tt.ns)
		}
		if len(got.Components) != len(tt.components) {
			t.Errorf("ParsePath(%q).Components = %q, want %q", tt.path, got.Components, tt.components)
			continue
		}
		for i := range tt.components {
			if got.Components[i] != tt.components[i] {
				t.Errorf("ParsePath(%q).Components[%d] = %q, want %q",
					tt.path, i, got.Components[i], tt.components[i])
			}
		}
		if got.IsRoot() != (len(tt.components) == 0) {
			t.Errorf("ParsePath(%q).IsRoot() = %v", tt.path, got.IsRoot())
		}
		// Путь уезжает клиенту в ответах и в событиях, поэтому обратная сборка
		// обязана давать ровно то, что разобрали.
		if got.String() != tt.path {
			t.Errorf("ParsePath(%q).String() = %q", tt.path, got.String())
		}
	}
}

// TestParsePathRejects — таблица нарушений §5.3 п. 7–9 и п. 1–6 в компонентах.
// Каждая строка нарушает РОВНО одно правило.
func TestParsePathRejects(t *testing.T) {
	tests := []struct {
		name string
		path string
	}{
		{"пустой путь", ""},
		{"не абсолютный", "home/a"},
		{"относительный с точкой", "./home/a"},
		{"только слэш", "/"},
		{"неизвестный namespace", "/files/a"},
		{"namespace другого регистра", "/Home/a"},
		{"legacy share root", "/a.bin"},
		{"повторный слэш", "/home//a"},
		{"хвостовой слэш у корня", "/home/"},
		{"хвостовой слэш у файла", "/home/a/"},
		{"компонент «.»", "/home/./a"},
		{"компонент «..»", "/home/../public/a"},
		{"обратный слэш в имени", `/home/a\b`},
		{"двоеточие в имени", "/home/a:b"},
		{"управляющий символ", "/home/a\x01b"},
		{"перевод строки", "/home/a\nb"},
		{"хвостовая точка", "/home/a."},
		{"хвостовой пробел", "/home/a "},
		{"зарезервированное имя Windows", "/home/CON"},
		{"зарезервированное имя с расширением", "/home/nul.txt"},
		{"компонент длиннее MaxNameLen", "/home/" + strings.Repeat("x", domain.MaxNameLen+1)},
		{"путь длиннее MaxPathLen", "/home/" + strings.Repeat("x", domain.MaxPathLen)},
		{"глубже MaxTreeDepth", "/home" + strings.Repeat("/d", domain.MaxTreeDepth+1)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := metadata.ParsePath(tt.path); err == nil {
				t.Fatalf("ParsePath(%q) прошёл", tt.path)
			} else if !errors.Is(err, metadata.ErrInvalidName) {
				// §5.3 назначает нарушению правил 1–9 один код INVALID_NAME,
				// поэтому граница server обязана увидеть один класс ошибок.
				t.Fatalf("ParsePath(%q) вернул %v, ожидалась обёртка ErrInvalidName", tt.path, err)
			}
		})
	}
}

// TestParsePathDepthBoundary — предел §5.3 п. 8 проверяется на самой границе:
// ровно MaxTreeDepth компонентов ниже корня допустимы, MaxTreeDepth+1 — нет.
// Тест на строгом неравенстве прошёл бы и при сдвиге предела на единицу.
func TestParsePathDepthBoundary(t *testing.T) {
	ok := "/home" + strings.Repeat("/d", domain.MaxTreeDepth)
	if _, err := metadata.ParsePath(ok); err != nil {
		t.Errorf("путь глубиной ровно MaxTreeDepth отвергнут: %v", err)
	}
	if _, err := metadata.ParsePath(ok + "/d"); err == nil {
		t.Error("путь глубиной MaxTreeDepth+1 принят")
	}
}

// TestParsePathDoesNotNormalize — сервер не исправляет путь молча: иначе он
// начал бы отвечать не на тот путь, о котором спросили, и два разных запроса
// стали бы одним.
func TestParsePathDoesNotNormalize(t *testing.T) {
	// Имя в NFD (e + U+0301) и в NFC (U+00E9) — разные байты и разные пути.
	nfd, nfc := "/home/é.txt", "/home/é.txt"
	a, err := metadata.ParsePath(nfd)
	if err != nil {
		t.Fatalf("ParsePath(NFD): %v", err)
	}
	b, err := metadata.ParsePath(nfc)
	if err != nil {
		t.Fatalf("ParsePath(NFC): %v", err)
	}
	if a.Components[0] == b.Components[0] {
		t.Error("формы NFD и NFC схлопнуты в одну: имя обязано храниться байт-в-байт (§5.3)")
	}
}
