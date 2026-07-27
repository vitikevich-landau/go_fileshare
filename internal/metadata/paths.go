package metadata

import (
	"fmt"
	"strings"

	"github.com/vitikevich-landau/go_fileshare/internal/domain"
)

// Path — разобранный VirtualPath (§5.3 п. 9).
//
// Разбор отделён от разрешения сознательно: правила формы пути (§5.3 п. 7–9) —
// чистая работа над строкой, а превращение пути в ResourceID требует обхода
// `resources` от корня namespace и решения о доступе, то есть выполняется
// authorization service (§7.3, §27).
type Path struct {
	// Namespace выведен из первого компонента: home или public (§5.3 п. 9,
	// §7.2). Третьего корня в системе нет — legacy share root после M12 не
	// существует как отдельная сущность дерева.
	Namespace domain.Namespace
	// Components — компоненты НИЖЕ virtual root в порядке следования. Пустой
	// срез означает сам корень namespace ("/home", "/public").
	Components []string
}

// IsRoot сообщает, что путь адресует корень namespace.
func (p Path) IsRoot() bool { return len(p.Components) == 0 }

// String собирает путь обратно в каноническую форму. Обратная сборка нужна не
// для красоты: путь уезжает клиенту в ответах и в событиях, и он обязан быть
// ровно тем, который разобрали, а не «похожим».
func (p Path) String() string {
	if p.IsRoot() {
		return "/" + string(p.Namespace)
	}
	return "/" + string(p.Namespace) + "/" + strings.Join(p.Components, "/")
}

// ParsePath разбирает VirtualPath по правилам §5.3 п. 7–9 и проверяет каждый
// компонент правилами §5.3 п. 1–6 (ValidateName).
//
// Все ошибки оборачивают ErrInvalidName, и это не небрежность: §5.3 назначает
// нарушению правил 1–9 ОДИН код INVALID_NAME. Отдельный sentinel для формы пути
// был бы вторым именем того же проводного кода — и первым же соблазном
// отобразить его в другой код на границе server.
//
// Нормализация НЕ выполняется: сервер хранит и возвращает имя байт-в-байт таким,
// каким его прислал клиент (§5.3). Поэтому «/home/./a» — не путь к /home/a, а
// нарушение правила 2, и «/home//a» — не путь к /home/a, а нарушение правила 9.
// Тихо исправив то и другое, сервер начал бы отвечать не на тот путь, о котором
// спросили, и два разных запроса стали бы одним.
func ParsePath(virtualPath string) (Path, error) {
	// §5.3 п. 7. Предел проверяется ДО разбора: путь произвольной длины не
	// должен доходить до пораздельной проверки компонентов.
	if len(virtualPath) > domain.MaxPathLen {
		return Path{}, fmt.Errorf("%w: path is %d bytes, limit is %d (§5.3 п. 7)",
			ErrInvalidName, len(virtualPath), domain.MaxPathLen)
	}
	// §5.3 п. 9: путь всегда абсолютный.
	if !strings.HasPrefix(virtualPath, "/") {
		return Path{}, fmt.Errorf("%w: path %q is not absolute (§5.3 п. 9)", ErrInvalidName, virtualPath)
	}

	parts := strings.Split(virtualPath[1:], "/")
	// §5.3 п. 9: пустые компоненты и повторные «/» запрещены. Хвостовой «/»
	// сюда же: он даёт пустой последний компонент, а «/home/» и «/home» иначе
	// стали бы двумя формами одного пути.
	for _, part := range parts {
		if part == "" {
			return Path{}, fmt.Errorf("%w: path %q has an empty component (§5.3 п. 9)",
				ErrInvalidName, virtualPath)
		}
	}

	ns, err := domain.ParseNamespace(parts[0])
	if err != nil {
		return Path{}, fmt.Errorf("%w: path %q must start with /%s or /%s (§5.3 п. 9)",
			ErrInvalidName, virtualPath, domain.NamespaceHome, domain.NamespacePublic)
	}

	components := parts[1:]
	// §5.3 п. 8: предел числа компонентов НИЖЕ virtual root.
	if len(components) > domain.MaxTreeDepth {
		return Path{}, fmt.Errorf("%w: path is %d components deep, limit is %d (§5.3 п. 8)",
			ErrInvalidName, len(components), domain.MaxTreeDepth)
	}
	for _, c := range components {
		if err := ValidateName(c); err != nil {
			return Path{}, fmt.Errorf("component %q of %q: %w", c, virtualPath, err)
		}
	}

	return Path{Namespace: ns, Components: components}, nil
}
