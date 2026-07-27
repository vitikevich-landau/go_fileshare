package domain

import "fmt"

// Namespace — виртуальный корень ресурса, колонка `resources.namespace` (§6.3).
// Ресурс никогда не меняет namespace: перемещение между namespace запрещено
// (§2.1, §9.3).
type Namespace string

// Значения Namespace. Перечень закрыт CHECK (namespace IN ('home','public')).
const (
	// NamespaceHome — личное дерево пользователя /home (§7.2).
	NamespaceHome Namespace = "home"
	// NamespacePublic — общий каталог /public. Имена в нём имеют обычную
	// семантику: два пользователя не могут создать в нём два файла с одним
	// именем, потому что owner_user_id не входит в ключ resources_uniq_name
	// (§6.3).
	NamespacePublic Namespace = "public"
)

// Valid сообщает, входит ли значение в закрытый словарь §6.3.
func (n Namespace) Valid() bool { return n == NamespaceHome || n == NamespacePublic }

// ParseNamespace разбирает namespace, отвергая значения вне словаря §6.3.
func ParseNamespace(s string) (Namespace, error) {
	if n := Namespace(s); n.Valid() {
		return n, nil
	}
	return "", fmt.Errorf("domain: namespace %q: want one of %v", s, AllNamespaces())
}

// AllNamespaces возвращает словарь §6.3 целиком, в порядке объявления.
func AllNamespaces() []Namespace { return []Namespace{NamespaceHome, NamespacePublic} }

// Kind — вид ресурса, колонка `resources.kind` (§6.3).
type Kind string

// Значения Kind. Перечень закрыт CHECK (kind IN ('file','dir')). Порядок
// значений в байтовом сравнении ('dir' < 'file') — это то, на чём держится режим
// сортировки SortKindNameAsc, ставящий каталоги перед файлами (§6.3).
const (
	KindFile Kind = "file"
	KindDir  Kind = "dir"
)

// Valid сообщает, входит ли значение в закрытый словарь §6.3.
func (k Kind) Valid() bool { return k == KindFile || k == KindDir }

// ParseKind разбирает вид ресурса, отвергая значения вне словаря §6.3.
func ParseKind(s string) (Kind, error) {
	if k := Kind(s); k.Valid() {
		return k, nil
	}
	return "", fmt.Errorf("domain: kind %q: want one of %v", s, AllKinds())
}

// AllKinds возвращает словарь §6.3 целиком, в порядке объявления.
func AllKinds() []Kind { return []Kind{KindFile, KindDir} }

// Revision — монотонно возрастающая версия содержимого ресурса (§2.1). По
// проводу это `uint64` (§3.10, §8.1), в БД — INTEGER колонки
// `resources.current_revision` и `versions.revision`.
type Revision uint64

// NoRevision — сентинел «проверка ревизии не выполняется» в полях
// ExpectedRevision (§2.1, §8.1, §12.1). Как значение current_revision он
// означает «содержимого ещё не было».
const NoRevision Revision = 0

// ChecksumAlgo — алгоритм контрольной суммы, колонки `checksum_algo` и
// `expected_checksum_algo` (§6.1). Пустое значение соответствует NULL в БД и
// проводному ChecksumAlgo = 0 (AlgoPending): сумма ещё не посчитана.
type ChecksumAlgo string

// Значения ChecksumAlgo. Непустой перечень закрыт
// CHECK (checksum_algo IN ('crc32','sha256')).
const (
	// ChecksumPending — сумма не посчитана: checksum_algo IS NULL и
	// checksum IS NULL (§6.1). Для uploads значение запрещено: v3-загрузка без
	// ожидаемой суммы невозможна (§6.4, §8.1).
	ChecksumPending ChecksumAlgo = ""
	ChecksumCRC32   ChecksumAlgo = "crc32"
	ChecksumSHA256  ChecksumAlgo = "sha256"
)

// Проводные коды ChecksumAlgo (§6.1). Значения обязаны совпадать с proto.Algo;
// пакет domain не импортирует proto, чтобы не разворачивать зависимость слоёв,
// поэтому совпадение проверяется тестом.
const (
	ChecksumWirePending uint8 = 0
	ChecksumWireCRC32   uint8 = 1
	ChecksumWireSHA256  uint8 = 2
)

// Valid сообщает, входит ли значение в словарь §6.1, включая ChecksumPending.
func (a ChecksumAlgo) Valid() bool {
	switch a {
	case ChecksumPending, ChecksumCRC32, ChecksumSHA256:
		return true
	}
	return false
}

// WireCode возвращает проводной код алгоритма (§6.1). Вызов на значении вне
// словаря — ошибка программиста, поэтому возвращается и признак корректности.
func (a ChecksumAlgo) WireCode() (uint8, bool) {
	switch a {
	case ChecksumPending:
		return ChecksumWirePending, true
	case ChecksumCRC32:
		return ChecksumWireCRC32, true
	case ChecksumSHA256:
		return ChecksumWireSHA256, true
	}
	return 0, false
}

// SignificantBytes — сколько байт колонки checksum значимы для алгоритма (§6.1):
// 4 для crc32, 32 для sha256, 0 для ChecksumPending.
func (a ChecksumAlgo) SignificantBytes() int {
	switch a {
	case ChecksumCRC32:
		return 4
	case ChecksumSHA256:
		return 32
	}
	return 0
}

// ChecksumAlgoFromWire разбирает проводной код (§6.1). Любое значение вне
// перечня — malformed input, а не повод подставить умолчание.
func ChecksumAlgoFromWire(code uint8) (ChecksumAlgo, error) {
	switch code {
	case ChecksumWirePending:
		return ChecksumPending, nil
	case ChecksumWireCRC32:
		return ChecksumCRC32, nil
	case ChecksumWireSHA256:
		return ChecksumSHA256, nil
	}
	return "", fmt.Errorf("domain: checksum algo code %d: want 0, 1 or 2", code)
}

// ParseChecksumAlgo разбирает текстовое имя алгоритма из БД (§6.1).
func ParseChecksumAlgo(s string) (ChecksumAlgo, error) {
	if a := ChecksumAlgo(s); a.Valid() {
		return a, nil
	}
	return "", fmt.Errorf("domain: checksum algo %q: want one of %v", s, AllChecksumAlgos())
}

// AllChecksumAlgos возвращает ЗНАЧИМЫЕ значения словаря §6.1 — те, что
// допускает CHECK в DDL. ChecksumPending в перечень не входит: в БД ему
// соответствует NULL, а не строка.
func AllChecksumAlgos() []ChecksumAlgo { return []ChecksumAlgo{ChecksumCRC32, ChecksumSHA256} }
