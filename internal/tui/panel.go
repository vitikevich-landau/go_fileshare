package tui

// Panel — одна из двух файловых панелей. Хранит листинг каталога, курсор,
// прокрутку и набор выделенных файлов. ВСЕ методы — чистые переходы состояния,
// поэтому их можно юнит-тестировать без терминала (та самая тестируемость
// UI-логики из docs/tz/01-architecture.md §4).
type Panel struct {
	Remote   bool            // удалённая панель (сервер) или локальная (диск клиента)
	Label    string          // подпись (локальный каталог или имя профиля для удалённой)
	Path     string          // текущий каталог
	Entries  []Entry         // записи; Entries[0] — «..», если есть родитель
	Cursor   int             // индекс записи под курсором
	Top      int             // индекс первой видимой строки (прокрутка)
	Selected map[string]bool // множественное выделение (по имени)
	LastSeen int64           // метка «виделось до» — для подсветки новых файлов
	Sort     sortMode        // текущий порядок сортировки (F2 переключает)
}

func newPanel(remote bool, label, path string) *Panel {
	return &Panel{Remote: remote, Label: label, Path: path, Selected: map[string]bool{}}
}

// SetEntries заменяет листинг: сортирует настоящие записи, помечает новые
// (по LastSeen), добавляет «..» в начало при hasParent и зажимает курсор в
// допустимых границах.
func (p *Panel) SetEntries(entries []Entry, hasParent bool) {
	sortEntriesBy(entries, p.Sort)
	for i := range entries {
		entries[i].IsNew = p.LastSeen > 0 && entries[i].Mtime > p.LastSeen
	}
	if hasParent {
		entries = append([]Entry{{Name: "..", IsDir: true, IsUp: true}}, entries...)
	}
	p.Entries = entries
	if p.Cursor >= len(entries) {
		p.Cursor = len(entries) - 1
	}
	if p.Cursor < 0 {
		p.Cursor = 0
	}
	p.Selected = map[string]bool{}
}

// findFile returns the named non-directory entry, if present.
func (p *Panel) findFile(name string) (Entry, bool) {
	for _, e := range p.Entries {
		if e.Name == name && !e.IsDir {
			return e, true
		}
	}
	return Entry{}, false
}

// Current returns the entry under the cursor.
func (p *Panel) Current() (Entry, bool) {
	if p.Cursor < 0 || p.Cursor >= len(p.Entries) {
		return Entry{}, false
	}
	return p.Entries[p.Cursor], true
}

// Move shifts the cursor by delta, clamps it, and keeps it visible within a
// viewport of the given row count.
func (p *Panel) Move(delta, viewport int) {
	if len(p.Entries) == 0 {
		p.Cursor, p.Top = 0, 0
		return
	}
	p.Cursor += delta
	if p.Cursor < 0 {
		p.Cursor = 0
	}
	if p.Cursor >= len(p.Entries) {
		p.Cursor = len(p.Entries) - 1
	}
	p.clamp(viewport)
}

// MoveTo places the cursor at an absolute index.
func (p *Panel) MoveTo(idx, viewport int) {
	p.Cursor = idx
	p.Move(0, viewport)
}

func (p *Panel) clamp(viewport int) {
	if viewport < 1 {
		viewport = 1
	}
	if p.Cursor < p.Top {
		p.Top = p.Cursor
	}
	if p.Cursor >= p.Top+viewport {
		p.Top = p.Cursor - viewport + 1
	}
	if p.Top < 0 {
		p.Top = 0
	}
}

// ToggleSelect flips the selection state of the current entry (never "..").
func (p *Panel) ToggleSelect() {
	e, ok := p.Current()
	if !ok || e.IsUp {
		return
	}
	if p.Selected[e.Name] {
		delete(p.Selected, e.Name)
	} else {
		p.Selected[e.Name] = true
	}
}

// InvertSelect flips the selection of every file entry (dirs and ".." are left
// untouched).
func (p *Panel) InvertSelect() {
	for _, e := range p.Entries {
		if e.IsDir || e.IsUp {
			continue
		}
		if p.Selected[e.Name] {
			delete(p.Selected, e.Name)
		} else {
			p.Selected[e.Name] = true
		}
	}
}

// Resort reorders the current entries by the panel's sort mode, keeping ".." at
// the top, and resets the cursor.
func (p *Panel) Resort() {
	rest := p.Entries
	hasUp := len(rest) > 0 && rest[0].IsUp
	if hasUp {
		rest = rest[1:]
	}
	sortEntriesBy(rest, p.Sort)
	if hasUp {
		p.Entries = append(p.Entries[:1], rest...)
	}
	p.Cursor, p.Top = 0, 0
}

// Targets returns the names to act on: the selection if any, else the current
// file entry. Directories and ".." are excluded.
func (p *Panel) Targets() []Entry {
	if len(p.Selected) > 0 {
		var out []Entry
		for _, e := range p.Entries {
			if p.Selected[e.Name] && !e.IsDir {
				out = append(out, e)
			}
		}
		return out
	}
	if e, ok := p.Current(); ok && !e.IsDir {
		return []Entry{e}
	}
	return nil
}

// TotalSize sums the sizes of file entries (ignoring dirs and "..").
func (p *Panel) TotalSize() uint64 {
	var sum uint64
	for _, e := range p.Entries {
		if !e.IsDir {
			sum += e.Size
		}
	}
	return sum
}

// FileCount counts file entries (ignoring dirs and "..").
func (p *Panel) FileCount() int {
	n := 0
	for _, e := range p.Entries {
		if !e.IsDir {
			n++
		}
	}
	return n
}

// NewCount counts entries flagged new.
func (p *Panel) NewCount() int {
	n := 0
	for _, e := range p.Entries {
		if e.IsNew {
			n++
		}
	}
	return n
}

// MarkAllSeen clears new highlighting by advancing LastSeen past every entry.
func (p *Panel) MarkAllSeen(now int64) {
	p.LastSeen = now
	for i := range p.Entries {
		p.Entries[i].IsNew = false
	}
}
