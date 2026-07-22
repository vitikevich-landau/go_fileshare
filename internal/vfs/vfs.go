// Package vfs раздаёт дерево каталогов, запертое внутри корня раздачи
// (share-root).
//
// Удержание в границах корня делегировано os.Root (Go 1.24+): любая операция
// остаётся под корнем даже при «..»-компонентах или симлинках наружу. Это
// заменяет ручную логику openat2/realpath из эталона на C++ и закрывает класс
// уязвимостей TOCTOU по построению (docs/tz/09-go-port.md §5.2, §7).
//
// Словарь предметной области и, главное, ТРИ ФОРМЫ ПУТИ (virtual → cleaned →
// OS-relative) описаны в types.go — прочитайте его прежде, чем править пути.
package vfs

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/vitikevich-landau/go_fileshare/internal/proto"
)

// Error несёт код ошибки протокола рядом с исходной причиной, чтобы сервер
// перевёл сбой VFS в правильный кадр ERROR (а не всегда в INTERNAL_ERROR).
type Error struct {
	Code proto.ErrCode // какой ERROR-код отдать клиенту
	Op   string        // операция: list / stat / open / checksum
	Path string        // путь, на котором произошёл сбой
	Err  error         // исходная ошибка ОС
}

func (e *Error) Error() string {
	return fmt.Sprintf("vfs %s %q: %v (%s)", e.Op, e.Path, e.Err, e.Code)
}
func (e *Error) Unwrap() error { return e.Err }

// CodeOf извлекает код ошибки протокола из ошибки, вернувшейся из этого пакета;
// по умолчанию — INTERNAL_ERROR.
func CodeOf(err error) proto.ErrCode {
	var ve *Error
	if errors.As(err, &ve) {
		return ve.Code
	}
	return proto.ErrInternal
}

var errBadPath = errors.New("malformed path")

// classify переводит ошибку уровня ОС в код ошибки протокола. Всё, что
// запертый os.Root отклонил и что НЕ является простым «не найдено»/«нет прав»
// (в первую очередь — симлинк или компонент, убегающий за корень), считаем
// ACCESS_DENIED.
func classify(err error) proto.ErrCode {
	// Проверки ENOTDIR/EISDIR должны идти ПЕРЕД fs.ErrNotExist: на Windows
	// syscall.ENOTDIR через Errno.Is выдаёт себя за fs.ErrNotExist, из-за чего
	// «не каталог» иначе ошибочно пометилось бы как «файл не найден».
	switch {
	case errors.Is(err, errBadPath):
		return proto.ErrBadRequest
	case errors.Is(err, syscall.ENOTDIR):
		return proto.ErrNotADirectory
	case errors.Is(err, syscall.EISDIR):
		return proto.ErrIsADirectory
	case errors.Is(err, fs.ErrNotExist):
		return proto.ErrFileNotFound
	case errors.Is(err, fs.ErrPermission):
		return proto.ErrAccessDenied
	}
	return proto.ErrAccessDenied
}

func coded(op, p string, err error) *Error {
	return &Error{Code: classify(err), Op: op, Path: p, Err: err}
}

// VFS — дерево каталогов, укоренённое в директории раздачи, с ленивым
// checksum-кэшем. Безопасно для конкурентного использования (кэш и статистика
// под своими мьютексами).
type VFS struct {
	root      *os.Root // запертый корень: все операции идут только через него
	rootName  string   // путь корня на «настоящей» ФС (для walk статистики)
	cacheFile string   // куда сохранять checksum-кэш (пусто — не сохранять)

	mu    sync.Mutex            // защищает cache и dirty
	cache map[string]cacheEntry // ключ — CleanedPath, значение — сумма + метки
	dirty bool                  // есть ли несохранённые изменения кэша

	statsMu sync.Mutex // защищает stats
	stats   shareStats // фоново обновляемая сводка по раздаче
}

// shareStats — периодически обновляемый снимок числа файлов и суммарного размера
// раздачи, чтобы ADMIN_STATS не обходил большое дерево при каждом обновлении
// (раз в несколько секунд).
type shareStats struct {
	files     FileCount // сколько обычных файлов в раздаче
	bytes     FileSize  // их суммарный размер в байтах
	at        time.Time // когда снимок посчитан (для проверки на устаревание)
	computing bool      // идёт ли прямо сейчас фоновый пересчёт
}

// cacheEntry — одна запись checksum-кэша В ПАМЯТИ. Ключ (size, mtime-nanos,
// ctime) позволяет определить, что файл не изменился, и вернуть готовую сумму
// без повторного чтения всего файла.
type cacheEntry struct {
	Size  FileSize                // размер на момент подсчёта
	Mtime UnixNanos               // mtime в наносекундах (гранулярность CR-09)
	Ctime int64                   // ctime в наносекундах, где доступен (иначе 0) — RR-5
	Algo  proto.Algo              // алгоритм суммы (сейчас SHA-256)
	Sum   [proto.ChecksumLen]byte // сама сумма
}

// New открывает shareRoot как запертый корень. Если cacheFile непустой и
// существует, из него подгружается checksum-кэш (битый/отсутствующий кэш не
// фатален — стартуем с пустого).
func New(shareRoot, cacheFile string) (*VFS, error) {
	root, err := os.OpenRoot(shareRoot)
	if err != nil {
		return nil, fmt.Errorf("vfs: open share root %q: %w", shareRoot, err)
	}
	v := &VFS{
		root:      root,
		rootName:  shareRoot,
		cacheFile: cacheFile,
		cache:     make(map[string]cacheEntry),
	}
	if cacheFile != "" {
		if err := v.loadCache(); err != nil {
			// A corrupt/absent cache is not fatal — start empty.
			v.cache = make(map[string]cacheEntry)
		}
	}
	return v, nil
}

// Close сохраняет checksum-кэш и освобождает дескриптор корня.
func (v *VFS) Close() error {
	err := v.SaveCache()
	if cerr := v.root.Close(); err == nil {
		err = cerr
	}
	return err
}

// RootName возвращает путь корня раздачи, с которым открыт этот VFS.
func (v *VFS) RootName() string { return v.rootName }

// CleanPath нормализует виртуальный путь в абсолютную форму с разделителем «/»,
// без «..», «//» и хвостового слэша («/» остаётся «/»). «..» не может подняться
// выше корня, потому что путь чистится так, будто укоренён в «/». NUL-байт
// отвергается как BAD_REQUEST. Это шаг VirtualPath → CleanedPath из types.go.
func CleanPath(vpath VirtualPath) (CleanedPath, error) {
	if strings.IndexByte(vpath, 0) >= 0 {
		return "", errBadPath
	}
	if vpath == "" {
		vpath = "/"
	}
	return path.Clean("/" + vpath), nil
}

// rel переводит очищенный путь в OS-relative форму для os.Root (шаг CleanedPath
// → OS-relative из types.go): убирает ведущий «/» и меняет разделитель на
// системный; корень «/» превращается в «.».
func rel(clean CleanedPath) string {
	r := strings.TrimPrefix(clean, "/")
	if r == "" {
		return "."
	}
	return filepath.FromSlash(r)
}

// entryFromInfo собирает проводную запись каталога из имени и os-метаданных.
// Отрицательный mtime (файлы «из прошлого» до эпохи) приводится к 0, потому что
// на проводе mtime — беззнаковые unix-секунды.
func entryFromInfo(name string, info fs.FileInfo) proto.DirEntry {
	kind := proto.KindFile
	if info.IsDir() {
		kind = proto.KindDir
	}
	mt := info.ModTime().Unix()
	if mt < 0 {
		mt = 0
	}
	return proto.DirEntry{
		Name:  name,
		Kind:  kind,
		Size:  uint64(info.Size()),
		Mtime: uint64(mt),
	}
}

// List возвращает записи каталога vpath: сначала директории, затем по имени.
// Записи, которые не удаётся разрешить внутри корня (симлинк наружу, битая
// ссылка, слишком длинное имя), СКРЫВАЮТСЯ, а не отдаются наружу — иначе одна
// плохая запись заставила бы собеседника отвергнуть весь кадр списка.
func (v *VFS) List(vpath VirtualPath) (CleanedPath, []proto.DirEntry, error) {
	clean, err := CleanPath(vpath)
	if err != nil {
		return "", nil, coded("list", vpath, err)
	}
	info, err := v.root.Stat(rel(clean))
	if err != nil {
		return clean, nil, coded("list", clean, err)
	}
	if !info.IsDir() {
		return clean, nil, coded("list", clean, syscall.ENOTDIR)
	}
	f, err := v.root.Open(rel(clean))
	if err != nil {
		return clean, nil, coded("list", clean, err)
	}
	defer f.Close()

	dirents, err := f.ReadDir(-1)
	if err != nil {
		return clean, nil, coded("list", clean, err)
	}

	entries := make([]proto.DirEntry, 0, len(dirents))
	for _, de := range dirents {
		name := de.Name()
		// Провод ограничивает имя MaxNameLen байтами; более длинное (бывает на
		// NTFS с многобайтными unicode-именами) заставило бы собеседника
		// отвергнуть весь кадр списка — поэтому прячем его, а не портим ответ.
		if len(name) > proto.MaxNameLen {
			continue
		}
		var info fs.FileInfo
		if de.Type()&fs.ModeSymlink != 0 {
			// Разрешаем через корень; ссылки наружу или битые — прячем.
			child := path.Join(clean, name)
			si, serr := v.root.Stat(rel(child))
			if serr != nil {
				continue
			}
			info = si
		} else {
			li, ierr := de.Info()
			if ierr != nil {
				continue
			}
			info = li
		}
		entries = append(entries, entryFromInfo(name, info))
	}

	sort.Slice(entries, func(i, j int) bool {
		di := entries[i].Kind == proto.KindDir
		dj := entries[j].Kind == proto.KindDir
		if di != dj {
			return di // директории — первыми
		}
		return entries[i].Name < entries[j].Name
	})
	return clean, entries, nil
}

// Stat возвращает метаданные одной записи по пути vpath.
func (v *VFS) Stat(vpath VirtualPath) (CleanedPath, proto.DirEntry, error) {
	clean, err := CleanPath(vpath)
	if err != nil {
		return "", proto.DirEntry{}, coded("stat", vpath, err)
	}
	info, err := v.root.Stat(rel(clean))
	if err != nil {
		return clean, proto.DirEntry{}, coded("stat", clean, err)
	}
	return clean, entryFromInfo(path.Base(clean), info), nil
}

// Open открывает файл vpath на чтение, не выходя за корень. Закрыть файл —
// обязанность вызывающего. Директория отклоняется с IS_A_DIRECTORY.
func (v *VFS) Open(vpath VirtualPath) (*os.File, fs.FileInfo, error) {
	clean, err := CleanPath(vpath)
	if err != nil {
		return nil, nil, coded("open", vpath, err)
	}
	f, err := v.root.Open(rel(clean))
	if err != nil {
		return nil, nil, coded("open", clean, err)
	}
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, nil, coded("open", clean, err)
	}
	if info.IsDir() {
		f.Close()
		return nil, nil, coded("open", clean, syscall.EISDIR)
	}
	return f, info, nil
}

// Checksum возвращает контрольную сумму файла vpath, вычисляя её ЛЕНИВО и
// кэшируя по ключу (путь, size, mtime, ctime). Текущий алгоритм — SHA-256.
func (v *VFS) Checksum(vpath VirtualPath) (CleanedPath, proto.Algo, [proto.ChecksumLen]byte, error) {
	return v.ChecksumCtx(context.Background(), vpath)
}

// ChecksumCtx — это Checksum, который при промахе кэша прерывает подсчёт хеша по
// отмене ctx: если передачу отменили во время финального подсчёта суммы по всему
// файлу, она перестаёт заново вычитывать большой файл сразу, а не блокируется на
// минуты (R4-3). При отмене возвращает ctx.Err() как есть, чтобы вызывающий это
// распознал.
func (v *VFS) ChecksumCtx(ctx context.Context, vpath VirtualPath) (CleanedPath, proto.Algo, [proto.ChecksumLen]byte, error) {
	var zero [proto.ChecksumLen]byte
	clean, err := CleanPath(vpath)
	if err != nil {
		return "", proto.AlgoPending, zero, coded("checksum", vpath, err)
	}
	f, info, err := v.Open(clean)
	if err != nil {
		return clean, proto.AlgoPending, zero, err
	}
	defer f.Close()

	size := uint64(info.Size())
	// Наносекундная гранулярность mtime (CR-09) плюс change-time (RR-5): ctime
	// меняется при ЛЮБОМ изменении содержимого/метаданных, даже если mtime
	// сохранён (unix), — это ловит подмену файла тем же размером и тем же mtime.
	// Всё это — ТОЛЬКО ключ кэша; проводной DirEntry.mtime остаётся в секундах.
	mtime := uint64(info.ModTime().UnixNano())
	ctime, ctimeOK := changeTimeNanos(info)

	// Доверяем попаданию в кэш, только если платформа даёт надёжный change-time.
	// Где его нет (например, Windows), пары (size, mtime) недостаточно, чтобы
	// доказать неизменность содержимого: подмена тем же размером с восстановленным
	// точным mtime вернула бы устаревшую сумму — поэтому пересчитываем (R3-5).
	v.mu.Lock()
	if e, ok := v.cache[clean]; ok && ctimeOK && e.Size == size && e.Mtime == mtime && e.Ctime == ctime {
		v.mu.Unlock()
		return clean, e.Algo, e.Sum, nil
	}
	v.mu.Unlock()

	h := sha256.New()
	if cerr := copyCtx(ctx, h, f); cerr != nil {
		if ctx.Err() != nil {
			return clean, proto.AlgoPending, zero, cerr // отмена/дедлайн: отдаём как есть
		}
		return clean, proto.AlgoPending, zero, coded("checksum", clean, cerr)
	}
	var sum [proto.ChecksumLen]byte
	copy(sum[:], h.Sum(nil))

	v.mu.Lock()
	v.cache[clean] = cacheEntry{Size: size, Mtime: mtime, Ctime: ctime, Algo: proto.AlgoSHA256, Sum: sum}
	v.dirty = true
	v.mu.Unlock()
	return clean, proto.AlgoSHA256, sum, nil
}

// copyCtx перекачивает src в dst, проверяя ctx перед каждым блоком, чтобы долгий
// подсчёт хеша быстро прерывался по отмене. Возвращает ctx.Err() при отмене,
// иначе первую ошибку чтения/записи, либо nil по достижении EOF.
func copyCtx(ctx context.Context, dst io.Writer, src io.Reader) error {
	buf := make([]byte, 128<<10)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		n, rerr := src.Read(buf)
		if n > 0 {
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return werr
			}
		}
		if rerr == io.EOF {
			return nil
		}
		if rerr != nil {
			return rerr
		}
	}
}

// shareStatsTTL ограничивает, как часто дерево раздачи обходится ради
// ADMIN_STATS.
const shareStatsTTL = 30 * time.Second

// ShareStats возвращает закэшированные число файлов и суммарный размер раздачи.
// Обход дерева идёт в фоне не чаще раза в shareStatsTTL, поэтому вызывающий
// никогда не блокируется на большом дереве; первый вызов вернёт нули, пока не
// завершится первичный обход.
func (v *VFS) ShareStats() (files, bytes uint64) {
	v.statsMu.Lock()
	files, bytes = v.stats.files, v.stats.bytes
	stale := time.Since(v.stats.at) >= shareStatsTTL
	if stale && !v.stats.computing {
		v.stats.computing = true
		go v.refreshStats()
	}
	v.statsMu.Unlock()
	return files, bytes
}

func (v *VFS) refreshStats() {
	files, bytes := walkStats(v.rootName)
	v.statsMu.Lock()
	v.stats.files, v.stats.bytes, v.stats.at = files, bytes, time.Now()
	v.stats.computing = false
	v.statsMu.Unlock()
}

// walkStats считает обычные файлы и суммирует их размеры под корнем. Необычные
// записи (симлинки, сокеты, устройства) исключены И из счёта, И из размера.
// Симлинки не разыменовываются (WalkDir считает их листьями), поэтому обход не
// может зациклиться. (R6-9: считаем только обычные файлы.)
func walkStats(root string) (files, bytes uint64) {
	_ = filepath.WalkDir(root, func(_ string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		info, e := d.Info()
		if e != nil || !info.Mode().IsRegular() {
			return nil
		}
		files++
		bytes += uint64(info.Size())
		return nil
	})
	return files, bytes
}

// InvalidateChecksum сбрасывает закэшированную сумму для vpath (вызывается, когда
// watcher сообщает об изменении файла).
func (v *VFS) InvalidateChecksum(vpath VirtualPath) {
	clean, err := CleanPath(vpath)
	if err != nil {
		return
	}
	v.mu.Lock()
	if _, ok := v.cache[clean]; ok {
		delete(v.cache, clean)
		v.dirty = true
	}
	v.mu.Unlock()
}
