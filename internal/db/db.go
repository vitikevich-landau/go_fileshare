// Package db открывает metadata DB и держит инварианты подключения, которые
// docs/tz/10-cloud-drive-spec.md §6.1 требует от СОЕДИНЕНИЯ, а не от кода
// репозиториев: WAL, foreign_keys, busy_timeout, synchronous, BEGIN IMMEDIATE
// для пишущих транзакций и обратная вычитка PRAGMA с падением при расхождении.
//
// Топология — два раздельных *sql.DB на один файл (ADR 0001 §4.2, §4.4):
//
//   - ПИШУЩИЙ handle: ровно одно соединение и _txlock=immediate. SQLite
//     допускает одного писателя физически, поэтому пул из N писателей не
//     увеличивает пропускную способность, а превращает конкуренцию за write-lock
//     в очередь внутри SQLite с непредсказуемым хвостом. immediate обязателен:
//     DEFERRED-транзакция, которая читает перед записью (а такова любая мутация
//     §9 с проверкой конфликта имени), получает SQLITE_BUSY_SNAPSHOT при
//     апгрейде снапшота до write-блокировки, и busy_timeout этот класс отказов
//     принципиально не ретраит — замер даёт 189 успешных транзакций из 2000
//     против 2000 из 2000 (ADR 0001 §3.6.D);
//   - ЧИТАЮЩИЙ handle: N соединений и mode=ro. WAL даёт снапшотное чтение без
//     блокировки писателя, а отдельный пул убирает конкуренцию читателей за
//     пишущее соединение: p99 страницы листинга 2.63 мс против 16.71 мс на
//     едином пуле (ADR 0001 §3.6.E).
package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// Config — параметры открытия пары handle'ов. Path, BusyTimeoutMs и
// Synchronous приходят из секции database конфига (§19.3): §6.1 требует сверять
// фактическое значение PRAGMA с ожидаемым, поэтому у ожидаемого обязан быть
// единственный источник, и зашивать его в DSN нельзя.
type Config struct {
	// Path — путь к файлу metadata.db. Рядом с ним драйвер создаёт -wal и -shm,
	// поэтому каталог обязан быть доступен на запись, а файловая система —
	// поддерживать рабочий fcntl-лок (не сетевая ФС).
	Path string
	// BusyTimeoutMs — database.busy_timeout_ms (§19.3). Обязан быть > 0.
	BusyTimeoutMs int
	// Synchronous — database.synchronous: "NORMAL" или "FULL" (§19.4 п. 17).
	Synchronous string
	// ReadConns — размер читающего пула. 0 означает max(4, GOMAXPROCS);
	// нагрузочные цифры §24.5 сняты на 8.
	ReadConns int
}

// DB — открытая metadata DB: пара handle'ов с уже проверенными PRAGMA.
type DB struct {
	// Writer обслуживает ВСЕ транзакции, способные выполнить запись. Каждая
	// его транзакция открывается как BEGIN IMMEDIATE — это обеспечено
	// _txlock=immediate в DSN, а не дисциплиной вызывающего.
	Writer *sql.DB
	// Reader обслуживает читающие транзакции. Запись через него физически
	// невозможна: mode=ro возвращает «attempt to write a readonly database».
	Reader *sql.DB

	cfg Config
}

// Open открывает metadata DB, применяет миграции и возвращает готовую пару
// handle'ов. Порядок фиксирован (ADR 0001 §4.4) и следует из mode=ro: читающий
// handle не создаёт ни файл БД, ни WAL, поэтому он открывается только после
// того, как пишущий handle создал базу и миграции её наполнили.
//
// Обратная вычитка PRAGMA выполняется сразу после открытия каждого соединения,
// как требует §6.1, то есть на пишущем handle — ДО миграций: смысл проверки в
// том, чтобы опечатка в DSN не позволила работать с базой, у которой молча
// отключены внешние ключи, а создание схемы — это уже работа с базой.
func Open(ctx context.Context, cfg Config, migrations []Migration) (*DB, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	if dir := filepath.Dir(cfg.Path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return nil, fmt.Errorf("db: create directory for %s: %w", cfg.Path, err)
		}
	}

	writer, err := openWriter(ctx, cfg)
	if err != nil {
		return nil, err
	}
	d := &DB{Writer: writer, cfg: cfg}

	if err := Migrate(ctx, writer, migrations); err != nil {
		writer.Close()
		return nil, err
	}

	reader, err := openReader(ctx, cfg)
	if err != nil {
		writer.Close()
		return nil, err
	}
	d.Reader = reader
	return d, nil
}

// Close закрывает оба handle'а. Ошибки обоих возвращаются вместе: молча терять
// одну из них нельзя, «БД не закрылась» — это диагностика, а не шум.
func (d *DB) Close() error {
	var errs []error
	if d.Reader != nil {
		if err := d.Reader.Close(); err != nil {
			errs = append(errs, fmt.Errorf("db: close reader: %w", err))
		}
	}
	if d.Writer != nil {
		if err := d.Writer.Close(); err != nil {
			errs = append(errs, fmt.Errorf("db: close writer: %w", err))
		}
	}
	return errors.Join(errs...)
}

// Write выполняет fn в пишущей транзакции. Транзакция открывается как
// BEGIN IMMEDIATE (_txlock=immediate в DSN пишущего handle), поэтому
// read-then-write внутри fn не упирается в SQLITE_BUSY_SNAPSHOT (§6.1, §23.2).
// При ошибке fn или паники транзакция откатывается.
func (d *DB) Write(ctx context.Context, fn func(*sql.Tx) error) error {
	return writeTx(ctx, d.Writer, fn)
}

func writeTx(ctx context.Context, w *sql.DB, fn func(*sql.Tx) error) (err error) {
	tx, err := w.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("db: begin write transaction: %w", err)
	}
	defer func() {
		if p := recover(); p != nil {
			tx.Rollback()
			panic(p)
		}
		if err != nil {
			tx.Rollback()
		}
	}()
	if err = fn(tx); err != nil {
		return err
	}
	if err = tx.Commit(); err != nil {
		return fmt.Errorf("db: commit: %w", err)
	}
	return nil
}

// ReadConns возвращает фактический размер читающего пула.
func (d *DB) ReadConns() int { return d.cfg.readConns() }

func (c Config) validate() error {
	if c.Path == "" {
		return errors.New("db: database.path must not be empty")
	}
	if c.BusyTimeoutMs <= 0 {
		return fmt.Errorf("db: database.busy_timeout_ms = %d, must be > 0", c.BusyTimeoutMs)
	}
	if _, err := synchronousCode(c.Synchronous); err != nil {
		return err
	}
	if c.ReadConns < 0 {
		return fmt.Errorf("db: ReadConns = %d, must be >= 0", c.ReadConns)
	}
	return nil
}

func (c Config) readConns() int {
	if c.ReadConns > 0 {
		return c.ReadConns
	}
	if n := runtime.GOMAXPROCS(0); n > 4 {
		return n
	}
	return 4
}

func openWriter(ctx context.Context, cfg Config) (*sql.DB, error) {
	w, err := openDriver(cfg.writerDSN())
	if err != nil {
		return nil, fmt.Errorf("db: open writer: %w", err)
	}
	// Ровно одно соединение: писатель у SQLite физически один, очередь на запись
	// держит database/sql, а не блокировки SQLite. Idle = 1, чтобы соединение не
	// пересоздавалось и не переприменяло PRAGMA на каждой транзакции; lifetime
	// без ограничения — пересоздавать локальное соединение незачем, а прогретый
	// page cache терять жалко (ADR 0001 §4.4).
	w.SetMaxOpenConns(1)
	w.SetMaxIdleConns(1)
	w.SetConnMaxLifetime(0)

	if err := verifyPragmas(ctx, w, cfg, 1, "writer"); err != nil {
		w.Close()
		return nil, err
	}
	return w, nil
}

func openReader(ctx context.Context, cfg Config) (*sql.DB, error) {
	n := cfg.readConns()
	r, err := openDriver(cfg.readerDSN())
	if err != nil {
		return nil, fmt.Errorf("db: open reader: %w", err)
	}
	r.SetMaxOpenConns(n)
	// Idle = Max, чтобы соединения не закрывались между всплесками журнального
	// polling и не переприменяли PRAGMA (ADR 0001 §4.4).
	r.SetMaxIdleConns(n)
	r.SetConnMaxLifetime(0)

	if err := verifyPragmas(ctx, r, cfg, n, "reader"); err != nil {
		r.Close()
		return nil, err
	}
	return r, nil
}

// verifyPragmas — обязательная обратная вычитка (§6.1, ADR 0001 §4.5).
//
// Драйвер МОЛЧА проглатывает любую опечатку в DSN: _pragma=foreign_keyz(1),
// _pragmaa=…, _pragma=busy_timeout(abc), неизвестный параметр целиком — ни
// ошибки, ни предупреждения, при этом foreign_keys остаётся 0. То есть одна
// опечатка тихо отключает ссылочную целостность на всём проде, и ни один тест
// этого не замечает: нарушения FK просто перестают отклоняться. Поэтому
// расхождение — фатальная ошибка с именем PRAGMA, ожидаемым и фактическим
// значением, а не предупреждение в лог.
//
// conns соединений берутся ОДНОВРЕМЕННО: PRAGMA действуют на соединение, и
// последовательная проверка N раз проверила бы одно и то же соединение.
func verifyPragmas(ctx context.Context, h *sql.DB, cfg Config, conns int, role string) error {
	wantSync, err := synchronousCode(cfg.Synchronous)
	if err != nil {
		return err
	}

	held := make([]*sql.Conn, 0, conns)
	defer func() {
		for _, c := range held {
			c.Close()
		}
	}()
	for i := 0; i < conns; i++ {
		c, err := h.Conn(ctx)
		if err != nil {
			return fmt.Errorf("db: %s: take connection %d/%d: %w", role, i+1, conns, err)
		}
		held = append(held, c)
	}

	for i, c := range held {
		var journalMode string
		if err := c.QueryRowContext(ctx, "PRAGMA journal_mode").Scan(&journalMode); err != nil {
			return fmt.Errorf("db: %s conn %d: read journal_mode: %w", role, i+1, err)
		}
		if !strings.EqualFold(journalMode, "wal") {
			return pragmaMismatch(role, i+1, "journal_mode", "wal", journalMode)
		}
		for _, p := range []struct {
			name string
			want int64
		}{
			{"foreign_keys", 1},
			{"busy_timeout", int64(cfg.BusyTimeoutMs)},
			{"synchronous", wantSync},
		} {
			var got int64
			if err := c.QueryRowContext(ctx, "PRAGMA "+p.name).Scan(&got); err != nil {
				return fmt.Errorf("db: %s conn %d: read %s: %w", role, i+1, p.name, err)
			}
			if got != p.want {
				return pragmaMismatch(role, i+1, p.name,
					fmt.Sprint(p.want), fmt.Sprint(got))
			}
		}
	}
	return nil
}

func pragmaMismatch(role string, conn int, pragma, want, got string) error {
	return fmt.Errorf(
		"db: %s conn %d: PRAGMA %s = %s, want %s; the driver accepts a malformed DSN silently, "+
			"so this mismatch means the connection is NOT configured as required "+
			"(docs/tz/10-cloud-drive-spec.md §6.1)",
		role, conn, pragma, got, want)
}

// synchronousCode переводит имя режима в число, которое возвращает
// PRAGMA synchronous: 1 — NORMAL, 2 — FULL. «OFF» (0) запрещён §19.4 п. 17.
func synchronousCode(name string) (int64, error) {
	switch name {
	case "NORMAL":
		return 1, nil
	case "FULL":
		return 2, nil
	}
	return 0, fmt.Errorf("db: database.synchronous %q must be NORMAL or FULL", name)
}

// writerDSN и readerDSN — дословно проверенные строки ADR 0001 §4.2.
//
// journal_mode указывается и читающему handle, хотя режим персистентен в
// заголовке файла: указание идемпотентно и даёт fail-fast, если базу кто-то
// перевёл обратно в delete.
func (c Config) writerDSN() string {
	return c.baseDSN() + "&_txlock=immediate"
}

func (c Config) readerDSN() string {
	return c.baseDSN() + "&mode=ro"
}

func (c Config) baseDSN() string {
	return fmt.Sprintf(
		"%s?_pragma=busy_timeout(%d)&_pragma=foreign_keys(1)&_pragma=journal_mode(WAL)&_pragma=synchronous(%s)",
		fileURI(c.Path), c.BusyTimeoutMs, c.Synchronous)
}

// fileURI строит file:-URI из пути ОС. Разделители приводятся к прямым слэшам
// (SQLite понимает `file:C:/dir/db` на Windows), а символы, значимые для URI,
// экранируются: без этого путь с '?' или '%' обрезался бы или расшифровывался
// как чужая последовательность.
func fileURI(path string) string {
	slashed := filepath.ToSlash(path)
	var b strings.Builder
	b.Grow(len(slashed) + 8)
	for i := 0; i < len(slashed); i++ {
		switch ch := slashed[i]; {
		case ch == '?' || ch == '#' || ch == '%' || ch == ' ':
			fmt.Fprintf(&b, "%%%02X", ch)
		default:
			b.WriteByte(ch)
		}
	}
	return "file:" + b.String()
}
