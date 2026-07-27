package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// scratchSchema — минимальная схема для проверок соединения: она повторяет
// ФОРМУ мутации §9 (проверка конфликта имени, затем вставка), а не схему §6 —
// та проверяется тестами миграции 0001.
var scratchSchema = Migration{
	Version: 1,
	Name:    "scratch",
	Apply: func(ctx context.Context, tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `
CREATE TABLE items (
    id     INTEGER PRIMARY KEY AUTOINCREMENT,
    name   TEXT NOT NULL UNIQUE,
    seq_ms INTEGER NOT NULL
) STRICT;`)
		return err
	},
}

func testConfig(t *testing.T) Config {
	t.Helper()
	return Config{
		Path:          filepath.Join(t.TempDir(), "metadata.db"),
		BusyTimeoutMs: 5000,
		Synchronous:   "NORMAL",
		ReadConns:     8,
	}
}

func openScratch(t *testing.T, cfg Config) *DB {
	t.Helper()
	d, err := Open(context.Background(), cfg, []Migration{scratchSchema})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { d.Close() })
	return d
}

// TestOpenAppliesPragmas — базовый случай: пара handle'ов поднимается, PRAGMA
// сверены, схема применена.
func TestOpenAppliesPragmas(t *testing.T) {
	cfg := testConfig(t)
	d := openScratch(t, cfg)

	version, err := SchemaVersion(context.Background(), d.Writer)
	if err != nil {
		t.Fatalf("SchemaVersion: %v", err)
	}
	if version != 1 {
		t.Fatalf("schema version = %d, want 1", version)
	}
	if d.ReadConns() != 8 {
		t.Fatalf("ReadConns = %d, want 8", d.ReadConns())
	}
}

// TestPragmasOnEveryConn — §6.1 «PRAGMA … на КАЖДОМ соединении пула». Все N
// читающих соединений берутся ОДНОВРЕМЕННО: последовательная проверка N раз
// проверила бы одно и то же соединение (ADR 0001 §3.7, §6.4 п. 3).
func TestPragmasOnEveryConn(t *testing.T) {
	ctx := context.Background()
	cfg := testConfig(t)
	d := openScratch(t, cfg)

	const n = 8
	conns := make([]*sql.Conn, 0, n)
	defer func() {
		for _, c := range conns {
			c.Close()
		}
	}()
	for i := 0; i < n; i++ {
		c, err := d.Reader.Conn(ctx)
		if err != nil {
			t.Fatalf("take reader conn %d: %v", i, err)
		}
		conns = append(conns, c)
	}
	wc, err := d.Writer.Conn(ctx)
	if err != nil {
		t.Fatalf("take writer conn: %v", err)
	}
	defer wc.Close()

	mismatching := 0
	check := func(role string, idx int, c *sql.Conn) {
		var journal string
		if err := c.QueryRowContext(ctx, "PRAGMA journal_mode").Scan(&journal); err != nil {
			t.Fatalf("%s %d: journal_mode: %v", role, idx, err)
		}
		if !strings.EqualFold(journal, "wal") {
			t.Errorf("%s %d: journal_mode = %q, want wal", role, idx, journal)
			mismatching++
		}
		for _, p := range []struct {
			name string
			want int64
		}{{"foreign_keys", 1}, {"busy_timeout", 5000}, {"synchronous", 1}} {
			var got int64
			if err := c.QueryRowContext(ctx, "PRAGMA "+p.name).Scan(&got); err != nil {
				t.Fatalf("%s %d: %s: %v", role, idx, p.name, err)
			}
			if got != p.want {
				t.Errorf("%s %d: %s = %d, want %d", role, idx, p.name, got, p.want)
				mismatching++
			}
		}
	}
	for i, c := range conns {
		check("reader", i, c)
	}
	check("writer", 0, wc)
	if mismatching != 0 {
		t.Fatalf("mismatching_conns = %d, want 0", mismatching)
	}
}

// TestFailFastOnDSNTypo — §6.1, ADR 0001 §4.5. Драйвер молча проглатывает
// опечатку в DSN: foreign_keys остаётся 0, ошибки при открытии нет. Обратная
// вычитка обязана превратить это в отказ старта с именем PRAGMA.
func TestFailFastOnDSNTypo(t *testing.T) {
	ctx := context.Background()
	cfg := testConfig(t)

	typos := map[string]string{
		"опечатка в имени PRAGMA":  "_pragma=foreign_keyz(1)",
		"опечатка в имени ключа":   "_pragmaa=foreign_keys(1)",
		"мусор в значении":         "_pragma=busy_timeout(abc)&_pragma=foreign_keys(1)",
		"параметр забыт полностью": "",
	}
	for name, broken := range typos {
		t.Run(name, func(t *testing.T) {
			dsn := fmt.Sprintf("%s?_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)&_txlock=immediate",
				fileURI(filepath.Join(t.TempDir(), "typo.db")))
			if broken != "" {
				dsn += "&" + broken
			}
			h, err := openDriver(dsn)
			if err != nil {
				// Часть опечаток драйвер отвергает сразу — это тоже отказ.
				return
			}
			defer h.Close()
			h.SetMaxOpenConns(1)

			// Негативная половина проверки: драйвер сам по себе НЕ ругается.
			var fk int64
			if err := h.QueryRowContext(ctx, "PRAGMA foreign_keys").Scan(&fk); err == nil && fk == 1 {
				t.Skipf("driver applied %q anyway; nothing to fail fast on", broken)
			}

			err = verifyPragmas(ctx, h, cfg, 1, "writer")
			if err == nil {
				t.Fatalf("verifyPragmas accepted a connection opened with %q", broken)
			}
			if !strings.Contains(err.Error(), "PRAGMA") {
				t.Fatalf("error must name the PRAGMA, got: %v", err)
			}
		})
	}
}

// TestWriteContentionUsesImmediate — главный тест §6.4 п. 1 ADR 0001.
//
// Проверяется форма транзакции «SELECT для проверки конфликта имени, затем
// INSERT» — та самая, в которой DEFERRED получает SQLITE_BUSY_SNAPSHOT при
// апгрейде read-снапшота до write-блокировки. busy_timeout этот класс отказов не
// ретраит принципиально, поэтому без _txlock=immediate отваливается 78–91%
// транзакций (ADR 0001 §3.6.D).
//
// Конкуренция создаётся НЕСКОЛЬКИМИ пишущими handle'ами: у одного handle пул из
// одного соединения, и очередь на запись держит database/sql, из-за чего
// разница immediate/deferred внутри него не проявляется вовсе. Несколько
// handle'ов воспроизводят ту же ситуацию, что и несколько процессов над одним
// файлом (ADR 0001 §3.6.C).
func TestWriteContentionUsesImmediate(t *testing.T) {
	ctx := context.Background()
	cfg := testConfig(t)
	d := openScratch(t, cfg)

	const (
		handles = 4
		perHand = 60
	)
	writers := make([]*sql.DB, 0, handles)
	defer func() {
		for _, w := range writers {
			w.Close()
		}
	}()
	writers = append(writers, d.Writer)
	for i := 1; i < handles; i++ {
		w, err := openDriver(cfg.writerDSN())
		if err != nil {
			t.Fatalf("open writer %d: %v", i, err)
		}
		w.SetMaxOpenConns(1)
		w.SetMaxIdleConns(1)
		writers = append(writers, w)
	}

	var (
		wg   sync.WaitGroup
		mu   sync.Mutex
		fail []error
	)
	for i, w := range writers {
		wg.Add(1)
		go func(worker int, w *sql.DB) {
			defer wg.Done()
			for j := 0; j < perHand; j++ {
				name := fmt.Sprintf("w%d-%d", worker, j)
				err := writeTx(ctx, w, func(tx *sql.Tx) error {
					var n int
					// Чтение ПЕРЕД записью — именно оно ломает DEFERRED.
					if err := tx.QueryRowContext(ctx,
						`SELECT count(*) FROM items WHERE name = ?`, name).Scan(&n); err != nil {
						return err
					}
					if n != 0 {
						return fmt.Errorf("name %q already exists", name)
					}
					_, err := tx.ExecContext(ctx,
						`INSERT INTO items (name, seq_ms) VALUES (?, ?)`, name, j)
					return err
				})
				if err != nil {
					mu.Lock()
					fail = append(fail, err)
					mu.Unlock()
					return
				}
			}
		}(i, w)
	}
	wg.Wait()

	if len(fail) != 0 {
		t.Fatalf("%d write transactions failed, first: %v", len(fail), fail[0])
	}
	var got int
	if err := d.Reader.QueryRowContext(ctx, `SELECT count(*) FROM items`).Scan(&got); err != nil {
		t.Fatalf("count: %v", err)
	}
	if want := handles * perHand; got != want {
		t.Fatalf("committed %d rows, want %d", got, want)
	}
}

// TestBusyTimeoutWaits — §6.4 п. 2 ADR 0001: при взятой write-блокировке второй
// писатель обязан ДОЖДАТЬСЯ её освобождения, а не вернуть SQLITE_BUSY
// мгновенно.
func TestBusyTimeoutWaits(t *testing.T) {
	ctx := context.Background()
	cfg := testConfig(t)
	cfg.BusyTimeoutMs = 3000
	d := openScratch(t, cfg)

	const hold = 600 * time.Millisecond

	other, err := openDriver(cfg.writerDSN())
	if err != nil {
		t.Fatalf("open second writer: %v", err)
	}
	defer other.Close()
	other.SetMaxOpenConns(1)

	tx, err := d.Writer.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("begin holder: %v", err)
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO items (name, seq_ms) VALUES ('holder', 0)`); err != nil {
		t.Fatalf("holder insert: %v", err)
	}

	released := make(chan struct{})
	go func() {
		time.Sleep(hold)
		close(released)
		tx.Commit()
	}()

	start := time.Now()
	err = writeTx(ctx, other, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO items (name, seq_ms) VALUES ('waiter', 1)`)
		return err
	})
	elapsed := time.Since(start)
	<-released

	if err != nil {
		t.Fatalf("second writer failed after %v instead of waiting: %v", elapsed, err)
	}
	if elapsed < hold/2 {
		t.Fatalf("second writer returned after %v, expected it to wait for the lock (~%v)", elapsed, hold)
	}
}

// TestReaderIsReadOnly — §6.4 п. 5: mode=ro отвергает запись физически, а не по
// договорённости.
func TestReaderIsReadOnly(t *testing.T) {
	d := openScratch(t, testConfig(t))
	_, err := d.Reader.ExecContext(context.Background(),
		`INSERT INTO items (name, seq_ms) VALUES ('x', 0)`)
	if err == nil {
		t.Fatal("write through the reader handle succeeded")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "readonly") {
		t.Fatalf("want a readonly-database error, got: %v", err)
	}
}

// TestWALDoesNotBlockReaders — §6.4 п. 6: при открытой незакоммиченной
// write-транзакции читатель видит ПРЕЖНЕЕ состояние и не блокируется.
func TestWALDoesNotBlockReaders(t *testing.T) {
	ctx := context.Background()
	d := openScratch(t, testConfig(t))

	if _, err := d.Writer.ExecContext(ctx,
		`INSERT INTO items (name, seq_ms) VALUES ('first', 0)`); err != nil {
		t.Fatalf("seed: %v", err)
	}

	tx, err := d.Writer.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO items (name, seq_ms) VALUES ('second', 1)`); err != nil {
		t.Fatalf("insert: %v", err)
	}

	count := func() int {
		var n int
		rctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		if err := d.Reader.QueryRowContext(rctx, `SELECT count(*) FROM items`).Scan(&n); err != nil {
			t.Fatalf("reader blocked or failed: %v", err)
		}
		return n
	}
	if got := count(); got != 1 {
		t.Fatalf("reader sees %d rows inside an open write transaction, want 1", got)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}
	if got := count(); got != 2 {
		t.Fatalf("reader sees %d rows after commit, want 2", got)
	}
}

// TestContextCancelInterruptsQuery — §6.4 п. 7: отмена контекста обязана
// прерывать ВЫПОЛНЯЮЩИЙСЯ запрос, а не только ожидание. Тест дисквалифицирует
// драйвер, у которого sqlite3_interrupt не вызывается (ADR 0001 §3.7).
func TestContextCancelInterruptsQuery(t *testing.T) {
	d := openScratch(t, testConfig(t))

	const heavy = `WITH RECURSIVE c(x) AS (
	    SELECT 1 UNION ALL SELECT x + 1 FROM c WHERE x < 500000000
	) SELECT count(*) FROM c`

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	start := time.Now()
	var n int64
	err := d.Reader.QueryRowContext(ctx, heavy).Scan(&n)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("heavy query completed within the deadline; the test query is not heavy enough")
	}
	if elapsed > 10*time.Second {
		t.Fatalf("query ran %v after a 300ms deadline: cancellation does not reach the driver", elapsed)
	}
	if !errors.Is(err, context.DeadlineExceeded) && !strings.Contains(err.Error(), "interrupt") {
		t.Fatalf("want a deadline/interrupt error, got: %v", err)
	}
}

// TestConfigValidation — негодная конфигурация отвергается до открытия файла.
func TestConfigValidation(t *testing.T) {
	base := testConfig(t)
	bad := map[string]func(*Config){
		"пустой path":        func(c *Config) { c.Path = "" },
		"нулевой busy":       func(c *Config) { c.BusyTimeoutMs = 0 },
		"отрицательный busy": func(c *Config) { c.BusyTimeoutMs = -1 },
		"synchronous OFF":    func(c *Config) { c.Synchronous = "OFF" },
		"synchronous пуст":   func(c *Config) { c.Synchronous = "" },
		"отрицательный пул":  func(c *Config) { c.ReadConns = -1 },
	}
	for name, mut := range bad {
		t.Run(name, func(t *testing.T) {
			cfg := base
			mut(&cfg)
			if _, err := Open(context.Background(), cfg, []Migration{scratchSchema}); err == nil {
				t.Fatal("Open accepted an invalid config")
			}
		})
	}
}

// TestDefaultReadConns — умолчание пула никогда не опускается ниже 4.
func TestDefaultReadConns(t *testing.T) {
	cfg := testConfig(t)
	cfg.ReadConns = 0
	d := openScratch(t, cfg)
	if d.ReadConns() < 4 {
		t.Fatalf("default ReadConns = %d, want >= 4", d.ReadConns())
	}
}

// TestReaderRequiresExistingDatabase — §6.4 п. 9 ADR 0001: mode=ro не создаёт ни
// файл БД, ни WAL, поэтому читающий handle, открытый до миграций, обязан дать
// ошибку, а не тихо создать пустую базу. Именно это и фиксирует порядок
// открытия §4.4.
func TestReaderRequiresExistingDatabase(t *testing.T) {
	cfg := testConfig(t)
	if _, err := openReader(context.Background(), cfg); err == nil {
		t.Fatal("reader opened a database that does not exist")
	}
}
