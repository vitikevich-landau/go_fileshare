package db

import (
	"database/sql"

	// ЕДИНСТВЕННОЕ место в дереве, где импортируется драйвер SQLite
	// (ADR 0001 §4.6). Репозитории, сервисы и миграции работают только через
	// database/sql. Запрет проверяется в CI: импорт драйвера в любом другом
	// .go-файле — красная сборка (ADR 0001 §6.5).
	//
	// Переход на заранее провалидированную запасную опцию
	// github.com/ncruces/go-sqlite3 (ADR 0001 §5.5) — правка ровно двух строк в
	// этом файле: импорта и driverName. DSN, синтаксис _pragma и _txlock у него
	// те же.
	_ "modernc.org/sqlite"
)

// driverName — имя, под которым драйвер регистрируется в database/sql.
// У modernc это "sqlite", у ncruces — "sqlite3".
const driverName = "sqlite"

// openDriver — единственный вызов sql.Open во всём дереве.
func openDriver(dsn string) (*sql.DB, error) { return sql.Open(driverName, dsn) }
