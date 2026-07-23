# go_fileshare — FShare Commander (Go)

[![ci](https://github.com/vitikevich-landau/go_fileshare/actions/workflows/ci.yml/badge.svg)](https://github.com/vitikevich-landau/go_fileshare/actions/workflows/ci.yml)
[![Go](https://img.shields.io/badge/Go-1.25%2B-00ADD8?logo=go&logoColor=white)](go.mod)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A from-scratch Go rewrite of the **fileshare v2** system ("FShare Commander"): a
directory-tree file server with a custom binary protocol and a full-screen
Midnight-Commander-style TUI client.

This port follows the self-sufficient specification in
[`docs/tz/09-go-port.md`](docs/tz/09-go-port.md). The wire protocol is
reproduced **byte-for-byte**, so a Go server can serve the original C++ client
and vice-versa.

> **📖 Интерактивная документация:** как устроена система целиком — карта
> пакетов, кадр протокола по байтам, карта сообщений, пошаговый разбор входа
> SCRAM и сквозные сценарии — живёт одной самодостаточной страницей в
> [`docs/interactive/index.html`](docs/interactive/index.html). Откройте её в
> браузере (`xdg-open docs/interactive/index.html`) или включите GitHub Pages.

## Components

| Binary | Role |
|---|---|
| `fshare-daemon` | Non-interactive server: serves a directory tree (VFS over `share_root`), challenge–response auth, push events on file changes, live config (rate limits etc.) with no restart, graceful shutdown, `SIGHUP` reload. |
| `fshare-commander` | Full-screen TUI in the style of Midnight Commander: two panels, hotkeys, downloads with progress/resume, new-file highlighting, connection indicator + auto-reconnect, admin panel (F9). Plus `--batch` for scripts. |

## Scope

Ports **M7–M11** of the roadmap (foundation + auth + TUI + live events + admin).
M12–M14 (multi-user/quotas, upload, TLS) are future work; data models leave room
for them.

## Status

**v2.0 complete — milestones M7–M11 implemented** (see [`docs/tz/08-roadmap.md`](docs/tz/08-roadmap.md)):

- **M7** — byte-exact wire protocol + `os.Root`-confined VFS
- **M8** — SCRAM-like challenge/response auth, sessions, downloads with resume
- **M9** — Bubble Tea Midnight-Commander-style TUI client
- **M10** — live `EVENT_FS` (fsnotify), heartbeats, auto-reconnect
- **M11** — live rate limiting + admin channel (config/kick/stats/shutdown) + admin panel (F9)

M12–M14 (multi-user/quotas, upload, TLS) are future work. Every package ships
tests run under `go test -race`.

### Post-M11 hardening

- **Admin F9 panel** completed to spec §2: live **Journal** tab, **graceful
  shutdown** and **Reload users** (F2 lifecycle menu), **kick confirmation**,
  **session details** (Enter), and **share stats** in the overview.
- **Hot user management** — `users.json` is re-read on `SIGHUP` or admin request,
  and sessions of a now-disabled/removed user are dropped (no restart).
- **Auth** — PBKDF2 iteration floor raised to **600k** (rejected below it at config
  load); failed authentications and IP bans are now **audited**.
- **TUI client** — interactive **command line** (`:`), **F2/F3/F4/Ctrl+O** hotkeys
  and invert-select, transfer **speed/ETA + queue** indicator, staged
  **connecting screen**, colour-coded link indicator + **reconnect plaque**.
- **Bounded growth** — idle rate-limit buckets are reaped and fsnotify watches are
  dropped on directory removal (two former unbounded-growth leaks).

## Quickstart

```bash
# 1. Build
go build -o bin/ ./cmd/fshare-daemon ./cmd/fshare-commander

# 2. Run the daemon over a directory (no users.json => any login is admin)
./bin/fshare-daemon --port 5555 --share-root ./some/dir

# 3a. Interactive TUI client
./bin/fshare-commander --host 127.0.0.1 --port 5555

# 3b. Or scripted
./bin/fshare-commander --batch --port 5555 --list /
./bin/fshare-commander --batch --port 5555 --get /file.bin --out ./file.bin
```

Add users (challenge/response auth) with:

```bash
./bin/fshare-daemon --config config.json --add-user vit --role admin   # prompts for a password
```

## Docker

```bash
mkdir -p data/share && cp somefiles/* data/share/
docker compose up --build           # serves ./data/share on :5555
```

The image is a static `scratch` build (`CGO_ENABLED=0`); `stop_grace_period`
matches the daemon's graceful drain.

## Layout

```
cmd/fshare-daemon      server entry point
cmd/fshare-commander   TUI client entry point
internal/proto         wire protocol (5-byte framing, messages, codecs)
internal/vfs           directory tree over os.Root (path confinement)
internal/auth          SCRAM-like challenge/response, users.json, IP ban guard
internal/config        settings + hot-reload hub (atomic snapshots)
internal/server        accept loop, sessions, dispatch, download, admin
internal/ratelimit     per-client + global token bucket
internal/watcher       fs events (fsnotify) -> EVENT_FS
internal/client        blocking client transport
internal/tui           Bubble Tea model/update/view + connection bridge
docs/tz                the specification this port follows
docs/interactive       single-page interactive architecture doc (open in a browser)
```

## Предметные типы и комментарии (для мейнтейнеров)

Код прокомментирован «под разбор и поддержку»: у каждого нетривиального шага
пояснено, ЗАЧЕМ он нужен (тонкости конкурентности, защита от рассинхронизации
потока, безопасность), а маркеры код-ревью (`CR-05`, `R3-7`, `RR-3`, `§8 bug 11`
и т.п.) сохранены рядом с соответствующим кодом.

В каждом пакете есть файл `types.go` — «словарь предметной области». В нём нет
логики, только объявления доменных типов, чтобы сигнатуры читались как
утверждения о протоколе, а не как безымянные числа. Доменные величины сделаны
**псевдонимами** (`type X = ...`) базовых типов: они полностью прозрачны для
сериализатора, поэтому переименование поля не меняет ни один байт на проводе.

```go
// internal/proto/types.go
type SessionID       = uint64             // номер сессии
type TransferID      = uint32             // номер одной передачи
type ByteOffset      = uint64             // смещение для докачки
type BytesPerSecond  = uint64             // скорость и лимиты
type SubscriptionMask = uint32            // маска подписки на события
type Challenge       = [ChallengeLen]byte // вызов challenge–response
```

Каждый `types.go` в шапке кратко объясняет ключевую идею своего пакета —
например, три формы пути в `vfs`, цепочку ключей SCRAM в `auth`, снапшоты
горячего конфига в `config`, token bucket в `ratelimit`, модель «горутина на
соединение» в `server`, архитектуру Model–Update–View в `tui`.

## Build

```bash
go build ./...                                   # everything
go build -o bin/ ./cmd/fshare-daemon ./cmd/fshare-commander
go test -race ./...                              # tests (race detector)
```

Requires Go 1.25+ (uses `os.Root` for path confinement).

## License

MIT — see [LICENSE](LICENSE).
