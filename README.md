# go_fileshare — FShare Commander (Go)

A from-scratch Go rewrite of the **fileshare v2** system ("FShare Commander"): a
directory-tree file server with a custom binary protocol and a full-screen
Midnight-Commander-style TUI client.

This port follows the self-sufficient specification in
[`docs/tz/09-go-port.md`](docs/tz/09-go-port.md). The wire protocol is
reproduced **byte-for-byte**, so a Go server can serve the original C++ client
and vice-versa.

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
```

## Build

```bash
go build ./...                                   # everything
go build -o bin/ ./cmd/fshare-daemon ./cmd/fshare-commander
go test -race ./...                              # tests (race detector)
```

Requires Go 1.25+ (uses `os.Root` for path confinement).

## License

MIT — see [LICENSE](LICENSE).
