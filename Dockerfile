# Build a static daemon binary and ship it in a minimal scratch image
# (docs/tz/09-go-port.md §10).
FROM golang:1.25 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# CGO_ENABLED=0 несёт функциональную нагрузку, а не только гигиеническую: с ним
# pure-Go драйвер SQLite (ADR 0001) даёт статический бинарник, пригодный для
# FROM scratch. Убрать флаг — значит получить собирающийся бинарник, который
# потащит динамическую линковку и в scratch не запустится.
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -o /out/fshare-daemon ./cmd/fshare-daemon

FROM scratch
COPY --from=build /out/fshare-daemon /fshare-daemon
# /data holds config.json, users.json, checksums.cache, share/ (bind-mounted)
# and metadata.db with its -wal/-shm neighbours. The database must live on a
# filesystem with working fcntl locks — not on a network share.
#
# `docker run … fshare-daemon --migrate-only` applies schema migrations and
# exits without opening the listener.
WORKDIR /data
EXPOSE 5555
STOPSIGNAL SIGTERM
ENTRYPOINT ["/fshare-daemon", "--config", "config.json", "--share-root", "share", "--port", "5555"]
