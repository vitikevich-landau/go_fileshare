# Build a static daemon binary and ship it in a minimal scratch image
# (docs/tz/09-go-port.md §10).
FROM golang:1.25 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -o /out/fshare-daemon ./cmd/fshare-daemon

FROM scratch
COPY --from=build /out/fshare-daemon /fshare-daemon
# /data holds config.json, users.json, checksums.cache and share/ (bind-mounted).
WORKDIR /data
EXPOSE 5555
STOPSIGNAL SIGTERM
ENTRYPOINT ["/fshare-daemon", "--config", "config.json", "--share-root", "share", "--port", "5555"]
