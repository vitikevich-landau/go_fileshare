package server_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vitikevich-landau/go_fileshare/internal/auth"
	"github.com/vitikevich-landau/go_fileshare/internal/client"
	"github.com/vitikevich-landau/go_fileshare/internal/config"
	"github.com/vitikevich-landau/go_fileshare/internal/proto"
	"github.com/vitikevich-landau/go_fileshare/internal/server"
	"github.com/vitikevich-landau/go_fileshare/internal/vfs"
)

const testIters = 4096

type env struct {
	addr   string
	share  string
	hub    *config.Hub
	users  *auth.DB
	guard  *auth.Guard
	cancel context.CancelFunc
	done   chan struct{}
	logs   *syncBuffer
}

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// syncBuffer is a goroutine-safe log sink so tests can assert on audit lines
// while the server keeps writing from its connection goroutines.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

func makeFile(t *testing.T, path string, size int) []byte {
	t.Helper()
	b := make([]byte, size)
	for i := range b {
		b[i] = byte(i*31 + 7)
	}
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}
	return b
}

// newEnv builds a share tree and starts a server on an ephemeral port.
func newEnv(t *testing.T, configure func(*config.Settings)) *env {
	return newEnvWithConfig(t, "", configure)
}

// newEnvWithConfig is newEnv with a config path so ADMIN_SET changes persist.
func newEnvWithConfig(t *testing.T, configPath string, configure func(*config.Settings)) *env {
	t.Helper()
	share := t.TempDir()
	makeFile(t, filepath.Join(share, "a.txt"), 5)
	makeFile(t, filepath.Join(share, "big.bin"), 200*1024) // spans many chunks
	if err := os.Mkdir(filepath.Join(share, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	makeFile(t, filepath.Join(share, "sub", "nested.txt"), 10)

	cfg := config.Default()
	cfg.Server.ShareRoot = share
	cfg.Auth.PBKDF2Iters = testIters
	cfg.Limits.HandshakeTimeoutS = 5
	cfg.Limits.IdleTimeoutS = 30
	if configure != nil {
		configure(&cfg)
	}
	hub := config.NewHub(cfg)

	v, err := vfs.New(share, filepath.Join(t.TempDir(), "checksums.cache"))
	if err != nil {
		t.Fatal(err)
	}
	users, err := auth.Load(filepath.Join(t.TempDir(), "users.json"))
	if err != nil {
		t.Fatal(err)
	}
	guard := auth.NewGuard(3)

	logs := &syncBuffer{}
	logger := slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	srv := server.New(server.Options{
		Hub: hub, VFS: v, Users: users, Guard: guard,
		Logger: logger, ServerName: "test", AuthFailDelay: 0,
		ConfigPath: configPath,
	})
	if err := srv.Listen("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		srv.Serve(ctx, 2*time.Second)
		close(done)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
		v.Close()
	})
	return &env{addr: srv.Addr().String(), share: share, hub: hub, users: users, guard: guard, cancel: cancel, done: done, logs: logs}
}

func dialNoAuth(t *testing.T, e *env) *client.Client {
	t.Helper()
	c, err := client.Dial(e.addr, client.Options{Login: "tester"})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func TestAuthFailureIsAudited(t *testing.T) {
	e := newEnv(t, nil)
	e.users.SetUser("vit", proto.RoleUser, "correct", testIters)

	// A wrong password must be refused AND recorded (docs/tz/06-security.md §5).
	if _, err := client.Dial(e.addr, client.Options{Login: "vit", Password: "wrong"}); err == nil {
		t.Fatal("expected auth to fail with a wrong password")
	}
	logs := e.logs.String()
	if !strings.Contains(logs, "authentication failed") {
		t.Fatalf("failed authentication was not audited:\n%s", logs)
	}
	if !strings.Contains(logs, "login=vit") || !strings.Contains(logs, "reason=bad_credentials") {
		t.Fatalf("audit line missing login/reason:\n%s", logs)
	}
}

func TestNoAuthListStatChecksumDownload(t *testing.T) {
	e := newEnv(t, nil)
	c := dialNoAuth(t, e)
	if c.Role() != proto.RoleAdmin {
		t.Fatalf("no-auth role = %v, want admin", c.Role())
	}

	clean, entries, err := c.ListDir("/")
	if err != nil {
		t.Fatal(err)
	}
	if clean != "/" {
		t.Fatalf("list path = %q", clean)
	}
	names := map[string]proto.Kind{}
	for _, en := range entries {
		names[en.Name] = en.Kind
	}
	if names["sub"] != proto.KindDir || names["a.txt"] != proto.KindFile || names["big.bin"] != proto.KindFile {
		t.Fatalf("unexpected listing: %v", names)
	}

	_, entry, err := c.Stat("/a.txt")
	if err != nil {
		t.Fatal(err)
	}
	if entry.Size != 5 {
		t.Fatalf("a.txt size = %d, want 5", entry.Size)
	}

	algo, _, err := c.Checksum("/big.bin")
	if err != nil {
		t.Fatal(err)
	}
	if algo != proto.AlgoSHA256 {
		t.Fatalf("checksum algo = %v", algo)
	}

	// Download and compare bytes.
	want, _ := os.ReadFile(filepath.Join(e.share, "big.bin"))
	dst := filepath.Join(t.TempDir(), "out.bin")
	if err := c.Download("/big.bin", dst, nil); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(dst)
	if !bytes.Equal(got, want) {
		t.Fatalf("download mismatch: got %d bytes, want %d", len(got), len(want))
	}
	if _, err := os.Stat(dst + ".part"); !errors.Is(err, os.ErrNotExist) {
		t.Fatal(".part should be gone after success")
	}
}

func TestDownloadResume(t *testing.T) {
	e := newEnv(t, nil)
	c := dialNoAuth(t, e)

	want, _ := os.ReadFile(filepath.Join(e.share, "big.bin"))
	dst := filepath.Join(t.TempDir(), "out.bin")

	// Pre-seed a .part with the first 50000 bytes to force a resume.
	const seeded = 50000
	if err := os.WriteFile(dst+".part", want[:seeded], 0o644); err != nil {
		t.Fatal(err)
	}
	if err := c.Download("/big.bin", dst, nil); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(dst)
	if !bytes.Equal(got, want) {
		t.Fatalf("resumed download mismatch: got %d bytes", len(got))
	}
}

func TestResumeOffsetTooLargeRestarts(t *testing.T) {
	e := newEnv(t, nil)
	c := dialNoAuth(t, e)

	want, _ := os.ReadFile(filepath.Join(e.share, "a.txt"))
	dst := filepath.Join(t.TempDir(), "a.out")
	// A .part larger than the file => server rejects the offset; client should
	// discard it and restart from scratch (bug #6).
	if err := os.WriteFile(dst+".part", []byte("way too many bytes here"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := c.Download("/a.txt", dst, nil); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(dst)
	if !bytes.Equal(got, want) {
		t.Fatalf("restart download mismatch: got %q, want %q", got, want)
	}
}

func TestChallengeAuth(t *testing.T) {
	e := newEnv(t, nil)
	e.users.SetUser("vit", proto.RoleUser, "s3cret", testIters)
	e.users.SetUser("ghost", proto.RoleUser, "boo", testIters)
	e.users.SetEnabled("ghost", false)

	// Correct credentials.
	c, err := client.Dial(e.addr, client.Options{Login: "vit", Password: "s3cret"})
	if err != nil {
		t.Fatalf("valid login failed: %v", err)
	}
	if c.Role() != proto.RoleUser {
		t.Fatalf("role = %v, want user", c.Role())
	}
	c.Close()

	// Wrong password.
	if _, err := client.Dial(e.addr, client.Options{Login: "vit", Password: "nope"}); err == nil {
		t.Fatal("wrong password accepted")
	} else {
		var ae *client.AuthError
		if !errors.As(err, &ae) {
			t.Fatalf("wrong password: err = %v, want AuthError", err)
		}
	}

	// Disabled user.
	if _, err := client.Dial(e.addr, client.Options{Login: "ghost", Password: "boo"}); err == nil {
		t.Fatal("disabled user accepted")
	}

	// Unknown user.
	if _, err := client.Dial(e.addr, client.Options{Login: "nobody", Password: "x"}); err == nil {
		t.Fatal("unknown user accepted")
	}
}

func TestBanAfterFailures(t *testing.T) {
	e := newEnv(t, nil)
	e.users.SetUser("vit", proto.RoleUser, "s3cret", testIters)

	for i := 0; i < 3; i++ {
		if _, err := client.Dial(e.addr, client.Options{Login: "vit", Password: "wrong"}); err == nil {
			t.Fatalf("attempt %d: wrong password accepted", i)
		}
	}
	// Now even the correct password is refused because the IP is banned.
	_, err := client.Dial(e.addr, client.Options{Login: "vit", Password: "s3cret"})
	if err == nil {
		t.Fatal("correct password accepted while banned")
	}
	var ae *client.AuthError
	if !errors.As(err, &ae) || ae.Reason != proto.AuthFailBanned {
		t.Fatalf("expected AuthFailBanned, got %v", err)
	}
}

func TestTraversalBlockedOverProtocol(t *testing.T) {
	e := newEnv(t, nil)
	c := dialNoAuth(t, e)

	// "/.." cleans to root; listing must not escape.
	clean, entries, err := c.ListDir("/../..")
	if err != nil {
		t.Fatal(err)
	}
	if clean != "/" {
		t.Fatalf("escaped path cleaned to %q, want /", clean)
	}
	for _, en := range entries {
		if en.Name == filepath.Base(e.share) {
			t.Fatal("parent directory leaked into listing")
		}
	}

	// Downloading an escaping path must fail, not read outside the share.
	dst := filepath.Join(t.TempDir(), "escape.out")
	err = c.Download("/../../etc/passwd", dst, nil)
	if err == nil {
		t.Fatal("escaping download succeeded")
	}
}

func TestMaxSessionsPerUser(t *testing.T) {
	e := newEnv(t, func(s *config.Settings) { s.Limits.MaxSessionsPerUser = 1 })
	e.users.SetUser("vit", proto.RoleUser, "pw", testIters)

	c1, err := client.Dial(e.addr, client.Options{Login: "vit", Password: "pw"})
	if err != nil {
		t.Fatal(err)
	}
	defer c1.Close()

	// Second concurrent session for the same user is refused.
	if _, err := client.Dial(e.addr, client.Options{Login: "vit", Password: "pw"}); err == nil {
		t.Fatal("second session accepted despite cap of 1")
	}

	// After closing the first, a new session is allowed again.
	c1.Close()
	// Give the server a moment to unregister the closed session.
	deadline := time.Now().Add(2 * time.Second)
	for {
		c3, err := client.Dial(e.addr, client.Options{Login: "vit", Password: "pw"})
		if err == nil {
			c3.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("session slot not freed after close: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestGracefulShutdownStopsAccepting(t *testing.T) {
	e := newEnv(t, nil)
	// A working connection first.
	c := dialNoAuth(t, e)
	if _, _, err := c.ListDir("/"); err != nil {
		t.Fatal(err)
	}

	e.cancel()
	<-e.done // Serve returned

	if _, err := client.Dial(e.addr, client.Options{Login: "x"}); err == nil {
		t.Fatal("dial succeeded after shutdown")
	}
}
