// Command fshare-daemon is the non-interactive fileshare v2 server: it serves a
// directory tree over the v2 protocol, applies config changes live, and shuts
// down gracefully (docs/tz/09-go-port.md §5.10, docs/tz/03-server-daemon.md).
package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"golang.org/x/term"

	"github.com/vitikevich-landau/go_fileshare/internal/auth"
	"github.com/vitikevich-landau/go_fileshare/internal/config"
	"github.com/vitikevich-landau/go_fileshare/internal/server"
	"github.com/vitikevich-landau/go_fileshare/internal/vfs"
)

const (
	version     = "go-fileshare/0.1"
	gracePeriod = 30 * time.Second
)

func main() {
	var (
		configPath  = flag.String("config", "", "path to config.json (defaults are used if empty/missing)")
		port        = flag.Int("port", 0, "override server.port")
		shareRoot   = flag.String("share-root", "", "override server.share_root")
		logLevel    = flag.String("log-level", "", "override log.level (debug|info|warn|error)")
		checkConfig = flag.Bool("check-config", false, "validate the config and exit")
		addUser     = flag.String("add-user", "", "add/update a user with this login (prompts for password), then exit")
		roleFlag    = flag.String("role", "user", "role for --add-user (user|admin)")
		resetPw     = flag.String("reset-password", "", "reset this user's password (prompts), then exit")
	)
	flag.Parse()

	cfg := config.Default()
	if *configPath != "" {
		loaded, err := config.Load(*configPath)
		if err != nil {
			fatalf("config: %v", err)
		}
		cfg = loaded
	}
	if *port != 0 {
		cfg.Server.Port = *port
	}
	if *shareRoot != "" {
		cfg.Server.ShareRoot = *shareRoot
	}
	if *logLevel != "" {
		cfg.Log.Level = *logLevel
	}
	if msg := cfg.Validate(); msg != "" {
		fatalf("config invalid: %s", msg)
	}

	if *checkConfig {
		fmt.Println("config OK")
		return
	}

	if *addUser != "" || *resetPw != "" {
		if err := runUserAdmin(cfg, *addUser, *roleFlag, *resetPw); err != nil {
			fatalf("%v", err)
		}
		return
	}

	if err := run(cfg, *configPath); err != nil {
		fatalf("%v", err)
	}
}

func run(cfg config.Settings, configPath string) error {
	logger, levelVar := newLogger(cfg.Log.Level)

	if cfg.Auth.PBKDF2Iters < config.MinPBKDF2Iters {
		logger.Warn("auth.pbkdf2_iters is below the recommended floor; raise it and re-create users with --reset-password",
			"pbkdf2_iters", cfg.Auth.PBKDF2Iters, "recommended", config.MinPBKDF2Iters)
	}

	v, err := vfs.New(cfg.Server.ShareRoot, cfg.Checksum.CacheFile)
	if err != nil {
		return err
	}
	defer v.Close()

	users, err := auth.Load(cfg.Auth.UsersFile)
	if err != nil {
		return err
	}
	guard := auth.NewGuard(3)
	hub := config.NewHub(cfg)

	srv := server.New(server.Options{
		Hub: hub, VFS: v, Users: users, Guard: guard,
		Logger: logger, ServerName: "fshared", Version: version,
		ConfigPath:    configPath,
		LogLevel:      levelVar,
		AuthFailDelay: time.Second,
	})
	if err := srv.Listen(fmt.Sprintf(":%d", cfg.Server.Port)); err != nil {
		return err
	}

	authMode := "challenge"
	if users.Empty() {
		authMode = "none (bootstrap: any login is admin)"
	}
	logger.Info("fshare-daemon listening",
		"addr", srv.Addr().String(),
		"share_root", cfg.Server.ShareRoot,
		"auth", authMode,
		"version", version)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// SIGHUP re-reads the config file, preserving restart-only keys.
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	go func() {
		for range hup {
			// Always hot-reload users.json (its path is independent of --config)
			// and drop sessions of any now-disabled user (§3.3).
			if dropped, err := srv.ReloadUsers(); err != nil {
				logger.Error("SIGHUP user reload failed", "err", err)
			} else {
				logger.Info("users reloaded (SIGHUP)", "dropped_sessions", dropped)
			}
			if configPath == "" {
				continue
			}
			nc, err := config.Load(configPath)
			if err != nil {
				logger.Error("SIGHUP reload failed", "err", err)
				continue
			}
			if err := applyReload(hub, levelVar, nc); err != nil {
				logger.Error("SIGHUP reload rejected", "err", err)
				continue
			}
			logger.Info("config reloaded (SIGHUP)")
		}
	}()

	if err := srv.Serve(ctx, gracePeriod); err != nil {
		return err
	}
	logger.Info("shutdown complete")
	return nil
}

func runUserAdmin(cfg config.Settings, addLogin, roleStr, resetLogin string) error {
	db, err := auth.Load(cfg.Auth.UsersFile)
	if err != nil {
		return err
	}
	switch {
	case addLogin != "":
		role, ok := auth.RoleFromString(roleStr)
		if !ok {
			return fmt.Errorf("invalid role %q (want user|admin)", roleStr)
		}
		pw, err := promptNewPassword()
		if err != nil {
			return err
		}
		db.SetUser(addLogin, role, pw, cfg.Auth.PBKDF2Iters)
		if err := db.Save(); err != nil {
			return err
		}
		fmt.Printf("user %q (%s) written to %s\n", addLogin, roleStr, cfg.Auth.UsersFile)
	case resetLogin != "":
		pw, err := promptNewPassword()
		if err != nil {
			return err
		}
		if err := db.SetPassword(resetLogin, pw, cfg.Auth.PBKDF2Iters); err != nil {
			return err
		}
		if err := db.Save(); err != nil {
			return err
		}
		fmt.Printf("password for %q reset in %s\n", resetLogin, cfg.Auth.UsersFile)
	}
	return nil
}

func promptNewPassword() (string, error) {
	pw, err := readPassword("New password: ")
	if err != nil {
		return "", err
	}
	if pw == "" {
		return "", fmt.Errorf("password must not be empty")
	}
	confirm, err := readPassword("Confirm password: ")
	if err != nil {
		return "", err
	}
	if pw != confirm {
		return "", fmt.Errorf("passwords do not match")
	}
	return pw, nil
}

func readPassword(prompt string) (string, error) {
	fmt.Fprint(os.Stderr, prompt)
	fd := int(os.Stdin.Fd())
	if term.IsTerminal(fd) {
		b, err := term.ReadPassword(fd)
		fmt.Fprintln(os.Stderr)
		return string(b), err
	}
	// Non-interactive: read a single line from stdin.
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	return strings.TrimRight(line, "\r\n"), err
}

// newLogger builds the stderr logger around a LevelVar so log.level can change
// at runtime (CR-08). The LevelVar is handed to the server, which updates it.
func newLogger(level string) (*slog.Logger, *slog.LevelVar) {
	lv := new(slog.LevelVar)
	lv.Set(levelFromString(level))
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: lv}))
	return logger, lv
}

// applyReload merges a freshly-loaded config into the running hub on SIGHUP. It
// preserves restart-only keys (port, share_root, workers, checksum, auth, and
// events — the watcher is built once) from the current snapshot, and applies the
// hot log.level to the live LevelVar (which a plain Apply does not do) — RR-4.
//
// The LevelVar update is applied through ApplyWith so it runs under the same hub
// writer lock as the snapshot swap: a concurrent ADMIN_SET log.level cannot
// interleave and leave the snapshot and the live logger diverged (R3-4).
func applyReload(hub *config.Hub, levelVar *slog.LevelVar, next config.Settings) error {
	cur := hub.Current()
	next.Server.Port = cur.Server.Port
	next.Server.ShareRoot = cur.Server.ShareRoot
	next.Server.Workers = cur.Server.Workers
	next.Checksum = cur.Checksum
	next.Auth = cur.Auth
	next.Events = cur.Events
	return hub.ApplyWith(next, func(s *config.Settings) {
		if levelVar != nil {
			levelVar.Set(levelFromString(s.Log.Level))
		}
	})
}

func levelFromString(level string) slog.Level {
	switch level {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "fshare-daemon: "+format+"\n", args...)
	os.Exit(1)
}
