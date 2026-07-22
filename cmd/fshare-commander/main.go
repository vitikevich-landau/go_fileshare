// Команда fshare-commander — клиент fileshare v2. По умолчанию запускает
// полноэкранный TUI в стиле Midnight Commander (Bubble Tea). Флаг --batch даёт
// скриптовый режим: перечислить каталог, узнать метаданные/сумму пути или
// скачать файл — и выйти (docs/tz/09-go-port.md §5.11).
//
// Один бинарь и для пользователя, и для админа: админ-функции открываются по
// роли, полученной при входе.
package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"golang.org/x/term"

	"github.com/vitikevich-landau/go_fileshare/internal/client"
	"github.com/vitikevich-landau/go_fileshare/internal/proto"
	"github.com/vitikevich-landau/go_fileshare/internal/tui"
)

func main() {
	var (
		host     = flag.String("host", "127.0.0.1", "server host")
		port     = flag.Int("port", 5555, "server port")
		login    = flag.String("login", "", "login")
		password = flag.String("password", "", "password (else $FILESHARE_PASSWORD, else prompt)")
		batch    = flag.Bool("batch", false, "run a single scripted action and exit")
		list     = flag.String("list", "", "list a remote directory")
		stat     = flag.String("stat", "", "stat a remote path")
		checksum = flag.String("checksum", "", "checksum a remote file")
		get      = flag.String("get", "", "download a remote file")
		out      = flag.String("out", "", "local output path for --get (default: basename in cwd)")
		profile  = flag.String("profile", "", "saved profile name to preload in the TUI")
	)
	flag.Parse()

	// Без --batch запускаем интерактивный TUI, предзаполнив форму подключения.
	if !*batch {
		pre := tui.Profile{}
		if *profile != "" {
			pre.Name = *profile // грузим сохранённый профиль; host/port по умолчанию игнорируем
		} else {
			pre.Host, pre.Port, pre.Login = *host, *port, *login
		}
		runTUI(pre)
		return
	}

	// Режим --batch: одно скриптовое действие и выход.
	pw := resolvePassword(*password, *login)
	addr := fmt.Sprintf("%s:%d", *host, *port)
	c, err := client.Dial(addr, client.Options{Login: *login, Password: pw, ClientName: "fshare-commander/batch"})
	if err != nil {
		fatalf("connect: %v", err)
	}
	defer c.Close()

	switch {
	case *list != "":
		doList(c, *list)
	case *stat != "":
		doStat(c, *stat)
	case *checksum != "":
		doChecksum(c, *checksum)
	case *get != "":
		doGet(c, *get, *out)
	default:
		fatalf("no action given (use --list/--stat/--checksum/--get)")
	}
}

func runTUI(pre tui.Profile) {
	p := tea.NewProgram(tui.New(pre), tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		fatalf("tui: %v", err)
	}
}

func doList(c *client.Client, path string) {
	clean, entries, err := c.ListDir(path)
	if err != nil {
		fatalf("list %s: %v", path, err)
	}
	sort.SliceStable(entries, func(i, j int) bool {
		di, dj := entries[i].Kind == proto.KindDir, entries[j].Kind == proto.KindDir
		if di != dj {
			return di
		}
		return entries[i].Name < entries[j].Name
	})
	fmt.Printf("%s (%d entries)\n", clean, len(entries))
	for _, e := range entries {
		marker := " "
		if e.Kind == proto.KindDir {
			marker = "/"
		}
		fmt.Printf("  %s%-40s %12d  %s\n", marker, e.Name, e.Size, time.Unix(int64(e.Mtime), 0).Format("2006-01-02 15:04"))
	}
}

func doStat(c *client.Client, path string) {
	clean, e, err := c.Stat(path)
	if err != nil {
		fatalf("stat %s: %v", path, err)
	}
	kind := "file"
	if e.Kind == proto.KindDir {
		kind = "dir"
	}
	fmt.Printf("%s  %s  size=%d  mtime=%s\n", clean, kind, e.Size, time.Unix(int64(e.Mtime), 0).Format(time.RFC3339))
}

func doChecksum(c *client.Client, path string) {
	algo, sum, err := c.Checksum(path)
	if err != nil {
		fatalf("checksum %s: %v", path, err)
	}
	name := map[proto.Algo]string{proto.AlgoPending: "pending", proto.AlgoCRC32: "crc32", proto.AlgoSHA256: "sha256"}[algo]
	fmt.Printf("%s  %s:%x\n", path, name, sum)
}

func doGet(c *client.Client, remote, out string) {
	if out == "" {
		out = filepath.Base(remote)
	}
	start := time.Now()
	err := c.Download(remote, out, func(p client.Progress) {
		if p.Total > 0 {
			fmt.Fprintf(os.Stderr, "\r%s: %d/%d bytes (%.0f%%)", remote, p.Received, p.Total, 100*float64(p.Received)/float64(p.Total))
		}
	})
	fmt.Fprintln(os.Stderr)
	if err != nil {
		fatalf("get %s: %v", remote, err)
	}
	fmt.Printf("downloaded %s -> %s in %s\n", remote, out, time.Since(start).Round(time.Millisecond))
}

// resolvePassword достаёт пароль по приоритету: флаг → переменная окружения
// FILESHARE_PASSWORD → запрос в терминале. Пустой логин = сервер без входа,
// пароль не нужен.
func resolvePassword(flagPw, login string) string {
	if flagPw != "" {
		return flagPw
	}
	if env := os.Getenv("FILESHARE_PASSWORD"); env != "" {
		return env
	}
	if login == "" {
		return "" // серверу без аутентификации пароль не нужен
	}
	fmt.Fprint(os.Stderr, "Password: ")
	fd := int(os.Stdin.Fd())
	if term.IsTerminal(fd) {
		b, _ := term.ReadPassword(fd)
		fmt.Fprintln(os.Stderr)
		return string(b)
	}
	line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	return strings.TrimRight(line, "\r\n")
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "fshare-commander: "+format+"\n", args...)
	os.Exit(1)
}
