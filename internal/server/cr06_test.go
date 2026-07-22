package server_test

import (
	"sync"
	"sync/atomic"
	"testing"

	"github.com/vitikevich-landau/go_fileshare/internal/client"
	"github.com/vitikevich-landau/go_fileshare/internal/config"
	"github.com/vitikevich-landau/go_fileshare/internal/proto"
)

// TestConcurrentLoginsRespectSessionCap covers CR-06: with a per-user cap of 1,
// many simultaneous handshakes for the same user must admit exactly one.
func TestConcurrentLoginsRespectSessionCap(t *testing.T) {
	e := newEnv(t, func(s *config.Settings) { s.Limits.MaxSessionsPerUser = 1 })
	e.users.SetUser("vit", proto.RoleUser, "pw", testIters)

	const n = 8
	var wg sync.WaitGroup
	var ok atomic.Int32
	clients := make([]*client.Client, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			c, err := client.Dial(e.addr, client.Options{Login: "vit", Password: "pw"})
			if err == nil {
				ok.Add(1)
				clients[i] = c
			}
		}(i)
	}
	wg.Wait()
	for _, c := range clients {
		if c != nil {
			c.Close()
		}
	}

	if got := ok.Load(); got != 1 {
		t.Fatalf("expected exactly 1 successful concurrent login, got %d", got)
	}
}
