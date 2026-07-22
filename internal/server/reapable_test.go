package server

import (
	"net"
	"sync"
	"testing"
	"time"
)

// TestReapableExemptsActiveWork covers R3-6 (and CR-03): the idle watchdog must
// not reap a connection that is streaming a download OR running a synchronous
// request handler, even once the idle timeout has elapsed. Once no work is in
// flight and it is still idle, it becomes reapable again.
func TestReapableExemptsActiveWork(t *testing.T) {
	var wg sync.WaitGroup
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	sess := newSession(1, c1, "203.0.113.1", &wg)
	sess.lastActivity.Store(time.Now().Add(-time.Hour).UnixNano()) // long idle
	idle := time.Second

	s := &Server{}

	if !s.reapable(sess, idle) {
		t.Fatal("an idle, inactive session should be reapable")
	}

	sess.inFlight.Store(true)
	if s.reapable(sess, idle) {
		t.Fatal("a session running a request handler must not be reaped (R3-6)")
	}
	sess.inFlight.Store(false)

	sess.downloading.Store(true)
	if s.reapable(sess, idle) {
		t.Fatal("a session streaming a download must not be reaped (CR-03)")
	}
	sess.downloading.Store(false)

	if !s.reapable(sess, idle) {
		t.Fatal("once work is done and still idle, the session is reapable again")
	}

	// A recently-active idle-exempt window is also respected.
	sess.touch()
	if s.reapable(sess, idle) {
		t.Fatal("a just-touched session is within its idle window, not reapable")
	}
}
