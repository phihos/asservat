package agent

import (
	"net"
	"testing"
	"time"
)

// The agent reaches the hub from its own source ports, also with several
// connections at once, and captures leave those ports out.
func TestHubConnectionsLeaveFromTheAgentsPorts(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		for {
			c, err := listener.Accept()
			if err != nil {
				return
			}
			defer c.Close()
		}
	}()
	used := map[int]bool{}
	for range 3 {
		conn, err := DialHub(t.Context(), "tcp", listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		port := conn.LocalAddr().(*net.TCPAddr).Port
		if port < hubPortFirst || port > hubPortLast || used[port] {
			t.Fatal("source port", port, used)
		}
		used[port] = true
	}
	for filter, want := range map[string]string{
		"":                     "not (tcp portrange 61000-61063)",
		"tcp port 8080 or udp": "(tcp port 8080 or udp) and not (tcp portrange 61000-61063)",
	} {
		if got := withoutOwnTraffic(filter); got != want {
			t.Errorf("withoutOwnTraffic(%q) = %q, want %q", filter, got, want)
		}
	}
}

// An address that does not answer is given up after the wait, not after
// the two minutes the kernel tries for: the agent tries anew by itself.
func TestHubThatDoesNotAnswerIsGivenUp(t *testing.T) {
	began := time.Now()
	// An address for documentation (RFC 5737): nothing answers there.
	conn, err := dialHub(t.Context(), "tcp", "192.0.2.1:80", 300*time.Millisecond)
	if err == nil {
		conn.Close()
		t.Fatal("connected to an address where nothing is")
	}
	if took := time.Since(began); took > 5*time.Second {
		t.Fatal("given up only after", took)
	}
}
