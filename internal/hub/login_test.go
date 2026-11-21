package hub

import (
	"bytes"
	"testing"
	"time"
)

func TestSessionCookie(t *testing.T) {
	h := &Hub{Config: Config{MasterKey: bytes.Repeat([]byte{1}, 32)}}
	other := &Hub{Config: Config{MasterKey: bytes.Repeat([]byte{2}, 32)}}
	now := time.Now()
	value := h.session(User{Name: "alice", Groups: []string{"payments"}}, now.Add(time.Hour))
	if u, err := h.openSession(value, now); err != nil || u.Name != "alice" || len(u.Groups) != 1 || u.Groups[0] != "payments" {
		t.Fatal("session", u, err)
	}
	if _, err := h.openSession(value, now.Add(time.Hour)); err == nil {
		t.Fatal("an expired session opened")
	}
	if _, err := other.openSession(value, now); err == nil {
		t.Fatal("a session of another hub opened")
	}
	// A user cannot extend the session or change its groups.
	forged := other.session(User{Name: "alice", Groups: []string{"admins"}}, now.Add(time.Hour))
	payload, _, _ := bytes.Cut([]byte(forged), []byte("."))
	_, mac, _ := bytes.Cut([]byte(value), []byte("."))
	for _, v := range []string{string(payload) + "." + string(mac), string(payload), "", "x.y"} {
		if _, err := h.openSession(v, now); err == nil {
			t.Fatalf("forged session %q opened", v)
		}
	}
}
