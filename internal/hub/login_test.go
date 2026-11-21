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

// Clusters come from the configuration: each needs a usable name and a join
// token that is long enough and its own.
func TestClusterConfiguration(t *testing.T) {
	token := func(c byte) string { return string(bytes.Repeat([]byte{c}, 32)) }
	config := func(clusters ...Cluster) error {
		_, err := New(Config{MasterKey: bytes.Repeat([]byte{1}, 32), Retention: time.Hour, Clusters: clusters})
		return err
	}
	if err := config(Cluster{"local", token('a')}, Cluster{"prod-eu", token('b')}); err != nil {
		t.Fatal(err)
	}
	for name, clusters := range map[string][]Cluster{
		"a short token":        {{"edge", "short"}},
		"a name with capitals": {{"Edge", token('a')}},
		"a name twice":         {{"edge", token('a')}, {"edge", token('b')}},
		"a token twice":        {{"edge", token('a')}, {"other", token('a')}},
	} {
		if config(clusters...) == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	h, _ := New(Config{MasterKey: bytes.Repeat([]byte{1}, 32), Retention: time.Hour, Clusters: []Cluster{{"local", token('a')}, {"edge", token('b')}}})
	if name, ok := h.clusterOf(token('b')); !ok || name != "edge" {
		t.Fatal("cluster of a token", name, ok)
	}
	if _, ok := h.clusterOf(token('c')); ok {
		t.Fatal("an unknown token joined")
	}
	if _, ok := h.clusterOf(""); ok {
		t.Fatal("an empty token joined")
	}
}
