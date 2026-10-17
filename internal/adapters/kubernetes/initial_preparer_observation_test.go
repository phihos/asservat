package kubernetes

import (
	"context"
	"net/http"
	"testing"
	"time"
)

func TestInitialPreparedInputReadKeepsOriginalPinsAndIndependentValues(t *testing.T) {
	f, p := finalInputFixture(t, "healthy")
	root, e := p.PrepareFinalInputs(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	before := map[string]int{}
	f.mu.Lock()
	for k, v := range f.posts {
		before[k] = v
	}
	f.mu.Unlock()
	got, e := p.ReadPreparedInputs(context.Background())
	if e != nil || got.Input.UID != root.Activation.Inputs.Creates[8].Receipt.UID || got.Configuration.Pod.UID != root.Activation.Pod.Receipt.UID || !time.Now().Before(got.ValidUntil) {
		t.Fatal("original public inputs unavailable", e)
	}
	got.Configuration.Postgres.Roots[0][0] ^= 0xff
	again, e := p.ReadPreparedInputs(context.Background())
	if e != nil {
		t.Fatal("returned value mutated retained producer settings", e)
	}
	if got.Configuration.Postgres.Roots[0][0] == again.Configuration.Postgres.Roots[0][0] {
		t.Fatal("returned provider roots alias producer")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if !equalJSON(before, f.posts) {
		t.Fatal("read issued preparation effects")
	}
}
func TestInitialPreparedInputReadRejectsReplacementAndExpiredObservation(t *testing.T) {
	for _, mode := range []string{"replacement", "late-final-read"} {
		t.Run(mode, func(t *testing.T) {
			f, p := finalInputFixture(t, "healthy")
			if _, e := p.PrepareFinalInputs(context.Background()); e != nil {
				t.Fatal(e)
			}
			path := "/api/v1/namespaces/initial-target/configmaps/inputs"
			f.mu.Lock()
			if mode == "replacement" {
				f.objects[path]["metadata"].(map[string]any)["uid"] = ownerID(999)
			} else {
				prior := f.extra
				f.extra = func(w http.ResponseWriter, r *http.Request) bool {
					if r.Method == "GET" && r.URL.Path == path {
						permissionReply(w, f.objects[path])
						f.shift = 6 * time.Second
						return true
					}
					return prior != nil && prior(w, r)
				}
			}
			f.mu.Unlock()
			got, e := p.ReadPreparedInputs(context.Background())
			if e == nil || got.Input.UID != "" {
				t.Fatal("replacement or expired read returned input authority")
			}
		})
	}
}
