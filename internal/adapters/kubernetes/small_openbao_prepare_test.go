package kubernetes

import (
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"testing"

	"asservat.local/asservat/internal/contracts"
	core "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
)

const baoStateID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"

type smallBaoStateFixture struct {
	mu                                  sync.Mutex
	t                                   *testing.T
	plan                                contracts.SmallOpenBaoPlan
	state                               *core.Secret
	unknownCreate, malformedCreate      bool
	gets, creates, patches, privateGets int
	after                               func(*http.Request)
}

func (f *smallBaoStateFixture) missing(w http.ResponseWriter) {
	http.Error(w, `{"kind":"Status","apiVersion":"v1","reason":"NotFound","code":404}`, 404)
}
func (f *smallBaoStateFixture) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	defer func() {
		if f.after != nil {
			f.after(r)
		}
	}()
	if r.Method == http.MethodGet {
		f.gets++
		if !strings.Contains(r.URL.Path, "/secrets/") {
			f.t.Errorf("unexpected read %s", r.URL.Path)
		}
		if f.state == nil {
			f.missing(w)
			return
		}
		f.privateGets++
		_ = json.NewEncoder(w).Encode(f.state)
		return
	}
	if r.Method == http.MethodPost {
		f.creates++
		if f.state != nil {
			f.t.Error("repeated create")
			w.WriteHeader(409)
			return
		}
		var v core.Secret
		if json.NewDecoder(r.Body).Decode(&v) != nil {
			f.t.Error("invalid secret create")
			w.WriteHeader(400)
			return
		}
		v.UID = types.UID(baoStateID)
		v.ResourceVersion = "1"
		f.state = v.DeepCopy()
		if f.unknownCreate {
			http.Error(w, `{"kind":"Status","apiVersion":"v1","reason":"InternalError","code":500}`, 500)
			return
		}
		w.WriteHeader(201)
		if f.malformedCreate {
			_, _ = w.Write([]byte(`{"kind":`))
			return
		}
		_ = json.NewEncoder(w).Encode(v)
		return
	}
	f.t.Errorf("unexpected method %s", r.Method)
	w.WriteHeader(500)
}
func (f *smallBaoStateFixture) counts() (int, int, int, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.gets, f.creates, f.patches, f.privateGets
}
func prepareSmallBao(t *testing.T, s *SmallOpenBaoPreparation) contracts.SmallOpenBaoPrepared {
	t.Helper()
	p, err := s.Prepare(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { clear(p.RootsPEM) })
	return p
}
