package kubernetes

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/execution"
	"k8s.io/client-go/rest"
)

func startRequest(now time.Time) value.Request {
	const id = "11111111-1111-4111-8111-111111111111"
	return value.Request{Binding: value.Binding{OperationID: id, CaptureID: id, AttemptID: id, ClusterID: id, IssuerEpoch: id, PodUID: id, NodeUID: id, NodeBootID: id, CollectorEpoch: id, ActionID: "pod-status", ScopeDigest: artifact.Digest{1}, AuthorityDigest: artifact.Digest{2}, BudgetDigest: artifact.Digest{3}, AuditDigest: artifact.Digest{4}, NativeBytes: 4096, NotBefore: now, NotAfter: now.Add(time.Minute)}, ObjectUID: id, CheckedAt: now, ValidUntil: now.Add(5 * time.Second)}
}

type startFixture struct {
	j      *StartJournal
	r      value.Request
	clock  atomic.Int64
	mu     sync.Mutex
	object map[string]any
	writes int
	mode   string
}

func newStartFixture(t *testing.T, mode string) *startFixture {
	t.Helper()
	f := &startFixture{mode: mode}
	now := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	f.clock.Store(now.UnixNano())
	f.r = startRequest(now)
	spec, _ := LocalStartSpec(f.r.Binding)
	b, _ := json.Marshal(spec)
	var sm map[string]any
	_ = json.Unmarshal(b, &sm)
	f.object = map[string]any{"apiVersion": "asservat.io/v1alpha1", "kind": "CapacityReservation", "metadata": map[string]any{"name": "start-" + f.r.Binding.AttemptID, "namespace": permissionControl.Name, "uid": f.r.ObjectUID, "generation": 1, "resourceVersion": "1"}, "spec": sm, "status": map[string]any{"phase": "Ready"}}
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		if r.URL.Path == "/api/v1/namespaces/asservat-system" {
			permissionReply(w, permissionNamespace(permissionControl.Name, permissionControl.UID))
			return
		}
		if r.Method == "GET" {
			permissionReply(w, f.object)
			if mode == "expired-read" {
				f.clock.Add(int64(5 * time.Second))
			}
			return
		}
		if r.Method != "PUT" || !strings.HasSuffix(r.URL.Path, "/status") {
			t.Error("unexpected request")
			http.Error(w, "bad", 400)
			return
		}
		var update map[string]any
		if json.NewDecoder(r.Body).Decode(&update) != nil {
			t.Error("bad request")
			return
		}
		old := f.object["metadata"].(map[string]any)
		next := update["metadata"].(map[string]any)
		if next["resourceVersion"] != old["resourceVersion"] {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(409)
			_ = json.NewEncoder(w).Encode(map[string]any{"apiVersion": "v1", "kind": "Status", "status": "Failure", "reason": "Conflict", "code": 409})
			return
		}
		f.writes++
		next["resourceVersion"] = fmt.Sprint(f.writes + 1)
		f.object = update
		if mode == "lost-reply" {
			connection, _, err := w.(http.Hijacker).Hijack()
			if err == nil {
				_ = connection.Close()
			}
			return
		}
		if mode == "expired-write" {
			f.clock.Add(int64(5 * time.Second))
		}
		permissionReply(w, f.object)
	}))
	t.Cleanup(s.Close)
	config := &rest.Config{Host: s.URL, TLSClientConfig: rest.TLSClientConfig{CAData: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.Certificate().Raw})}}
	var err error
	f.j, err = NewStartJournal(config, permissionCluster, permissionControl, func() time.Time { return time.Unix(0, f.clock.Load()).UTC() })
	if err != nil {
		t.Fatal(err)
	}
	return f
}
func TestLocalStartSingleUse(t *testing.T) {
	f := newStartFixture(t, "")
	var wg sync.WaitGroup
	var starts atomic.Int64
	for range 12 {
		wg.Go(func() {
			d, err := f.j.ConsumeStart(context.Background(), f.r)
			if err != nil && !errors.Is(err, value.ErrConflict) {
				t.Error(err)
			}
			if d.MayStart {
				starts.Add(1)
			}
		})
	}
	wg.Wait()
	if starts.Load() != 1 || f.writes != 1 {
		t.Fatal("duplicate start", starts.Load(), f.writes)
	}
	d, err := f.j.LookupStart(context.Background(), f.r)
	if err != nil || d.MayStart || d.Phase != value.StartCommitted {
		t.Fatal(d, err)
	}
	// A reconstructed adapter has no in-memory deduplication history.
	restarted := *f.j
	d, err = restarted.ConsumeStart(context.Background(), f.r)
	if err != nil || d.MayStart || f.writes != 1 {
		t.Fatal(d, err)
	}
}
func TestLocalStartUncertainAndExpired(t *testing.T) {
	for _, mode := range []string{"lost-reply", "expired-read", "expired-write"} {
		t.Run(mode, func(t *testing.T) {
			f := newStartFixture(t, mode)
			d, err := f.j.ConsumeStart(context.Background(), f.r)
			if err == nil || d.MayStart {
				t.Fatal("uncertain/expired write authorized", d, err)
			}
			if mode == "expired-read" {
				if f.writes != 0 {
					t.Fatal("started after read deadline")
				}
				return
			}
			d, err = f.j.LookupStart(context.Background(), f.r)
			if err != nil || d.Phase != value.StartCommitted || d.MayStart || f.writes != 1 {
				t.Fatal("uncertain spend lost", d, err)
			}
		})
	}
}
func TestLocalStartSubstitution(t *testing.T) {
	for _, name := range []string{"uid", "namespace", "boot", "collector", "audit", "bytes", "generation", "owner", "deleting", "phase", "unknown", "case-alias"} {
		t.Run(name, func(t *testing.T) {
			f := newStartFixture(t, "")
			m := f.object["metadata"].(map[string]any)
			s := f.object["spec"].(map[string]any)
			switch name {
			case "uid":
				m["uid"] = "22222222-2222-4222-8222-222222222222"
			case "namespace":
				m["namespace"] = "other"
			case "boot":
				s["nodeBootID"] = "22222222-2222-4222-8222-222222222222"
			case "collector":
				s["collectorEpoch"] = "22222222-2222-4222-8222-222222222222"
			case "audit":
				s["auditDigest"] = strings.Repeat("2", 64)
			case "bytes":
				s["nativeBytes"] = 8192
			case "generation":
				m["generation"] = 2
			case "owner":
				m["ownerReferences"] = []any{map[string]any{"uid": "parent"}}
			case "deleting":
				m["deletionTimestamp"] = "2026-10-10T12:00:00Z"
			case "phase":
				f.object["status"] = map[string]any{"phase": "Ready", "committedAt": "2026-10-10T12:00:00Z"}
			case "unknown":
				s["command"] = "other"
			case "case-alias":
				s["PROFILE"] = s["profile"]
				delete(s, "profile")
			}
			d, err := f.j.ConsumeStart(context.Background(), f.r)
			if err == nil || d.MayStart || f.writes != 0 {
				t.Fatal("substitution accepted", d, err)
			}
		})
	}
}
