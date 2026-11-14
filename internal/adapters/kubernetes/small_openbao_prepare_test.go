package kubernetes

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
	core "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
)

const baoStateID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
const baoPVCID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
const baoOtherID = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"

type smallBaoStateFixture struct {
	mu                                  sync.Mutex
	t                                   *testing.T
	plan                                contracts.SmallOpenBaoPlan
	state                               *core.Secret
	unknownCreate, malformedCreate      bool
	gets, creates, patches, privateGets int
	after                               func(*http.Request)
}

func newSmallBaoStateFixture(t *testing.T) (*SmallOpenBaoPreparation, *smallBaoStateFixture) {
	t.Helper()
	f := &smallBaoStateFixture{t: t, plan: smallOpenBaoFixturePlan(t, time.Now())}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Finish fixture hooks before releasing the response to the client.
		response := httptest.NewRecorder()
		f.serve(response, r)
		for name, values := range response.Header() {
			for _, value := range values {
				w.Header().Add(name, value)
			}
		}
		w.WriteHeader(response.Code)
		_, _ = w.Write(response.Body.Bytes())
	}))
	t.Cleanup(server.Close)
	s, err := NewSmallOpenBaoPreparation(&rest.Config{Host: server.URL, TLSClientConfig: rest.TLSClientConfig{CAData: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})}}, f.plan)
	if err != nil {
		t.Fatal(err)
	}
	return s, f
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

func TestSmallOpenBaoPrepareCreateReplayAndLostReplies(t *testing.T) {
	for _, unknown := range []bool{false, true} {
		t.Run(map[bool]string{false: "acknowledged", true: "unknown"}[unknown], func(t *testing.T) {
			s, f := newSmallBaoStateFixture(t)
			f.unknownCreate = unknown
			first := prepareSmallBao(t, s)
			second := prepareSmallBao(t, s)
			if first.State != second.State || first.BackendID != second.BackendID || !bytes.Equal(first.RootsPEM, second.RootsPEM) {
				t.Fatal("replay changed original state")
			}
			gets, creates, patches, _ := f.counts()
			// Only the named state Secret is read: no PVC, StatefulSet or Pod.
			if creates != 1 || patches != 0 || gets != 2+map[bool]int{false: 0, true: 1}[unknown] {
				t.Fatalf("unexpected API counts: %d %d %d", gets, creates, patches)
			}
		})
	}
}

func TestSmallOpenBaoPrepareRefusesSubstitutedRetainedState(t *testing.T) {
	for _, mode := range []string{"foreign-state", "unknown-annotation", "unknown-material", "ready-marker", "backend-annotation"} {
		t.Run(mode, func(t *testing.T) {
			s, f := newSmallBaoStateFixture(t)
			prepareSmallBao(t, s)
			f.mu.Lock()
			switch mode {
			case "foreign-state":
				f.state.Labels["asservat.io/private-role"] = "foreign"
			case "unknown-annotation":
				f.state.Annotations["foreign"] = "value"
			case "unknown-material":
				f.state.Data["unexpected"] = []byte("no")
			case "ready-marker":
				f.state.Annotations[contracts.SmallOpenBaoReadyAnnotation] = baoOtherID + "/" + baoPVCID
			case "backend-annotation":
				f.state.Annotations[contracts.SmallOpenBaoBackendAnnotation] = baoOtherID
			}
			f.mu.Unlock()
			_, c, pn, _ := f.counts()
			got, err := s.Prepare(t.Context())
			clear(got.RootsPEM)
			if err == nil {
				t.Fatal("substituted state accepted")
			}
			if _, c2, p2, _ := f.counts(); c != c2 || pn != p2 {
				t.Fatal("refusal recreated/mutated state")
			}
		})
	}
}

func TestSmallOpenBaoPreparationPreservesCancellationAndOriginalDeadline(t *testing.T) {
	for _, mode := range []string{"canceled", "late-state", "late-create"} {
		t.Run(mode, func(t *testing.T) {
			s, f := newSmallBaoStateFixture(t)
			original := time.Now()
			var late atomic.Bool
			s.now = func() time.Time {
				if late.Load() {
					return original.Add(time.Minute)
				}
				return original
			}
			ctx, end := context.WithDeadline(t.Context(), original.Add(20*time.Second))
			defer end()
			if mode == "canceled" {
				end()
			}
			f.after = func(r *http.Request) {
				if mode == "late-state" && r.Method == http.MethodGet || mode == "late-create" && r.Method == http.MethodPost {
					late.Store(true)
				}
			}
			f.unknownCreate = mode == "late-create"
			got, err := s.Prepare(ctx)
			clear(got.RootsPEM)
			if err == nil {
				t.Fatal("expired/canceled preparation acknowledged")
			}
			gets, creates, _, _ := f.counts()
			if gets != map[string]int{"canceled": 0, "late-state": 1, "late-create": 1}[mode] || mode != "late-create" && creates != 0 {
				t.Fatalf("performed work after original bound: gets=%d creates=%d", gets, creates)
			}
		})
	}
}

// A successful HTTP status does not acknowledge an undecodable write result.
// One exact readback may recover only the original effect, never create again.
func TestSmallOpenBaoPrepareRecoversMalformedSuccessfulWriteOnce(t *testing.T) {
	for _, changed := range []bool{false, true} {
		t.Run(map[bool]string{false: "original", true: "changed-readback"}[changed], func(t *testing.T) {
			s, f := newSmallBaoStateFixture(t)
			f.malformedCreate = true
			if changed {
				f.after = func(r *http.Request) {
					if r.Method == http.MethodPost {
						f.state.Data[contracts.SmallOpenBaoSealKey][0] ^= 1
					}
				}
			}
			result, err := s.Prepare(t.Context())
			defer clear(result.RootsPEM)
			if (err != nil) != changed || !changed && (result.State.UID != baoStateID || result.BackendID == "" || len(result.RootsPEM) == 0) {
				t.Fatalf("malformed reply original recovery=%t, changed=%t", err == nil, changed)
			}
			if gets, creates, _, _ := f.counts(); creates != 1 || gets != 2 {
				t.Fatalf("readback was not exactly once: gets=%d creates=%d", gets, creates)
			}
		})
	}
}
