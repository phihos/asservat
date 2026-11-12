package kubernetes

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
)

func seaweedReadyFixture(t *testing.T) (*SmallSeaweedBinding, *seaweedBindingFixture, contracts.SmallSeaweedBindingRequest, contracts.SmallSeaweedBindingReceipt) {
	t.Helper()
	s, f, r := newSeaweedBindingFixture(t)
	pending, p, err := s.Begin(t.Context(), r)
	clear(p.RootsPEM)
	if err != nil {
		t.Fatal(err)
	}
	ready, err := s.MarkReady(t.Context(), pending)
	if err != nil {
		t.Fatal(err)
	}
	return s, f, r, ready
}

// Buffer each synthetic HTTP response so the hook deterministically runs before
// the client finishes that read. No sleep or wall-clock race creates expiry.
func seaweedBindingReadHook(t *testing.T, s *SmallSeaweedBinding, f *seaweedBindingFixture, hook func(*http.Request)) {
	t.Helper()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		response := httptest.NewRecorder()
		f.serve(response, r)
		if hook != nil {
			hook(r)
		}
		for name, values := range response.Header() {
			for _, value := range values {
				w.Header().Add(name, value)
			}
		}
		w.WriteHeader(response.Code)
		_, _ = w.Write(response.Body.Bytes())
	}))
	t.Cleanup(server.Close)
	api, err := newBoundedAPI(&rest.Config{Host: server.URL, TLSClientConfig: rest.TLSClientConfig{CAData: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})}})
	if err != nil {
		t.Fatal(err)
	}
	s.api = api
}

func seaweedBindingCounts(f *seaweedBindingFixture) (int, int, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.gets, f.creates, f.updates
}

func TestSmallSeaweedBindingStopsReadsAtOriginalDeadline(t *testing.T) {
	for _, operation := range []string{"begin-ready", "mark-ready"} {
		for _, at := range []string{"binding", "state", "iam", "pvc"} {
			t.Run(operation+"/"+at, func(t *testing.T) {
				s, f, r, ready := seaweedReadyFixture(t)
				before, creates, updates := seaweedBindingCounts(f)
				var late atomic.Bool
				original := time.Now()
				s.now = func() time.Time {
					if late.Load() {
						return r.StorageUseUntil.Add(time.Second)
					}
					return original
				}
				path := map[string]string{"binding": "/configmaps/" + s.name(), "state": "/secrets/" + f.state.Name, "iam": "/secrets/" + f.iam.Name, "pvc": "/persistentvolumeclaims/" + f.pvc.Name}[at]
				seaweedBindingReadHook(t, s, f, func(request *http.Request) {
					if request.Method == http.MethodGet && strings.HasSuffix(request.URL.Path, path) {
						late.Store(true)
					}
				})
				if operation == "begin-ready" {
					_, p, err := s.Begin(t.Context(), r)
					clear(p.RootsPEM)
					if err == nil {
						t.Fatal("expired initial operation succeeded")
					}
				} else {
					if _, err := s.MarkReady(t.Context(), ready); err == nil {
						t.Fatal("expired ready replay succeeded")
					}
				}
				after, c, u := seaweedBindingCounts(f)
				wanted := map[string]int{"binding": 1, "state": 2, "iam": 3, "pvc": 4}[at]
				if after-before != wanted {
					t.Fatalf("read after original expiry: got %d GETs, want %d", after-before, wanted)
				}
				if c != creates || u != updates {
					t.Fatal("late source read caused a write")
				}
			})
		}
	}
}

func TestSmallSeaweedReadReadyAllowsHistoricalExpiryWithoutRenewal(t *testing.T) {
	s, f, r, ready := seaweedReadyFixture(t)
	expandSeaweedBindingIAM(t, f)
	original := f.binding.Data[contracts.SmallSeaweedBindingFile]
	s.now = func() time.Time { return r.StorageUseUntil.Add(time.Second) }
	ctx, end := context.WithDeadline(t.Context(), r.StorageUseUntil.Add(time.Minute))
	defer end()
	before, c, u := seaweedBindingCounts(f)
	got, p, err := s.ReadReady(ctx, r.InstallationID, r.RequestID, r.Bucket)
	defer clear(p.RootsPEM)
	if err != nil {
		t.Fatal("historical ready/source observation failed", err)
	}
	if got != ready || !got.Binding.StorageUseUntil.Equal(r.StorageUseUntil) || got.Binding.Initialization.Pending || p.State.UID != ready.Binding.Initialization.StateSecretUID || p.IAM.UID != ready.Binding.IAMSecretUID {
		t.Fatal("ready read changed original receipt or source pins")
	}
	after, c2, u2 := seaweedBindingCounts(f)
	if after-before != 4 || c2 != c || u2 != u || original != f.binding.Data[contracts.SmallSeaweedBindingFile] {
		t.Fatal("read-only observation mutated or renewed original state")
	}
	if _, p, err = s.Begin(ctx, r); err == nil {
		clear(p.RootsPEM)
		t.Fatal("ReadReady revived expired Begin")
	}
	clear(p.RootsPEM)
	if _, err = s.MarkReady(ctx, ready); err == nil {
		t.Fatal("ReadReady revived expired MarkReady")
	}
	final, _, _ := seaweedBindingCounts(f)
	if final != after {
		t.Fatal("expired initial methods performed another read")
	}
}

func TestSmallSeaweedReadReadyRefusesPendingAndSubstitutions(t *testing.T) {
	for _, mode := range []string{"pending", "installation", "request", "bucket", "state-uid", "iam-uid", "pvc-uid", "backend-id", "initialization-id", "endpoint", "image", "invalid-record-uid"} {
		t.Run(mode, func(t *testing.T) {
			s, f, r, _ := seaweedReadyFixture(t)
			var binding contracts.SmallSeaweedBinding
			if json.Unmarshal([]byte(f.binding.Data[contracts.SmallSeaweedBindingFile]), &binding) != nil {
				t.Fatal("fixture binding")
			}
			switch mode {
			case "pending":
				binding.Initialization.Pending = true
			case "installation":
				r.InstallationID = swID("9")
			case "request":
				r.RequestID = swID("9")
			case "bucket":
				r.Bucket = "another-audit"
			case "state-uid":
				f.state.UID = types.UID(swID("9"))
			case "iam-uid":
				f.iam.UID = types.UID(swID("9"))
			case "pvc-uid":
				f.pvc.UID = types.UID(swID("9"))
			case "backend-id":
				f.state.Data[contracts.SmallSeaweedBackendKey] = []byte(swID("9"))
			case "initialization-id":
				f.state.Data[contracts.SmallSeaweedInitializationKey] = []byte(swID("9"))
			case "endpoint":
				binding.Initialization.Endpoint = "https://replacement.invalid"
			case "image":
				binding.Initialization.Image = "registry.invalid/replacement@sha256:" + strings.Repeat("f", 64)
			case "invalid-record-uid":
				f.binding.UID = "invalid"
			}
			raw, _ := json.Marshal(binding)
			f.binding.Data[contracts.SmallSeaweedBindingFile] = string(raw)
			before := []byte(f.binding.Data[contracts.SmallSeaweedBindingFile])
			_, c, u := seaweedBindingCounts(f)
			ctx, end := context.WithTimeout(t.Context(), time.Minute)
			defer end()
			_, p, err := s.ReadReady(ctx, r.InstallationID, r.RequestID, r.Bucket)
			clear(p.RootsPEM)
			if err == nil {
				t.Fatal("pending or substituted original accepted")
			}
			_, c2, u2 := seaweedBindingCounts(f)
			if c2 != c || u2 != u || !bytes.Equal(before, []byte(f.binding.Data[contracts.SmallSeaweedBindingFile])) {
				t.Fatal("refusal changed original binding")
			}
		})
	}
}

func TestSmallSeaweedReadReadyKeepsCallerBoundAfterEachRead(t *testing.T) {
	for _, mode := range []string{"unbounded", "canceled", "binding", "state", "iam", "pvc", "cancel-during-state"} {
		t.Run(mode, func(t *testing.T) {
			s, f, r, _ := seaweedReadyFixture(t)
			before, c, u := seaweedBindingCounts(f)
			if mode == "unbounded" {
				_, p, err := s.ReadReady(t.Context(), r.InstallationID, r.RequestID, r.Bucket)
				clear(p.RootsPEM)
				if err == nil {
					t.Fatal("unbounded ready reader accepted")
				}
				after, _, _ := seaweedBindingCounts(f)
				if after != before {
					t.Fatal("unbounded reader reached API")
				}
				return
			}
			original := time.Now()
			deadline := original.Add(20 * time.Second)
			var late atomic.Bool
			s.now = func() time.Time {
				if late.Load() {
					return deadline.Add(time.Second)
				}
				return original
			}
			ctx, end := context.WithDeadline(t.Context(), deadline)
			defer end()
			if mode == "canceled" {
				end()
			}
			target := mode
			if mode == "cancel-during-state" {
				target = "state"
			}
			path := map[string]string{"binding": "/configmaps/" + s.name(), "state": "/secrets/" + f.state.Name, "iam": "/secrets/" + f.iam.Name, "pvc": "/persistentvolumeclaims/" + f.pvc.Name}[target]
			seaweedBindingReadHook(t, s, f, func(request *http.Request) {
				if request.Method == http.MethodGet && strings.HasSuffix(request.URL.Path, path) {
					if mode == "cancel-during-state" {
						end()
					} else {
						late.Store(true)
					}
				}
			})
			_, p, err := s.ReadReady(ctx, r.InstallationID, r.RequestID, r.Bucket)
			clear(p.RootsPEM)
			if err == nil {
				t.Fatal("late/canceled read supplied a result")
			}
			after, c2, u2 := seaweedBindingCounts(f)
			wanted := map[string]int{"canceled": 0, "binding": 1, "state": 2, "iam": 3, "pvc": 4, "cancel-during-state": 2}[mode]
			if after-before != wanted || c2 != c || u2 != u {
				t.Fatalf("late read changed request/effect count GET=%d want=%d", after-before, wanted)
			}
		})
	}
}

func TestSmallSeaweedBindingUnknownReplyAtDeadlineDoesNotReadAgain(t *testing.T) {
	for _, operation := range []string{"create", "ready-update"} {
		t.Run(operation, func(t *testing.T) {
			s, f, r := newSeaweedBindingFixture(t)
			var late atomic.Bool
			original := time.Now()
			s.now = func() time.Time {
				if late.Load() {
					return r.StorageUseUntil.Add(time.Second)
				}
				return original
			}
			f.afterUnknown = func() { late.Store(true) }
			if operation == "create" {
				f.createUnknown = true
				_, p, err := s.Begin(t.Context(), r)
				clear(p.RootsPEM)
				if err == nil {
					t.Fatal("late unknown CREATE acknowledged")
				}
				gets, c, u := seaweedBindingCounts(f)
				if gets != 4 || c != 1 || u != 0 {
					t.Fatalf("late unknown CREATE issued another request: GET=%d create=%d update=%d", gets, c, u)
				}
			} else {
				pending, p, err := s.Begin(t.Context(), r)
				clear(p.RootsPEM)
				if err != nil {
					t.Fatal(err)
				}
				before, _, _ := seaweedBindingCounts(f)
				f.updateUnknown = true
				if _, err = s.MarkReady(t.Context(), pending); err == nil {
					t.Fatal("late unknown readiness UPDATE acknowledged")
				}
				after, c, u := seaweedBindingCounts(f)
				if after-before != 4 || c != 1 || u != 1 {
					t.Fatalf("late unknown UPDATE issued another request: GET=%d create=%d update=%d", after-before, c, u)
				}
			}
		})
	}
}
