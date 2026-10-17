package kubernetes

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	core "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
)

func TestProviderOwnerOperationUnknownRootCreatePinsExactAttemptAcrossCalls(t *testing.T) {
	for _, lost := range []bool{true, false} {
		name := "positive-create-final-denied"
		if lost {
			name = "lost-create-final-denied"
		}
		t.Run(name, func(t *testing.T) {
			f := newOwnerIdentityOperationFixture(t)
			startOwnerIdentityOperationAcceptedObserver(t, f)
			f.api.mu.Lock()
			previous := f.api.extra
			f.api.extra = func(w http.ResponseWriter, r *http.Request) bool {
				if r.Method == http.MethodPost && r.URL.Path == f.root.path() {
					recorder := httptest.NewRecorder()
					if !previous(recorder, r) {
						t.Error("private CREATE escaped fixture")
						return true
					}
					f.fault.Store(1) // deny the real final bracket after the request was stored
					if lost {
						w.WriteHeader(http.StatusServiceUnavailable)
						return true
					}
					for key, values := range recorder.Header() {
						for _, value := range values {
							w.Header().Add(key, value)
						}
					}
					w.WriteHeader(recorder.Code)
					_, _ = w.Write(recorder.Body.Bytes())
					return true
				}
				return previous(w, r)
			}
			f.api.mu.Unlock()
			if _, err := f.root.OpenProviderOwnerIdentityRoles(context.Background()); err == nil {
				t.Fatal("failed final native bracket reported completed root")
			}
			if f.root.pendingOperationRoot == nil {
				t.Fatal("uncertain root forgot its exact private attempt")
			}
			f.api.mu.Lock()
			f.api.extra = previous
			f.fault.Store(0)
			path := f.root.path() + "/" + f.root.name()
			raw, err := json.Marshal(f.api.objects[path])
			if err != nil {
				f.api.mu.Unlock()
				t.Fatal(err)
			}
			var original core.Secret
			if json.Unmarshal(raw, &original) != nil {
				f.api.mu.Unlock()
				t.Fatal("fixture Secret")
			}
			replacement := original.DeepCopy()
			if lost {
				state := *f.root.pendingOperationRoot
				state.OperationID = ownerID(4991)
				replacement.Data["state.json"], err = json.Marshal(state)
				if err != nil {
					f.api.mu.Unlock()
					t.Fatal(err)
				}
			} else {
				replacement.UID = types.UID(ownerID(4992))
			}
			changed, _ := json.Marshal(replacement)
			var object map[string]any
			_ = json.Unmarshal(changed, &object)
			f.api.objects[path] = object
			f.api.mu.Unlock()
			if _, err := f.root.InspectProviderOwnerIdentityRoles(context.Background()); err == nil {
				t.Fatal("later call adopted a replacement for original uncertain CREATE")
			}
			f.api.mu.Lock()
			_ = json.Unmarshal(raw, &object)
			f.api.objects[path] = object
			creates := f.api.posts[path]
			f.api.mu.Unlock()
			if creates != 1 {
				t.Fatal("uncertain CREATE repeated", creates)
			}
			if _, err := f.root.InspectProviderOwnerIdentityRoles(context.Background()); err != nil {
				t.Fatal("original exact result could not be inspected", err)
			}
			if f.root.pendingOperationRoot != nil || f.root.operationRootUID != string(original.UID) {
				t.Fatal("positive original read did not retain permanent UID")
			}
		})
	}
}
