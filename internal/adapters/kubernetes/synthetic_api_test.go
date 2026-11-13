package kubernetes

import (
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
)

// downloadWorkerAPI is a synthetic API server that stores created objects by
// path and applies updates; it enforces no admission or RBAC.
type downloadWorkerAPI struct {
	mu      sync.Mutex
	objects map[string]map[string]any
	uid     int
}

func newDownloadWorkerAPI(t *testing.T) (*downloadWorkerAPI, *rest.Config) {
	t.Helper()
	a := &downloadWorkerAPI{objects: map[string]map[string]any{}}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a.mu.Lock()
		defer a.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		status := func(code int, reason meta.StatusReason) {
			w.WriteHeader(code)
			_ = json.NewEncoder(w).Encode(meta.Status{TypeMeta: meta.TypeMeta{Kind: "Status", APIVersion: "v1"}, Status: meta.StatusFailure, Reason: reason, Code: int32(code)})
		}
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		key := r.URL.Path
		switch r.Method {
		case http.MethodPost:
			key += "/" + body["metadata"].(map[string]any)["name"].(string)
			if a.objects[key] != nil {
				status(409, meta.StatusReasonAlreadyExists)
				return
			}
			a.uid++
			m := body["metadata"].(map[string]any)
			m["uid"] = strings.Replace("20000000-0000-4000-8000-0000000000xx", "xx", string(rune('a'+a.uid/10))+string(rune('0'+a.uid%10)), 1)
			m["resourceVersion"], m["generation"] = "1", 1
			a.objects[key] = body
		case http.MethodPut:
			old := a.objects[key]
			if old == nil {
				status(404, meta.StatusReasonNotFound)
				return
			}
			if immutable, _ := old["immutable"].(bool); immutable {
				status(422, meta.StatusReasonInvalid)
				return
			}
			body["metadata"].(map[string]any)["uid"] = old["metadata"].(map[string]any)["uid"]
			a.objects[key] = body
		}
		if a.objects[key] == nil {
			status(404, meta.StatusReasonNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(a.objects[key])
	}))
	t.Cleanup(server.Close)
	return a, &rest.Config{Host: server.URL, BearerToken: "synthetic-only", TLSClientConfig: rest.TLSClientConfig{CAData: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})}}
}

func (a *downloadWorkerAPI) object(path string) map[string]any {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.objects[path]
}
