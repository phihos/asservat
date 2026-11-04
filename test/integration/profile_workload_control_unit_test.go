package integration

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// Real client-go Pod/proxy requests against synthetic Kubernetes/fixture replies;
// this checks the fixture's producer/consumer contract, not native profiling.
func TestProfileWorkloadControlPinsPodAndFixedProtocol(t *testing.T) {
	const uid = "11111111-1111-4111-8111-111111111111"
	for _, mode := range []string{"state", "start", "stop", "normal", "missing", "replaced", "missing-field", "extra-field", "trailing", "negative", "oversize"} {
		t.Run(mode, func(t *testing.T) {
			command := mode
			if mode == "replaced" {
				command = "start"
			} else if strings.Contains(mode, "field") || mode == "trailing" || mode == "negative" || mode == "oversize" {
				command = "state"
			}
			reads, mutations := 0, 0
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				const base = "/api/v1/namespaces/app/pods/"
				if r.Method == "GET" && r.URL.Path == base+"profile-0" {
					id := uid
					if mode == "replaced" {
						id = "22222222-2222-4222-8222-222222222222"
					}
					_, _ = fmt.Fprintf(w, `{"apiVersion":"v1","kind":"Pod","metadata":{"name":"profile-0","namespace":"app","uid":%q}}`, id)
					return
				}
				if r.Method == "POST" {
					mutations++
					path := "cpu-profiler/" + command
					if command == "normal" || command == "missing" {
						path = "profile-mode"
						b, err := io.ReadAll(r.Body)
						if err != nil || string(b) != command {
							t.Error("fixture mode body changed", err)
						}
					}
					if r.URL.Path != base+"profile-0:8080/proxy/fixture/"+path {
						t.Error("fixture command path changed", r.URL.Path)
					}
					w.WriteHeader(http.StatusNoContent)
					return
				}
				if r.Method != "GET" || r.URL.Path != base+"profile-0:8080/proxy/fixture/cpu-profiler" {
					t.Error("unexpected fixture read", r.Method, r.URL.Path)
					w.WriteHeader(404)
					return
				}
				reads++
				body := `{"owner_running":true,"runtime_busy":true,"profile_requests":7}`
				switch mode {
				case "missing-field":
					body = `{"owner_running":true,"runtime_busy":true}`
				case "extra-field":
					body = `{"owner_running":true,"runtime_busy":true,"profile_requests":7,"private":"forbidden"}`
				case "trailing":
					body += " {}"
				case "negative":
					body = `{"owner_running":true,"runtime_busy":true,"profile_requests":-1}`
				case "oversize":
					body += strings.Repeat(" ", 257)
				}
				_, _ = io.WriteString(w, body)
			}))
			defer server.Close()
			k, err := kubernetes.NewForConfig(&rest.Config{Host: server.URL, TLSClientConfig: rest.TLSClientConfig{Insecure: true}})
			if err != nil {
				t.Fatal(err)
			}
			state, err := profileWorkloadControl(t.Context(), k, "app", "profile-0", uid, command)
			good := mode == "state" || mode == "start" || mode == "stop" || mode == "normal" || mode == "missing"
			if good {
				if err != nil || !state.OwnerRunning || !state.RuntimeBusy || state.ProfileRequests != 7 || reads != 1 {
					t.Fatal("fixture protocol mismatch", state, reads, err)
				}
				want := 1
				if command == "state" {
					want = 0
				}
				if mutations != want {
					t.Fatal("extra fixture mutation", mutations)
				}
			} else if err == nil || mutations != 0 {
				t.Fatal("invalid fixture state or replacement accepted", state, mutations, err)
			}
		})
	}
}
