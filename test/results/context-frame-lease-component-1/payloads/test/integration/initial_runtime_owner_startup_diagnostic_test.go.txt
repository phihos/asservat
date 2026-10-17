package integration

import (
	"asservat.local/asservat/internal/adapters/mounts"
	"asservat.local/asservat/internal/bootstrap"
	"context"
	"encoding/json"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// This component test uses only an owned loopback API. It proves diagnostic
// selection/bounds, not native Pod identity or authority.
func TestOriginalOwnerStartupLogsKeepOnlyClosedOriginalPodDiagnostics(t *testing.T) {
	for _, mode := range []string{"original", "replacement", "oversized", "cancelled"} {
		t.Run(mode, func(t *testing.T) {
			original := &core.Pod{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "Pod"}, ObjectMeta: meta.ObjectMeta{Name: "original", Namespace: "synthetic", UID: types.UID("10000000-0000-4000-8000-000000000001")}}
			diagnostic := bootstrap.OwnerStartupDiagnostic(mounts.ErrUnavailable)
			var gets, logs atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet {
					t.Error("diagnostics attempted mutation")
					http.Error(w, "denied", 403)
					return
				}
				if r.URL.Path == "/api/v1/namespaces/synthetic/pods/original/log" {
					logs.Add(1)
					if r.URL.Query().Get("container") != "hub" || r.URL.Query().Get("limitBytes") != "8192" || r.URL.Query().Get("tailLines") != "32" || r.URL.Query().Get("follow") == "true" {
						t.Error("unbounded/wrong-container logs")
					}
					if mode == "oversized" {
						_, _ = w.Write([]byte(strings.Repeat("x", 8193)))
						return
					}
					_, _ = w.Write([]byte("synthetic-private-dsn-and-token\n" + diagnostic + "\nother-private-output\n"))
					return
				}
				if r.URL.Path != "/api/v1/namespaces/synthetic/pods/original" {
					t.Error("diagnostics selected another object")
					http.NotFound(w, r)
					return
				}
				n := gets.Add(1)
				pod := original.DeepCopy()
				if mode == "replacement" && n == 2 {
					pod.UID = types.UID("10000000-0000-4000-8000-000000000002")
				}
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(pod)
			}))
			defer server.Close()
			api, err := kubernetes.NewForConfig(&rest.Config{Host: server.URL})
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if mode == "cancelled" {
				cancel()
			}
			got := originalOwnerStartupLogDiagnostics(ctx, api, original)
			if mode == "original" {
				if len(got) != 2 || got[0] != "current: "+diagnostic || got[1] != "previous: "+diagnostic {
					t.Fatal("missing or unsafe original diagnostic")
				}
			} else if len(got) != 0 {
				t.Fatal("replacement/oversized/cancelled logs retained")
			}
			if mode == "cancelled" {
				if gets.Load() != 0 || logs.Load() != 0 {
					t.Fatal("cancelled log collection made requests")
				}
			} else if gets.Load() != 2 || logs.Load() != 2 {
				t.Fatal("unexpected original diagnostic request census")
			}
		})
	}
}
