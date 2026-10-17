package kubernetes

import (
	"context"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	cfg "asservat.local/asservat/internal/domain/configuration"
	value "asservat.local/asservat/internal/domain/fleet"
	"k8s.io/client-go/rest"
)

func TestOwnerObservationDialCandidatesRetainCompleteMembership(t *testing.T) {
	for _, mode := range []string{"complete", "unknown-list", "changed-final-service"} {
		t.Run(mode, func(t *testing.T) {
			v := ownerFixtureObjects()
			setInstalledOwnerEndpointPorts(&v)
			v.pool.NativeCandidateLimit = value.OwnerRegistrationsPerPool
			start := time.Now().UTC()
			candidates := value.APIContextOwnerCandidates{Pool: v.pool, ObservedAt: start, ValidUntil: start.Add(5 * time.Second)}
			for i := 0; i < 32; i++ {
				b := v.binding
				b.ProcessEpoch = ownerID(100 + i)
				candidates.Owners = append(candidates.Owners, b)
			}
			var lists, services, namespaces atomic.Int32
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != "GET" {
					t.Error("routing discovery effect")
				}
				switch r.URL.Path {
				case "/api/v1/namespaces/owners":
					namespaces.Add(1)
					permissionReply(w, v.ns)
				case "/api/v1/namespaces/owners/services/hub-owner":
					n := services.Add(1)
					s := v.svc.DeepCopy()
					if mode == "changed-final-service" && n == 2 {
						s.ResourceVersion = "changed"
					}
					permissionReply(w, s)
				case "/apis/discovery.k8s.io/v1/namespaces/owners/endpointslices":
					lists.Add(1)
					if mode == "unknown-list" {
						http.Error(w, "unavailable", 503)
						return
					}
					permissionReply(w, v.list)
				default:
					t.Error("unneeded per-Pod native traversal")
					http.NotFound(w, r)
				}
			}))
			defer server.Close()
			c, err := NewPermissionClient(&rest.Config{Host: server.URL, BearerToken: "fixture", TLSClientConfig: rest.TLSClientConfig{CAData: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})}}, v.pool.ClusterID, cfg.NamespaceRef{Name: v.pool.Namespace, UID: v.pool.NamespaceUID}, time.Now)
			if err != nil {
				t.Fatal(err)
			}
			reader, err := NewOwnerEndpoints(c, v.pool)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithDeadline(context.Background(), start.Add(time.Second))
			defer cancel()
			got, err := reader.ReadOwnerObservationDialCandidates(ctx, candidates)
			if mode != "complete" {
				if err == nil || len(got.Addresses) != 0 {
					t.Fatal("unknown observation supplied dial hints")
				}
				return
			}
			if err != nil || !got.Groups.Valid(time.Now()) || len(got.Groups.Groups) != 1 || len(got.Groups.Groups[0].Owners) != 32 || len(got.Addresses[v.binding.PodUID]) == 0 {
				t.Fatal("complete original candidate groups", err)
			}
			if lists.Load() != 1 || services.Load() != 2 || namespaces.Load() != 2 {
				t.Fatal("amplified discovery", lists.Load(), services.Load(), namespaces.Load())
			}
			got.Groups.Groups[0].Owners[0].ProcessEpoch = ownerID(900)
			if candidates.Owners[0].ProcessEpoch == ownerID(900) {
				t.Fatal("returned membership aliases SQL original")
			}
		})
	}
}
