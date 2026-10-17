package kubernetes

import (
	"context"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	cfg "asservat.local/asservat/internal/domain/configuration"
	value "asservat.local/asservat/internal/domain/fleet"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
	"k8s.io/utils/ptr"
)

func TestOwnerObservationCandidateReadyIntersectionOneCompleteList(t *testing.T) {
	modes := []string{"one-ready-many-processes", "retained-ceiling", "dead-retained-pod", "known-unready-other-pod", "two-pages", "empty-ready", "nil-ready", "inconsistent-ready", "changed-list-version", "cycle", "unknown-list", "wrong-service", "changed-service", "foreign-namespace", "wrong-port", "unknown-endpoint", "missing-list-version", "slice-overflow", "endpoint-overflow", "cursor-overflow", "expired-original-sql", "expired-final-namespace", "original-caller-bound"}
	for _, mode := range modes {
		t.Run(mode, func(t *testing.T) {
			v := ownerFixtureObjects()
			setInstalledOwnerEndpointPorts(&v)
			v.pool.NativeCandidateLimit = value.OwnerRegistrationsPerPool
			now := time.Now().UTC()
			clock := atomic.Int64{}
			clock.Store(now.UnixNano())
			candidates := value.APIContextOwnerCandidates{Pool: v.pool, ObservedAt: now, ValidUntil: now.Add(4 * time.Second)}
			processes := 17
			if mode == "retained-ceiling" {
				processes = value.OwnerRegistrationsPerPool
			}
			for i := 0; i < processes; i++ {
				b := v.binding
				b.ProcessEpoch = ownerID(100 + i)
				candidates.Owners = append(candidates.Owners, b)
			}
			if mode == "dead-retained-pod" || mode == "known-unready-other-pod" {
				b := v.binding
				b.PodUID = ownerID(90)
				b.ProcessEpoch = ownerID(91)
				candidates.Owners = append(candidates.Owners, b)
			}
			switch mode {
			case "known-unready-other-pod":
				ep := v.list.Items[0].Endpoints[0].DeepCopy()
				ep.TargetRef.UID = types.UID(ownerID(90))
				ep.TargetRef.Name = "not-ready"
				ep.Conditions.Ready = ptr.To(false)
				v.list.Items[0].Endpoints = append(v.list.Items[0].Endpoints, *ep)
			case "empty-ready":
				v.list.Items[0].Endpoints[0].Conditions.Ready = ptr.To(false)
			case "nil-ready":
				v.list.Items[0].Endpoints[0].Conditions.Ready = nil
			case "inconsistent-ready":
				ep := v.list.Items[0].Endpoints[0].DeepCopy()
				ep.Conditions.Ready = ptr.To(false)
				v.list.Items[0].Endpoints = append(v.list.Items[0].Endpoints, *ep)
			case "wrong-service":
				v.list.Items[0].OwnerReferences[0].UID = types.UID(ownerID(99))
			case "foreign-namespace":
				v.ns.UID = types.UID(ownerID(99))
			case "wrong-port":
				v.list.Items[0].Ports[0].Port = ptr.To(int32(9446))
			case "unknown-endpoint":
				v.list.Items[0].Endpoints[0].TargetRef = nil
			case "missing-list-version":
				v.list.ResourceVersion = ""
			case "slice-overflow":
				for len(v.list.Items) < 65 {
					v.list.Items = append(v.list.Items, *v.list.Items[0].DeepCopy())
				}
			case "endpoint-overflow":
				for len(v.list.Items[0].Endpoints) < 1025 {
					v.list.Items[0].Endpoints = append(v.list.Items[0].Endpoints, *v.list.Items[0].Endpoints[0].DeepCopy())
				}
			case "cursor-overflow":
				v.list.Continue = strings.Repeat("x", 4097)
			}
			var lists, services, namespaces, other atomic.Int32
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != "GET" || r.Header.Get("Authorization") != "Bearer synthetic-owner" {
					t.Error("unexpected request purpose")
				}
				base := "/api/v1/namespaces/" + v.pool.Namespace
				switch r.URL.Path {
				case base:
					if namespaces.Add(1) > 1 && mode == "expired-final-namespace" {
						clock.Store(candidates.ValidUntil.UnixNano())
					}
					permissionReply(w, v.ns)
				case base + "/services/" + v.pool.Service:
					n := services.Add(1)
					copy := v.svc.DeepCopy()
					if mode == "changed-service" && n > 1 {
						copy.ResourceVersion = "11"
					}
					permissionReply(w, copy)
				case "/apis/discovery.k8s.io/v1/namespaces/" + v.pool.Namespace + "/endpointslices":
					n := lists.Add(1)
					if r.URL.Query().Get("labelSelector") != "kubernetes.io/service-name="+v.pool.Service || r.URL.Query().Get("limit") != "64" {
						t.Error("unbounded endpoint selection")
					}
					if mode == "unknown-list" {
						http.Error(w, "unavailable", 503)
						return
					}
					if mode == "original-caller-bound" {
						<-r.Context().Done()
						return
					}
					copy := v.list.DeepCopy()
					if mode == "two-pages" || mode == "changed-list-version" || mode == "cycle" {
						if n == 1 {
							copy.Items = nil
							copy.Continue = "next"
						} else {
							if r.URL.Query().Get("continue") != "next" {
								t.Error("lost original page cursor")
							}
							if mode == "changed-list-version" {
								copy.ResourceVersion = "11"
							}
							if mode == "cycle" {
								copy.Continue = "next"
							}
						}
					}
					if mode == "expired-original-sql" {
						clock.Store(candidates.ValidUntil.UnixNano())
					}
					permissionReply(w, copy)
				default:
					other.Add(1)
					http.NotFound(w, r)
				}
			}))
			defer server.Close()
			client, err := NewPermissionClient(&rest.Config{Host: server.URL, BearerToken: "synthetic-owner", TLSClientConfig: rest.TLSClientConfig{CAData: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})}}, v.pool.ClusterID, cfg.NamespaceRef{Name: v.pool.Namespace, UID: v.pool.NamespaceUID}, func() time.Time { return time.Unix(0, clock.Load()).UTC() })
			if err != nil {
				t.Fatal(err)
			}
			reader, err := NewOwnerEndpoints(client, v.pool)
			if err != nil {
				t.Fatal(err)
			}
			duration := time.Second
			if mode == "original-caller-bound" {
				duration = 100 * time.Millisecond
			}
			ctx, cancel := context.WithTimeout(context.Background(), duration)
			defer cancel()
			original, _ := ctx.Deadline()
			got, err := reader.ReadyOwnerObservationCandidates(ctx, candidates)
			good := mode == "one-ready-many-processes" || mode == "retained-ceiling" || mode == "dead-retained-pod" || mode == "known-unready-other-pod" || mode == "two-pages"
			if (err == nil) != good {
				t.Fatal("complete Ready intersection", mode, err)
			}
			if good {
				if !got.Valid(time.Unix(0, clock.Load())) || len(got.Groups) != 1 || len(got.Groups[0].Owners) != processes || len(got.Candidates.Owners) != len(candidates.Owners) || got.ValidUntil.After(original) {
					t.Fatal("changed/missing original provenance")
				}
				expected := int32(1)
				if mode == "two-pages" {
					expected = 2
				}
				if lists.Load() != expected || other.Load() != 0 || services.Load() != 2 || namespaces.Load() != 2 {
					t.Fatal("candidate count multiplied API traffic", lists.Load(), other.Load(), services.Load())
				}
				candidates.Owners[0].ProcessEpoch = ownerID(9999)
				if !got.Valid(time.Unix(0, clock.Load())) || got.Candidates.Owners[0] == candidates.Owners[0] {
					t.Fatal("caller retained mutable ownership of returned candidates")
				}
			}
			if mode == "original-caller-bound" && ctx.Err() == nil {
				t.Fatal("blocked original caller did not expire")
			}
		})
	}
}
