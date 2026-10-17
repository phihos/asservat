package kubernetes

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	app "asservat.local/asservat/internal/application/capacity"
	cfg "asservat.local/asservat/internal/domain/configuration"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/util/flowcontrol"
)

func TestCapacityWorkloadObservationsBindNamespaceAndPermanentUID(t *testing.T) {
	for _, mode := range []string{"deployment", "statefulset-zero-replicas", "unowned-pod", "owned-pod", "replacement-pod", "replacement-namespace", "changed-selector", "unrelated-status", "changed-generation", "expired", "parent-deadline"} {
		t.Run(mode, func(t *testing.T) {
			n := time.Now().UTC().Truncate(time.Microsecond)
			start := n
			var tick atomic.Int64
			tick.Store(n.UnixNano())
			now := func() time.Time { return time.Unix(0, tick.Load()).UTC() }
			namespace := cfg.NamespaceRef{Name: "payments", UID: "namespace-uid"}
			ref := cfg.WorkloadRef{Kind: "Deployment", Name: "api", UID: "workload-uid"}
			if strings.Contains(mode, "pod") {
				ref.Kind = "Pod"
			}
			if mode == "statefulset-zero-replicas" {
				ref.Kind = "StatefulSet"
			}
			var nsReads, workloadReads atomic.Int64
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if r.Method != http.MethodGet {
					t.Errorf("unexpected mutation %s", r.Method)
					w.WriteHeader(405)
					return
				}
				if r.URL.Path == "/api/v1/namespaces/payments" {
					nsRead := nsReads.Add(1)
					uid := namespace.UID
					label := "core"
					if mode == "replacement-namespace" && nsRead > 1 {
						uid = "replacement"
					}
					if mode == "changed-selector" && nsRead > 1 {
						label = "other"
					}
					_ = json.NewEncoder(w).Encode(map[string]any{"apiVersion": "v1", "kind": "Namespace", "metadata": map[string]any{"name": "payments", "uid": uid, "resourceVersion": "ns-current", "labels": map[string]string{"capacity.example/team": label, "foreign.example/value": "not exported"}}})
					return
				}
				path, _ := capacityWorkloadPath(namespace.Name, ref.Kind)
				if r.URL.Path != path+"/"+ref.Name || r.Header.Get("Accept") != capacityMetadataAccept {
					t.Errorf("unexpected bounded metadata request")
					w.WriteHeader(404)
					return
				}
				workloadRead := workloadReads.Add(1)
				m := metav1.PartialObjectMetadata{TypeMeta: metav1.TypeMeta{APIVersion: "meta.k8s.io/v1", Kind: "PartialObjectMetadata"}, ObjectMeta: metav1.ObjectMeta{Name: ref.Name, Namespace: namespace.Name, UID: types.UID(ref.UID), ResourceVersion: "workload-original", Generation: 1}}
				if mode == "replacement-pod" && workloadRead > 1 {
					m.UID = "other-uid"
				}
				if mode == "owned-pod" {
					m.OwnerReferences = []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "ReplicaSet", Name: "controller", UID: "controller-uid"}}
				}
				if mode == "unrelated-status" && workloadRead > 1 {
					m.ResourceVersion = "status-update"
				}
				if mode == "changed-generation" && workloadRead > 1 {
					m.Generation++
				}
				if mode == "expired" {
					tick.Store(start.Add(5 * time.Second).UnixNano())
				}
				_ = json.NewEncoder(w).Encode(m)
			}))
			defer srv.Close()
			client, e := NewPermissionClient(&rest.Config{Host: srv.URL, TLSClientConfig: rest.TLSClientConfig{CAData: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})}, RateLimiter: flowcontrol.NewFakeAlwaysRateLimiter()}, "50000000-0000-4000-8000-000000000001", cfg.NamespaceRef{Name: "control", UID: "control-uid"}, now)
			if e != nil {
				t.Fatal(e)
			}
			ctx := context.Background()
			var cancel context.CancelFunc
			if mode == "parent-deadline" {
				ctx, cancel = context.WithDeadline(ctx, start.Add(time.Second))
				defer cancel()
			}
			out, e := client.ReadCapacityWorkload(ctx, namespace, ref, []string{"capacity.example/team"})
			valid := mode == "deployment" || mode == "statefulset-zero-replicas" || mode == "unowned-pod" || mode == "unrelated-status" || mode == "parent-deadline"
			if valid {
				if e != nil || !out.Valid(now()) || out.Workload != ref || len(out.Namespace.Labels) != 1 || out.Namespace.Labels["capacity.example/team"] != "core" {
					t.Fatalf("current workload unavailable: %v", e)
				}
				until := start.Add(5 * time.Second)
				if mode == "parent-deadline" {
					until = start.Add(time.Second)
				}
				if !out.ObservedAt.Equal(start) || !out.FreshUntil.Equal(until) || nsReads.Load() != 2 || workloadReads.Load() != 2 {
					t.Fatal("original interval or exact rechecks lost")
				}
			} else if e == nil {
				t.Fatal("changed workload accepted")
			}
		})
	}
}

func TestCapacityDiscoveryIsBoundedCandidateEnumeration(t *testing.T) {
	for _, mode := range []string{"page", "too-many", "same-cursor", "wrong-kind", "duplicate-uid", "owned-pod"} {
		t.Run(mode, func(t *testing.T) {
			n := time.Now().UTC()
			var calls atomic.Int64
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				w.Header().Set("Content-Type", "application/json")
				if r.Method != "GET" || r.Header.Get("Accept") != capacityMetadataListAccept || r.URL.Query().Get("limit") != "64" || r.URL.Query().Get("continue") != "original-cursor" {
					t.Error("unbounded or changed discovery request")
				}
				page := metav1.PartialObjectMetadataList{TypeMeta: metav1.TypeMeta{APIVersion: "meta.k8s.io/v1", Kind: "PartialObjectMetadataList"}, ListMeta: metav1.ListMeta{ResourceVersion: "opaque-list", Continue: "next-cursor"}}
				count := 1
				if mode == "too-many" {
					count = app.CapacityDiscoveryPageSize + 1
				}
				if mode == "duplicate-uid" {
					count = 2
				}
				for i := 0; i < count; i++ {
					m := metav1.PartialObjectMetadata{ObjectMeta: metav1.ObjectMeta{Name: "pod", Namespace: "payments", UID: "pod-uid", ResourceVersion: "object-rv"}}
					if mode == "owned-pod" {
						m.OwnerReferences = []metav1.OwnerReference{{Name: "owner"}}
					}
					page.Items = append(page.Items, m)
				}
				if mode == "same-cursor" {
					page.Continue = "original-cursor"
				}
				if mode == "wrong-kind" {
					page.Kind = "PodList"
				}
				_ = json.NewEncoder(w).Encode(page)
			}))
			defer srv.Close()
			c, e := NewPermissionClient(&rest.Config{Host: srv.URL, TLSClientConfig: rest.TLSClientConfig{CAData: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})}, RateLimiter: flowcontrol.NewFakeAlwaysRateLimiter()}, "50000000-0000-4000-8000-000000000001", cfg.NamespaceRef{Name: "control", UID: "control-uid"}, func() time.Time { return n })
			if e != nil {
				t.Fatal(e)
			}
			out, e := c.DiscoverCapacityWorkloads(context.Background(), cfg.NamespaceRef{Name: "payments", UID: "namespace-uid"}, "Pod", "original-cursor")
			if mode == "page" {
				if e != nil || len(out.Workloads) != 1 || out.Continue != "next-cursor" {
					t.Fatal("candidate page unavailable")
				}
			} else if mode == "owned-pod" {
				if e != nil || len(out.Workloads) != 0 {
					t.Fatal("owned Pod minted a separate workload account")
				}
			} else if e == nil {
				t.Fatal("incomplete/malformed page accepted")
			}
			if calls.Load() != 1 {
				t.Fatal("discovery continued beyond its one bounded page")
			}
		})
	}
}
