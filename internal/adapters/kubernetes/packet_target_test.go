package kubernetes

import (
	"context"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	cfg "asservat.local/asservat/internal/domain/configuration"
	value "asservat.local/asservat/internal/domain/targets"
)

func TestPacketTargetReusesFinalExactPodWithoutNodeAuthority(t *testing.T) {
	for _, mode := range []string{"short-parent", "short-parent-generic", "available", "node-changed", "host-network", "not-running", "unscheduled", "pod-replaced", "pod-deleted", "owner-changed", "namespace-replaced", "original-expiry"} {
		t.Run(mode, func(t *testing.T) {
			start := time.Now().UTC()
			clock := &atomic.Int64{}
			clock.Store(start.UnixNano())
			var pods, namespaces, calls atomic.Int64
			resolver := workloadClient(t, clock, func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				var object map[string]any
				switch r.URL.Path {
				case "/api/v1/namespaces/payments":
					n := namespaces.Add(1)
					object = permissionNamespace("payments", "payments-uid")
					if mode == "namespace-replaced" && n > 1 {
						object["metadata"].(map[string]any)["uid"] = "replacement"
					}
				case "/api/v1/namespaces/payments/pods/app":
					n := pods.Add(1)
					object = workloadFixturePod("app")
					object["spec"].(map[string]any)["nodeName"] = "worker"
					object["status"] = map[string]any{"phase": "Running"}
					if n > 1 {
						object["metadata"].(map[string]any)["resourceVersion"] = "final-rv"
						switch mode {
						case "node-changed":
							object["spec"].(map[string]any)["nodeName"] = "new-worker"
						case "host-network":
							object["spec"].(map[string]any)["hostNetwork"] = true
						case "not-running":
							object["status"] = map[string]any{"phase": "Pending"}
						case "unscheduled":
							object["spec"].(map[string]any)["nodeName"] = ""
						case "pod-replaced":
							object["metadata"].(map[string]any)["uid"] = "replacement"
						case "pod-deleted":
							object["metadata"].(map[string]any)["deletionTimestamp"] = start.Format(time.RFC3339)
						case "owner-changed":
							object["metadata"].(map[string]any)["ownerReferences"] = []any{targetOwner("ReplicaSet", "rs", "new-owner")}
						case "original-expiry":
							clock.Store(start.Add(5 * time.Second).UnixNano())
						}
					}
				case "/apis/apps/v1/namespaces/payments/replicasets/rs":
					object = targetMetadata("ReplicaSet", "rs", "rs-uid")
					object["metadata"].(map[string]any)["ownerReferences"] = []any{targetOwner("Deployment", "app", "root-uid")}
				case "/apis/apps/v1/namespaces/payments/deployments/app":
					object = targetMetadata("Deployment", "app", "root-uid")
				default:
					t.Errorf("unexpected extra discovery: %s", r.URL.Path)
					w.WriteHeader(403)
					return
				}
				permissionReply(w, object)
			})
			resolver.executionClass = artifact.ContextAPIExecution
			request := value.Request{ClusterID: permissionCluster, Namespace: cfg.NamespaceRef{Name: "payments", UID: "payments-uid"}, Workload: cfg.WorkloadRef{Kind: "Deployment", Name: "app", UID: "root-uid"}, PodName: "app", PodUID: "pod-app"}
			ctx := context.Background()
			var cancel context.CancelFunc
			if mode == "short-parent" || mode == "short-parent-generic" {
				ctx, cancel = context.WithTimeout(ctx, 500*time.Millisecond)
				defer cancel()
			}
			var p value.PodResolution
			var node string
			var err error
			if mode == "short-parent-generic" {
				p, err = resolver.ResolvePod(ctx, request)
			} else {
				p, node, err = resolver.ResolvePacketPod(ctx, request)
			}
			refused := mode == "pod-replaced" || mode == "pod-deleted" || mode == "owner-changed" || mode == "namespace-replaced" || mode == "original-expiry"
			if refused {
				if err == nil || p != (value.PodResolution{}) || node != "" {
					t.Fatal("changed or expired target retained availability", p, node, err)
				}
				return
			}
			if err != nil || !p.Valid(start) || p.Pin.NodeName != "" || p.NodeUID != "" || p.NodeBootID != "" || p.Request != request || p.PodResourceVersion != "final-rv" {
				t.Fatal("API target/provenance changed", p, node, err)
			}
			want := "worker"
			if mode == "node-changed" {
				want = "new-worker"
			}
			if mode == "host-network" || mode == "not-running" || mode == "unscheduled" || mode == "short-parent-generic" {
				want = ""
			}
			if node != want || pods.Load() != 2 || namespaces.Load() != 2 || calls.Load() != 8 {
				t.Fatal("did not use final existing read", node, want, pods.Load(), namespaces.Load(), calls.Load())
			}
			if mode == "short-parent" || mode == "short-parent-generic" {
				deadline, _ := ctx.Deadline()
				if !p.FreshUntil.Equal(start.Add(5*time.Second)) || !p.FreshUntil.After(deadline) {
					t.Fatal("completed API metadata inherited caller I/O deadline", p, deadline)
				}
			}
			if !p.ObservedAt.Equal(start) || p.FreshUntil.After(start.Add(5*time.Second)) {
				t.Fatal("original target times extended", p)
			}
		})
	}
}
