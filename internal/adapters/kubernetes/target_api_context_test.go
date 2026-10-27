package kubernetes

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/targets"
)

func TestAPIContextResolvesUnscheduledPodWithoutNodeAuthority(t *testing.T) {
	for _, mode := range []string{"selection-expiry", "selection-aged", "unscheduled", "scheduled-during-read", "pod-reference", "pod-replaced", "owner-replaced", "list-denied", "no-eligible-pod", "original-expiry", "canceled"} {
		t.Run(mode, func(t *testing.T) {
			var podReads atomic.Int64
			clock := &atomic.Int64{}
			start := time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)
			clock.Store(start.UnixNano())
			resolver := workloadClient(t, clock, func(w http.ResponseWriter, r *http.Request) {
				var object map[string]any
				switch r.URL.Path {
				case "/api/v1/namespaces/payments":
					if mode == "selection-aged" {
						clock.CompareAndSwap(start.UnixNano(), start.Add(2*time.Second).UnixNano())
					}
					if mode == "selection-expiry" {
						clock.CompareAndSwap(start.UnixNano(), start.Add(3*time.Second).UnixNano())
					}
					object = permissionNamespace("payments", "payments-uid")
				case "/apis/apps/v1/namespaces/payments/deployments/app":
					object = targetMetadata("Deployment", "app", "root-uid")
					object["metadata"].(map[string]any)["generation"] = 1
					object["spec"] = map[string]any{"selector": map[string]any{"matchLabels": map[string]string{"app": "checkout"}}}
				case "/apis/apps/v1/namespaces/payments/replicasets/rs":
					object = targetMetadata("ReplicaSet", "rs", "rs-uid")
					object["metadata"].(map[string]any)["ownerReferences"] = []any{targetOwner("Deployment", "app", "root-uid")}
				case "/apis/apps/v1/namespaces/payments/replicasets/other":
					object = targetMetadata("ReplicaSet", "other", "other")
					object["metadata"].(map[string]any)["ownerReferences"] = []any{targetOwner("Deployment", "foreign", "foreign")}
				case "/api/v1/namespaces/payments/pods":
					if mode == "list-denied" {
						w.WriteHeader(http.StatusForbidden)
						permissionReply(w, map[string]any{"apiVersion": "v1", "kind": "Status", "code": 403, "reason": "Forbidden", "message": "MUST-NOT-LEAK"})
						return
					}
					items := []any{workloadFixturePod("z-app"), workloadFixturePod("a-unscheduled")}
					if mode == "no-eligible-pod" {
						items = []any{}
					}
					object = map[string]any{"apiVersion": "v1", "kind": "PodList", "metadata": map[string]any{"resourceVersion": "1", "continue": ""}, "items": items}
				case "/api/v1/namespaces/payments/pods/a-unscheduled":
					count := podReads.Add(1)
					object = workloadFixturePod("a-unscheduled")
					if count > 1 {
						switch mode {
						case "scheduled-during-read":
							object["spec"].(map[string]any)["nodeName"] = "now-assigned"
						case "pod-replaced":
							object["metadata"].(map[string]any)["uid"] = "replacement"
						case "owner-replaced":
							object["metadata"].(map[string]any)["ownerReferences"] = []any{targetOwner("ReplicaSet", "other", "other")}
						case "selection-expiry":
							clock.Store(start.Add(6 * time.Second).UnixNano())
						case "original-expiry":
							clock.Store(start.Add(5 * time.Second).UnixNano())
						}
					}
				default:
					t.Errorf("API context attempted forbidden/unexpected endpoint: %s", r.URL.Path)
					w.WriteHeader(http.StatusForbidden)
					return
				}
				permissionReply(w, object)
			})
			api, err := NewAPIContextTargets(resolver.client)
			if err != nil {
				t.Fatal(err)
			}
			request := value.WorkloadRequest{ClusterID: permissionCluster, Namespace: "payments", Kind: "Deployment", Name: "app"}
			if mode == "pod-reference" {
				request.Kind, request.Name = "Pod", "a-unscheduled"
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if mode == "canceled" {
				cancel()
			}
			out, err := api.ResolveWorkload(ctx, request)
			if mode == "selection-aged" || mode == "unscheduled" || mode == "scheduled-during-read" || mode == "pod-reference" {
				if err != nil || !out.Valid(time.Unix(0, clock.Load())) || out.ExecutionClass != artifact.ContextAPIExecution || out.Pin.NodeName != "" || out.NodeUID != "" || out.NodeBootID != "" || out.Request.PodName != "a-unscheduled" || out.Request.Workload.UID != "root-uid" || !out.ObservedAt.Equal(start) || !out.FreshUntil.Equal(start.Add(5*time.Second)) {
					t.Fatalf("API target lost exact identity, class or interval: %+v %v", out, err)
				}
				if podReads.Load() < 2 {
					t.Fatal("Pod identity not rechecked")
				}
				return
			}
			if err == nil || out != (value.PodResolution{}) || strings.Contains(err.Error(), "MUST-NOT-LEAK") {
				t.Fatalf("unverified API target returned: %+v %v", out, err)
			}
			if mode == "no-eligible-pod" && !errors.Is(err, value.ErrNoEligiblePods) {
				t.Fatal("empty API selection misleadingly requires scheduling", err)
			}
		})
	}
}
