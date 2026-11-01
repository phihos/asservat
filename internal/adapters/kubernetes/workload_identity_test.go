package kubernetes

import (
	"encoding/json"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	value "asservat.local/asservat/internal/domain/targets"
)

func TestRecordingInventoryWorkloadIdentityNeedsNoLivePod(t *testing.T) {
	clock := &atomic.Int64{}
	start := time.Date(2026, 10, 30, 0, 0, 0, 0, time.UTC)
	clock.Store(start.UnixNano())
	var gets, podReads atomic.Int64
	resolver := workloadClient(t, clock, func(w http.ResponseWriter, r *http.Request) {
		gets.Add(1)
		var object map[string]any
		switch r.URL.Path {
		case "/api/v1/namespaces/payments":
			object = permissionNamespace("payments", "namespace-uid")
		case "/apis/apps/v1/namespaces/payments/deployments/app":
			object = targetMetadata("Deployment", "app", "deployment-uid")
			object["metadata"].(map[string]any)["generation"] = 1
			object["spec"] = map[string]any{"selector": map[string]any{"matchLabels": map[string]string{"app": "checkout"}}}
		default:
			podReads.Add(1)
			object = map[string]any{"apiVersion": "v1", "kind": "PodList", "metadata": map[string]any{"resourceVersion": "1"}, "items": []any{}}
		}
		_ = json.NewEncoder(w).Encode(object)
	})
	out, err := resolver.ResolveWorkloadIdentity(t.Context(), value.WorkloadRequest{ClusterID: permissionCluster, Namespace: "payments", Kind: "Deployment", Name: "app"})
	if err != nil {
		t.Fatal("recording inventory depends on selecting a live Pod", err)
	}
	if !out.Valid(start) || out.Target().WorkloadUID != "deployment-uid" || out.Namespace.UID != "namespace-uid" || out.ObservedAt != start || !out.FreshUntil.Equal(start.Add(5*time.Second)) {
		t.Fatal("wrong root identity or renewed clock", out)
	}
	if podReads.Load() != 0 || gets.Load() != 2 {
		t.Fatal("workload identity read Pod payload/list", gets.Load(), podReads.Load())
	}
}

func TestWorkloadIdentityObservationRejectsChangedDeniedAndExpiredReads(t *testing.T) {
	for _, mode := range []string{"statefulset", "namespace-denied", "workload-denied", "missing-workload", "wrong-name", "deleting-root", "late-original", "clock-rollback"} {
		t.Run(mode, func(t *testing.T) {
			clock := &atomic.Int64{}
			start := time.Date(2026, 10, 30, 0, 0, 0, 0, time.UTC)
			clock.Store(start.UnixNano())
			kind, plural := "Deployment", "deployments"
			if mode == "statefulset" {
				kind, plural = "StatefulSet", "statefulsets"
			}
			var gets, podReads atomic.Int64
			resolver := workloadClient(t, clock, func(w http.ResponseWriter, r *http.Request) {
				gets.Add(1)
				var object map[string]any
				switch r.URL.Path {
				case "/api/v1/namespaces/payments":
					if mode == "namespace-denied" {
						http.Error(w, "forbidden", http.StatusForbidden)
						return
					}
					object = permissionNamespace("payments", "namespace-uid")
					if mode == "late-original" {
						clock.Add(int64(3 * time.Second))
					}
				case "/apis/apps/v1/namespaces/payments/" + plural + "/app":
					if mode == "workload-denied" {
						http.Error(w, "forbidden", http.StatusForbidden)
						return
					}
					if mode == "missing-workload" {
						http.NotFound(w, r)
						return
					}
					object = targetMetadata(kind, "app", "workload-uid")
					object["metadata"].(map[string]any)["generation"] = 1
					if mode == "wrong-name" {
						object["metadata"].(map[string]any)["name"] = "replacement"
					}
					if mode == "deleting-root" {
						object["metadata"].(map[string]any)["deletionTimestamp"] = "2026-10-30T00:00:00Z"
					}
					if mode == "late-original" {
						clock.Add(int64(3 * time.Second))
					}
					if mode == "clock-rollback" {
						clock.Store(start.Add(-time.Second).UnixNano())
					}
				default:
					podReads.Add(1)
					http.Error(w, "unexpected Pod lookup", http.StatusInternalServerError)
					return
				}
				_ = json.NewEncoder(w).Encode(object)
			})
			out, err := resolver.ResolveWorkloadIdentity(t.Context(), value.WorkloadRequest{ClusterID: permissionCluster, Namespace: "payments", Kind: kind, Name: "app"})
			if podReads.Load() != 0 {
				t.Fatal("identity observation queried Pods", podReads.Load())
			}
			if mode == "statefulset" {
				if err != nil || !out.Valid(start) || out.Workload.Kind != kind || gets.Load() != 2 {
					t.Fatal("empty StatefulSet identity failed", out, err, gets.Load())
				}
			} else if err == nil || out != (value.WorkloadIdentityResolution{}) {
				t.Fatal("changed, denied or expired observation returned identity", out, err)
			}
		})
	}
}
