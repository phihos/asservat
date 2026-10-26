package kubernetes

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	value "asservat.local/asservat/internal/domain/targets"
)

func restartFixturePod(name, rs string, restarts int, reason string, exit int, waiting bool) map[string]any {
	pod := targetMetadata("Pod", name, "pod-"+name)
	m := pod["metadata"].(map[string]any)
	m["labels"] = map[string]string{"app": "checkout"}
	m["ownerReferences"] = []any{targetOwner("ReplicaSet", rs, rs+"-uid")}
	status := map[string]any{"restartCount": restarts, "state": map[string]any{"running": map[string]any{}}}
	if waiting {
		status["state"] = map[string]any{"waiting": map[string]any{"reason": "CrashLoopBackOff", "message": "MUST-NOT-LEAK"}}
	}
	if reason != "" {
		status["lastState"] = map[string]any{"terminated": map[string]any{"reason": reason, "exitCode": exit, "finishedAt": "2026-10-25T12:00:00Z", "message": "MUST-NOT-LEAK"}}
	}
	pod["spec"] = map[string]any{"containers": []any{map[string]any{"name": "app", "env": []any{map[string]any{"name": "secret", "value": "MUST-NOT-LEAK"}}}}}
	// The second container's termination has no finishedAt: it is never the
	// attributed (most recent) termination.
	pod["status"] = map[string]any{"containerStatuses": []any{status, map[string]any{"restartCount": 1, "lastState": map[string]any{"terminated": map[string]any{"reason": "Error", "exitCode": 1}}}}}
	return pod
}

func TestWorkloadRestartObservationListsOwnedPodsOnce(t *testing.T) {
	for _, mode := range []string{"deployment", "statefulset", "foreign-owner", "truncated", "remaining", "oversized", "denied", "workload-deleting", "rs-limit"} {
		t.Run(mode, func(t *testing.T) {
			var lists, sets, pods atomic.Int64
			clock := &atomic.Int64{}
			clock.Store(time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC).UnixNano())
			kind := "Deployment"
			if mode == "statefulset" {
				kind = "StatefulSet"
			}
			observer := workloadClient(t, clock, func(w http.ResponseWriter, r *http.Request) {
				var object map[string]any
				switch r.URL.Path {
				case "/api/v1/namespaces/payments":
					object = permissionNamespace("payments", "payments-uid")
				case "/apis/apps/v1/namespaces/payments/deployments/app", "/apis/apps/v1/namespaces/payments/statefulsets/app":
					object = targetMetadata(kind, "app", "root-uid")
					object["metadata"].(map[string]any)["generation"] = 1
					if mode == "workload-deleting" {
						object["metadata"].(map[string]any)["deletionTimestamp"] = "2026-10-25T12:00:00Z"
					}
					object["spec"] = map[string]any{"selector": map[string]any{"matchLabels": map[string]string{"app": "checkout"}}}
				case "/api/v1/namespaces/payments/pods":
					lists.Add(1)
					if mode == "denied" {
						w.WriteHeader(403)
						permissionReply(w, map[string]any{"apiVersion": "v1", "kind": "Status", "reason": "Forbidden", "status": "Failure", "code": 403})
						return
					}
					if r.URL.Query().Get("limit") != fmt.Sprint(value.MaxRestartPods+1) || r.URL.Query().Get("labelSelector") != "app=checkout" {
						t.Errorf("unexpected Pod LIST: %s", r.URL.RawQuery)
					}
					items := []any{restartFixturePod("a", "rs", 3, "OOMKilled", 137, false), restartFixturePod("b", "rs", 0, "", 0, true), restartFixturePod("c", "foreign", 9, "Error", 1, false)}
					if mode == "statefulset" {
						for _, item := range items[:2] {
							item.(map[string]any)["metadata"].(map[string]any)["ownerReferences"] = []any{targetOwner("StatefulSet", "app", "root-uid")}
						}
					}
					if mode == "rs-limit" {
						items = nil
						for n := range restartOwnerSets + 1 {
							items = append(items, restartFixturePod(fmt.Sprintf("p%d", n), fmt.Sprintf("rs%d", n), 0, "", 0, false))
						}
					}
					if mode == "oversized" {
						items = nil
						for n := range value.MaxRestartPods + 1 {
							items = append(items, restartFixturePod(fmt.Sprintf("p%03d", n), "rs", 0, "", 0, false))
						}
					}
					metadata := map[string]any{"resourceVersion": "list-rv"}
					if mode == "truncated" {
						metadata["continue"] = "more"
					}
					if mode == "remaining" {
						metadata["remainingItemCount"] = 2
					}
					object = map[string]any{"apiVersion": "v1", "kind": "PodList", "metadata": metadata, "items": items}
				default:
					sets.Add(1)
					var rs string
					if _, err := fmt.Sscanf(r.URL.Path, "/apis/apps/v1/namespaces/payments/replicasets/%s", &rs); err != nil {
						pods.Add(1)
						t.Errorf("unexpected read %s", r.URL.Path)
						w.WriteHeader(404)
						return
					}
					object = targetMetadata("ReplicaSet", rs, rs+"-uid")
					owner := targetOwner("Deployment", "app", "root-uid")
					if rs == "foreign" {
						owner = targetOwner("Deployment", "other", "other-uid")
					}
					object["metadata"].(map[string]any)["ownerReferences"] = []any{owner}
				}
				permissionReply(w, object)
			})
			o, err := observer.ObserveWorkloadRestarts(context.Background(), value.WorkloadRequest{ClusterID: permissionCluster, Namespace: "payments", Kind: kind, Name: "app"})
			switch mode {
			case "truncated", "remaining", "oversized", "rs-limit":
				if !errors.Is(err, value.ErrLimit) {
					t.Fatal("incomplete LIST was not refused", err)
				}
				return
			case "denied":
				if !errors.Is(err, value.ErrDenied) {
					t.Fatal("denied LIST", err)
				}
				return
			case "workload-deleting":
				if !errors.Is(err, value.ErrChanged) {
					t.Fatal("deleting workload observed", err)
				}
				return
			}
			if err != nil || !o.Valid(time.Unix(0, clock.Load())) || o.Workload.UID != "root-uid" || o.Namespace.UID != "payments-uid" || lists.Load() != 1 || pods.Load() != 0 {
				t.Fatal(o, err)
			}
			if len(o.Pods) != 2 {
				t.Fatal("foreign-owned Pod included", o.Pods)
			}
			a, b := o.Pods[0], o.Pods[1]
			if a.Name != "a" || a.UID != "pod-a" || a.Restarts != 4 || a.Reason != "OOMKilled" || a.ExitCode != 137 || a.Waiting || b.UID != "pod-b" || b.Restarts != 1 || !b.Waiting || b.Reason != "" {
				t.Fatal("whole-pod counters", o.Pods)
			}
			if kind == "Deployment" && sets.Load() != 2 {
				t.Fatal("each ReplicaSet must be verified once", sets.Load())
			}
		})
	}
}
