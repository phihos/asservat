package kubernetes

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	cfg "asservat.local/asservat/internal/domain/configuration"
	value "asservat.local/asservat/internal/domain/targets"
)

func targetMetadata(kind, name, uid string) map[string]any {
	metadata := map[string]any{"name": name, "uid": uid, "resourceVersion": "rv-" + uid, "namespace": "payments"}
	api := "apps/v1"
	if kind == "Pod" || kind == "Node" {
		api = "v1"
	}
	if kind == "Node" {
		delete(metadata, "namespace")
	}
	return map[string]any{"apiVersion": api, "kind": kind, "metadata": metadata}
}
func targetOwner(kind, name, uid string) map[string]any {
	return map[string]any{"apiVersion": "apps/v1", "kind": kind, "name": name, "uid": uid, "controller": true}
}
func TestPodTargetsPinEntireOwnershipAndNodeChain(t *testing.T) {
	modes := []string{"valid-deployment", "valid-statefulset", "valid-unowned", "pod-replaced", "root-replaced", "replicaset-replaced", "wrong-root-owner", "controller-changed", "node-replaced", "node-rebooted", "node-changed", "unscheduled", "unexpected-controller", "duplicate-controller", "owner-case-alias", "denied", "late", "rollback"}
	for _, mode := range modes {
		t.Run(mode, func(t *testing.T) {
			var podReads, nodeReads atomic.Int64
			var clock *atomic.Int64
			f := newPermissionFixture(t, func(w http.ResponseWriter, r *http.Request) bool {
				var object map[string]any
				switch r.URL.Path {
				case "/api/v1/namespaces/payments/pods/app":
					count := podReads.Add(1)
					if mode == "denied" {
						w.WriteHeader(403)
						permissionReply(w, map[string]any{"apiVersion": "v1", "kind": "Status", "status": "Failure", "reason": "Forbidden", "code": 403, "message": "MUST-NOT-LEAK"})
						return true
					}
					object = targetMetadata("Pod", "app", "pod-uid")
					metadata := object["metadata"].(map[string]any)
					owner := targetOwner("ReplicaSet", "rs", "rs-uid")
					if mode == "valid-statefulset" {
						owner = targetOwner("StatefulSet", "app", "root-uid")
					}
					if mode == "pod-replaced" && count > 1 {
						metadata["uid"] = "replacement-pod"
					}
					if mode == "controller-changed" && count > 1 {
						owner["uid"] = "new-owner"
					}
					if mode == "owner-case-alias" {
						owner["UID"] = owner["uid"]
						delete(owner, "uid")
					}
					owners := []any{owner}
					if mode == "valid-unowned" {
						owners = nil
					}
					if mode == "duplicate-controller" {
						owners = append(owners, targetOwner("ReplicaSet", "other", "other-rs"))
					}
					metadata["ownerReferences"] = owners
					node := "node"
					if mode == "unscheduled" {
						node = ""
					}
					if mode == "node-changed" && count > 1 {
						node = "other"
					}
					object["spec"] = map[string]any{"nodeName": node, "containers": []any{map[string]any{"name": "secret-name", "env": []any{map[string]any{"name": "secret", "value": "MUST-NOT-LEAK"}}}}}
				case "/apis/apps/v1/namespaces/payments/replicasets/rs":
					object = targetMetadata("ReplicaSet", "rs", "rs-uid")
					metadata := object["metadata"].(map[string]any)
					if mode == "replicaset-replaced" {
						metadata["uid"] = "replacement-rs"
					}
					owner := targetOwner("Deployment", "app", "root-uid")
					if mode == "wrong-root-owner" {
						owner["uid"] = "other-deployment"
					}
					metadata["ownerReferences"] = []any{owner}
				case "/apis/apps/v1/namespaces/payments/deployments/app":
					object = targetMetadata("Deployment", "app", "root-uid")
					if mode == "root-replaced" {
						object["metadata"].(map[string]any)["uid"] = "new-root"
					}
				case "/apis/apps/v1/namespaces/payments/statefulsets/app":
					object = targetMetadata("StatefulSet", "app", "root-uid")
				case "/api/v1/nodes/node":
					count := nodeReads.Add(1)
					object = targetMetadata("Node", "node", "node-uid")
					boot := "11111111-1111-4111-8111-111111111111"
					if mode == "node-rebooted" && count > 1 {
						boot = "22222222-2222-4222-8222-222222222222"
					}
					if mode == "node-replaced" && count > 1 {
						object["metadata"].(map[string]any)["uid"] = "other-node"
					}
					object["status"] = map[string]any{"nodeInfo": map[string]any{"bootID": boot}}
					if mode == "late" {
						clock.Add(int64(3 * time.Second))
					}
					if mode == "rollback" {
						clock.Add(-int64(time.Second))
					}
				default:
					return false
				}
				permissionReply(w, object)
				return true
			})
			clock = f.clock
			reader, err := NewPodTargets(f.client)
			if err != nil {
				t.Fatal(err)
			}
			request := value.Request{ClusterID: permissionCluster, Namespace: cfg.NamespaceRef{Name: "payments", UID: "payments-uid"}, Workload: cfg.WorkloadRef{Kind: "Deployment", Name: "app", UID: "root-uid"}, PodName: "app", PodUID: "pod-uid"}
			if mode == "valid-statefulset" {
				request.Workload.Kind = "StatefulSet"
			}
			if mode == "valid-unowned" || mode == "unexpected-controller" {
				request.Workload.Kind = "Pod"
				request.Workload.UID = "pod-uid"
			}
			result, err := reader.ResolvePod(context.Background(), request)
			if strings.HasPrefix(mode, "valid-") {
				now := time.Unix(0, clock.Load())
				if err != nil || !result.Valid(now) || result.NodeUID != "node-uid" || result.Target().WorkloadUID != request.Workload.UID {
					t.Fatalf("resolution: %+v %v", result, err)
				}
				if result.FreshUntil.Sub(result.ObservedAt) != 5*time.Second || podReads.Load() != 2 || nodeReads.Load() != 2 {
					t.Fatal("missing identity recheck/freshness bound")
				}
				return
			}
			if err == nil || result.Request.ClusterID != "" || strings.Contains(err.Error(), "MUST-NOT-LEAK") {
				t.Fatalf("unsafe target result: %+v %v", result, err)
			}
			if mode == "denied" && !errors.Is(err, value.ErrDenied) {
				t.Fatal("permission failure concealed")
			}
			if mode == "unscheduled" && !errors.Is(err, value.ErrUnscheduled) {
				t.Fatal("unscheduled diagnostic lost")
			}
		})
	}
}
