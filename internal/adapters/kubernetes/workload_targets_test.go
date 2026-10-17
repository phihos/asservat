package kubernetes

import (
	"context"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	value "asservat.local/asservat/internal/domain/targets"
	"k8s.io/client-go/rest"
)

func workloadFixturePod(name string) map[string]any {
	pod := targetMetadata("Pod", name, "pod-"+name)
	m := pod["metadata"].(map[string]any)
	m["labels"] = map[string]string{"app": "checkout", "track": "stable"}
	m["ownerReferences"] = []any{targetOwner("ReplicaSet", "rs", "rs-uid")}
	if name == "a-foreign" {
		m["ownerReferences"] = []any{targetOwner("ReplicaSet", "foreign-rs", "foreign-rs-uid")}
	}
	pod["spec"] = map[string]any{"nodeName": "node", "containers": []any{map[string]any{"name": "not-public", "env": []any{map[string]any{"name": "private", "value": "MUST-NOT-LEAK"}}}}}
	if name == "a-unscheduled" {
		pod["spec"].(map[string]any)["nodeName"] = ""
	}
	if name == "a-deleting" {
		m["deletionTimestamp"] = "2026-10-11T12:00:00Z"
	}
	return pod
}

func workloadClient(t *testing.T, clock *atomic.Int64, serve func(http.ResponseWriter, *http.Request)) *PodTargets {
	t.Helper()
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" || r.Header.Get("Authorization") != "Bearer synthetic-only" || r.URL.Query().Has("resourceVersion") || r.URL.Query().Has("resourceVersionMatch") {
			t.Error("target observation changed HTTP method, credential or cache semantics")
		}
		serve(w, r)
	}))
	t.Cleanup(s.Close)
	config := &rest.Config{Host: s.URL, BearerToken: "synthetic-only", TLSClientConfig: rest.TLSClientConfig{CAData: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.Certificate().Raw})}}
	client, err := NewPermissionClient(config, permissionCluster, permissionControl, func() time.Time { return time.Unix(0, clock.Load()).UTC() })
	if err != nil {
		t.Fatal(err)
	}
	resolver, err := NewPodTargets(client)
	if err != nil {
		t.Fatal(err)
	}
	return resolver
}

func TestNamedWorkloadResolutionPinsSelectedPodAndRealOwner(t *testing.T) {
	modes := []string{"deployment", "statefulset", "expressions", "frozen-request", "pod-deployment", "pod-statefulset", "pod-unowned", "pod-job", "pod-unscheduled", "foreign-only", "empty", "namespace-replaced", "workload-replaced", "pod-replaced", "node-rebooted", "list-denied", "list-incomplete", "list-remaining", "list-oversized", "list-wrong-label", "list-duplicate-name", "list-duplicate-uid", "list-missing-rv", "selector-empty", "selector-invalid", "selector-case-alias", "late-original", "clock-rollback"}
	for _, mode := range modes {
		t.Run(mode, func(t *testing.T) {
			var nsReads, rootReads, podReads, nodeReads, lists atomic.Int64
			var replace atomic.Bool
			clock := &atomic.Int64{}
			start := time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)
			clock.Store(start.UnixNano())
			kind := "Deployment"
			if mode == "statefulset" || mode == "pod-statefulset" {
				kind = "StatefulSet"
			}
			resolver := workloadClient(t, clock, func(w http.ResponseWriter, r *http.Request) {
				var object map[string]any
				switch r.URL.Path {
				case "/api/v1/namespaces/payments":
					count := nsReads.Add(1)
					uid := "payments-uid"
					if mode == "namespace-replaced" && count > 1 {
						uid = "replacement-ns"
					}
					object = permissionNamespace("payments", uid)
					if mode == "late-original" && (count == 1 || count == 3) {
						clock.Add(int64(3 * time.Second))
					}
				case "/apis/apps/v1/namespaces/payments/deployments/app", "/apis/apps/v1/namespaces/payments/statefulsets/app":
					count := rootReads.Add(1)
					object = targetMetadata(kind, "app", "root-uid")
					object["metadata"].(map[string]any)["generation"] = 1
					if mode == "workload-replaced" && count > 1 {
						object["metadata"].(map[string]any)["uid"] = "replacement-root"
					}
					selector := map[string]any{"matchLabels": map[string]string{"app": "checkout"}}
					if mode == "expressions" {
						selector["matchExpressions"] = []any{map[string]any{"key": "track", "operator": "In", "values": []string{"stable"}}}
					}
					if mode == "selector-empty" {
						selector = map[string]any{}
					}
					if mode == "selector-invalid" {
						selector["matchExpressions"] = []any{map[string]any{"key": "track", "operator": "Whatever"}}
					}
					if mode == "selector-case-alias" {
						selector["MatchLabels"] = selector["matchLabels"]
						delete(selector, "matchLabels")
					}
					object["spec"] = map[string]any{"selector": selector}
					if mode == "clock-rollback" {
						clock.Store(start.Add(-time.Second).UnixNano())
					}
				case "/api/v1/namespaces/payments/pods":
					lists.Add(1)
					if mode == "list-denied" {
						w.WriteHeader(403)
						permissionReply(w, map[string]any{"apiVersion": "v1", "kind": "Status", "reason": "Forbidden", "status": "Failure", "message": "MUST-NOT-LEAK", "code": 403})
						return
					}
					selector := "app=checkout"
					if mode == "expressions" {
						selector += ",track in (stable)"
					}
					if r.URL.Query().Get("labelSelector") != selector || r.URL.Query().Get("limit") != "257" || r.URL.Query().Get("timeout") != "5s" || len(r.URL.Query()) != 3 {
						t.Errorf("unexpected candidate enumeration: %s", r.URL.RawQuery)
					}
					items := []any{workloadFixturePod("z-app"), workloadFixturePod("a-foreign"), workloadFixturePod("b-app"), workloadFixturePod("a-unscheduled"), workloadFixturePod("a-deleting")}
					if mode == "foreign-only" {
						items = []any{workloadFixturePod("a-foreign")}
					}
					if mode == "empty" {
						items = []any{}
					}
					if mode == "list-oversized" {
						items = nil
						for n := range workloadCandidateLimit + 1 {
							items = append(items, workloadFixturePod(fmt.Sprintf("pod-%03d", n)))
						}
					}
					if mode == "list-duplicate-name" {
						items = append(items, workloadFixturePod("b-app"))
					}
					if mode == "list-duplicate-uid" {
						items[0].(map[string]any)["metadata"].(map[string]any)["uid"] = "pod-b-app"
					}
					if mode == "list-wrong-label" {
						items[0].(map[string]any)["metadata"].(map[string]any)["labels"] = map[string]string{"app": "other"}
					}
					metadata := map[string]any{"resourceVersion": "list-rv", "continue": ""}
					if mode == "list-incomplete" {
						metadata["continue"] = "more"
					}
					if mode == "list-missing-rv" {
						delete(metadata, "resourceVersion")
					}
					if mode == "list-remaining" {
						metadata["remainingItemCount"] = 3
					}
					object = map[string]any{"apiVersion": "v1", "kind": "PodList", "metadata": metadata, "items": items}
				case "/api/v1/namespaces/payments/pods/a-foreign":
					object = workloadFixturePod("a-foreign")
				case "/api/v1/namespaces/payments/pods/b-app":
					count := podReads.Add(1)
					object = workloadFixturePod("b-app")
					m := object["metadata"].(map[string]any)
					if (mode == "pod-replaced" && count > 1) || replace.Load() {
						m["uid"] = "replacement-pod"
					}
					if kind == "StatefulSet" {
						m["ownerReferences"] = []any{targetOwner(kind, "app", "root-uid")}
					}
					if mode == "pod-unowned" {
						delete(m, "ownerReferences")
					}
					if mode == "pod-job" {
						owner := targetOwner("Job", "job", "job-uid")
						owner["apiVersion"] = "batch/v1"
						m["ownerReferences"] = []any{owner}
					}
					if mode == "pod-unscheduled" {
						object["spec"].(map[string]any)["nodeName"] = ""
					}
				case "/apis/apps/v1/namespaces/payments/replicasets/rs", "/apis/apps/v1/namespaces/payments/replicasets/foreign-rs":
					name := "rs"
					rootName, rootUID := "app", "root-uid"
					if strings.HasSuffix(r.URL.Path, "/foreign-rs") {
						name, rootName, rootUID = "foreign-rs", "other", "other-root"
					}
					object = targetMetadata("ReplicaSet", name, name+"-uid")
					object["metadata"].(map[string]any)["ownerReferences"] = []any{targetOwner("Deployment", rootName, rootUID)}
				case "/api/v1/nodes/node":
					count := nodeReads.Add(1)
					boot := "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
					if mode == "node-rebooted" && count > 1 {
						boot = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
					}
					object = targetMetadata("Node", "node", "node-uid")
					object["status"] = map[string]any{"nodeInfo": map[string]any{"bootID": boot}}
				default:
					t.Errorf("unexpected API path: %s", r.URL.Path)
					http.NotFound(w, r)
					return
				}
				permissionReply(w, object)
			})
			r := value.WorkloadRequest{ClusterID: permissionCluster, Namespace: "payments", Kind: kind, Name: "app"}
			if strings.HasPrefix(mode, "pod-") && mode != "pod-replaced" {
				r.Kind, r.Name = "Pod", "b-app"
			}
			out, err := resolver.ResolveWorkload(context.Background(), r)
			success := mode == "deployment" || mode == "statefulset" || mode == "expressions" || mode == "frozen-request" || mode == "pod-deployment" || mode == "pod-statefulset" || mode == "pod-unowned"
			if success {
				if err != nil || !out.Valid(time.Unix(0, clock.Load())) || out.Request.PodName != "b-app" || out.Request.PodUID != "pod-b-app" || out.Request.Namespace.UID != "payments-uid" || out.NodeUID != "node-uid" || !out.ObservedAt.Equal(start) || !out.FreshUntil.Equal(start.Add(5*time.Second)) {
					t.Fatalf("selection failed or pins changed: %+v, %v", out, err)
				}
				if mode == "pod-unowned" {
					if out.Request.Workload.Kind != "Pod" || out.Request.Workload.UID != "pod-b-app" {
						t.Fatal("unowned pod did not keep its own identity")
					}
				} else if out.Request.Workload.Kind != kind || out.Request.Workload.UID != "root-uid" {
					t.Fatal("public Pod reference bypassed actual workload identity")
				}
			} else if err == nil || out != (value.PodResolution{}) || strings.Contains(fmt.Sprint(err), "MUST-NOT-LEAK") {
				t.Fatalf("invalid selection admitted or leaked partial data: %+v, %v", out, err)
			}
			if (mode == "list-incomplete" || mode == "list-oversized" || mode == "list-remaining") && !errors.Is(err, value.ErrLimit) {
				t.Fatalf("incomplete enumeration was not a limit failure: %v", err)
			}
			if (mode == "foreign-only" || mode == "empty") && !errors.Is(err, value.ErrNoScheduledPods) {
				t.Fatalf("missing own pods: %v", err)
			}
			if mode == "pod-job" && !errors.Is(err, value.ErrUnsupported) {
				t.Fatalf("unsupported owner accepted: %v", err)
			}
			if r.Kind == "Pod" && lists.Load() != 0 {
				t.Fatal("explicit pod selection listed or selected another pod")
			}
			if mode == "frozen-request" {
				replace.Store(true)
				if _, err := resolver.ResolvePod(context.Background(), out.Request); !errors.Is(err, value.ErrChanged) || lists.Load() != 1 {
					t.Fatalf("frozen selection was silently reselected or replaced: %v", err)
				}
			}
		})
	}
}

func TestNamedWorkloadRejectsInvalidScopeAndCancellation(t *testing.T) {
	clock := &atomic.Int64{}
	clock.Store(time.Now().UnixNano())
	entered := make(chan struct{})
	var calls atomic.Int64
	resolver := workloadClient(t, clock, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		close(entered)
		<-r.Context().Done()
	})
	for _, r := range []value.WorkloadRequest{
		{ClusterID: "22222222-2222-4222-8222-222222222222", Namespace: "payments", Kind: "Deployment", Name: "app"},
		{ClusterID: permissionCluster, Namespace: "payments/../other", Kind: "Deployment", Name: "app"},
		{ClusterID: permissionCluster, Namespace: "payments", Kind: "Deployment", Name: "../other"},
		{ClusterID: permissionCluster, Namespace: "payments", Kind: "Container", Name: "app"},
	} {
		if _, err := resolver.ResolveWorkload(context.Background(), r); !errors.Is(err, value.ErrInvalid) {
			t.Fatalf("invalid scope admitted: %v", err)
		}
	}
	if calls.Load() != 0 {
		t.Fatal("invalid reference caused API reads")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() {
		_, err := resolver.ResolveWorkload(ctx, value.WorkloadRequest{ClusterID: permissionCluster, Namespace: "payments", Kind: "Deployment", Name: "app"})
		result <- err
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("request did not enter actual TLS API")
	}
	cancel()
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("canceled observation succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("canceled API observation did not finish")
	}
}
