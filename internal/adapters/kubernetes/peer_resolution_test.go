package kubernetes

import (
	"errors"
	"fmt"
	"net/http"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	cfg "asservat.local/asservat/internal/domain/configuration"
	value "asservat.local/asservat/internal/domain/targets"
)

func peerFixturePod(name, uid, ip string, owner map[string]any) map[string]any {
	pod := targetMetadata("Pod", name, uid)
	m := pod["metadata"].(map[string]any)
	m["labels"] = map[string]string{"app": "api"}
	if owner != nil {
		m["ownerReferences"] = []any{owner}
	}
	pod["spec"] = map[string]any{"containers": []any{map[string]any{"name": "app", "env": []any{map[string]any{"name": "secret", "value": "MUST-NOT-LEAK"}}}}}
	pod["status"] = map[string]any{"phase": "Running", "podIP": ip, "podIPs": []any{map[string]any{"ip": ip}}}
	return pod
}

func peerNotFound(w http.ResponseWriter) {
	w.WriteHeader(404)
	permissionReply(w, map[string]any{"apiVersion": "v1", "kind": "Status", "reason": "NotFound", "status": "Failure", "code": 404})
}

// ADR-283 PR 2: the region reads only the target namespace with bounded,
// paged, consistent LISTs and answers resolved members, never objects.
func TestResolvePacketPeersReadsTheTargetNamespace(t *testing.T) {
	ns := cfg.NamespaceRef{Name: "payments", UID: "payments-uid"}
	deployment := value.PeerEntry{Resource: &value.PeerResourceRef{Kind: "Deployment", Namespace: "payments", Name: "api"}}
	svc := func(name, mode string) value.PeerEntry {
		return value.PeerEntry{Resource: &value.PeerResourceRef{Kind: "Service", Namespace: "payments", Name: name, ServiceMode: mode}}
	}
	for name, tc := range map[string]struct {
		entry value.PeerEntry
		mode  string
		want  []value.PeerMember
		err   error
	}{
		"deployment paged":   {deployment, "", []value.PeerMember{{Kind: "Pod", UID: "pod-a", IP: "10.0.0.11"}, {Kind: "Pod", UID: "pod-b", IP: "10.0.0.12"}}, nil},
		"service both":       {svc("api", "both"), "", []value.PeerMember{{Kind: "Pod", UID: "pod-a", IP: "10.0.0.11"}, {Kind: "Service", UID: "svc-uid", IP: "10.96.0.10"}}, nil},
		"external name":      {svc("external", "backends"), "", nil, value.ErrPeerUnsupported},
		"missing":            {svc("gone", "backends"), "", nil, value.ErrPeerMissing},
		"namespace replaced": {deployment, "namespace-replaced", nil, value.ErrChanged},
		"inconsistent pages": {deployment, "inconsistent", nil, value.ErrUnavailable},
		"endless pagination": {deployment, "endless", nil, value.ErrPeerLimit},
		"denied":             {deployment, "denied", nil, value.ErrUnavailable},
		"foreign replicaset": {deployment, "foreign-rs", []value.PeerMember{{Kind: "Pod", UID: "pod-a", IP: "10.0.0.11"}}, nil},
		"too many endpoints": {deployment, "limit", nil, value.ErrPeerLimit},
	} {
		t.Run(name, func(t *testing.T) {
			clock := &atomic.Int64{}
			clock.Store(time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC).UnixNano())
			var podLists atomic.Int64
			targets := workloadClient(t, clock, func(w http.ResponseWriter, r *http.Request) {
				var object map[string]any
				switch r.URL.Path {
				case "/api/v1/namespaces/payments":
					uid := "payments-uid"
					if tc.mode == "namespace-replaced" {
						uid = "other-uid"
					}
					object = permissionNamespace("payments", uid)
				case "/apis/apps/v1/namespaces/payments/deployments/api":
					object = targetMetadata("Deployment", "api", "dep-uid")
					object["metadata"].(map[string]any)["generation"] = 1
					object["spec"] = map[string]any{"selector": map[string]any{"matchLabels": map[string]string{"app": "api"}}}
				case "/apis/apps/v1/namespaces/payments/replicasets/api-1":
					object = targetMetadata("ReplicaSet", "api-1", "rs-1")
					object["metadata"].(map[string]any)["ownerReferences"] = []any{targetOwner("Deployment", "api", "dep-uid")}
				case "/apis/apps/v1/namespaces/payments/replicasets/api-2":
					object = targetMetadata("ReplicaSet", "api-2", "rs-2")
					owner := "dep-uid"
					if tc.mode == "foreign-rs" {
						owner = "other-dep"
					}
					object["metadata"].(map[string]any)["ownerReferences"] = []any{targetOwner("Deployment", "api", owner)}
				case "/api/v1/namespaces/payments/services/api":
					object = map[string]any{"apiVersion": "v1", "kind": "Service", "metadata": map[string]any{"name": "api", "namespace": "payments", "uid": "svc-uid"}, "spec": map[string]any{"type": "ClusterIP", "selector": map[string]string{"app": "api"}, "clusterIP": "10.96.0.10", "clusterIPs": []string{"10.96.0.10"}}}
				case "/api/v1/namespaces/payments/services/external":
					object = map[string]any{"apiVersion": "v1", "kind": "Service", "metadata": map[string]any{"name": "external", "namespace": "payments", "uid": "ext-uid"}, "spec": map[string]any{"type": "ExternalName", "externalName": "db.example.invalid"}}
				case "/api/v1/namespaces/payments/services/gone":
					peerNotFound(w)
					return
				case "/api/v1/namespaces/payments/pods":
					n := podLists.Add(1)
					if tc.mode == "denied" {
						w.WriteHeader(403)
						permissionReply(w, map[string]any{"apiVersion": "v1", "kind": "Status", "reason": "Forbidden", "status": "Failure", "code": 403})
						return
					}
					if r.URL.Query().Get("labelSelector") != "app=api" || r.URL.Query().Get("limit") != "256" {
						t.Errorf("unexpected Pod LIST %s", r.URL.RawQuery)
					}
					list := map[string]any{"apiVersion": "v1", "kind": "PodList", "metadata": map[string]any{"resourceVersion": "rv-1"}}
					switch {
					case tc.mode == "endless":
						list["metadata"].(map[string]any)["continue"] = fmt.Sprint("page-", n)
						list["items"] = []any{}
					case tc.mode == "limit":
						var items []any
						for i := range 256 {
							items = append(items, peerFixturePod(fmt.Sprint("p", i), fmt.Sprint("pod-", i), fmt.Sprintf("10.1.%d.%d", i/200, i%200+1), targetOwner("ReplicaSet", "api-1", "rs-1")))
						}
						list["items"] = items
					case r.URL.Query().Get("continue") == "":
						list["metadata"].(map[string]any)["continue"] = "next"
						list["items"] = []any{peerFixturePod("a", "pod-a", "10.0.0.11", targetOwner("ReplicaSet", "api-1", "rs-1"))}
					default:
						if tc.mode == "inconsistent" {
							list["metadata"].(map[string]any)["resourceVersion"] = "rv-2"
						}
						list["items"] = []any{peerFixturePod("b", "pod-b", "10.0.0.12", targetOwner("ReplicaSet", "api-2", "rs-2"))}
					}
					object = list
				case "/apis/discovery.k8s.io/v1/namespaces/payments/endpointslices":
					if r.URL.Query().Get("labelSelector") != "kubernetes.io/service-name=api" {
						t.Errorf("unexpected EndpointSlice LIST %s", r.URL.RawQuery)
					}
					object = map[string]any{"apiVersion": "discovery.k8s.io/v1", "kind": "EndpointSliceList", "metadata": map[string]any{"resourceVersion": "rv-3"}, "items": []any{
						map[string]any{"metadata": map[string]any{"name": "api-x", "namespace": "payments", "labels": map[string]string{"kubernetes.io/service-name": "api", "endpointslice.kubernetes.io/managed-by": "endpointslice-controller.k8s.io"}, "ownerReferences": []any{map[string]any{"apiVersion": "v1", "kind": "Service", "name": "api", "uid": "svc-uid", "controller": true}}},
							"addressType": "IPv4", "endpoints": []any{
								map[string]any{"addresses": []string{"10.0.0.11"}, "conditions": map[string]any{"ready": true}, "targetRef": map[string]any{"kind": "Pod", "namespace": "payments", "name": "a", "uid": "pod-a"}},
								// Not a listed Pod's address: never a member.
								map[string]any{"addresses": []string{"203.0.113.9"}, "conditions": map[string]any{"ready": true}, "targetRef": map[string]any{"kind": "Pod", "namespace": "payments", "name": "a", "uid": "pod-a"}},
							}},
					}}
				default:
					t.Errorf("unexpected read %s", r.URL.Path)
					peerNotFound(w)
					return
				}
				permissionReply(w, object)
			})
			r := value.PeerRequest{ClusterID: permissionCluster, Namespace: ns, Entries: []value.PeerEntry{tc.entry}, MaxEndpoints: 4096}
			if tc.mode == "limit" {
				r.MaxEndpoints = 8
			}
			if tc.entry.Resource.Kind == "Service" {
				r.Entries[0].Resource.ServiceMode = map[string]string{"api": "both", "external": "backends", "gone": "backends"}[tc.entry.Resource.Name]
			}
			got, err := targets.ResolvePacketPeers(t.Context(), r)
			if !errors.Is(err, tc.err) || (tc.err == nil) != (err == nil) {
				t.Fatalf("error %v, want %v", err, tc.err)
			}
			if tc.err == nil && (!slices.Equal(got.Members, tc.want) || !got.Answers(r) || !got.ResolvedAt.IsZero()) {
				t.Fatalf("resolution %+v", got)
			}
		})
	}
}
