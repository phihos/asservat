package bootstrap

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/application/delivery"
	"asservat.local/asservat/internal/domain/collector"
	"asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/targets"
	"k8s.io/client-go/rest"
)

func TestRegionalArgumentSourceRequiresSyscallNodeAndOriginalBound(t *testing.T) {
	for _, mode := range []string{"syscall", "packet only", "stale", "wrong node", "replacement pod", "cancelled"} {
		t.Run(mode, func(t *testing.T) {
			now := time.Now().UTC().Truncate(time.Microsecond)
			api := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet || r.Header.Get("Authorization") != "Bearer synthetic" {
					t.Error("unexpected target request")
				}
				var obj map[string]any
				switch r.URL.Path {
				case "/api/v1/namespaces/synthetic":
					obj = map[string]any{"apiVersion": "v1", "kind": "Namespace", "metadata": map[string]any{"name": "synthetic", "uid": "ns-uid", "resourceVersion": "1"}}
				case "/api/v1/namespaces/synthetic/pods/app":
					uid := "pod-uid"
					if mode == "replacement pod" {
						uid = "replacement"
					}
					node := "worker"
					if mode == "wrong node" {
						node = "replacement"
					}
					obj = map[string]any{"apiVersion": "v1", "kind": "Pod", "metadata": map[string]any{"name": "app", "namespace": "synthetic", "uid": uid, "resourceVersion": "1", "ownerReferences": []any{map[string]any{"apiVersion": "apps/v1", "kind": "StatefulSet", "name": "app", "uid": "workload-uid", "controller": true}}}, "spec": map[string]any{"nodeName": node}, "status": map[string]any{"phase": "Running"}}
				case "/apis/apps/v1/namespaces/synthetic/statefulsets/app":
					obj = map[string]any{"apiVersion": "apps/v1", "kind": "StatefulSet", "metadata": map[string]any{"name": "app", "namespace": "synthetic", "uid": "workload-uid", "resourceVersion": "1"}}
				default:
					t.Errorf("unexpected discovery %s", r.URL.Path)
					w.WriteHeader(http.StatusForbidden)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(obj)
			}))
			defer api.Close()
			client, err := kube.NewPermissionClient(&rest.Config{Host: api.URL, BearerToken: "synthetic", TLSClientConfig: rest.TLSClientConfig{CAData: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: api.Certificate().Raw})}}, runtimeID, configuration.NamespaceRef{Name: "control", UID: "control-uid"}, func() time.Time { return now })
			if err != nil {
				t.Fatal(err)
			}
			pods, err := kube.NewAPIContextTargets(client)
			if err != nil {
				t.Fatal(err)
			}
			mechanism := collector.MechanismSyscall
			if mode == "packet only" {
				mechanism = collector.MechanismPacket
			}
			nodes := &packetTargetNodes{view: delivery.NodeView{Identity: collector.Identity{NodeUID: "node-uid", BootID: "boot", PodUID: "collector", Epoch: "epoch"}, Current: mode != "stale", ReportedAt: now.Add(-time.Second), Report: &collector.Report{Mechanisms: []collector.Availability{{Mechanism: mechanism, Prerequisites: true, Adapter: collector.AdapterAvailable}}}}}
			resolver := reportedTargets{PodTargets: pods, recordings: &ConnectorRecordings{nodes: nodes, now: func() time.Time { return now }}}
			ctx, cancel := context.WithDeadline(t.Context(), now.Add(3*time.Second))
			defer cancel()
			if mode == "cancelled" {
				cancel()
			}
			request := targets.Request{ClusterID: runtimeID, Namespace: configuration.NamespaceRef{Name: "synthetic", UID: "ns-uid"}, Workload: configuration.WorkloadRef{Kind: "StatefulSet", Name: "app", UID: "workload-uid"}, PodName: "app", PodUID: "pod-uid"}
			got, err := resolver.ResolveArgumentSource(ctx, request)
			if mode != "syscall" {
				if err == nil && got.ValidSource(now) {
					t.Fatal("unqualified source accepted", mode, got)
				}
				return
			}
			if err != nil || !got.ValidSource(now) || got.Target.Request != request || got.Target.Pin.NodeName != "" || got.Recorder.Source.NodeUID != nodes.view.Identity.NodeUID || got.Recorder.Source.CollectorEpoch != nodes.view.Identity.Epoch || got.Recorder.Source.FreshUntil.After(now.Add(3*time.Second)) || len(nodes.names) != 1 {
				t.Fatal("argument source lost exact identity or original bound", got, err)
			}
		})
	}
}
