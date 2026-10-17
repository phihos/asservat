package kubernetes

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	planner "asservat.local/asservat/internal/application/planning"
	"asservat.local/asservat/internal/domain/artifact"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/execution"
	plan "asservat.local/asservat/internal/domain/planning"
	value "asservat.local/asservat/internal/domain/targets"
)

func profileNetworkRequest() value.Request {
	return value.Request{ClusterID: permissionCluster, Namespace: cfg.NamespaceRef{Name: "payments", UID: "payments-uid"}, Workload: cfg.WorkloadRef{Kind: "Deployment", Name: "app", UID: "root-uid"}, PodName: "app", PodUID: "pod-uid"}
}

func profileNetworkPod() map[string]any {
	p := targetMetadata("Pod", "app", "pod-uid")
	p["metadata"].(map[string]any)["ownerReferences"] = []any{targetOwner("ReplicaSet", "rs", "rs-uid")}
	p["spec"] = map[string]any{"nodeName": "node", "containers": []any{map[string]any{"name": "MUST-NOT-LEAK", "env": []any{map[string]any{"name": "secret", "value": "MUST-NOT-LEAK"}}, "ports": []any{map[string]any{"name": "diagnostics", "containerPort": 6060}}}}, "initContainers": []any{map[string]any{"name": "sidecar", "restartPolicy": "Always", "ports": []any{map[string]any{"name": "9-metrics", "containerPort": 9090, "protocol": "TCP"}}}}, "ephemeralContainers": []any{map[string]any{"name": "debug"}}}
	p["status"] = map[string]any{"podIP": "10.0.0.5", "podIPs": []any{map[string]any{"ip": "10.0.0.5"}, map[string]any{"ip": "fd00::5"}}}
	return p
}

func profileNetworkAPIObject(path string) map[string]any {
	switch path {
	case "/apis/apps/v1/namespaces/payments/replicasets/rs":
		p := targetMetadata("ReplicaSet", "rs", "rs-uid")
		p["metadata"].(map[string]any)["ownerReferences"] = []any{targetOwner("Deployment", "app", "root-uid")}
		return p
	case "/apis/apps/v1/namespaces/payments/deployments/app":
		return targetMetadata("Deployment", "app", "root-uid")
	case "/api/v1/nodes/node":
		p := targetMetadata("Node", "node", "node-uid")
		p["status"] = map[string]any{"nodeInfo": map[string]any{"bootID": "22222222-2222-4222-8222-222222222222"}}
		return p
	}
	return nil
}

func TestProfileNetworkExactWholePodObservation(t *testing.T) {
	for _, mode := range []string{"valid", "init-duplicate", "host-network", "replacement", "changed-rv", "changed-port-rv", "node-reboot", "earlier-outer", "late", "denied"} {
		t.Run(mode, func(t *testing.T) {
			var pods, nodes atomic.Int64
			var clock *atomic.Int64
			f := newPermissionFixture(t, func(w http.ResponseWriter, r *http.Request) bool {
				p := profileNetworkAPIObject(r.URL.Path)
				if r.URL.Path == "/api/v1/namespaces/payments/pods/app" {
					n := pods.Add(1)
					p = profileNetworkPod()
					m := p["metadata"].(map[string]any)
					spec := p["spec"].(map[string]any)
					if mode == "denied" {
						w.WriteHeader(403)
						permissionReply(w, map[string]any{"apiVersion": "v1", "kind": "Status", "status": "Failure", "reason": "Forbidden", "code": 403, "message": "MUST-NOT-LEAK"})
						return true
					}
					if mode == "replacement" && n > 1 {
						m["uid"] = "replacement"
					}
					if (mode == "changed-rv" || mode == "changed-port-rv") && n > 1 {
						m["resourceVersion"] = "new-rv"
					}
					if mode == "changed-port-rv" && n > 1 {
						spec["containers"].([]any)[0].(map[string]any)["ports"].([]any)[0].(map[string]any)["containerPort"] = 6061
					}
					if mode == "init-duplicate" {
						spec["initContainers"].([]any)[0].(map[string]any)["ports"] = []any{map[string]any{"name": "diagnostics", "containerPort": 6060}}
					}
					if mode == "host-network" {
						spec["hostNetwork"] = true
					}
					if mode == "earlier-outer" && n == 1 {
						clock.Add(int64(2 * time.Second))
					}
				}
				if r.URL.Path == "/api/v1/nodes/node" {
					n := nodes.Add(1)
					if mode == "node-reboot" && n == 2 {
						p["status"].(map[string]any)["nodeInfo"].(map[string]any)["bootID"] = "33333333-3333-4333-8333-333333333333"
					}
					if mode == "late" && n == 2 {
						clock.Add(int64(6 * time.Second))
					}
				}
				if p == nil {
					return false
				}
				permissionReply(w, p)
				return true
			})
			clock = f.clock
			start := time.Unix(0, clock.Load()).UTC()
			reader, _ := NewPodTargets(f.client)
			got, err := reader.ObserveProfileNetwork(context.Background(), profileNetworkRequest())
			if mode == "valid" || mode == "init-duplicate" || mode == "host-network" || mode == "earlier-outer" {
				now := time.Unix(0, clock.Load()).UTC()
				if err != nil || !got.Valid(now) || got.Target.Request != profileNetworkRequest() || got.Target.PodResourceVersion != "rv-pod-uid" || got.PrimaryIP.String() != "10.0.0.5" || len(got.PodIPs) != 2 || len(got.Ports) != 2 || pods.Load() != 3 || nodes.Load() != 2 {
					t.Fatalf("observation: %+v %v", got, err)
				}
				if !got.Target.ObservedAt.Equal(start) || !got.Target.FreshUntil.Equal(start.Add(5*time.Second)) {
					t.Fatal("nested resolver renewed original outer interval")
				}
				b, _ := json.Marshal(got)
				if strings.Contains(string(b), "MUST-NOT-LEAK") || strings.Contains(string(b), "sidecar") {
					t.Fatal("container configuration leaked")
				}
				// Exercise the actual pure planner with the observed pod-wide facts.
				d := plan.GoEndpointDefinition{Source: plan.GoEndpointSource{ClusterID: permissionCluster, ResourceUID: "44444444-4444-4444-8444-444444444444", Name: "pprof", Digest: artifact.Digest{1}}, PathPolicy: plan.GoEndpointPathPolicy, Host: "pprof.example.invalid", AddressModes: []string{"targetLoopback"}, MinimumPort: 6000, MaximumPort: 6999, LoopbackFamily: "ipv4"}
				input := plan.GoEndpointInput{SourceRef: "local", Bindings: []plan.GoEndpointBinding{{Name: "local", TemplateRef: "pprof", AddressMode: "targetLoopback", PortName: "diagnostics"}}, Catalog: plan.GoEndpointCatalog{Templates: []plan.GoEndpointDefinition{d}, ObservedAt: now, FreshUntil: now.Add(5 * time.Second)}, Network: got, Parameters: execution.GoProfileParameters{Type: "heap", Mode: "snapshot"}, NativeLimit: 1024, Deadline: now.Add(5 * time.Second)}
				resolved, e := planner.ResolveGoProfileEndpoint(input, now)
				if mode == "init-duplicate" {
					if !errors.Is(e, plan.ErrProfileEndpointAmbiguous) {
						t.Fatal("init-sidecar duplicate not rejected", e)
					}
				} else if mode == "host-network" {
					if !errors.Is(e, plan.ErrProfileHostNetwork) {
						t.Fatal("host-network qualification gap hidden", e)
					}
				} else if e != nil || resolved.Port != 6060 || resolved.RouteIP.String() != "127.0.0.1" {
					t.Fatalf("synthetic API observer/planner boundary: %+v %v", resolved, e)
				}
				return
			}
			if err == nil || !reflect.DeepEqual(got, value.ProfileNetwork{}) || strings.Contains(err.Error(), "MUST-NOT-LEAK") {
				t.Fatalf("unsafe result: %+v %v", got, err)
			}
			if mode == "denied" && !errors.Is(err, value.ErrDenied) {
				t.Fatal("denial classification lost")
			}
		})
	}
}

func TestProfileNetworkRejectsMalformedAndUnboundedFields(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(map[string]any)
	}{
		{"port-case-alias", func(p map[string]any) {
			spec := p["spec"].(map[string]any)
			spec["containers"].([]any)[0].(map[string]any)["ports"] = []any{map[string]any{"name": "diagnostics", "ContainerPort": 6060}}
		}},
		{"ephemeral-ports", func(p map[string]any) {
			p["spec"].(map[string]any)["ephemeralContainers"] = []any{map[string]any{"name": "debug", "ports": []any{map[string]any{"containerPort": 6060}}}}
		}},
		{"oversized-port", func(p map[string]any) {
			p["spec"].(map[string]any)["containers"].([]any)[0].(map[string]any)["ports"] = []any{map[string]any{"containerPort": 65536}}
		}},
		{"too-many-ports", func(p map[string]any) {
			ports := make([]any, 257)
			for i := range ports {
				ports[i] = map[string]any{"containerPort": 6000 + i}
			}
			p["spec"].(map[string]any)["containers"].([]any)[0].(map[string]any)["ports"] = ports
		}},
		{"metadata-case-alias", func(p map[string]any) { m := p["metadata"].(map[string]any); m["UID"] = m["uid"]; delete(m, "uid") }},
		{"invalid-address", func(p map[string]any) { p["status"].(map[string]any)["podIP"] = "fd00::not-an-address" }},
		{"too-many-addresses", func(p map[string]any) {
			p["status"].(map[string]any)["podIPs"] = []any{map[string]any{"ip": "10.0.0.1"}, map[string]any{"ip": "10.0.0.2"}, map[string]any{"ip": "10.0.0.3"}}
		}},
		{"hostNetwork-null", func(p map[string]any) { p["spec"].(map[string]any)["hostNetwork"] = nil }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := profileNetworkPod()
			tc.change(p)
			raw, e := json.Marshal(p)
			if e != nil {
				t.Fatal(e)
			}
			_, _, err := decodeProfileNetwork(raw)
			if err == nil {
				t.Fatal("malformed routing fields accepted")
			}
		})
	}
}

func TestProfileNetworkPreservesCallerCancellationAndDeadline(t *testing.T) {
	t.Run("blocked-read", func(t *testing.T) {
		started := make(chan struct{})
		ended := make(chan struct{})
		f := newPermissionFixture(t, func(w http.ResponseWriter, r *http.Request) bool {
			if r.URL.Path != "/api/v1/namespaces/payments/pods/app" {
				return false
			}
			close(started)
			<-r.Context().Done()
			close(ended)
			return true
		})
		reader, _ := NewPodTargets(f.client)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		done := make(chan error, 1)
		go func() { _, err := reader.ObserveProfileNetwork(ctx, profileNetworkRequest()); done <- err }()
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatal("read did not start")
		}
		cancel()
		select {
		case err := <-done:
			if err == nil {
				t.Fatal("canceled observation returned success")
			}
		case <-time.After(time.Second):
			t.Fatal("canceled read did not join")
		}
		select {
		case <-ended:
		case <-time.After(time.Second):
			t.Fatal("API request was not canceled")
		}
	})
	t.Run("original-deadline", func(t *testing.T) {
		f := newPermissionFixture(t, func(w http.ResponseWriter, r *http.Request) bool {
			p := profileNetworkAPIObject(r.URL.Path)
			if r.URL.Path == "/api/v1/namespaces/payments/pods/app" {
				p = profileNetworkPod()
			}
			if p == nil {
				return false
			}
			permissionReply(w, p)
			return true
		})
		f.clock.Store(time.Now().UTC().UnixNano())
		reader, _ := NewPodTargets(f.client)
		deadline := time.Now().Add(time.Second)
		ctx, cancel := context.WithDeadline(context.Background(), deadline)
		defer cancel()
		got, err := reader.ObserveProfileNetwork(ctx, profileNetworkRequest())
		if err != nil || !got.Target.FreshUntil.Equal(deadline) {
			t.Fatal("original caller deadline not retained", err, got.Target.FreshUntil, deadline)
		}
	})
	t.Run("invalid-composition", func(t *testing.T) {
		var reader *PodTargets
		if _, err := reader.ObserveProfileNetwork(context.Background(), profileNetworkRequest()); err == nil {
			t.Fatal("nil reader accepted")
		}
		reader = &PodTargets{}
		if _, err := reader.ObserveProfileNetwork(nil, profileNetworkRequest()); err == nil {
			t.Fatal("nil context accepted")
		}
	})
}

func TestProfileNetworkNormalizesEquivalentIPAddresses(t *testing.T) {
	var pods atomic.Int64
	f := newPermissionFixture(t, func(w http.ResponseWriter, r *http.Request) bool {
		p := profileNetworkAPIObject(r.URL.Path)
		if r.URL.Path == "/api/v1/namespaces/payments/pods/app" {
			p = profileNetworkPod()
			primary := "fd00::5"
			if pods.Add(1) == 1 {
				primary = "FD00:0000:0000:0000:0000:0000:0000:0005"
			}
			p["status"] = map[string]any{"podIP": primary, "podIPs": []any{map[string]any{"ip": "fd00::5"}, map[string]any{"ip": "10.0.0.5"}}}
		}
		if p == nil {
			return false
		}
		permissionReply(w, p)
		return true
	})
	reader, _ := NewPodTargets(f.client)
	var first plan.GoEndpointPlan
	for i := 0; i < 2; i++ {
		network, err := reader.ObserveProfileNetwork(context.Background(), profileNetworkRequest())
		if err != nil || network.PrimaryIP.String() != "fd00::5" || network.PodIPs[0] != network.PrimaryIP {
			t.Fatalf("equivalent IPv6 representation rejected: %+v %v", network, err)
		}
		now := time.Unix(0, f.clock.Load()).UTC()
		d := plan.GoEndpointDefinition{Source: plan.GoEndpointSource{ClusterID: permissionCluster, ResourceUID: "44444444-4444-4444-8444-444444444444", Name: "pprof", Digest: artifact.Digest{1}}, PathPolicy: plan.GoEndpointPathPolicy, Host: "pprof.example.invalid", AddressModes: []string{"podIP"}, MinimumPort: 6000, MaximumPort: 6999}
		in := plan.GoEndpointInput{SourceRef: "local", Bindings: []plan.GoEndpointBinding{{Name: "local", TemplateRef: "pprof", AddressMode: "podIP", PortName: "diagnostics"}}, Catalog: plan.GoEndpointCatalog{Templates: []plan.GoEndpointDefinition{d}, ObservedAt: now, FreshUntil: now.Add(5 * time.Second)}, Network: network, Parameters: execution.GoProfileParameters{Type: "heap", Mode: "snapshot"}, NativeLimit: 1024, Deadline: now.Add(5 * time.Second)}
		resolved, err := planner.ResolveGoProfileEndpoint(in, now)
		if err != nil || resolved.RouteIP.String() != "fd00::5" {
			t.Fatalf("normalized route rejected: %+v %v", resolved, err)
		}
		if i == 0 {
			first = resolved
		} else if !reflect.DeepEqual(first, resolved) {
			t.Fatal("equivalent address presentation changed route or digest")
		}
	}
	if pods.Load() != 6 {
		t.Fatal("unexpected replacement or fallback read")
	}
}
