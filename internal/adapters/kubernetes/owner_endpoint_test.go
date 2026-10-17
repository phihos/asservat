package kubernetes

import (
	"context"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	cfg "asservat.local/asservat/internal/domain/configuration"
	value "asservat.local/asservat/internal/domain/fleet"
	apps "k8s.io/api/apps/v1"
	core "k8s.io/api/core/v1"
	discovery "k8s.io/api/discovery/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/rest"
	"k8s.io/utils/ptr"
)

func ownerID(n int) string { return fmt.Sprintf("00000000-0000-4000-8000-%012d", n) }

type ownerObjects struct {
	pool    value.OwnerPool
	binding value.OwnerBinding
	ns      core.Namespace
	svc     core.Service
	sa      core.ServiceAccount
	deploy  apps.Deployment
	pod     core.Pod
	rs      apps.ReplicaSet
	list    discovery.EndpointSliceList
}

func ownerFixtureObjects() ownerObjects {
	p := value.OwnerPool{InstallationID: ownerID(1), ClusterID: ownerID(2), IssuerEpoch: ownerID(3), Namespace: "owners", NamespaceUID: ownerID(4), Service: "hub-owner", ServiceUID: ownerID(5), Deployment: "hub", DeploymentUID: ownerID(6), ServiceAccount: "hub", AccountUID: ownerID(7), Port: 9443}
	b := value.OwnerBinding{InstallationID: p.InstallationID, ClusterID: p.ClusterID, IssuerEpoch: p.IssuerEpoch, PodUID: ownerID(8), ProcessEpoch: ownerID(9)}
	m := func(name, uid string) meta.ObjectMeta {
		return meta.ObjectMeta{Name: name, Namespace: p.Namespace, UID: types.UID(uid), ResourceVersion: "10"}
	}
	ref := func(kind, version, name, uid string) meta.OwnerReference {
		return meta.OwnerReference{APIVersion: version, Kind: kind, Name: name, UID: types.UID(uid), Controller: ptr.To(true)}
	}
	labels := map[string]string{"app": "hub"}
	v := ownerObjects{pool: p, binding: b,
		ns:     core.Namespace{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "Namespace"}, ObjectMeta: m(p.Namespace, p.NamespaceUID)},
		svc:    core.Service{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "Service"}, ObjectMeta: m(p.Service, p.ServiceUID), Spec: core.ServiceSpec{Type: core.ServiceTypeClusterIP, ClusterIP: "None", Selector: labels, Ports: []core.ServicePort{{Name: "owner-control", Protocol: core.ProtocolTCP, Port: 9443, TargetPort: intstr.FromInt(9443)}}}},
		sa:     core.ServiceAccount{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "ServiceAccount"}, ObjectMeta: m(p.ServiceAccount, p.AccountUID)},
		deploy: apps.Deployment{TypeMeta: meta.TypeMeta{APIVersion: "apps/v1", Kind: "Deployment"}, ObjectMeta: m(p.Deployment, p.DeploymentUID), Spec: apps.DeploymentSpec{Selector: &meta.LabelSelector{MatchLabels: labels}}},
		pod:    core.Pod{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "Pod"}, ObjectMeta: m("hub-rs-pod", b.PodUID), Spec: core.PodSpec{ServiceAccountName: p.ServiceAccount, NodeName: "node"}, Status: core.PodStatus{Phase: core.PodRunning, Conditions: []core.PodCondition{{Type: core.PodReady, Status: core.ConditionTrue}}, PodIPs: []core.PodIP{{IP: "10.2.3.4"}}}},
		rs:     apps.ReplicaSet{TypeMeta: meta.TypeMeta{APIVersion: "apps/v1", Kind: "ReplicaSet"}, ObjectMeta: m("hub-rs", ownerID(10))},
		list:   discovery.EndpointSliceList{TypeMeta: meta.TypeMeta{APIVersion: "discovery.k8s.io/v1", Kind: "EndpointSliceList"}, ListMeta: meta.ListMeta{ResourceVersion: "10"}},
	}
	v.ns.Namespace = ""
	v.pod.Labels = labels
	v.pod.OwnerReferences = []meta.OwnerReference{ref("ReplicaSet", "apps/v1", v.rs.Name, string(v.rs.UID))}
	v.rs.OwnerReferences = []meta.OwnerReference{ref("Deployment", "apps/v1", p.Deployment, p.DeploymentUID)}
	item := discovery.EndpointSlice{ObjectMeta: m("hub-owner-slice", ownerID(11)), AddressType: discovery.AddressTypeIPv4, Ports: []discovery.EndpointPort{{Name: ptr.To("owner-control"), Protocol: ptr.To(core.ProtocolTCP), Port: ptr.To(int32(p.Port))}}, Endpoints: []discovery.Endpoint{{Addresses: []string{"10.2.3.4"}, NodeName: ptr.To("node"), Conditions: discovery.EndpointConditions{Ready: ptr.To(true)}, TargetRef: &core.ObjectReference{APIVersion: "v1", Kind: "Pod", Namespace: p.Namespace, Name: v.pod.Name, UID: v.pod.UID}}}}
	item.Labels = map[string]string{"kubernetes.io/service-name": p.Service, "endpointslice.kubernetes.io/managed-by": "endpointslice-controller.k8s.io"}
	item.OwnerReferences = []meta.OwnerReference{ref("Service", "v1", p.Service, p.ServiceUID)}
	v.list.Items = []discovery.EndpointSlice{item}
	return v
}

func TestOwnerEndpointBoundedDiscovery(t *testing.T) {
	cases := map[string]func(*ownerObjects){
		"valid":           func(*ownerObjects) {},
		"installed-owner": setInstalledOwnerEndpointPorts,
		"installed-reordered": func(v *ownerObjects) {
			setInstalledOwnerEndpointPorts(v)
			v.list.Items[0].Ports[0], v.list.Items[0].Ports[2] = v.list.Items[0].Ports[2], v.list.Items[0].Ports[0]
		},
		"installed-unopted":           func(v *ownerObjects) { setInstalledOwnerEndpointPorts(v); v.pool.NativeBootstrap = "" },
		"installed-unknown-profile":   func(v *ownerObjects) { setInstalledOwnerEndpointPorts(v); v.pool.NativeBootstrap = "unknown/v1" },
		"installed-wrong-native-port": func(v *ownerObjects) { setInstalledOwnerEndpointPorts(v); v.pool.NativePort++ },
		"installed-wrong-owner-port":  func(v *ownerObjects) { setInstalledOwnerEndpointPorts(v); v.pool.Port += 2 },
		"installed-service-missing":   func(v *ownerObjects) { setInstalledOwnerEndpointPorts(v); v.svc.Spec.Ports = v.svc.Spec.Ports[:2] },
		"installed-service-extra": func(v *ownerObjects) {
			setInstalledOwnerEndpointPorts(v)
			v.svc.Spec.Ports = append(v.svc.Spec.Ports, core.ServicePort{Name: "extra", Protocol: core.ProtocolTCP, Port: 9446, TargetPort: intstr.FromInt(9446)})
		},
		"installed-service-duplicate": func(v *ownerObjects) { setInstalledOwnerEndpointPorts(v); v.svc.Spec.Ports[2] = v.svc.Spec.Ports[1] },
		"installed-service-number":    func(v *ownerObjects) { setInstalledOwnerEndpointPorts(v); v.svc.Spec.Ports[1].Port++ },
		"installed-service-target": func(v *ownerObjects) {
			setInstalledOwnerEndpointPorts(v)
			v.svc.Spec.Ports[1].TargetPort = intstr.FromString("observation")
		},
		"installed-service-protocol": func(v *ownerObjects) {
			setInstalledOwnerEndpointPorts(v)
			v.svc.Spec.Ports[1].Protocol = core.ProtocolUDP
		},
		"installed-slice-missing": func(v *ownerObjects) {
			setInstalledOwnerEndpointPorts(v)
			v.list.Items[0].Ports = v.list.Items[0].Ports[:2]
		},
		"installed-slice-extra": func(v *ownerObjects) {
			setInstalledOwnerEndpointPorts(v)
			v.list.Items[0].Ports = append(v.list.Items[0].Ports, discovery.EndpointPort{Name: ptr.To("extra"), Protocol: ptr.To(core.ProtocolTCP), Port: ptr.To(int32(9446))})
		},
		"installed-slice-duplicate": func(v *ownerObjects) {
			setInstalledOwnerEndpointPorts(v)
			v.list.Items[0].Ports[2] = v.list.Items[0].Ports[1]
		},
		"installed-slice-number": func(v *ownerObjects) {
			setInstalledOwnerEndpointPorts(v)
			v.list.Items[0].Ports[1].Port = ptr.To(int32(9446))
		},
		"installed-slice-unknown-protocol": func(v *ownerObjects) { setInstalledOwnerEndpointPorts(v); v.list.Items[0].Ports[1].Protocol = nil },
		"legacy-owner-alias": func(v *ownerObjects) {
			v.svc.Spec.Ports[0].Name = "owner"
			v.list.Items[0].Ports[0].Name = ptr.To("owner")
		},

		"omitted-target-version": func(v *ownerObjects) { v.list.Items[0].Endpoints[0].TargetRef.APIVersion = "" },
		"foreign-target-version": func(v *ownerObjects) { v.list.Items[0].Endpoints[0].TargetRef.APIVersion = "apps/v1" },
		"dual-stack": func(v *ownerObjects) {
			other := v.list.Items[0].DeepCopy()
			other.Name += "-v6"
			other.UID = types.UID(ownerID(12))
			other.AddressType = discovery.AddressTypeIPv6
			other.Endpoints[0].Addresses = []string{"fd00::4"}
			v.list.Items = append(v.list.Items, *other)
			v.pod.Status.PodIPs = append(v.pod.Status.PodIPs, core.PodIP{IP: "fd00::4"})
		},
		"duplicate-observation":  func(v *ownerObjects) { v.list.Items = append(v.list.Items, *v.list.Items[0].DeepCopy()) },
		"foreign-namespace":      func(v *ownerObjects) { v.ns.UID = types.UID(ownerID(99)) },
		"foreign-service":        func(v *ownerObjects) { v.svc.UID = types.UID(ownerID(99)) },
		"foreign-account":        func(v *ownerObjects) { v.sa.UID = types.UID(ownerID(99)) },
		"foreign-deployment":     func(v *ownerObjects) { v.deploy.UID = types.UID(ownerID(99)) },
		"replacement-pod":        func(v *ownerObjects) { v.pod.UID = types.UID(ownerID(99)) },
		"replacement-replicaset": func(v *ownerObjects) { v.rs.UID = types.UID(ownerID(99)) },
		"wrong-controller":       func(v *ownerObjects) { v.rs.OwnerReferences[0].UID = types.UID(ownerID(99)) },
		"two-controllers":        func(v *ownerObjects) { v.pod.OwnerReferences = append(v.pod.OwnerReferences, v.pod.OwnerReferences[0]) },
		"missing-controller":     func(v *ownerObjects) { v.pod.OwnerReferences = nil },
		"deleted-pod":            func(v *ownerObjects) { v.pod.DeletionTimestamp = &meta.Time{Time: time.Now()} },
		"not-ready":              func(v *ownerObjects) { v.pod.Status.Conditions[0].Status = core.ConditionFalse },
		"wrong-selector":         func(v *ownerObjects) { v.pod.Labels = map[string]string{"app": "other"} },
		"host-network":           func(v *ownerObjects) { v.pod.Spec.HostNetwork = true },
		"wrong-pod-account":      func(v *ownerObjects) { v.pod.Spec.ServiceAccountName = "other" },
		"wrong-node":             func(v *ownerObjects) { v.pod.Spec.NodeName = "other" },
		"external-service":       func(v *ownerObjects) { v.svc.Spec.Type = core.ServiceTypeExternalName },
		"publish-not-ready":      func(v *ownerObjects) { v.svc.Spec.PublishNotReadyAddresses = true },
		"named-port":             func(v *ownerObjects) { v.svc.Spec.Ports[0].TargetPort = intstr.FromString("owner-control") },
		"wrong-slice-owner":      func(v *ownerObjects) { v.list.Items[0].OwnerReferences[0].UID = types.UID(ownerID(99)) },
		"manual-slice":           func(v *ownerObjects) { v.list.Items[0].Labels["endpointslice.kubernetes.io/managed-by"] = "untrusted" },
		"unknown-readiness":      func(v *ownerObjects) { v.list.Items[0].Endpoints[0].Conditions.Ready = nil },
		"terminating":            func(v *ownerObjects) { v.list.Items[0].Endpoints[0].Conditions.Terminating = ptr.To(true) },
		"not-serving":            func(v *ownerObjects) { v.list.Items[0].Endpoints[0].Conditions.Serving = ptr.To(false) },
		"wrong-port":             func(v *ownerObjects) { v.list.Items[0].Ports[0].Port = ptr.To(int32(443)) },
		"wrong-family":           func(v *ownerObjects) { v.list.Items[0].AddressType = discovery.AddressTypeIPv6 },
		"wrong-ip":               func(v *ownerObjects) { v.list.Items[0].Endpoints[0].Addresses[0] = "10.2.3.5" },
		"loopback": func(v *ownerObjects) {
			v.list.Items[0].Endpoints[0].Addresses[0] = "127.0.0.1"
			v.pod.Status.PodIPs[0].IP = "127.0.0.1"
		},
		"missing-pod": func(v *ownerObjects) { v.list.Items[0].Endpoints[0].TargetRef.UID = types.UID(ownerID(99)) },
		"too-many-endpoints": func(v *ownerObjects) {
			for len(v.list.Items[0].Endpoints) < 1025 {
				v.list.Items[0].Endpoints = append(v.list.Items[0].Endpoints, v.list.Items[0].Endpoints[0])
			}
		},
		"too-many-slices": func(v *ownerObjects) {
			for len(v.list.Items) < 65 {
				v.list.Items = append(v.list.Items, v.list.Items[0])
			}
		},
		"continuation-loop":   func(v *ownerObjects) { v.list.Continue = "same-token" },
		"changed-service":     func(*ownerObjects) {},
		"changed-pod":         func(*ownerObjects) {},
		"expired-observation": func(*ownerObjects) {},
		"unavailable":         func(*ownerObjects) {},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			v := ownerFixtureObjects()
			mutate(&v)
			var clock atomic.Int64
			clock.Store(time.Now().UTC().UnixNano())
			calls := map[string]int{}
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != "GET" || r.Header.Get("Authorization") != "Bearer synthetic-owner" {
					t.Error("unexpected authority request")
				}
				calls[r.URL.Path]++
				if calls[r.URL.Path] > 3 {
					t.Error("unbounded discovery")
					http.Error(w, "unavailable", 503)
					return
				}
				base := "/api/v1/namespaces/" + v.pool.Namespace
				appsBase := "/apis/apps/v1/namespaces/" + v.pool.Namespace
				var obj any
				switch r.URL.Path {
				case base:
					obj = v.ns
				case base + "/services/" + v.pool.Service:
					if name == "changed-service" && calls[r.URL.Path] > 1 {
						v.svc.ResourceVersion = "11"
					}
					obj = v.svc
				case base + "/serviceaccounts/" + v.pool.ServiceAccount:
					obj = v.sa
				case appsBase + "/deployments/" + v.pool.Deployment:
					obj = v.deploy
				case appsBase + "/replicasets/" + v.rs.Name:
					obj = v.rs
				case base + "/pods/" + v.pod.Name:
					if name == "changed-pod" && calls[r.URL.Path] > 1 {
						v.pod.ResourceVersion = "11"
					}
					if name == "expired-observation" {
						clock.Add(int64(5 * time.Second))
					}
					obj = v.pod
				case "/apis/discovery.k8s.io/v1/namespaces/" + v.pool.Namespace + "/endpointslices":
					if r.URL.Query().Get("labelSelector") != "kubernetes.io/service-name="+v.pool.Service || r.URL.Query().Get("limit") != "64" {
						t.Error("unbounded selector")
					}
					if name == "unavailable" {
						http.Error(w, "unavailable", 503)
						return
					}
					obj = v.list
				default:
					t.Error("unexpected path", r.URL.Path)
					http.NotFound(w, r)
					return
				}
				permissionReply(w, obj)
			}))
			defer server.Close()
			client, err := NewPermissionClient(&rest.Config{Host: server.URL, BearerToken: "synthetic-owner", TLSClientConfig: rest.TLSClientConfig{CAData: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})}}, v.pool.ClusterID, cfg.NamespaceRef{Name: v.pool.Namespace, UID: v.pool.NamespaceUID}, func() time.Time { return time.Unix(0, clock.Load()).UTC() })
			if err != nil {
				t.Fatal(err)
			}
			reader, err := NewOwnerEndpoints(client, v.pool)
			if err != nil {
				if name == "installed-unknown-profile" {
					return
				}
				t.Fatal(err)
			}
			got, err := reader.OwnerEndpoint(context.Background(), v.binding)
			want := name == "valid" || name == "omitted-target-version" || name == "dual-stack" || name == "duplicate-observation" || name == "installed-owner" || name == "installed-reordered"
			if (err == nil) != want {
				t.Fatalf("success=%v error=%v", err == nil, err)
			}
			if want {
				addresses := []string{"10.2.3.4"}
				if name == "dual-stack" {
					addresses = append(addresses, "fd00::4")
				}
				if !got.Valid(time.Unix(0, clock.Load()).UTC()) || got.Binding != v.binding || got.Pool != v.pool || !reflect.DeepEqual(got.Addresses, addresses) {
					t.Fatal("invalid discovery result")
				}
			} else if got.Binding.Valid() || len(got.Addresses) != 0 {
				t.Fatal("partial discovery escaped")
			}
		})
	}
}

func setInstalledOwnerEndpointPorts(v *ownerObjects) {
	v.pool.NativeBootstrap = value.OwnerBootstrapProfile
	v.pool.NativePort = 9444
	v.svc.Spec.Ports = nil
	v.list.Items[0].Ports = nil
	for _, p := range []struct {
		name   string
		number int32
	}{{"owner", 9443}, {"observation", 9444}, {"public", 9445}} {
		v.svc.Spec.Ports = append(v.svc.Spec.Ports, core.ServicePort{Name: p.name, Protocol: core.ProtocolTCP, Port: p.number, TargetPort: intstr.FromInt32(p.number)})
		v.list.Items[0].Ports = append(v.list.Items[0].Ports, discovery.EndpointPort{Name: ptr.To(p.name), Protocol: ptr.To(core.ProtocolTCP), Port: ptr.To(p.number)})
	}
}
