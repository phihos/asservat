package targets

import (
	"errors"
	"math/rand/v2"
	"slices"
	"testing"

	"asservat.local/asservat/internal/domain/configuration"
)

const peerCluster = "11111111-1111-4111-8111-111111111111"

func peerRequest(max int, entries ...PeerEntry) PeerRequest {
	return PeerRequest{ClusterID: peerCluster, Namespace: configuration.NamespaceRef{Name: "shop", UID: "ns-uid"}, Entries: entries, MaxEndpoints: max}
}

func ref(kind, name string) PeerEntry {
	return PeerEntry{Resource: &PeerResourceRef{Kind: kind, Namespace: "shop", Name: name}}
}

func service(name, mode string, readyOnly bool) PeerEntry {
	return PeerEntry{Resource: &PeerResourceRef{Kind: "Service", Namespace: "shop", Name: name, ServiceMode: mode, ReadyOnly: readyOnly}}
}

func selector(labels map[string]string) PeerEntry {
	return PeerEntry{Pods: &PeerPodSelector{Namespace: "shop", MatchLabels: labels}}
}

func ready(b bool) *bool { return &b }

// peerSnapshot is a synthetic namespace: a Deployment "api" with a current
// and an old ReplicaSet, a StatefulSet "db", a foreign ReplicaSet, a
// terminated Pod, a hostNetwork Pod and Services over them.
func peerSnapshot() PeerSnapshot {
	return PeerSnapshot{
		Namespace: "shop",
		Pods: []PeerPod{
			{Name: "api-a", UID: "pod-api-a", Labels: map[string]string{"app": "api"}, IPs: []string{"10.0.0.11", "fd00::11"}, ControllerKind: "ReplicaSet", ControllerUID: "rs-new", Phase: "Running"},
			{Name: "api-b", UID: "pod-api-b", Labels: map[string]string{"app": "api"}, IPs: []string{"10.0.0.12"}, ControllerKind: "ReplicaSet", ControllerUID: "rs-old", Phase: "Running"},
			{Name: "api-done", UID: "pod-api-done", Labels: map[string]string{"app": "api"}, IPs: []string{"10.0.0.13"}, ControllerKind: "ReplicaSet", ControllerUID: "rs-new", Phase: "Succeeded"},
			{Name: "imposter", UID: "pod-imposter", Labels: map[string]string{"app": "api"}, IPs: []string{"10.0.0.14"}, ControllerKind: "ReplicaSet", ControllerUID: "rs-foreign", Phase: "Running"},
			{Name: "db-0", UID: "pod-db-0", Labels: map[string]string{"app": "db"}, IPs: []string{"10.0.0.21"}, ControllerKind: "StatefulSet", ControllerUID: "sts-db", Phase: "Running"},
			{Name: "db-1", UID: "pod-db-1", Labels: map[string]string{"app": "db"}, IPs: []string{"10.0.0.22"}, ControllerKind: "StatefulSet", ControllerUID: "sts-db", Phase: "Pending"},
			{Name: "agent", UID: "pod-agent", Labels: map[string]string{"app": "agent"}, IPs: []string{"192.168.1.5"}, Phase: "Running", HostNetwork: true},
		},
		ReplicaSets: []PeerOwned{{Name: "api-new", UID: "rs-new", ControllerKind: "Deployment", ControllerUID: "dep-api"}, {Name: "api-old", UID: "rs-old", ControllerKind: "Deployment", ControllerUID: "dep-api"}, {Name: "other", UID: "rs-foreign", ControllerKind: "Deployment", ControllerUID: "dep-other"}},
		Workloads:   []PeerWorkload{{Kind: "Deployment", Name: "api", UID: "dep-api"}, {Kind: "StatefulSet", Name: "db", UID: "sts-db"}},
		Services: []PeerService{
			{Name: "api", UID: "svc-api", Type: "ClusterIP", Selector: map[string]string{"app": "api"}, ClusterIPs: []string{"10.96.0.10", "fd00:96::10"}},
			{Name: "db", UID: "svc-db", Type: "ClusterIP", Selector: map[string]string{"app": "db"}, ClusterIPs: []string{"None"}},
			{Name: "external", UID: "svc-ext", Type: "ExternalName"},
			{Name: "manual", UID: "svc-manual", Type: "ClusterIP", ClusterIPs: []string{"10.96.0.20"}},
			{Name: "agent", UID: "svc-agent", Type: "ClusterIP", Selector: map[string]string{"app": "agent"}, ClusterIPs: []string{"10.96.0.30"}},
		},
		EndpointSlices: []PeerEndpointSlice{
			// api-a appears in two slices (dedup); api-b is not ready.
			{ServiceName: "api", ServiceUID: "svc-api", Managed: true, AddressType: "IPv4", Endpoints: []PeerEndpoint{{Addresses: []string{"10.0.0.11"}, Ready: ready(true), PodUID: "pod-api-a"}, {Addresses: []string{"10.0.0.12"}, Ready: ready(false), PodUID: "pod-api-b"}}},
			{ServiceName: "api", ServiceUID: "svc-api", Managed: true, AddressType: "IPv4", Endpoints: []PeerEndpoint{{Addresses: []string{"10.0.0.11"}, PodUID: "pod-api-a"}}},
			{ServiceName: "api", ServiceUID: "svc-api", Managed: true, AddressType: "IPv6", Endpoints: []PeerEndpoint{{Addresses: []string{"fd00::11"}, Ready: ready(true), PodUID: "pod-api-a"}}},
			// Forged: unmanaged, foreign owner, address not the Pod's, no targetRef.
			{ServiceName: "api", ServiceUID: "svc-api", Managed: false, AddressType: "IPv4", Endpoints: []PeerEndpoint{{Addresses: []string{"203.0.113.9"}, PodUID: "pod-api-a"}}},
			{ServiceName: "api", ServiceUID: "svc-other", Managed: true, AddressType: "IPv4", Endpoints: []PeerEndpoint{{Addresses: []string{"10.0.0.14"}, PodUID: "pod-imposter"}}},
			{ServiceName: "api", ServiceUID: "svc-api", Managed: true, AddressType: "IPv4", Endpoints: []PeerEndpoint{{Addresses: []string{"203.0.113.10"}, PodUID: "pod-api-b"}, {Addresses: []string{"10.0.0.12"}}}},
			{ServiceName: "db", ServiceUID: "svc-db", Managed: true, AddressType: "IPv4", Endpoints: []PeerEndpoint{{Addresses: []string{"10.0.0.21"}, Ready: ready(true), PodUID: "pod-db-0"}}},
			{ServiceName: "agent", ServiceUID: "svc-agent", Managed: true, AddressType: "IPv4", Endpoints: []PeerEndpoint{{Addresses: []string{"192.168.1.5"}, PodUID: "pod-agent"}}},
		},
	}
}

func m(kind, uid, ip string) PeerMember { return PeerMember{kind, uid, ip} }

func TestResolvePeers(t *testing.T) {
	for name, tc := range map[string]struct {
		request PeerRequest
		want    []PeerMember
		err     error
	}{
		"deployment via replicasets": {peerRequest(16, ref("Deployment", "api")), []PeerMember{m("Pod", "pod-api-a", "10.0.0.11"), m("Pod", "pod-api-b", "10.0.0.12"), m("Pod", "pod-api-a", "fd00::11")}, nil},
		"statefulset":                {peerRequest(16, ref("StatefulSet", "db")), []PeerMember{m("Pod", "pod-db-0", "10.0.0.21"), m("Pod", "pod-db-1", "10.0.0.22")}, nil},
		"pod":                        {peerRequest(16, ref("Pod", "db-0")), []PeerMember{m("Pod", "pod-db-0", "10.0.0.21")}, nil},
		"terminated pod is empty":    {peerRequest(16, ref("Pod", "api-done")), []PeerMember{}, nil},
		"pod selector":               {peerRequest(16, selector(map[string]string{"app": "api"})), []PeerMember{m("Pod", "pod-api-a", "10.0.0.11"), m("Pod", "pod-api-b", "10.0.0.12"), m("Pod", "pod-imposter", "10.0.0.14"), m("Pod", "pod-api-a", "fd00::11")}, nil},
		"service backends dedup":     {peerRequest(16, service("api", "backends", false)), []PeerMember{m("Pod", "pod-api-a", "10.0.0.11"), m("Pod", "pod-api-b", "10.0.0.12"), m("Pod", "pod-api-a", "fd00::11")}, nil},
		"service readyOnly":          {peerRequest(16, service("api", "backends", true)), []PeerMember{m("Pod", "pod-api-a", "10.0.0.11"), m("Pod", "pod-api-a", "fd00::11")}, nil},
		"service virtualIP":          {peerRequest(16, service("api", "virtualIP", false)), []PeerMember{m("Service", "svc-api", "10.96.0.10"), m("Service", "svc-api", "fd00:96::10")}, nil},
		"service both":               {peerRequest(16, service("api", "both", true)), []PeerMember{m("Pod", "pod-api-a", "10.0.0.11"), m("Service", "svc-api", "10.96.0.10"), m("Pod", "pod-api-a", "fd00::11"), m("Service", "svc-api", "fd00:96::10")}, nil},
		"entries union":              {peerRequest(16, ref("Pod", "db-0"), service("db", "backends", false), ref("Pod", "db-0")), []PeerMember{m("Pod", "pod-db-0", "10.0.0.21")}, nil},
		"headless backends":          {peerRequest(16, service("db", "backends", false)), []PeerMember{m("Pod", "pod-db-0", "10.0.0.21")}, nil},
		"headless virtualIP":         {peerRequest(16, service("db", "virtualIP", false)), nil, ErrPeerUnsupported},
		"external name":              {peerRequest(16, service("external", "backends", false)), nil, ErrPeerUnsupported},
		"selectorless":               {peerRequest(16, service("manual", "virtualIP", false)), nil, ErrPeerUnsupported},
		"host network pod":           {peerRequest(16, ref("Pod", "agent")), nil, ErrPeerUnsupported},
		"host network backend":       {peerRequest(16, service("agent", "backends", false)), nil, ErrPeerUnsupported},
		"missing":                    {peerRequest(16, ref("Deployment", "gone")), nil, ErrPeerMissing},
		"missing service":            {peerRequest(16, service("gone", "both", false)), nil, ErrPeerMissing},
		"maxEndpoints exceeded":      {peerRequest(2, ref("Deployment", "api")), nil, ErrPeerLimit},
		"other namespace":            {PeerRequest{ClusterID: peerCluster, Namespace: configuration.NamespaceRef{Name: "shop", UID: "ns-uid"}, Entries: []PeerEntry{{Resource: &PeerResourceRef{Kind: "Pod", Namespace: "admin", Name: "db-0"}}}, MaxEndpoints: 4}, nil, ErrInvalid},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := ResolvePeers(tc.request, peerSnapshot())
			if !errors.Is(err, tc.err) || (tc.err == nil) != (err == nil) {
				t.Fatalf("error %v, want %v", err, tc.err)
			}
			if tc.err == nil && !slices.Equal(got, tc.want) {
				t.Fatalf("members %v, want %v", got, tc.want)
			}
			if tc.err == nil && !(PeerResolution{Request: tc.request, Members: got}).Answers(tc.request) {
				t.Fatal("a resolver result is not a canonical answer")
			}
		})
	}
}

// The members do not depend on LIST order.
func TestResolvePeersIgnoresListOrder(t *testing.T) {
	r := peerRequest(16, service("api", "both", false), ref("StatefulSet", "db"))
	want, err := ResolvePeers(r, peerSnapshot())
	if err != nil {
		t.Fatal(err)
	}
	for seed := range uint64(20) {
		s := peerSnapshot()
		rng := rand.New(rand.NewPCG(seed, seed))
		rng.Shuffle(len(s.Pods), func(i, j int) { s.Pods[i], s.Pods[j] = s.Pods[j], s.Pods[i] })
		rng.Shuffle(len(s.EndpointSlices), func(i, j int) { s.EndpointSlices[i], s.EndpointSlices[j] = s.EndpointSlices[j], s.EndpointSlices[i] })
		rng.Shuffle(len(s.ReplicaSets), func(i, j int) { s.ReplicaSets[i], s.ReplicaSets[j] = s.ReplicaSets[j], s.ReplicaSets[i] })
		got, err := ResolvePeers(r, s)
		if err != nil || !slices.Equal(got, want) {
			t.Fatalf("seed %d: %v %v", seed, got, err)
		}
	}
}

func TestPeerRequestAndAnswerBounds(t *testing.T) {
	good := peerRequest(4, ref("Pod", "db-0"))
	for name, r := range map[string]PeerRequest{
		"no entries":        peerRequest(4),
		"bad label":         peerRequest(4, selector(map[string]string{"app": "-x"})),
		"empty labels":      peerRequest(4, selector(map[string]string{})),
		"service no mode":   peerRequest(4, service("api", "", false)),
		"pod with mode":     peerRequest(4, PeerEntry{Resource: &PeerResourceRef{Kind: "Pod", Namespace: "shop", Name: "x", ServiceMode: "backends"}}),
		"kind":              peerRequest(4, ref("DaemonSet", "x")),
		"max endpoints":     peerRequest(4097, ref("Pod", "x")),
		"foreign namespace": {ClusterID: peerCluster, Namespace: configuration.NamespaceRef{Name: "shop", UID: "u"}, Entries: []PeerEntry{selector(map[string]string{"a": "b"})}, MaxEndpoints: 1},
	} {
		if name == "foreign namespace" {
			r.Entries[0].Pods.Namespace = "kube-system"
		}
		if r.Valid() {
			t.Errorf("%s: valid", name)
		}
	}
	if !good.Valid() {
		t.Fatal("valid request refused")
	}
	for name, members := range map[string][]PeerMember{
		"unsorted":      {m("Pod", "b", "10.0.0.2"), m("Pod", "a", "10.0.0.1")},
		"duplicate":     {m("Pod", "a", "10.0.0.1"), m("Pod", "a", "10.0.0.1")},
		"non canonical": {m("Pod", "a", "fd00:0::1")},
		"mapped":        {m("Pod", "a", "::ffff:10.0.0.1")},
		"loopback":      {m("Pod", "a", "127.0.0.1")},
		"kind":          {m("Node", "a", "10.0.0.1")},
		"too many":      {m("Pod", "a", "10.0.0.1"), m("Pod", "b", "10.0.0.2"), m("Pod", "c", "10.0.0.3"), m("Pod", "d", "10.0.0.4"), m("Pod", "e", "10.0.0.5")},
	} {
		if (PeerResolution{Request: good, Members: members}).Answers(good) {
			t.Errorf("%s: answer accepted", name)
		}
	}
	other := good
	other.Entries = []PeerEntry{ref("Pod", "db-1")}
	if (PeerResolution{Request: other}).Answers(good) {
		t.Fatal("an answer to another query was accepted")
	}
}
