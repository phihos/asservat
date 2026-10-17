package targets

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	cfg "asservat.local/asservat/internal/domain/configuration"
)

func TestProfileNetworkRetainsPodWideRoutingFacts(t *testing.T) {
	now := time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)
	fixture := func() ProfileNetwork {
		r := Request{ClusterID: "11111111-1111-4111-8111-111111111111", Namespace: cfg.NamespaceRef{Name: "app", UID: "namespace"}, Workload: cfg.WorkloadRef{Kind: "Pod", Name: "app", UID: "pod"}, PodName: "app", PodUID: "pod"}
		p := PodResolution{Request: r, Pin: artifact.PinnedPod{Namespace: "app", NamespaceUID: "namespace", Name: "app", UID: "pod", NodeName: "node"}, NodeUID: "node", NodeBootID: "22222222-2222-4222-8222-222222222222", PodResourceVersion: "12", WorkloadResourceVersion: "12", ObservedAt: now, FreshUntil: now.Add(5 * time.Second)}
		return ProfileNetwork{Target: p, Ports: []ProfilePodPort{{Name: "debug", Protocol: "TCP", Port: 6060}}, PrimaryIP: netip.MustParseAddr("10.4.0.2"), PodIPs: []netip.Addr{netip.MustParseAddr("10.4.0.2"), netip.MustParseAddr("fd00::2")}}
	}
	for _, tc := range []struct {
		name   string
		change func(*ProfileNetwork)
	}{
		{"wrong-primary", func(p *ProfileNetwork) { p.PrimaryIP = netip.MustParseAddr("10.4.0.3") }},
		{"duplicate-family", func(p *ProfileNetwork) { p.PodIPs[1] = netip.MustParseAddr("10.4.0.3") }},
		{"loopback-pod-ip", func(p *ProfileNetwork) { p.PrimaryIP = netip.MustParseAddr("127.0.0.1"); p.PodIPs = nil }},
		{"metadata-ip", func(p *ProfileNetwork) { p.PrimaryIP = netip.MustParseAddr("169.254.169.254"); p.PodIPs = nil }},
		{"mapped-address", func(p *ProfileNetwork) { p.PrimaryIP = netip.MustParseAddr("::ffff:10.4.0.2"); p.PodIPs = nil }},
		{"missing-primary", func(p *ProfileNetwork) { p.PrimaryIP = netip.Addr{} }},
		{"old-target", func(p *ProfileNetwork) { p.Target.FreshUntil = now }},
		{"invalid-protocol", func(p *ProfileNetwork) { p.Ports[0].Protocol = "HTTP" }},
		{"invalid-port", func(p *ProfileNetwork) { p.Ports[0].Port = 0 }},
		{"API-target", func(p *ProfileNetwork) {
			p.Target.ExecutionClass = artifact.ContextAPIExecution
			p.Target.NodeUID = ""
			p.Target.NodeBootID = ""
			p.Target.Pin.NodeName = ""
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := fixture()
			if !p.Valid(now) {
				t.Fatal("fixture")
			}
			tc.change(&p)
			if p.Valid(now) {
				t.Fatal("unsafe routing facts accepted")
			}
		})
	}
	p := fixture()
	p.PrimaryIP = netip.Addr{}
	p.PodIPs = nil
	if !p.Valid(now) {
		t.Fatal("unallocated IP must permit loopback planning")
	}
	p = fixture()
	p.Ports = append(p.Ports, p.Ports[0])
	if !p.Valid(now) {
		t.Fatal("observer must retain duplicate declarations for resolver ambiguity")
	}
	p.HostNetwork = true
	if !p.Valid(now) {
		t.Fatal("observer must retain host-network fact for explicit unavailable reason")
	}
}

func TestProfilePortNameMatchesPublicSyntax(t *testing.T) {
	for _, tc := range []struct {
		name  string
		valid bool
	}{
		{"a", true}, {"a0", true}, {"a-0", true}, {"a--b", true},
		{strings.Repeat("a", 15), true},
		{"", false}, {"0", false}, {"9-metrics", false}, {"Diagnostics", false},
		{"a-", false}, {"-a", false}, {"a_b", false}, {"a/b", false},
		{"a b", false}, {"a\n", false}, {"é", false},
		{strings.Repeat("a", 16), false},
	} {
		if ProfilePortName(tc.name) != tc.valid {
			t.Fatalf("public port name %q accepted=%t want=%t", tc.name, ProfilePortName(tc.name), tc.valid)
		}
	}
}
