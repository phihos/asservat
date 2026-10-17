package planning

import (
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/execution"
	value "asservat.local/asservat/internal/domain/planning"
	"asservat.local/asservat/internal/domain/targets"
)

func endpointID(n int) string { return fmt.Sprintf("00000000-0000-4000-8000-%012d", n) }

func endpointInput() (value.GoEndpointInput, time.Time) {
	now := time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)
	r := targets.Request{ClusterID: endpointID(1), Namespace: cfg.NamespaceRef{Name: "payments", UID: endpointID(2)}, Workload: cfg.WorkloadRef{Kind: "Deployment", Name: "api", UID: endpointID(3)}, PodName: "api-pod", PodUID: endpointID(4)}
	p := targets.PodResolution{Request: r, Pin: artifact.PinnedPod{Namespace: r.Namespace.Name, NamespaceUID: r.Namespace.UID, Name: r.PodName, UID: r.PodUID, NodeName: "node", ControllerUID: endpointID(7)}, NodeUID: endpointID(5), NodeBootID: endpointID(6), PodResourceVersion: "37", WorkloadResourceVersion: "14", ObservedAt: now.Add(-time.Second), FreshUntil: now.Add(4 * time.Second)}
	d := value.GoEndpointDefinition{Source: value.GoEndpointSource{ClusterID: r.ClusterID, ResourceUID: endpointID(8), Name: "go-pprof", Digest: artifact.Digest{1}}, PathPolicy: value.GoEndpointPathPolicy, Host: "pprof.example.invalid", AddressModes: []string{"targetLoopback", "podIP"}, MinimumPort: 6000, MaximumPort: 6999, LoopbackFamily: "ipv4"}
	in := value.GoEndpointInput{SourceRef: "local-pprof", Bindings: []value.GoEndpointBinding{{Name: "local-pprof", TemplateRef: "go-pprof", AddressMode: "targetLoopback", PortName: "diagnostics"}}, Catalog: value.GoEndpointCatalog{Templates: []value.GoEndpointDefinition{d}, ObservedAt: now.Add(-2 * time.Second), FreshUntil: now.Add(3 * time.Second)}, Network: targets.ProfileNetwork{Target: p, Ports: []targets.ProfilePodPort{{Name: "diagnostics", Port: 6060, Protocol: "TCP"}}, PrimaryIP: netip.MustParseAddr("10.0.0.3"), PodIPs: []netip.Addr{netip.MustParseAddr("10.0.0.3"), netip.MustParseAddr("fd00::3")}}, Parameters: execution.GoProfileParameters{Type: "cpu", Mode: "interval", Duration: 10 * time.Second}, NativeLimit: 16 << 20, Deadline: now.Add(2 * time.Second)}
	return in, now
}

func addEndpointCredential(in *value.GoEndpointInput) {
	d := &in.Catalog.Templates[0]
	trust := d.Source
	trust.ResourceUID = endpointID(9)
	trust.Name = "pprof-trust"
	policy := d.Source
	policy.ResourceUID = endpointID(10)
	policy.Name = "pprof-credential"
	d.TLS = &value.GoEndpointTLS{Trust: trust, ServerName: "pprof.example.invalid"}
	r := in.Network.Target.Request
	d.Credential = &value.GoEndpointCredential{Policy: policy, Audiences: []value.GoEndpointAudience{{ClusterID: r.ClusterID, NamespaceUID: r.Namespace.UID, WorkloadKind: r.Workload.Kind, WorkloadUID: r.Workload.UID}}}
}

func TestGoEndpointResolvesExistingRecipeAndAdministratorProfiles(t *testing.T) {
	for _, mode := range []string{"loopback-v4", "loopback-v6", "pod-ip", "administrator", "statefulset", "unowned-pod", "control-namespace-source"} {
		t.Run(mode, func(t *testing.T) {
			in, now := endpointInput()
			expectedIP := "127.0.0.1"
			expectedKind := "templateBinding"
			switch mode {
			case "control-namespace-source":
				in.Catalog.Templates[0].Source.NamespaceUID = endpointID(90)
				in.Catalog.Templates[0].ScopeNamespaceUID = in.Network.Target.Request.Namespace.UID
				addEndpointCredential(&in)
			case "loopback-v6":
				in.Catalog.Templates[0].LoopbackFamily = "ipv6"
				expectedIP = "::1"
			case "pod-ip":
				in.Bindings[0].AddressMode = "podIP"
				expectedIP = "10.0.0.3"
			case "administrator":
				d := in.Catalog.Templates[0]
				d.Source.Name = "local-pprof"
				in.Catalog.Templates = nil
				in.Catalog.Profiles = []value.GoEndpointProfile{{Definition: d, AddressMode: "podIP", Port: 6061}}
				in.Bindings = nil
				in.Network.Ports = nil
				expectedIP = "10.0.0.3"
				expectedKind = "administratorProfile"
			case "statefulset":
				in.Network.Target.Request.Workload.Kind = "StatefulSet"
				in.Network.Target.Pin.ControllerUID = in.Network.Target.Request.Workload.UID
			case "unowned-pod":
				r := &in.Network.Target.Request
				r.Workload = cfg.WorkloadRef{Kind: "Pod", Name: r.PodName, UID: r.PodUID}
				in.Network.Target.Pin.ControllerUID = ""
			}
			p, err := ResolveGoProfileEndpoint(in, now)
			if err != nil || p.RouteIP.String() != expectedIP || p.SourceKind != expectedKind || p.EndpointDigest == (artifact.Digest{}) || p.DefinitionDigest == (artifact.Digest{}) || p.Pin != in.Network.Target.Pin || p.Target != in.Network.Target.Request || p.NodeBootID != in.Network.Target.NodeBootID {
				t.Fatalf("resolution: %+v %v", p, err)
			}
			if !p.ValidUntil.Equal(in.Deadline) || !p.ObservedAt.Equal(in.Catalog.ObservedAt) {
				t.Fatal("original observation/caller bound lost")
			}
			if mode == "administrator" && (p.Port != 6061 || p.DeclaredPortName != "") {
				t.Fatal("fully configured profile incorrectly requires declaration")
			}
			if mode != "administrator" && (p.Port != 6060 || p.DeclaredPortName != "diagnostics") {
				t.Fatal("declared port not bound")
			}
		})
	}
}

func TestGoEndpointRejectsAmbiguityAndCredentialRedirection(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*value.GoEndpointInput)
		want   error
	}{
		{"duplicate-declaration", func(in *value.GoEndpointInput) { in.Network.Ports = append(in.Network.Ports, in.Network.Ports[0]) }, value.ErrProfileEndpointAmbiguous},
		{"same-name-different-port", func(in *value.GoEndpointInput) {
			p := in.Network.Ports[0]
			p.Port++
			in.Network.Ports = append(in.Network.Ports, p)
		}, value.ErrProfileEndpointAmbiguous},
		{"same-name-UDP", func(in *value.GoEndpointInput) {
			p := in.Network.Ports[0]
			p.Protocol = "UDP"
			in.Network.Ports = append(in.Network.Ports, p)
		}, value.ErrProfileEndpointAmbiguous},
		{"duplicate-binding", func(in *value.GoEndpointInput) { in.Bindings = append(in.Bindings, in.Bindings[0]) }, value.ErrProfileEndpointAmbiguous},
		{"duplicate-template", func(in *value.GoEndpointInput) {
			in.Catalog.Templates = append(in.Catalog.Templates, in.Catalog.Templates[0])
		}, value.ErrProfileEndpointAmbiguous},
		{"namespace-shadow", func(in *value.GoEndpointInput) {
			d := in.Catalog.Templates[0]
			d.ScopeNamespaceUID = in.Network.Target.Request.Namespace.UID
			d.Source.ResourceUID = endpointID(19)
			in.Catalog.Templates = append(in.Catalog.Templates, d)
		}, value.ErrProfileEndpointAmbiguous},
		{"catalog-kind-shadow", func(in *value.GoEndpointInput) {
			in.Catalog.Profiles = []value.GoEndpointProfile{{Definition: in.Catalog.Templates[0], AddressMode: "podIP", Port: 6060}}
		}, value.ErrProfileEndpointAmbiguous},
		{"binding-profile-shadow", func(in *value.GoEndpointInput) {
			d := in.Catalog.Templates[0]
			d.Source.Name = in.SourceRef
			in.Catalog.Profiles = []value.GoEndpointProfile{{Definition: d, AddressMode: "podIP", Port: 6060}}
		}, value.ErrProfileEndpointAmbiguous},
		{"undeclared-port", func(in *value.GoEndpointInput) { in.Network.Ports = nil }, value.ErrProfileEndpointUnavailable},
		{"UDP-only", func(in *value.GoEndpointInput) { in.Network.Ports[0].Protocol = "UDP" }, value.ErrProfileEndpointUnavailable},
		{"no-IP", func(in *value.GoEndpointInput) {
			in.Bindings[0].AddressMode = "podIP"
			in.Network.PrimaryIP = netip.Addr{}
			in.Network.PodIPs = nil
		}, value.ErrProfileEndpointUnavailable},
		{"out-of-range", func(in *value.GoEndpointInput) { in.Network.Ports[0].Port = 7070 }, value.ErrProfileEndpointDenied},
		{"unapproved-address-mode", func(in *value.GoEndpointInput) {
			in.Catalog.Templates[0].AddressModes = []string{"targetLoopback"}
			in.Bindings[0].AddressMode = "podIP"
		}, value.ErrProfileEndpointDenied},
		{"foreign-catalog-namespace", func(in *value.GoEndpointInput) { in.Catalog.Templates[0].ScopeNamespaceUID = endpointID(20) }, value.ErrProfileEndpointUnavailable},
		{"foreign-catalog-cluster", func(in *value.GoEndpointInput) { in.Catalog.Templates[0].Source.ClusterID = endpointID(20) }, value.ErrProfileEndpointUnavailable},
		{"credential-workload", func(in *value.GoEndpointInput) {
			addEndpointCredential(in)
			in.Catalog.Templates[0].Credential.Audiences[0].WorkloadUID = endpointID(21)
		}, value.ErrProfileEndpointDenied},
		{"credential-namespace", func(in *value.GoEndpointInput) {
			addEndpointCredential(in)
			in.Catalog.Templates[0].Credential.Audiences[0].NamespaceUID = endpointID(21)
		}, value.ErrProfileEndpointDenied},
		{"credential-cluster", func(in *value.GoEndpointInput) {
			addEndpointCredential(in)
			in.Catalog.Templates[0].Credential.Audiences[0].ClusterID = endpointID(21)
		}, value.ErrProfileEndpointDenied},
		{"foreign-trust-policy", func(in *value.GoEndpointInput) {
			addEndpointCredential(in)
			in.Catalog.Templates[0].TLS.Trust.ClusterID = endpointID(21)
		}, value.ErrProfileEndpointDenied},
		{"foreign-credential-policy", func(in *value.GoEndpointInput) {
			addEndpointCredential(in)
			in.Catalog.Templates[0].Credential.Policy.ClusterID = endpointID(21)
		}, value.ErrProfileEndpointDenied},
		{"host-network", func(in *value.GoEndpointInput) { in.Network.HostNetwork = true }, value.ErrProfileHostNetwork},
		{"expired-catalog", func(in *value.GoEndpointInput) { in.Catalog.FreshUntil = in.Catalog.ObservedAt }, value.ErrProfileEndpointInvalid},
		{"expired-target", func(in *value.GoEndpointInput) { in.Network.Target.FreshUntil = in.Network.Target.ObservedAt }, value.ErrProfileEndpointInvalid},
		{"expired-caller", func(in *value.GoEndpointInput) { in.Deadline = in.Catalog.ObservedAt }, value.ErrProfileEndpointInvalid},
		{"missing-template", func(in *value.GoEndpointInput) { in.Bindings[0].TemplateRef = "missing" }, value.ErrProfileEndpointUnavailable},
		{"template-without-binding", func(in *value.GoEndpointInput) { in.SourceRef = "go-pprof" }, value.ErrProfileEndpointUnavailable},
		{"unbounded-native-output", func(in *value.GoEndpointInput) { in.NativeLimit = execution.MaximumGoProfileBytes + 1 }, value.ErrProfileEndpointInvalid},
		{"too-many-bindings", func(in *value.GoEndpointInput) { in.Bindings = make([]value.GoEndpointBinding, 17) }, value.ErrProfileEndpointInvalid},
		{"too-many-definitions", func(in *value.GoEndpointInput) { in.Catalog.Templates = make([]value.GoEndpointDefinition, 129) }, value.ErrProfileEndpointInvalid},
		{"catalog-clock-rollback", func(in *value.GoEndpointInput) { in.Catalog.ObservedAt = in.Deadline }, value.ErrProfileEndpointInvalid},
		{"source-reference-byte-bound", func(in *value.GoEndpointInput) { in.SourceRef = strings.Repeat("é", 32) }, value.ErrProfileEndpointInvalid},
		{"source-reference-control", func(in *value.GoEndpointInput) { in.SourceRef = "local\npprof" }, value.ErrProfileEndpointInvalid},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in, now := endpointInput()
			tc.change(&in)
			p, err := ResolveGoProfileEndpoint(in, now)
			if !errors.Is(err, tc.want) || !reflect.DeepEqual(p, value.GoEndpointPlan{}) {
				t.Fatalf("unsafe resolution: %+v %v, want %v", p, err, tc.want)
			}
		})
	}
}

func TestGoEndpointDigestBindsResolvedRouteAndPolicyWithoutFreshnessRenewal(t *testing.T) {
	base, now := endpointInput()
	addEndpointCredential(&base)
	p, err := ResolveGoProfileEndpoint(base, now)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		change func(*value.GoEndpointInput)
	}{
		{"port", func(in *value.GoEndpointInput) { in.Network.Ports[0].Port++ }},
		{"loopback-family", func(in *value.GoEndpointInput) { in.Catalog.Templates[0].LoopbackFamily = "ipv6" }},
		{"source-definition", func(in *value.GoEndpointInput) { in.Catalog.Templates[0].Source.Digest[0]++ }},
		{"source-replacement", func(in *value.GoEndpointInput) { in.Catalog.Templates[0].Source.ResourceUID = endpointID(40) }},
		{"TLS-name", func(in *value.GoEndpointInput) { in.Catalog.Templates[0].TLS.ServerName = "other.example.invalid" }},
		{"TLS-trust", func(in *value.GoEndpointInput) { in.Catalog.Templates[0].TLS.Trust.Digest[0]++ }},
		{"credential-policy", func(in *value.GoEndpointInput) { in.Catalog.Templates[0].Credential.Policy.Digest[0]++ }},
		{"duration", func(in *value.GoEndpointInput) { in.Parameters.Duration = time.Second }},
		{"byte-limit", func(in *value.GoEndpointInput) { in.NativeLimit-- }},
		{"pod-replacement", func(in *value.GoEndpointInput) {
			in.Network.Target.Pin.UID = endpointID(44)
			in.Network.Target.Request.PodUID = endpointID(44)
		}},
		{"node-reboot", func(in *value.GoEndpointInput) { in.Network.Target.NodeBootID = endpointID(45) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in, n := endpointInput()
			addEndpointCredential(&in)
			tc.change(&in)
			q, e := ResolveGoProfileEndpoint(in, n)
			if e != nil || q.EndpointDigest == p.EndpointDigest {
				t.Fatalf("material scope not bound: %v", e)
			}
		})
	}
	in, n := endpointInput()
	addEndpointCredential(&in)
	slices.Reverse(in.Catalog.Templates[0].AddressModes)
	in.Network.Target.PodResourceVersion = "99"
	in.Network.Target.WorkloadResourceVersion = "100"
	in.Catalog.ObservedAt = n
	in.Catalog.FreshUntil = n.Add(time.Second)
	in.Network.Target.ObservedAt = n
	in.Network.Target.FreshUntil = n.Add(2 * time.Second)
	q, e := ResolveGoProfileEndpoint(in, n)
	if e != nil || q.EndpointDigest != p.EndpointDigest || !q.ValidUntil.Equal(n.Add(time.Second)) {
		t.Fatal("freshness changed scope or earlier cutoff lost", e)
	}
	// Mutating caller-owned catalog storage after resolution cannot mutate a plan.
	in.Catalog.Templates[0].TLS.ServerName = "mutated.example.invalid"
	in.Catalog.Templates[0].Credential.Audiences[0].WorkloadUID = endpointID(50)
	in.Catalog.Templates[0].AddressModes[0] = "invalid"
	if !reflect.DeepEqual(q.Definition, p.Definition) {
		t.Fatal("resolved definition aliases input")
	}
}

func TestGoEndpointPlanMatchesExistingAcquisitionContractOnly(t *testing.T) {
	in, now := endpointInput()
	p, err := ResolveGoProfileEndpoint(in, now)
	if err != nil {
		t.Fatal(err)
	}
	r := execution.GoProfileRequest{Binding: artifact.Binding{ClusterID: in.Network.Target.Request.ClusterID, ArtifactID: endpointID(30), AttemptID: endpointID(31), MediaType: execution.GoProfileMediaType}, Pin: p.Pin, NodeUID: p.NodeUID, NodeBootID: p.NodeBootID, SourceRef: p.SourceRef, EndpointDigest: p.EndpointDigest, Parameters: p.Parameters, NativeLimit: p.NativeLimit, NotBefore: now, Deadline: now.Add(15 * time.Second)}
	if r.Validate(now) != nil || !p.MatchesAcquisition(r) {
		t.Fatal("valid resolved endpoint cannot match mechanism")
	}
	r.EndpointDigest[0]++
	if p.MatchesAcquisition(r) {
		t.Fatal("changed endpoint bypassed accepted digest")
	}
	r.EndpointDigest = p.EndpointDigest
	r.NodeBootID = endpointID(41)
	if p.MatchesAcquisition(r) {
		t.Fatal("replacement boot accepted")
	}
}

func TestGoEndpointMixedCatalogDoesNotDisableSelectedScope(t *testing.T) {
	for _, selected := range []string{"template", "administrator"} {
		t.Run(selected, func(t *testing.T) {
			in, now := endpointInput()
			if selected == "administrator" {
				d := in.Catalog.Templates[0]
				d.Source.Name = in.SourceRef
				in.Catalog.Profiles = []value.GoEndpointProfile{{Definition: d, AddressMode: "podIP", Port: 6060}}
				in.Catalog.Templates, in.Bindings = nil, nil
			}
			base, err := ResolveGoProfileEndpoint(in, now)
			if err != nil {
				t.Fatal(err)
			}
			other, _ := endpointInput()
			// Both unique names and names overlapping the selected scope must
			// remain invisible when they only apply elsewhere.
			for _, name := range []string{"foreign-only", "go-pprof", "local-pprof"} {
				foreignNamespace := other.Catalog.Templates[0]
				foreignNamespace.Source.Name = name
				foreignNamespace.ScopeNamespaceUID = endpointID(70)
				in.Catalog.Templates = append(in.Catalog.Templates, foreignNamespace)
				foreignCluster := foreignNamespace
				foreignCluster.ScopeNamespaceUID = ""
				foreignCluster.Source.ClusterID = endpointID(71)
				in.Catalog.Profiles = append(in.Catalog.Profiles, value.GoEndpointProfile{Definition: foreignCluster, AddressMode: "podIP", Port: 6061})
			}
			got, err := ResolveGoProfileEndpoint(in, now)
			if err != nil || !reflect.DeepEqual(got, base) {
				t.Fatalf("unrelated catalog entries changed selected plan: %+v %v", got, err)
			}
			// Absence and out-of-scope existence return the same minimized error.
			for _, name := range []string{"foreign-only", "absent"} {
				denied := in
				denied.SourceRef, denied.Bindings = name, nil
				p, err := ResolveGoProfileEndpoint(denied, now)
				if !errors.Is(err, value.ErrProfileEndpointUnavailable) || !reflect.DeepEqual(p, value.GoEndpointPlan{}) {
					t.Fatalf("foreign administrator entry disclosed: %+v %v", p, err)
				}
				denied.SourceRef = "local"
				denied.Bindings = []value.GoEndpointBinding{{Name: "local", TemplateRef: name, AddressMode: "targetLoopback", PortName: "diagnostics"}}
				p, err = ResolveGoProfileEndpoint(denied, now)
				if !errors.Is(err, value.ErrProfileEndpointUnavailable) || !reflect.DeepEqual(p, value.GoEndpointPlan{}) {
					t.Fatalf("foreign template entry disclosed: %+v %v", p, err)
				}
			}
		})
	}
}
