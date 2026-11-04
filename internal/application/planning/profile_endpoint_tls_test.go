package planning

import (
	"crypto/sha256"
	"encoding/json"
	"strings"
	"testing"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/execution"
	value "asservat.local/asservat/internal/domain/planning"
	"asservat.local/asservat/internal/domain/targets"
)

// Certificate syntax belongs to the protected adapter; here public material
// tests the selected definition/sidecar binding without acquiring an endpoint.
func TestProfileEndpointTLSSelectedMaterialAndPublicPolicyIdentity(t *testing.T) {
	in, now := endpointInput()
	material := execution.GoProfileTLSMaterial{RootsPEM: "synthetic public certificate material", ServerName: "pprof.example.invalid"}
	material.RootsDigest = artifact.Digest(sha256.Sum256([]byte(material.RootsPEM)))
	d := in.Catalog.Templates[0]
	trust := d.Source
	trust.Digest = material.RootsDigest
	d.TLS = &value.GoEndpointTLS{Trust: trust, ServerName: material.ServerName}
	entries := []ProfileEndpointEntry{{Definition: d, TLSMaterial: material}}
	r := targets.ProfileEndpointRequest{Target: in.Network.Target.Request, SourceRef: in.SourceRef, Bindings: []targets.ProfileEndpointBinding{{Name: in.SourceRef, TemplateRef: d.Source.Name, AddressMode: "targetLoopback", PortName: "diagnostics"}}, Type: "cpu", Mode: "interval", DurationSeconds: 10, NativeLimit: 16 << 20}
	plan, err := ResolveProfileEndpointPlan(entries, in.Network, r, now)
	if err != nil || plan.TLSMaterial != material {
		t.Fatal("current selected TLS material", err)
	}
	definition := targets.ProfileEndpointDefinitionRequest{ClusterID: r.Target.ClusterID, Namespace: r.Target.Namespace, SourceRef: r.SourceRef, Bindings: r.Bindings}
	a, err := ResolveProfileEndpointDefinition(entries, definition)
	if err != nil {
		t.Fatal(err)
	}
	pin, err := PolicyProfileEndpointFromResolution(a)
	if err != nil || pin.DefinitionDigest != plan.DefinitionDigest {
		t.Fatal("manual/policy TLS definition differs", err)
	}
	child, err := ResolveProfileEndpointRequest(entries, in.Network, r, now)
	if err != nil || !child.TLS || !pin.Matches(child) {
		t.Fatal("reviewed TLS child mismatch", err)
	}
	for _, v := range []any{plan, a, pin, child} {
		b, _ := json.Marshal(v)
		if strings.Contains(string(b), material.RootsPEM) || strings.Contains(string(b), "RootsPEM") {
			t.Fatal("public certificate material entered approval/transport metadata")
		}
	}
	child.TLS = false
	if pin.Matches(child) {
		t.Fatal("TLS approval matches HTTP child")
	}
	for _, change := range []func(*execution.GoProfileTLSMaterial){
		func(m *execution.GoProfileTLSMaterial) { *m = execution.GoProfileTLSMaterial{} },
		func(m *execution.GoProfileTLSMaterial) { m.RootsPEM += "changed" },
		func(m *execution.GoProfileTLSMaterial) { m.ServerName = "changed.invalid" },
		func(m *execution.GoProfileTLSMaterial) { m.RootsDigest[0]++ },
	} {
		e := entries[0]
		change(&e.TLSMaterial)
		if _, err := ResolveProfileEndpointPlan([]ProfileEndpointEntry{e}, in.Network, r, now); err == nil {
			t.Fatal("unbound material accepted")
		}
	}
	addEndpointCredential(&in)
	e := entries[0]
	e.Definition.Credential = in.Catalog.Templates[0].Credential
	if _, err := ResolveProfileEndpointPlan([]ProfileEndpointEntry{e}, in.Network, r, now); err != nil {
		t.Fatal("approved TLS credential policy unavailable", err)
	}
	e = entries[0]
	e.Definition.TLS = nil
	if _, err := ResolveProfileEndpointPlan([]ProfileEndpointEntry{e}, in.Network, r, now); err == nil {
		t.Fatal("HTTP carried TLS sidecar")
	}
}
