package planning

import (
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/execution"
	"asservat.local/asservat/internal/domain/targets"
	"crypto/sha256"
	"encoding/json"
	"testing"
)

func TestPolicyProfileAuthorizationManualAndStableDefinitionMatch(t *testing.T) {
	in, now := endpointInput()
	addEndpointCredential(&in)
	material := execution.GoProfileTLSMaterial{RootsPEM: "synthetic certificate", ServerName: in.Catalog.Templates[0].TLS.ServerName}
	material.RootsDigest = artifact.Digest(sha256.Sum256([]byte(material.RootsPEM)))
	in.Catalog.Templates[0].TLS.Trust.Digest = material.RootsDigest
	entries := []ProfileEndpointEntry{{Definition: in.Catalog.Templates[0], TLSMaterial: material}}
	r := targets.ProfileEndpointRequest{Target: in.Network.Target.Request, SourceRef: in.SourceRef, Bindings: []targets.ProfileEndpointBinding{{Name: in.SourceRef, TemplateRef: entries[0].Definition.Source.Name, AddressMode: "targetLoopback", PortName: "diagnostics"}}, Type: "cpu", Mode: "interval", DurationSeconds: 10, NativeLimit: 16 << 20}
	child, err := ResolveProfileEndpointRequest(entries, in.Network, r, now)
	if err != nil || !child.Credential || !child.TLS {
		t.Fatal("manual credential definition unavailable", err)
	}
	answer, err := ResolveProfileEndpointDefinition(entries, targets.ProfileEndpointDefinitionRequest{ClusterID: r.Target.ClusterID, Namespace: r.Target.Namespace, SourceRef: r.SourceRef, Bindings: r.Bindings})
	if err != nil {
		t.Fatal(err)
	}
	pin, err := PolicyProfileEndpointFromResolution(answer)
	if err != nil || !pin.Matches(child) {
		t.Fatal("stable policy differs from manual acquisition", err)
	}
	raw, _ := json.Marshal(answer)
	var wire targets.ProfileEndpointDefinitionResolution
	if json.Unmarshal(raw, &wire) != nil {
		t.Fatal("wire decode")
	}
	if round, err := PolicyProfileEndpointFromResolution(wire); err != nil || !round.Matches(child) {
		t.Fatal("public credential facts lost on wire", err)
	}
	clone := answer.Clone()
	clone.Credential.Audiences[0].WorkloadUID = endpointID(44)
	if answer.Credential.Audiences[0].WorkloadUID == clone.Credential.Audiences[0].WorkloadUID {
		t.Fatal("audience alias")
	}
	if _, err := PolicyProfileEndpointFromResolution(clone); err == nil {
		t.Fatal("changed public audience retained approval digest")
	}
	child.Request.Target.Workload.UID = endpointID(44)
	if pin.Matches(child) {
		t.Fatal("approved credential redirected to another workload")
	}
	wrong := in.Network
	wrong.Target.Request.Workload.UID = endpointID(44)
	r.Target = wrong.Target.Request
	if _, err := ResolveProfileEndpointPlan(entries, wrong, r, now); err == nil {
		t.Fatal("credential plan accepted wrong root")
	}
}
