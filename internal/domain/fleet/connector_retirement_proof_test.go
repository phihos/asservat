package fleet

import (
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/identity"
)

func connectorRetirementProofFixture(now time.Time) ConnectorRetirementProof {
	id := "00000000-0000-4000-8000-000000000001"
	b := PeerBinding{InstallationID: id, ClusterID: id, IssuerEpoch: id, PeerID: id, Role: ConnectorPeer}
	d := ConnectorDeployment{Namespace: "connector", NamespaceUID: id, ServiceAccount: "connector", AccountUID: id, Deployment: "connector", DeploymentUID: id, ServingSlots: 2, RetainedProcesses: 8}
	c := ConnectorCredentialProfile{RootID: id, Binding: b, Revision: identity.Revision{UID: id, Generation: 1, Digest: artifact.Digest{1}}, ProtectionDigest: artifact.Digest{2}, ServerName: "connector.invalid", Deployment: d, ClientIssuerRoots: [][]byte{{1}}, ServerIssuerRoots: [][]byte{{2}}, Suspended: true, Retiring: true}
	return ConnectorRetirementProof{Process: ConnectorProcessIdentity{Binding: b, PodUID: id, ProcessEpoch: id}, Configuration: ConnectorCredentialObservation{Backing: ConnectorBackingObservation{Revision: 1, Digest: artifact.Digest{31}, SourceDigest: artifact.Digest{32}}, Profile: c, ObservedAt: now.Add(time.Second), FreshUntil: now.Add(4 * time.Second)}, Pod: "connector-1", ReplicaSet: "connector", ReplicaSetUID: id, ClientKeyDigest: artifact.Digest{1}, ServerKeyDigest: artifact.Digest{2}, TokenDigest: artifact.Digest{3}, WorkloadDigest: artifact.Digest{4}, ProtectionDigest: artifact.Digest{5}, ObservedAt: now, FreshUntil: now.Add(4 * time.Second)}
}

func TestConnectorRetirementProofCannotSupplyOrdinaryAuthority(t *testing.T) {
	now := time.Date(2026, 10, 12, 12, 0, 0, 0, time.UTC)
	p := connectorRetirementProofFixture(now)
	if !p.WellFormed() || !p.Valid(now.Add(time.Second)) || p.Valid(now) || p.Valid(now.Add(4*time.Second)) {
		t.Fatal("retirement proof lost original overlapping intervals")
	}
	if ConnectorProcessProof(p).Valid(now.Add(time.Second)) || p.Configuration.Valid(now.Add(time.Second)) {
		t.Fatal("suspended retirement source authorizes ordinary operations")
	}
	for _, tc := range []struct {
		name   string
		change func(*ConnectorRetirementProof)
	}{
		{"suspended-only", func(p *ConnectorRetirementProof) { p.Configuration.Profile.Retiring = false }},
		{"retiring-without-suspension", func(p *ConnectorRetirementProof) { p.Configuration.Profile.Suspended = false }},
		{"wrong-actor", func(p *ConnectorRetirementProof) { p.Process.Binding.PeerID = "00000000-0000-4000-8000-000000000002" }},
		{"no-pod", func(p *ConnectorRetirementProof) { p.Process.PodUID = "" }},
		{"no-epoch", func(p *ConnectorRetirementProof) { p.Process.ProcessEpoch = "" }},
		{"same-key", func(p *ConnectorRetirementProof) { p.ClientKeyDigest = p.ServerKeyDigest }},
		{"no-token-proof", func(p *ConnectorRetirementProof) { p.TokenDigest = artifact.Digest{} }},
		{"no-workload-proof", func(p *ConnectorRetirementProof) { p.WorkloadDigest = artifact.Digest{} }},
		{"no-native-guard", func(p *ConnectorRetirementProof) { p.ProtectionDigest = artifact.Digest{} }},
		{"no-complete-source", func(p *ConnectorRetirementProof) { p.Configuration.Backing.SourceDigest = artifact.Digest{} }},
		{"no-backing-revision", func(p *ConnectorRetirementProof) { p.Configuration.Backing.Revision = 0 }},
		{"longer-than-source", func(p *ConnectorRetirementProof) { p.FreshUntil = now.Add(5 * time.Second) }},
		{"extended-interval", func(p *ConnectorRetirementProof) { p.ObservedAt = now.Add(-2 * time.Second) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			q := p.Clone()
			tc.change(&q)
			if q.WellFormed() || q.Valid(now.Add(time.Second)) {
				t.Fatal("invalid retirement proof accepted")
			}
		})
	}
	q := p.Clone()
	q.Configuration.Profile.ClientIssuerRoots[0][0]++
	if p.Configuration.Profile.ClientIssuerRoots[0][0] != 1 {
		t.Fatal("retirement proof aliases current source")
	}
}
