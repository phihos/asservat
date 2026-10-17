package fleet

import (
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/identity"
	"testing"
	"time"
)

func TestConnectorProcessProofSeparatesLogicalIdentityAndBoundedChildren(t *testing.T) {
	now := time.Date(2026, 10, 12, 12, 0, 0, 0, time.UTC)
	id := "00000000-0000-4000-8000-000000000001"
	b := PeerBinding{InstallationID: id, ClusterID: id, IssuerEpoch: id, PeerID: id, Role: ConnectorPeer}
	d := ConnectorDeployment{Namespace: "connector", NamespaceUID: id, ServiceAccount: "connector", AccountUID: id, Deployment: "connector", DeploymentUID: id, ServingSlots: 2, RetainedProcesses: 8}
	c := ConnectorCredentialProfile{RootID: id, Binding: b, Revision: identity.Revision{UID: id, Generation: 1, Digest: artifact.Digest{1}}, ProtectionDigest: artifact.Digest{2}, ServerName: "connector.invalid", Deployment: d, ClientIssuerRoots: [][]byte{{1}}, ServerIssuerRoots: [][]byte{{2}}}
	p := ConnectorProcessProof{Process: ConnectorProcessIdentity{Binding: b, PodUID: id, ProcessEpoch: id}, Configuration: ConnectorCredentialObservation{Backing: ConnectorBackingObservation{Revision: 1, Digest: artifact.Digest{31}, SourceDigest: artifact.Digest{32}}, Profile: c, ObservedAt: now.Add(time.Second), FreshUntil: now.Add(4 * time.Second)}, Pod: "connector-1", ReplicaSet: "connector", ReplicaSetUID: id, ClientKeyDigest: artifact.Digest{1}, ServerKeyDigest: artifact.Digest{2}, TokenDigest: artifact.Digest{3}, WorkloadDigest: artifact.Digest{4}, ProtectionDigest: artifact.Digest{5}, ObservedAt: now, FreshUntil: now.Add(4 * time.Second)}
	if !p.WellFormed() || !p.Valid(now.Add(time.Second)) || p.Valid(now.Add(4*time.Second)) {
		t.Fatal("original proof/source intervals not preserved")
	}
	for _, mutate := range []func(*ConnectorProcessProof){func(q *ConnectorProcessProof) { q.ServerKeyDigest = q.ClientKeyDigest }, func(q *ConnectorProcessProof) { q.Process.PodUID = "" }, func(q *ConnectorProcessProof) { q.Process.ProcessEpoch = "" }, func(q *ConnectorProcessProof) { q.Configuration.Profile.Deployment.ServingSlots = 0 }, func(q *ConnectorProcessProof) { q.Configuration.Profile.Deployment.RetainedProcesses = 2 }, func(q *ConnectorProcessProof) { q.Process.Binding.Role = NodePeer }, func(q *ConnectorProcessProof) { q.FreshUntil = now.Add(5 * time.Second) }} {
		q := p.Clone()
		mutate(&q)
		if q.WellFormed() {
			t.Fatal("invalid process proof accepted")
		}
	}
	q := p.Clone()
	q.Configuration.Profile.ClientIssuerRoots[0][0] = 99
	if p.Configuration.Profile.ClientIssuerRoots[0][0] != 1 {
		t.Fatal("proof aliases mutable source")
	}
}
