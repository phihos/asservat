package fleet

import (
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/identity"
)

func overlappingConnectorPermit(attested bool) ConnectorCredentialPermit {
	const id = "10000000-0000-4000-8000-000000000001"
	n := time.Date(2026, 10, 12, 12, 0, 0, 0, time.UTC)
	b := PeerBinding{InstallationID: id, ClusterID: id, IssuerEpoch: id, PeerID: id, Role: ConnectorPeer}
	rev := identity.Revision{UID: id, Generation: 1, Digest: artifact.Digest{1}}
	profile := ConnectorCredentialProfile{RootID: id, Binding: b, Revision: rev, ProtectionDigest: artifact.Digest{2}, ServerName: "connector.invalid", ClientIssuerRoots: [][]byte{{1}}, ServerIssuerRoots: [][]byte{{2}}, Deployment: ConnectorDeployment{Namespace: "connector", NamespaceUID: id, ServiceAccount: "connector", AccountUID: id, Deployment: "connector", DeploymentUID: id, ServingSlots: 2, RetainedProcesses: 8}}
	configuration := ConnectorCredentialObservation{Profile: profile, Backing: ConnectorBackingObservation{Revision: 1, Digest: artifact.Digest{3}, SourceDigest: artifact.Digest{4}}, ObservedAt: n.Add(time.Millisecond), FreshUntil: n.Add(5 * time.Second)}
	process := ConnectorCredentialProcess{BootstrapID: id, Binding: b, ClientKeyDigest: artifact.Digest{5}, ServerKeyDigest: artifact.Digest{6}, ClaimedAt: n, InitialCertificateNotAfter: n.Add(30 * time.Minute)}
	p := ConnectorCredentialPermit{ID: id, Process: process, Usage: "server", Configuration: configuration, CurrentPeer: AuthenticatedPeer{Certificate: PeerCertificate{Binding: b, Digest: artifact.Digest{7}, NotBefore: n.Add(-time.Second), NotAfter: n.Add(30 * time.Minute)}, RegistrationRevision: rev, VerifiedAt: n.Add(2 * time.Millisecond), ValidUntil: n.Add(5 * time.Second)}, Recovery: RecoveryState{InstallationID: id, IssuerEpoch: id, Revision: rev, ObservedAt: n.Add(3 * time.Millisecond), FreshUntil: n.Add(5 * time.Second)}, IntentDigest: artifact.Digest{8}, Epoch: 0, Ordinal: 1, CheckedAt: n, SignBefore: n.Add(5 * time.Second), CertificateNotAfter: n.Add(30 * time.Minute)}
	if attested {
		process.BootstrapID = ""
		process.Attested = &ConnectorProcessIdentity{Binding: b, PodUID: id, ProcessEpoch: id}
		process.RunUntil = n.Add(time.Hour)
		p.Process = process
		p.CurrentPeer = AuthenticatedPeer{}
		p.ProcessProof = &ConnectorProcessProof{Process: *process.Attested, Configuration: configuration, Pod: "connector-pod", ReplicaSet: "connector-rs", ReplicaSetUID: id, ClientKeyDigest: process.ClientKeyDigest, ServerKeyDigest: process.ServerKeyDigest, TokenDigest: artifact.Digest{9}, WorkloadDigest: artifact.Digest{10}, ProtectionDigest: profile.ProtectionDigest, ObservedAt: n.Add(2 * time.Millisecond), FreshUntil: n.Add(5 * time.Second)}
	}
	return p
}

func TestConnectorHistoricalPermitRequiresOriginalIntervalIntersection(t *testing.T) {
	for _, attested := range []bool{false, true} {
		p := overlappingConnectorPermit(attested)
		if !p.WellFormed() || p.Valid(p.CheckedAt) || !p.Valid(p.CheckedAt.Add(4*time.Millisecond)) || p.Valid(p.SignBefore) {
			t.Fatal("sequential original intervals were not distinguished from current authority", attested)
		}
		checked, end := p.CheckedAt, p.SignBefore
		for name, change := range map[string]func(*ConnectorCredentialPermit){
			"source after end":          func(p *ConnectorCredentialPermit) { p.Configuration.ObservedAt = p.SignBefore },
			"recovery after end":        func(p *ConnectorCredentialPermit) { p.Recovery.ObservedAt = p.SignBefore.Add(time.Nanosecond) },
			"shortened source":          func(p *ConnectorCredentialPermit) { p.Configuration.FreshUntil = p.Recovery.ObservedAt },
			"source interval too long":  func(p *ConnectorCredentialPermit) { p.Configuration.ObservedAt = p.CheckedAt.Add(-time.Second) },
			"request interval too long": func(p *ConnectorCredentialPermit) { p.CheckedAt = p.CheckedAt.Add(-time.Second) },
			"missing recovery start":    func(p *ConnectorCredentialPermit) { p.Recovery.ObservedAt = time.Time{} },
			"wrong issuer":              func(p *ConnectorCredentialPermit) { p.Recovery.IssuerEpoch = "20000000-0000-4000-8000-000000000001" },
			"detached actor": func(p *ConnectorCredentialPermit) {
				if p.ProcessProof != nil {
					p.ProcessProof.ObservedAt = p.SignBefore
				} else {
					p.CurrentPeer.VerifiedAt = p.SignBefore
				}
			},
			"shortened actor": func(p *ConnectorCredentialPermit) {
				if p.ProcessProof != nil {
					p.ProcessProof.FreshUntil = p.SignBefore.Add(-time.Millisecond)
				} else {
					p.CurrentPeer.ValidUntil = p.SignBefore.Add(-time.Millisecond)
				}
			},
		} {
			t.Run(name+map[bool]string{false: "/TLS", true: "/Pod"}[attested], func(t *testing.T) {
				q := overlappingConnectorPermit(attested)
				change(&q)
				if q.WellFormed() {
					t.Fatal("invalid original interval or binding accepted")
				}
			})
		}
		if !p.CheckedAt.Equal(checked) || !p.SignBefore.Equal(end) {
			t.Fatal("historical validation mutated original times")
		}
		// A still-fresh cached source may begin before request entry.
		cached := overlappingConnectorPermit(attested)
		cached.Configuration.ObservedAt = checked.Add(-time.Second)
		cached.Configuration.FreshUntil = checked.Add(4 * time.Second)
		cached.SignBefore = cached.Configuration.FreshUntil
		if !cached.WellFormed() || !cached.Valid(checked.Add(4*time.Millisecond)) || cached.Valid(cached.SignBefore) {
			t.Fatal("cached proof lost its original shorter deadline", attested)
		}
	}
}
