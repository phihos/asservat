package fleet

import (
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/identity"
)

func connectorObservationFixture() (ConnectorObservationPin, ConnectorObservation, time.Time) {
	now := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
	id := "00000000-0000-4000-8000-000000000001"
	b := PeerBinding{InstallationID: id, ClusterID: id, IssuerEpoch: id, PeerID: id, Role: ConnectorPeer}
	d := ConnectorDeployment{Namespace: "connector", NamespaceUID: id, ServiceAccount: "connector", AccountUID: id, Deployment: "connector", DeploymentUID: id, ServingSlots: 2, RetainedProcesses: 8}
	p := ConnectorObservationPin{Profile: ConnectorCredentialProfile{RootID: id, Binding: b, Revision: identity.Revision{UID: id, Generation: 1, Digest: artifact.Digest{1}}, ProtectionDigest: artifact.Digest{2}, ServerName: "connector.invalid", Deployment: d, ClientIssuerRoots: [][]byte{{1}}, ServerIssuerRoots: [][]byte{{2}}}, Roles: ConnectorIdentityRoles{Source: "src", Journal: "journal", Acknowledgement: "ack", Cleanup: "clean", Verifier: "verify", Finalizer: "final"}, TemplateDigest: artifact.Digest{3}, ImageDigest: artifact.Digest{4}, ProtectionDigest: artifact.Digest{17}}
	s := ConnectorIdentitySource{Roles: p.Roles, Observation: ConnectorCredentialObservation{Profile: p.Profile.Clone(), Backing: ConnectorBackingObservation{Revision: 1, Digest: artifact.Digest{5}, SourceDigest: artifact.Digest{6}}, ObservedAt: now, FreshUntil: now.Add(4 * time.Second)}}
	w := ConnectorObservationWorkload{Process: ConnectorProcessIdentity{Binding: b, PodUID: id, ProcessEpoch: id}, Pod: "connector-1", ReplicaSetUID: id, TemplateDigest: p.TemplateDigest, ImageDigest: p.ImageDigest, ProtectionDigest: p.ProtectionDigest, WorkloadDigest: artifact.Digest{7}, ObservedAt: now, FreshUntil: now.Add(3 * time.Second)}
	o := ConnectorObservation{Request: OwnerObservationRequest{RootID: id, ID: id, Challenge: id, RequestedAt: now, NotAfter: now.Add(5 * time.Second)}, Ordinal: 1, ConnectionBinding: artifact.Digest{8}, Certificate: ConnectorCredentialCertificate{Binding: b, Usage: "client", Digest: artifact.Digest{9}, PublicKeyDigest: artifact.Digest{10}, NotBefore: now.Add(-time.Second), NotAfter: now.Add(20 * time.Minute)}, Source: s, Workload: w, ObservedAt: now, FreshUntil: now.Add(3 * time.Second)}
	return p, o, now
}

func TestConnectorObservationKeepsOriginalChildBoundsAndPins(t *testing.T) {
	p, o, n := connectorObservationFixture()
	if !o.Matches(p, n) || o.Matches(p, n.Add(3*time.Second)) {
		t.Fatal("original native workload deadline lost")
	}
	for name, change := range map[string]func(*ConnectorObservation){
		"workload-expiry":  func(v *ConnectorObservation) { v.FreshUntil = v.FreshUntil.Add(time.Nanosecond) },
		"source-expiry":    func(v *ConnectorObservation) { v.Source.Observation.FreshUntil = n.Add(2 * time.Second) },
		"caller-expiry":    func(v *ConnectorObservation) { v.Request.NotAfter = n.Add(2 * time.Second) },
		"no-channel":       func(v *ConnectorObservation) { v.ConnectionBinding = artifact.Digest{} },
		"first-ordinal":    func(v *ConnectorObservation) { v.Ordinal = 0 },
		"ordinal-ceiling":  func(v *ConnectorObservation) { v.Ordinal = 5 },
		"changed-image":    func(v *ConnectorObservation) { v.Workload.ImageDigest[0]++ },
		"changed-template": func(v *ConnectorObservation) { v.Workload.TemplateDigest[0]++ },
		"changed-guard":    func(v *ConnectorObservation) { v.Workload.ProtectionDigest[0]++ },
		"changed-roles":    func(v *ConnectorObservation) { v.Source.Roles.Source = "different" },
		"source-mutation":  func(v *ConnectorObservation) { v.Source.Observation.Profile.Revision.Digest[0]++ },
		"suspended":        func(v *ConnectorObservation) { v.Source.Observation.Profile.Suspended = true },
		"replacement-source": func(v *ConnectorObservation) {
			v.Source.Observation.Profile.Revision.UID = "00000000-0000-4000-8000-000000000002"
		},
	} {
		t.Run(name, func(t *testing.T) {
			v := o
			v.Source.Observation.Profile = o.Source.Observation.Profile.Clone()
			change(&v)
			if v.Matches(p, n) {
				t.Fatal("changed original proof accepted")
			}
		})
	}
}

func TestConnectorObservationCompatibleRevisionDoesNotAcceptOrRenewSource(t *testing.T) {
	p, o, n := connectorObservationFixture()
	original := o.Source.Observation.FreshUntil
	o.Source.Observation.Profile.Revision.Generation++
	o.Source.Observation.Profile.Revision.Digest[0]++
	if !p.Compatible(o.Source) || !o.Matches(p, n) || !o.Source.Observation.FreshUntil.Equal(original) || o.Matches(p, n.Add(4*time.Second)) {
		t.Fatal("compatibility changed the original interval")
	}
	for name, change := range map[string]func(*ConnectorIdentitySource){
		"roots": func(s *ConnectorIdentitySource) { s.Observation.Profile.ClientIssuerRoots[0][0]++ },
		"deployment": func(s *ConnectorIdentitySource) {
			s.Observation.Profile.Deployment.DeploymentUID = "00000000-0000-4000-8000-000000000002"
		},
		"roles":          func(s *ConnectorIdentitySource) { s.Roles.Source = "new_source" },
		"serving-budget": func(s *ConnectorIdentitySource) { s.Observation.Profile.Deployment.ServingSlots++ },
		"suspended":      func(s *ConnectorIdentitySource) { s.Observation.Profile.Suspended = true },
	} {
		t.Run(name, func(t *testing.T) {
			s := o.Source
			s.Observation.Profile = s.Observation.Profile.Clone()
			change(&s)
			if p.Compatible(s) {
				t.Fatal("installed delegation silently widened")
			}
		})
	}
	copy := p.Clone()
	copy.Profile.ClientIssuerRoots[0][0]++
	if p.Profile.ClientIssuerRoots[0][0] != 1 {
		t.Fatal("caller changed original roots")
	}
}
