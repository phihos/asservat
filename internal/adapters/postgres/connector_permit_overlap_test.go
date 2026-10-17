package postgres

import (
	auditapp "asservat.local/asservat/internal/application/audit"
	app "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	"bytes"
	"encoding/json"
	"testing"
	"time"
)

// This is a persisted-result decoder regression, not a synthetic SQL authority.
func overlappingConnectorPermit(attested bool) value.ConnectorCredentialPermit {
	const id = "10000000-0000-4000-8000-000000000001"
	n := time.Date(2026, 10, 12, 12, 0, 0, 0, time.UTC)
	b := value.PeerBinding{InstallationID: id, ClusterID: id, IssuerEpoch: id, PeerID: id, Role: value.ConnectorPeer}
	rev := identity.Revision{UID: id, Generation: 1, Digest: artifact.Digest{1}}
	profile := value.ConnectorCredentialProfile{RootID: id, Binding: b, Revision: rev, ProtectionDigest: artifact.Digest{2}, ServerName: "connector.invalid", ClientIssuerRoots: [][]byte{{1}}, ServerIssuerRoots: [][]byte{{2}}, Deployment: value.ConnectorDeployment{Namespace: "connector", NamespaceUID: id, ServiceAccount: "connector", AccountUID: id, Deployment: "connector", DeploymentUID: id, ServingSlots: 2, RetainedProcesses: 8}}
	configuration := value.ConnectorCredentialObservation{Profile: profile, Backing: value.ConnectorBackingObservation{Revision: 1, Digest: artifact.Digest{3}, SourceDigest: artifact.Digest{4}}, ObservedAt: n.Add(time.Millisecond), FreshUntil: n.Add(5 * time.Second)}
	process := value.ConnectorCredentialProcess{BootstrapID: id, Binding: b, ClientKeyDigest: artifact.Digest{5}, ServerKeyDigest: artifact.Digest{6}, ClaimedAt: n, InitialCertificateNotAfter: n.Add(30 * time.Minute)}
	p := value.ConnectorCredentialPermit{ID: id, Process: process, Usage: "server", Configuration: configuration, CurrentPeer: value.AuthenticatedPeer{Certificate: value.PeerCertificate{Binding: b, Digest: artifact.Digest{7}, NotBefore: n.Add(-time.Second), NotAfter: n.Add(30 * time.Minute)}, RegistrationRevision: rev, VerifiedAt: n.Add(2 * time.Millisecond), ValidUntil: n.Add(5 * time.Second)}, Recovery: value.RecoveryState{InstallationID: id, IssuerEpoch: id, Revision: rev, ObservedAt: n.Add(3 * time.Millisecond), FreshUntil: n.Add(5 * time.Second)}, IntentDigest: artifact.Digest{8}, Epoch: 0, Ordinal: 1, CheckedAt: n, SignBefore: n.Add(5 * time.Second), CertificateNotAfter: n.Add(30 * time.Minute)}
	if attested {
		process.BootstrapID = ""
		process.Attested = &value.ConnectorProcessIdentity{Binding: b, PodUID: id, ProcessEpoch: id}
		process.RunUntil = n.Add(time.Hour)
		p.Process = process
		p.CurrentPeer = value.AuthenticatedPeer{}
		p.ProcessProof = &value.ConnectorProcessProof{Process: *process.Attested, Configuration: configuration, Pod: "connector-pod", ReplicaSet: "connector-rs", ReplicaSetUID: id, ClientKeyDigest: process.ClientKeyDigest, ServerKeyDigest: process.ServerKeyDigest, TokenDigest: artifact.Digest{9}, WorkloadDigest: artifact.Digest{10}, ProtectionDigest: profile.ProtectionDigest, ObservedAt: n.Add(2 * time.Millisecond), FreshUntil: n.Add(5 * time.Second)}
	}
	return p
}

func TestConnectorCredentialDecoderAcceptsOriginalOverlappingObservations(t *testing.T) {
	p := overlappingConnectorPermit(true)
	n := p.CheckedAt
	id := p.ID
	in := audit.OperationIntent{ID: id, RootID: p.Configuration.Profile.RootID, TraceID: id, Name: "connector_server_certificate", InputFormat: "connector-credential/v1", MACVersion: "mac-v1", AccountVersion: "account-v1", Process: &audit.OperationConnectorProcessActor{Process: *p.Process.Attested, Deployment: p.Configuration.Profile.Deployment, ClientKeyDigest: p.Process.ClientKeyDigest, ServerKeyDigest: p.Process.ServerKeyDigest}, PrincipalDigest: artifact.Digest{21}, InputDigest: artifact.Digest{22}, CreatedAt: n, RequestUntil: p.SignBefore, WriteUntil: n.Add(30 * time.Second), RetainUntil: n.Add(3 * time.Hour)}
	q := audit.OperationHistoryQualification{ID: id, Digest: artifact.Digest{23}, Layout: audit.ConnectorOperationHistoryLayout, MaximumRowFootprintBytes: 1 << 20, MaximumTransitionWALBytes: 1 << 20, BackupCopies: 1, WALCopies: 1}
	policy := audit.OperationLifecyclePolicy{RootID: in.RootID, Lane: "identity", InstallationID: p.Process.Binding.InstallationID, StoreID: id, PolicyID: id, BackupProfileID: id, PolicyDigest: artifact.Digest{24}, BackupProfileDigest: artifact.Digest{25}, BackingRevision: 1, MetadataSlots: 1, MaxPurgeLeases: 2, CleanupBudgetSeconds: 60, ProofWindowSeconds: 60, ValidUntil: n.Add(time.Hour), History: &q}
	policy.BackupReservedBytes, policy.WALReservedBytes = q.SlotBacking(policy.MaxPurgeLeases)
	var err error
	in, err = auditapp.BindOperationLifecycle(in, policy)
	if err != nil {
		t.Fatal(err)
	}
	p.IntentDigest = auditapp.OperationLifecycleDigest(in)
	if !p.Valid(n.Add(4 * time.Millisecond)) {
		t.Fatal("fixture original observations do not overlap")
	}
	original := app.ConnectorCredentialAttempt{Permit: p, Intent: in}
	wire, err := json.Marshal(original)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := connectorCredentialAttempt(wire)
	if err != nil {
		t.Fatal("valid stored overlapping permit rejected", err)
	}
	again, err := json.Marshal(decoded)
	if err != nil || !bytes.Equal(wire, again) {
		t.Fatal("historical decoding rewrote original facts", err)
	}
	original.Permit.Recovery.ObservedAt = p.SignBefore
	wire, _ = json.Marshal(original)
	if _, err = connectorCredentialAttempt(wire); err == nil {
		t.Fatal("nonoverlapping persisted permit accepted")
	}
}
