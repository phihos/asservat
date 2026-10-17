package fleet

import (
	auditapp "asservat.local/asservat/internal/application/audit"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	"context"
	"crypto/sha256"
	"errors"
	"testing"
	"time"
)

// These are explicitly synthetic authority/provider facets. Tests below qualify
// coordinator ordering/deadlines; they are not SQL, TLS or provider acceptance.
type connectorRenewalFixture struct {
	now                                            time.Time
	binding                                        value.PeerBinding
	cert                                           value.PeerCertificate
	profile                                        value.ConnectorCredentialProfile
	roles                                          value.ConnectorIdentityRoles
	request                                        ConnectorCredentialRequest
	process                                        value.ConnectorCredentialProcess
	row                                            *ConnectorCredentialAttempt
	mac                                            *auditapp.OperationMAC
	reads, signs, claims, stores, activations      int
	intentAck, outcomeAck                          bool
	failBegin, failFinish, loseProvider, loseStore bool
	registryDenied                                 bool
	retired, loseActivation                        bool
	finishCalls                                    int
	sourceHook                                     func(*connectorRenewalFixture)
	issuerHook                                     func(*connectorRenewalFixture, context.Context)
	providerDeadline                               time.Time
}

func newConnectorRenewalFixture(t *testing.T) (*connectorRenewalFixture, ConnectorRenewal) {
	t.Helper()
	n := time.Now().UTC().Truncate(time.Microsecond)
	const id = "10000000-0000-4000-8000-000000000001"
	b := value.PeerBinding{InstallationID: id, ClusterID: id, IssuerEpoch: id, PeerID: id, Role: value.ConnectorPeer}
	rev := identity.Revision{UID: id, Generation: 1, Digest: artifact.Digest{1}}
	f := &connectorRenewalFixture{now: n, binding: b, roles: value.ConnectorIdentityRoles{Source: "connector_source", Journal: "connector_journal", Acknowledgement: "connector_ack", Cleanup: "connector_cleanup", Verifier: "connector_verifier", Finalizer: "connector_finalizer"}, request: ConnectorCredentialRequest{ID: id, BootstrapID: id, Usage: "server", CSR: make([]byte, 64)}}
	f.process = value.ConnectorCredentialProcess{BootstrapID: id, Binding: b, ClientKeyDigest: artifact.Digest{1}, ServerKeyDigest: artifact.Digest{2}, ClaimedAt: n, InitialCertificateNotAfter: n.Add(30 * time.Minute).Truncate(time.Second)}
	f.cert = value.PeerCertificate{Binding: b, Digest: artifact.Digest{3}, NotBefore: n.Add(-time.Second), NotAfter: f.process.InitialCertificateNotAfter}
	f.profile = value.ConnectorCredentialProfile{Deployment: value.ConnectorDeployment{Namespace: "connector", NamespaceUID: id, ServiceAccount: "connector", AccountUID: id, Deployment: "connector", DeploymentUID: id, ServingSlots: 2, RetainedProcesses: 8}, RootID: id, Binding: b, Revision: rev, ProtectionDigest: artifact.Digest{4}, ServerName: "connector.invalid", ClientIssuerRoots: [][]byte{{1}}, ServerIssuerRoots: [][]byte{{2}}}
	var e error
	f.mac, e = auditapp.NewOperationMAC("mac-v1", make([]byte, 32), "account-v1", append([]byte{1}, make([]byte, 31)...))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(f.mac.Close)
	return f, ConnectorRenewal{Proof: f, Registry: f, Source: f, Recovery: f, Journal: f, Audit: f, MAC: f.mac, Issuer: f, Verifier: f, Now: func() time.Time { return f.now }}
}
func (f *connectorRenewalFixture) EnrollmentKey(csr []byte) (artifact.Digest, error) {
	if len(csr) > 0 && csr[0] == 1 {
		return f.process.ClientKeyDigest, nil
	}
	return f.process.ServerKeyDigest, nil
}
func (f *connectorRenewalFixture) PeerRegistration(context.Context, value.PeerBinding) (value.PeerRegistration, error) {
	if f.registryDenied {
		return value.PeerRegistration{}, value.ErrDenied
	}
	return value.PeerRegistration{Binding: f.binding, Revision: f.profile.Revision, Enabled: true, Certificates: []value.PeerCertificate{f.cert}, ObservedAt: f.now, FreshUntil: f.now.Add(5 * time.Second)}, nil
}
func (f *connectorRenewalFixture) ReadConnectorIdentitySource(context.Context) (value.ConnectorIdentitySource, error) {
	f.reads++
	if f.sourceHook != nil {
		f.sourceHook(f)
	}
	return value.ConnectorIdentitySource{Observation: value.ConnectorCredentialObservation{Backing: value.ConnectorBackingObservation{Revision: 1, Digest: artifact.Digest{31}, SourceDigest: artifact.Digest{32}}, Profile: f.profile.Clone(), ObservedAt: f.now, FreshUntil: f.now.Add(5 * time.Second)}, Roles: f.roles}, nil
}
func (f *connectorRenewalFixture) RecoveryState(context.Context) (value.RecoveryState, error) {
	return value.RecoveryState{InstallationID: f.binding.InstallationID, IssuerEpoch: f.binding.IssuerEpoch, Revision: f.profile.Revision, ObservedAt: f.now, FreshUntil: f.now.Add(5 * time.Second)}, nil
}
func (f *connectorRenewalFixture) PrepareConnectorCredential(_ context.Context, c ConnectorCredentialCandidate) (ConnectorCredentialAttempt, error) {
	if f.row != nil {
		return *f.row, nil
	}
	epoch, end, _ := f.process.Window(c.Current.ObservedAt)
	in := audit.OperationIntent{ID: c.ID, RootID: f.profile.RootID, TraceID: c.ID, Name: "connector_" + c.Usage + "_certificate", InputFormat: "connector-credential/v1", MACVersion: "mac-v1", AccountVersion: "account-v1", Peer: &audit.OperationPeerActor{Binding: f.binding, CertificateDigest: f.cert.Digest}, PrincipalDigest: artifact.Digest{5}, InputDigest: artifact.Digest{6}, CreatedAt: c.Current.ObservedAt, RequestUntil: c.Current.Until, WriteUntil: c.Current.ObservedAt.Add(30 * time.Second), RetainUntil: c.Current.ObservedAt.Add(3 * time.Hour)}
	if c.Current.ProcessProof != nil {
		actor := connectorProcessActor(*c.Current.ProcessProof)
		in.Peer = nil
		in.Process = &actor
	}
	q := audit.OperationHistoryQualification{ID: c.ID, Digest: artifact.Digest{7}, Layout: audit.ConnectorOperationHistoryLayout, MaximumRowFootprintBytes: 1 << 20, MaximumTransitionWALBytes: 1 << 20, BackupCopies: 1, WALCopies: 1}
	policy := audit.OperationLifecyclePolicy{RootID: f.profile.RootID, Lane: "identity", InstallationID: f.binding.InstallationID, StoreID: c.ID, PolicyID: c.ID, BackupProfileID: c.ID, PolicyDigest: artifact.Digest{8}, BackupProfileDigest: artifact.Digest{9}, BackingRevision: 1, MetadataSlots: 1, MaxPurgeLeases: 2, CleanupBudgetSeconds: 60, ProofWindowSeconds: 60, ValidUntil: c.Current.ObservedAt.Add(time.Hour), History: &q}
	policy.BackupReservedBytes, policy.WALReservedBytes = q.SlotBacking(policy.MaxPurgeLeases)
	var e error
	in, e = auditapp.BindOperationLifecycle(in, policy)
	if e != nil {
		return ConnectorCredentialAttempt{}, e
	}
	p := value.ConnectorCredentialPermit{ID: c.ID, Process: f.process, Usage: c.Usage, Configuration: c.Current.Source.Observation, CurrentPeer: c.Current.Peer, ProcessProof: c.Current.ProcessProof, Recovery: c.Current.Recovery, IntentDigest: auditapp.OperationLifecycleDigest(in), Epoch: epoch, Ordinal: 1, CheckedAt: c.Current.ObservedAt, SignBefore: c.Current.Until, CertificateNotAfter: end}
	a := ConnectorCredentialAttempt{Permit: p, Intent: in}
	f.row = &a
	return a, nil
}
func (f *connectorRenewalFixture) Begin(context.Context, audit.OperationIntent) error {
	if f.failBegin {
		return value.ErrUnavailable
	}
	f.intentAck = true
	return nil
}
func (f *connectorRenewalFixture) Finish(_ context.Context, out audit.OperationOutcome) error {
	f.finishCalls++
	if f.failFinish || !f.now.Before(out.Intent.WriteUntil) {
		return value.ErrUnavailable
	}
	f.outcomeAck = true
	return nil
}
func (f *connectorRenewalFixture) ClaimConnectorCredential(_ context.Context, a ConnectorCredentialAttempt, c ConnectorCredentialCurrent) (bool, error) {
	f.claims++
	if !f.intentAck || !c.Valid(f.now) || f.row.ProviderStarted {
		return false, value.ErrDenied
	}
	f.row.ProviderStarted = true
	return true, nil
}
func (f *connectorRenewalFixture) SignConnectorCredential(ctx context.Context, p value.ConnectorCredentialPermit, _ []byte) (value.IssuedConnectorCredential, error) {
	f.signs++
	f.providerDeadline, _ = ctx.Deadline()
	if f.issuerHook != nil {
		f.issuerHook(f, ctx)
	}
	if f.loseProvider {
		return value.IssuedConnectorCredential{}, value.ErrUnavailable
	}
	der := []byte("synthetic public certificate; no cryptographic authority")
	return value.IssuedConnectorCredential{Certificate: value.ConnectorCredentialCertificate{Binding: f.binding, Usage: p.Usage, ServerName: func() string {
		if p.Usage == "server" {
			return f.profile.ServerName
		}
		return ""
	}(), Digest: artifact.Digest(sha256.Sum256(der)), PublicKeyDigest: p.PublicKeyDigest(), NotBefore: p.CheckedAt.Add(-time.Second).Truncate(time.Second), NotAfter: p.CertificateNotAfter}, DER: der}, nil
}
func (f *connectorRenewalFixture) CheckConnectorCredentialCurrent(p value.ConnectorCredentialPermit, _ []byte, der []byte, chain [][]byte, _ value.ConnectorCredentialObservation) (value.IssuedConnectorCredential, error) {
	return value.IssuedConnectorCredential{Certificate: value.ConnectorCredentialCertificate{Binding: f.binding, Usage: p.Usage, ServerName: func() string {
		if p.Usage == "server" {
			return f.profile.ServerName
		}
		return ""
	}(), Digest: artifact.Digest(sha256.Sum256(der)), PublicKeyDigest: p.PublicKeyDigest(), NotBefore: p.CheckedAt.Add(-time.Second).Truncate(time.Second), NotAfter: p.CertificateNotAfter}, DER: append([]byte(nil), der...), ChainDER: chain}, nil
}
func (f *connectorRenewalFixture) StoreConnectorCredential(_ context.Context, _ ConnectorCredentialAttempt, c value.IssuedConnectorCredential, out audit.OperationOutcome) error {
	f.stores++
	f.row.Certificate = &c
	f.row.Outcome = &out
	if f.loseStore {
		return value.ErrUnavailable
	}
	return nil
}
func (f *connectorRenewalFixture) ActivateConnectorCredential(_ context.Context, a ConnectorCredentialAttempt, c ConnectorCredentialCurrent) (value.IssuedConnectorCredential, error) {
	if !f.intentAck || !f.outcomeAck || f.retired || !c.Valid(f.now) {
		return value.IssuedConnectorCredential{}, value.ErrDenied
	}
	f.activations++
	f.row.Activated = true
	if f.loseActivation {
		return value.IssuedConnectorCredential{}, value.ErrUnavailable
	}
	return a.Certificate.Clone(), nil
}
func TestConnectorRenewalPreservesOneUseSigningAcrossLostReplies(t *testing.T) {
	t.Run("provider unknown", func(t *testing.T) {
		f, s := newConnectorRenewalFixture(t)
		f.loseProvider = true
		if _, e := s.Issue(context.Background(), f.cert, f.request); e == nil {
			t.Fatal("unknown signing delivered")
		}
		f.loseProvider = false
		if _, e := s.Issue(context.Background(), f.cert, f.request); !errors.Is(e, value.ErrPending) || f.signs != 1 || f.stores != 0 || f.activations != 0 {
			t.Fatal("unknown provider result retried", e, f.signs)
		}
	})
	t.Run("stored reply lost", func(t *testing.T) {
		f, s := newConnectorRenewalFixture(t)
		f.loseStore = true
		if _, e := s.Issue(context.Background(), f.cert, f.request); e == nil {
			t.Fatal("lost store acknowledged")
		}
		f.loseStore = false
		f.now = f.now.Add(6 * time.Second)
		if _, e := s.Issue(context.Background(), f.cert, f.request); e != nil || f.signs != 1 || f.stores != 1 || f.activations != 1 {
			t.Fatal("exact stored result was not reconciled", e, f.signs, f.stores, f.activations)
		}
	})
}
func TestConnectorRenewalRequiresAuditAndCurrentOriginalAuthority(t *testing.T) {
	tests := map[string]func(*connectorRenewalFixture){
		"intent unavailable": func(f *connectorRenewalFixture) { f.failBegin = true },
		"source changed after audit": func(f *connectorRenewalFixture) {
			f.sourceHook = func(f *connectorRenewalFixture) {
				if f.reads == 2 {
					f.profile.Revision.Generation++
				}
			}
		},
		"source blocked beyond original observation": func(f *connectorRenewalFixture) {
			f.sourceHook = func(f *connectorRenewalFixture) {
				if f.reads == 2 {
					f.now = f.now.Add(6 * time.Second)
				}
			}
		},
		"revoked peer": func(f *connectorRenewalFixture) { f.registryDenied = true },
	}
	for name, change := range tests {
		t.Run(name, func(t *testing.T) {
			f, s := newConnectorRenewalFixture(t)
			change(f)
			if _, e := s.Issue(context.Background(), f.cert, f.request); e == nil || f.signs != 0 || f.activations != 0 {
				t.Fatal("unavailable authority permitted issuance", e, f.signs, f.activations)
			}
		})
	}
	t.Run("provider blocked", func(t *testing.T) {
		f, s := newConnectorRenewalFixture(t)
		f.issuerHook = func(f *connectorRenewalFixture, _ context.Context) { f.now = f.now.Add(6 * time.Second) }
		if _, e := s.Issue(context.Background(), f.cert, f.request); e == nil || f.signs != 1 || f.stores != 0 || f.activations != 0 {
			t.Fatal("expired provider response stored", e)
		}
	})
	t.Run("outcome unavailable", func(t *testing.T) {
		f, s := newConnectorRenewalFixture(t)
		f.failFinish = true
		if _, e := s.Issue(context.Background(), f.cert, f.request); e == nil || f.signs != 1 || f.stores != 1 || f.activations != 0 {
			t.Fatal("unaudited result activated", e)
		}
	})
	t.Run("final source changed", func(t *testing.T) {
		f, s := newConnectorRenewalFixture(t)
		f.sourceHook = func(f *connectorRenewalFixture) {
			if f.reads == 4 {
				f.profile.Suspended = true
			}
		}
		if _, e := s.Issue(context.Background(), f.cert, f.request); e == nil || f.activations != 1 {
			t.Fatal("stale result disclosed", e, f.activations)
		}
	})
}
