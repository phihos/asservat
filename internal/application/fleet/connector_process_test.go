package fleet

import (
	"context"
	"errors"
	"testing"
	"time"

	auditapp "asservat.local/asservat/internal/application/audit"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	value "asservat.local/asservat/internal/domain/fleet"
)

// Only coordinator authority/order is synthetic here. The Kubernetes adapter
// suite exercises the independent TokenReview/controller proof separately.
type connectorProcessFixture struct {
	*connectorRenewalFixture
	request                                   value.ConnectorProcessRequest
	admission                                 *ConnectorProcessAdmission
	proofReads, processStores, processAccepts int
	proofHook                                 func(*connectorProcessFixture)
	prepareHook                               func(*connectorProcessFixture)
	loseProcessStore, loseProcessAccept       bool
}

func newConnectorProcessFixture(t *testing.T) (*connectorProcessFixture, ConnectorProcessEnrollment, ConnectorRenewal) {
	t.Helper()
	f, renew := newConnectorRenewalFixture(t)
	process := value.ConnectorProcessIdentity{Binding: f.binding, PodUID: f.request.ID, ProcessEpoch: f.request.ID}
	f.process.BootstrapID = ""
	f.process.Attested = &process
	f.process.RunUntil = f.now.Add(2 * time.Hour)
	r := value.ConnectorProcessRequest{Process: process, ClientCSRDER: make([]byte, 64), ServerCSRDER: make([]byte, 64)}
	r.ClientCSRDER[0] = 1
	r.ServerCSRDER[0] = 2
	p := &connectorProcessFixture{connectorRenewalFixture: f, request: r}
	renew.ProcessProof = p
	enroll := ConnectorProcessEnrollment{Proof: p, Recovery: f, Journal: p, Audit: f, MAC: f.mac, Now: func() time.Time { return f.now }}
	return p, enroll, renew
}
func (f *connectorProcessFixture) ReadConnectorProcessProof(ctx context.Context, r value.ConnectorProcessRequest) (value.ConnectorProcessProof, error) {
	f.proofReads++
	if f.proofHook != nil {
		f.proofHook(f)
	}
	if ctx.Err() != nil {
		return value.ConnectorProcessProof{}, ctx.Err()
	}
	return value.ConnectorProcessProof{Process: r.Process, Configuration: value.ConnectorCredentialObservation{Backing: value.ConnectorBackingObservation{Revision: 1, Digest: artifact.Digest{31}, SourceDigest: artifact.Digest{32}}, Profile: f.profile.Clone(), ObservedAt: f.now, FreshUntil: f.now.Add(5 * time.Second)}, Pod: "connector-pod", ReplicaSet: "connector-rs", ReplicaSetUID: f.request.Process.PodUID, ClientKeyDigest: f.process.ClientKeyDigest, ServerKeyDigest: f.process.ServerKeyDigest, TokenDigest: artifact.Digest{21}, WorkloadDigest: artifact.Digest{22}, ProtectionDigest: artifact.Digest{23}, ObservedAt: f.now, FreshUntil: f.now.Add(5 * time.Second)}, nil
}
func (f *connectorProcessFixture) PrepareConnectorProcess(_ context.Context, id string, c ConnectorProcessCurrent) (ConnectorProcessAdmission, error) {
	if f.prepareHook != nil {
		f.prepareHook(f)
	}
	if f.admission != nil {
		return *f.admission, nil
	}
	actor := connectorProcessActor(c.Proof)
	in := audit.OperationIntent{ID: id, RootID: f.profile.RootID, TraceID: id, Name: "connector_process_enrollment", InputFormat: "connector-process/v1", MACVersion: "mac-v1", AccountVersion: "account-v1", Process: &actor, PrincipalDigest: artifact.Digest{5}, InputDigest: artifact.Digest{6}, CreatedAt: c.ObservedAt, RequestUntil: c.Until, WriteUntil: c.ObservedAt.Add(30 * time.Second), RetainUntil: c.ObservedAt.Add(3 * time.Hour)}
	q := audit.OperationHistoryQualification{ID: id, Digest: artifact.Digest{7}, Layout: audit.ConnectorOperationHistoryLayout, MaximumRowFootprintBytes: 1 << 20, MaximumTransitionWALBytes: 1 << 20, BackupCopies: 1, WALCopies: 1}
	policy := audit.OperationLifecyclePolicy{RootID: f.profile.RootID, Lane: "identity", InstallationID: f.binding.InstallationID, StoreID: id, PolicyID: id, BackupProfileID: id, PolicyDigest: artifact.Digest{8}, BackupProfileDigest: artifact.Digest{9}, BackingRevision: 1, MetadataSlots: 1, MaxPurgeLeases: 2, CleanupBudgetSeconds: 60, ProofWindowSeconds: 60, ValidUntil: c.ObservedAt.Add(time.Hour), History: &q}
	policy.BackupReservedBytes, policy.WALReservedBytes = q.SlotBacking(policy.MaxPurgeLeases)
	var e error
	in, e = auditapp.BindOperationLifecycle(in, policy)
	if e != nil {
		return ConnectorProcessAdmission{}, e
	}
	a := ConnectorProcessAdmission{Process: f.process, Intent: in}
	f.admission = &a
	return a, nil
}
func (f *connectorProcessFixture) StoreConnectorProcessOutcome(_ context.Context, _ ConnectorProcessAdmission, o audit.OperationOutcome) error {
	f.processStores++
	f.admission.Outcome = &o
	if f.loseProcessStore {
		return value.ErrUnavailable
	}
	return nil
}
func (f *connectorProcessFixture) AcceptConnectorProcess(_ context.Context, a ConnectorProcessAdmission, c ConnectorProcessCurrent) (value.ConnectorCredentialProcess, error) {
	if !f.intentAck || !f.outcomeAck || f.retired || !c.Valid(f.now) {
		return value.ConnectorCredentialProcess{}, value.ErrDenied
	}
	f.processAccepts++
	f.admission.Activated = true
	if f.loseProcessAccept {
		return value.ConnectorCredentialProcess{}, value.ErrUnavailable
	}
	return a.Process, nil
}
func TestConnectorProcessEnrollmentRequiresCurrentProofAndBothAuditAcknowledgements(t *testing.T) {
	cases := map[string]func(*connectorProcessFixture){
		"intent unavailable":  func(f *connectorProcessFixture) { f.failBegin = true },
		"outcome unavailable": func(f *connectorProcessFixture) { f.failFinish = true },
		"controller changes after intent": func(f *connectorProcessFixture) {
			f.proofHook = func(f *connectorProcessFixture) {
				if f.proofReads == 2 {
					f.profile.Deployment.DeploymentUID = "20000000-0000-4000-8000-000000000001"
				}
			}
		},
		"blocking proof expires original operation": func(f *connectorProcessFixture) {
			f.proofHook = func(f *connectorProcessFixture) {
				if f.proofReads == 2 {
					f.now = f.now.Add(6 * time.Second)
				}
			}
		},
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			f, s, _ := newConnectorProcessFixture(t)
			change(f)
			if _, e := s.Enroll(context.Background(), f.connectorRenewalFixture.request.ID, f.request); e == nil || f.processAccepts != 0 || f.signs != 0 {
				t.Fatal("unavailable process became accepted", e, f.processAccepts)
			}
		})
	}
	t.Run("final mutation", func(t *testing.T) {
		f, s, _ := newConnectorProcessFixture(t)
		f.proofHook = func(f *connectorProcessFixture) {
			if f.proofReads == 4 {
				f.profile.Suspended = true
			}
		}
		if _, e := s.Enroll(context.Background(), f.connectorRenewalFixture.request.ID, f.request); e == nil || f.processAccepts != 1 {
			t.Fatal("final current proof not enforced", e, f.processAccepts)
		}
	})
}
func TestConnectorProcessEnrollmentReconcilesOnlyExactStoredOutcome(t *testing.T) {
	for _, phase := range []string{"outcome store", "acceptance"} {
		t.Run(phase, func(t *testing.T) {
			f, s, _ := newConnectorProcessFixture(t)
			f.loseProcessStore = phase == "outcome store"
			f.loseProcessAccept = phase == "acceptance"
			id := f.connectorRenewalFixture.request.ID
			if _, e := s.Enroll(context.Background(), id, f.request); e == nil {
				t.Fatal("unknown result acknowledged")
			}
			f.loseProcessStore = false
			f.loseProcessAccept = false
			f.now = f.now.Add(6 * time.Second)
			if p, e := s.Enroll(context.Background(), id, f.request); e != nil || p.Attested == nil || *p.Attested != f.request.Process || f.processStores != 1 || f.signs != 0 {
				t.Fatal("exact acknowledged process not reconciled", e, f.processStores)
			}
			changed := f.request
			changed.Process.ProcessEpoch = "20000000-0000-4000-8000-000000000001"
			if _, e := s.Enroll(context.Background(), id, changed); e == nil {
				t.Fatal("same key changed process")
			}
		})
	}
}
func TestConnectorInitialCredentialsUsePodProofWithoutFabricatingTLS(t *testing.T) {
	for _, usage := range []string{"client", "server"} {
		t.Run(usage, func(t *testing.T) {
			f, _, s := newConnectorProcessFixture(t)
			f.registryDenied = true
			out, e := s.IssueProcess(context.Background(), f.connectorRenewalFixture.request.ID, usage, f.request)
			if e != nil || out.Certificate.Usage != usage || f.signs != 1 || f.row.Intent.Peer != nil || f.row.Intent.Process == nil || f.row.Permit.CurrentPeer != (value.AuthenticatedPeer{}) {
				t.Fatal("initial process signing did not retain its actual actor", e)
			}
		})
	}
	t.Run("uncertain provider", func(t *testing.T) {
		f, _, s := newConnectorProcessFixture(t)
		f.loseProvider = true
		id := f.connectorRenewalFixture.request.ID
		if _, e := s.IssueProcess(context.Background(), id, "client", f.request); e == nil {
			t.Fatal("unknown provider success")
		}
		f.loseProvider = false
		if _, e := s.IssueProcess(context.Background(), id, "client", f.request); !errors.Is(e, value.ErrPending) || f.signs != 1 {
			t.Fatal("uncertain process signing was retried", e, f.signs)
		}
	})
}

func TestConnectorActivatedReplayAfterAuditWriteDeadline(t *testing.T) {
	for _, kind := range []string{"process", "client", "server"} {
		t.Run(kind, func(t *testing.T) {
			f, enroll, renew := newConnectorProcessFixture(t)
			id := f.connectorRenewalFixture.request.ID
			f.loseProcessAccept, f.loseActivation = true, true
			invoke := func() error {
				if kind == "process" {
					_, e := enroll.Enroll(context.Background(), id, f.request)
					return e
				}
				_, e := renew.IssueProcess(context.Background(), id, kind, f.request)
				return e
			}
			if e := invoke(); e == nil {
				t.Fatal("lost acknowledgement reported success")
			}
			if kind == "process" && !f.admission.Activated || kind != "process" && !f.row.Activated {
				t.Fatal("fixture did not commit original activation")
			}
			f.loseProcessAccept, f.loseActivation = false, false
			f.now = f.now.Add(31 * time.Second)
			finishes := f.finishCalls
			if e := invoke(); e != nil {
				t.Fatal("durably activated original result could not be recovered", e)
			}
			if f.finishCalls != finishes || f.signs > 1 || f.stores > 1 || f.processStores > 1 {
				t.Fatal("replay repeated old audit/signing work")
			}
			f.retired = true
			if e := invoke(); e == nil {
				t.Fatal("retired old epoch recovered after replacement")
			}
			f.retired = false
			f.outcomeAck = false
			if e := invoke(); e == nil {
				t.Fatal("unacknowledged original result recovered")
			}
		})
	}
}
