package integration

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/adapters/postgres"
	auditapp "asservat.local/asservat/internal/application/audit"
	app "asservat.local/asservat/internal/application/capacity"
	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/application/planning"
	"asservat.local/asservat/internal/domain/artifact"
	auditvalue "asservat.local/asservat/internal/domain/audit"
	"asservat.local/asservat/internal/domain/authorization"
	capturevalue "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/domain/privacy"
)

// This path consumes the actual managed enrollment. It never inserts or
// replaces custody/control/capture pools, an allocation, or its storage binding.
// Only the initial human and Kubernetes target observations are synthetic.
func (f *capacitySQLFixture) admitManagedContext(t *testing.T, root app.RootConfiguration, enrollment app.Enrollment) (captureAdmissionScenario, capturevalue.Accepted) {
	t.Helper()
	return f.admitManagedContextRetention(t, root, enrollment, capacityNativeRetentionSeconds)
}

// Select the fixture's finite retention before policy acceptance and original
// submission preparation. This never edits a persisted cutoff or renews a
// request; the existing renewal cases retain their original 20-second default.
func (f *capacitySQLFixture) admitManagedContextRetention(t *testing.T, root app.RootConfiguration, enrollment app.Enrollment, retentionSeconds int64) (captureAdmissionScenario, capturevalue.Accepted) {
	t.Helper()
	n := time.Now().UTC().Truncate(time.Microsecond)
	target := capacityNativeTarget(f.input.ControlClusterID, f.namespace, f.workloads[0], n)
	policyInput := capacityNativeRetentionPolicy()
	policyInput.Policy.DefaultSeconds = retentionSeconds
	retention := newRetentionEffectFixturesWithPolicy(t, f.ctx, f.fixturePool, f.store, f.keys, policyInput)(t, f.input.PermissionRootID, target.Target())
	recovery := &recoveryEffectFixture{installation: f.input.InstallationID}
	var err error
	recovery.observation, err = readSyntheticFleetObservationBinding(f.ctx, f.admin, f.input.InstallationID)
	if err != nil {
		t.Fatal(err)
	}
	recovery.reader, err = postgres.NewRecoveryReader(f.ctx, f.fixturePool("peer_read_runtime", "synthetic-peer-read"), f.input.InstallationID)
	if err != nil {
		t.Fatal(err)
	}
	recovery.guard, err = postgres.NewRecoveryTransactionGuard(f.input.PermissionRootID, f.input.InstallationID)
	if err != nil {
		t.Fatal(err)
	}
	material := f.root.value.State.MAC
	mac, err := auditapp.NewOperationMAC(material.InputVersion, material.InputKey, material.AccountVersion, material.AccountKey)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(mac.Close)
	guards := postgres.EffectTransactionGuards{Retention: retention.guard, Recovery: recovery.guard}
	admission, err := postgres.NewAuditedContextAdmissions(f.ctx, f.roles["capture-admit"], f.input.PermissionRootID, mac, guards)
	if err != nil {
		t.Fatal(err)
	}
	policy := f.qualification.RootBacking.Capture.Policy
	policy.ValidUntil = root.PlannedUntil
	policy.BackingRevision = root.Revision
	journal, err := postgres.NewCaptureAuditJournal(f.ctx, f.roles["capture-journal"], policy)
	if err != nil {
		t.Fatal(err)
	}
	ack, err := postgres.NewCaptureAuditAcknowledgements(f.ctx, f.roles["capture-ack"], policy)
	if err != nil {
		t.Fatal(err)
	}
	completed, err := postgres.NewCaptureOperationIntents(f.ctx, f.roles["capture-intent-read"], f.input.PermissionRootID)
	if err != nil {
		t.Fatal(err)
	}
	writer, err := objectstore.NewClosedOperationAuditObjects(f.store, policy.StoreID, f.keys, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	publisher := auditapp.CaptureOperationPublication{RootID: f.input.PermissionRootID, Completed: completed, Journal: journal, Acknowledgements: ack, Writer: writer, Reader: &objectstore.OperationAuditObjects{Store: f.store, Seal: f.keys, Open: f.keys}, MAC: mac, Now: time.Now}
	f.checkManagedCapturePolicyWire(t, enrollment.AllocationID)
	// Refresh the actual independently accepted sources before this NEW request.
	// Nothing rewrites a capture, session, or prior phase to get more time.
	observation := f.workloadObservation(t, 0)
	if err = f.enrollments.RefreshCapacityEnrollment(f.ctx, observation, enrollment); err != nil {
		t.Fatal(err)
	}
	policies, err := retention.policies(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	n = time.Now().UTC().Truncate(time.Microsecond)
	target.ObservedAt, target.FreshUntil = n, n.Add(5*time.Second)
	retained, err := privacy.Resolve(policies, privacy.Input{Target: target.Target(), PrivacyClass: "potentialPersonalData", EvidenceType: "context", AnchorAt: n, RequestedSeconds: retentionSeconds}, n)
	if err != nil {
		t.Fatal(err)
	}
	if retained.DeleteBy.After(root.PlannedUntil) {
		t.Fatal("original processing backing cannot cover requested fixture retention")
	}
	actor := identity.Identity{Principal: identity.Principal{Issuer: "https://id.example.test", Subject: "capacity-developer", ClientID: "console", Kind: identity.Human}, Scopes: []string{"evidence:capture"}, Groups: []string{"maintainers"}, Policy: identity.Revision{UID: "synthetic-identity", Generation: 1, Digest: artifact.Digest{21}}, VerifiedAt: n, ValidUntil: n.Add(5 * time.Second)}
	projection, err := f.permission.Permissions(f.ctx, target.Target())
	if err != nil {
		t.Fatal(err)
	}
	eligibility := authorization.ContextEligibility(actor, projection, target.Target(), time.Now())
	if !eligibility.Eligible {
		t.Fatal("managed context ordinary eligibility", eligibility.Reason)
	}
	plan, err := planning.CompileContext(capacityNativeContextInput(target, retained, actor.Principal, custodyID(), n), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	storage, err := postgres.NewContextStorageReader(f.ctx, f.roles["hub-runtime"], f.input.PermissionRootID)
	if err != nil {
		t.Fatal(err)
	}
	selected, err := storage.ContextStorage(f.ctx, target.Target())
	if err != nil {
		t.Fatal("managed storage selection", err)
	}
	if selected.Selection.AllocationID != enrollment.AllocationID {
		t.Fatal("request selected another workload account")
	}
	r := artifact.Registration{Location: artifact.Location{ClusterID: f.input.ControlClusterID, ArtifactID: custodyID(), AttemptID: custodyID()}, StoreID: selected.Selection.StoreID, AllocationID: selected.Selection.AllocationID, PoolRevision: selected.Selection.PoolRevision, AllocationRevision: selected.Selection.AllocationRevision, NativeLimit: 4096, AnchorAt: retained.AnchorAt, WriteUntil: plan.Input.Deadline, ExpiresAt: retained.ExpiresAt, DeleteBy: retained.DeleteBy}
	proof, err := recovery.reader.RecoveryState(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	request := capturevalue.Admission{Recovery: proof, RootID: f.input.PermissionRootID, IdempotencyKey: "capacity-managed-session", SubmissionDigest: artifact.Digest{24}, Plan: plan, Eligibility: eligibility, Storage: selected.Binding, Registration: r, CaseID: custodyID(), OccurrenceID: custodyID()}
	f.checkManagedProcessingAdmission(t, admission, recovery.guard, policies, request)
	start := time.Now()
	accepted, err := admission.AdmitContext(f.ctx, request)
	if err != nil {
		t.Fatal("actual managed SQL52 admission", err)
	}
	if _, err = publisher.AcknowledgedCaptureIntent(f.ctx, accepted.CaptureID); err != nil {
		t.Fatal("actual managed encrypted intent pair", err)
	}
	t.Logf("managed_admission_pair_ms=%d original_request_remaining_ms=%d", time.Since(start).Milliseconds(), time.Until(actor.ValidUntil).Milliseconds())
	return captureAdmissionScenario{p: f.permission, s: admission, batch: f.batch, a: request, poolID: f.qualification.Backends[0].PoolID, retention: retention, recovery: recovery}, accepted
}

func (f *capacitySQLFixture) currentManagedPublication(ctx context.Context, s captureAdmissionScenario, e artifact.ContextExpectation) (artifact.PublicationAuthority, error) {
	p, err := s.p.Permissions(ctx, s.a.Eligibility.Target)
	if err != nil {
		return artifact.PublicationAuthority{}, err
	}
	retained, err := s.retention.policies(ctx)
	if err != nil {
		return artifact.PublicationAuthority{}, err
	}
	recovery, err := s.recovery.reader.RecoveryState(ctx)
	if err != nil {
		return artifact.PublicationAuthority{}, err
	}
	n := time.Now().UTC()
	return artifact.PublicationAuthority{Recovery: recovery, Retention: retained.Proof, RootID: s.a.RootID, CaptureID: e.CaptureUID, PermissionEpoch: p.Revision.UID, PermissionSequence: p.Revision.Generation, ProjectionDigest: artifact.Digest(p.Revision.Digest), ExpectationDigest: evidence.ContextExpectationDigest(e), AuthorityDigest: artifact.Digest{25}, CheckedAt: n, ValidUntil: identity.Earlier(retained.Proof.ValidUntil, identity.Earlier(p.FreshUntil, recovery.FreshUntil))}, nil
}

// Inspect only the exact original managed account before beginning a new human
// request. This is bounded fixture evidence, never runtime policy authority.
func (f *capacitySQLFixture) checkManagedCapturePolicyWire(t *testing.T, allocation string) {
	t.Helper()
	ctx, end := context.WithTimeout(f.ctx, 5*time.Second)
	defer end()
	var raw []byte
	if err := f.admin.QueryRow(ctx, `SELECT policy FROM capture_audit_allocation WHERE root_id=$1 AND allocation_id=$2`, f.input.PermissionRootID, allocation).Scan(&raw); err != nil {
		t.Fatal("managed policy diagnostic read unavailable")
	}
	var p auditvalue.OperationLifecyclePolicy
	if json.Unmarshal(raw, &p) != nil || !p.Valid() {
		t.Fatal("managed policy diagnostic typed shape unavailable")
	}
	encoded, err := json.Marshal(p)
	if err != nil {
		t.Fatal("managed policy diagnostic encoding unavailable")
	}
	var exact, remainder, instant bool
	if err = f.admin.QueryRow(ctx, `SELECT $1::jsonb=$2::jsonb, ($1::jsonb-'ValidUntil')=($2::jsonb-'ValidUntil'), ($1::jsonb->>'ValidUntil')::timestamptz=($2::jsonb->>'ValidUntil')::timestamptz`, raw, encoded).Scan(&exact, &remainder, &instant); err != nil {
		t.Fatal("managed policy diagnostic comparison unavailable")
	}
	t.Logf("managed_policy_roundtrip exact=%t non_time_fields=%t same_cutoff=%t", exact, remainder, instant)
	if !exact || !remainder || !instant {
		t.Fatal("managed capture policy does not survive typed wire roundtrip")
	}
}
