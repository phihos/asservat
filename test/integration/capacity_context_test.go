package integration

import (
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/postgres"
	"asservat.local/asservat/internal/application/planning"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	capturevalue "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/domain/privacy"
)

// This path consumes the actual managed enrollment. It never inserts or
// replaces custody/control/capture pools, an allocation, or its storage binding.
// Only the initial human and Kubernetes target observations are synthetic.
func (f *capacitySQLFixture) admitManagedContext(t *testing.T, root capacityRoot, enrollment capacityEnrollment) (captureAdmissionScenario, capturevalue.Accepted) {
	t.Helper()
	return f.admitManagedContextRetention(t, root, enrollment, capacityNativeRetentionSeconds)
}

// Select the fixture's finite retention before policy acceptance and original
// submission preparation. This never edits a persisted cutoff or renews a
// request; the existing renewal cases retain their original 20-second default.
func (f *capacitySQLFixture) admitManagedContextRetention(t *testing.T, root capacityRoot, enrollment capacityEnrollment, retentionSeconds int64) (captureAdmissionScenario, capturevalue.Accepted) {
	t.Helper()
	s, publisher, _ := f.prepareManagedContext(t, root, enrollment, retentionSeconds)
	start := time.Now()
	accepted, err := s.s.AdmitContext(f.ctx, s.a)
	if err != nil {
		t.Fatal("actual managed SQL52 admission", err)
	}
	if _, err = publisher.AcceptedCaptureIntent(f.ctx, accepted.CaptureID); err != nil {
		t.Fatal("actual managed encrypted intent pair", err)
	}
	t.Logf("managed_admission_pair_ms=%d original_request_remaining_ms=%d", time.Since(start).Milliseconds(), time.Until(s.a.Eligibility.ValidUntil).Milliseconds())
	return s, accepted
}

func (f *capacitySQLFixture) prepareManagedContext(t *testing.T, root capacityRoot, enrollment capacityEnrollment, retentionSeconds int64, additional ...privacy.ScopedPolicy) (captureAdmissionScenario, *postgres.CaptureIntents, privacy.PolicySet) {
	t.Helper()
	n := time.Now().UTC().Truncate(time.Microsecond)
	target := capacityNativeTarget(f.input.ControlClusterID, f.namespace, f.workloads[0], n)
	policyInput := capacityNativeRetentionPolicy()
	policyInput.Policy.DefaultSeconds = retentionSeconds
	retentionFactory, _ := newRetentionEffectFixturesWithPolicy(t, f.ctx, f.fixturePool, f.store, f.keys, policyInput, additional...)
	retention := retentionFactory(t, f.input.PermissionRootID, target.Target())
	recovery := &recoveryEffectFixture{installation: f.input.InstallationID}
	var err error
	recovery.observation, err = readSyntheticFleetBinding(f.ctx, f.admin, f.input.InstallationID)
	if err != nil {
		t.Fatal(err)
	}
	admission, err := postgres.NewContextAdmissions(f.ctx, f.roles["capture-admit"], f.input.PermissionRootID, f.input.InstallationID)
	if err != nil {
		t.Fatal(err)
	}
	publisher, err := postgres.NewCaptureIntents(f.ctx, f.roles["capture-admit"], f.input.PermissionRootID)
	if err != nil {
		t.Fatal(err)
	}
	// Refresh the actual independently accepted sources before this NEW request.
	// Nothing rewrites a capture, session, or prior phase to get more time.
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
	request := capturevalue.Admission{RootID: f.input.PermissionRootID, IdempotencyKey: "capacity-managed-session", SubmissionDigest: artifact.Digest{24}, Plan: plan, Eligibility: eligibility, Storage: selected.Binding, Registration: r, CaseID: custodyID(), OccurrenceID: custodyID()}
	return captureAdmissionScenario{p: f.permission, s: admission, batch: f.batch, a: request, poolID: f.qualification.Backends[0].PoolID, retention: retention, recovery: recovery}, publisher, policies
}

// Inspect only the exact original managed account before beginning a new human
// request. This is bounded fixture evidence, never runtime policy authority.
