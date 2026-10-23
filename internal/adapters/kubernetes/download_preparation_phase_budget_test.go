package kubernetes

import (
	"context"
	"strings"
	"testing"
	"time"

	auditapp "asservat.local/asservat/internal/application/audit"
	authapp "asservat.local/asservat/internal/application/authorization"
	"asservat.local/asservat/internal/application/evidence"
	identities "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	value "asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/domain/privacy"
)

// Only policy HTTP, its native-protection reader, CurrentDownloadEnvironment,
// and coordinator/runtime/dispatcher ordering are real. All other authority,
// SQL/audit and Job ports are explicitly synthetic and complete without delay.
// No database, object store, Kubernetes cluster, worker or native bytes exist.
type preparationPhaseBudget struct {
	*downloadPolicyBudgetFixture
	t              *testing.T
	started, until time.Time
	i              identity.Identity
	a              artifact.DownloadAuthority
	record         authapp.ContextDownloadEvidence
	recovery       artifact.RecoveryProof
	processing     artifact.DownloadProcessingProof
	source         evidence.ContextDownloadSource
	profile        value.DownloadWorkerProfile
	session        artifact.DownloadSession
	intent         value.DownloadWorkerIntent
	job            value.DownloadWorkerJob
	environment    authapp.CurrentDownloadEnvironment
	// Nil isolates deployment-policy cost. The stronger fixture supplies the
	// actual ordinary authorizer without changing coordinator ordering.
	authority                       evidence.CurrentDownloadAuthority
	steps                           []string
	checks, policyReads, policiesOK int
	created, recorded, pending      bool
}

// The public runtime constructor checks the complete installed interface shape.
// These unused downstream ports intentionally embed nil implementations: any
// unexpected enrollment/native/content call fails the test instead of supplying
// a permissive fake. The measured target ends at an acknowledged pending Job.
type preparationPhaseUnused struct {
	evidence.FirstContextPreparationSessions
	evidence.WorkerEnrollmentBindings
	evidence.WorkerOwnerStore
	evidence.WorkerCSRVerifier
	evidence.WorkerEnrollmentLedger
	evidence.WorkerCertificateActivator
	evidence.WorkerCertificateIssuer
	auditapp.WorkerEnrollmentWriter
	auditapp.WorkerEnrollmentAcknowledgements
	auditapp.DownloadWriter
	evidence.DownloadAuditAcknowledger
	evidence.NativeOperations
	evidence.NativeFenceReader
	evidence.NativeExchangeRegistrar
	evidence.DownloadKeyBindingLedger
	evidence.NativeWindowKeyBindings
}

func (*preparationPhaseUnused) FirstContextObservationsOnly() {}

type preparationPhaseLedger struct {
	evidence.DownloadWorkerLedger
	*preparationPhaseBudget
}

type preparationPhaseJobs struct {
	evidence.DownloadWorkerJobs
	*preparationPhaseBudget
}

func (f *preparationPhaseBudget) step(ctx context.Context, name string) error {
	f.steps = append(f.steps, name)
	deadline, ok := ctx.Deadline()
	if !ok || deadline.After(f.until) {
		f.t.Fatalf("%s lost original request bound: %s > %s", name, deadline, f.until)
	}
	return ctx.Err()
}

func (f *preparationPhaseBudget) DownloadPolicy(ctx context.Context) (privacy.DownloadPolicy, error) {
	f.policyReads++
	p, err := f.downloadPolicyBudgetFixture.source.DownloadPolicy(ctx)
	if err == nil {
		f.policiesOK++
	}
	return p, err
}

func (f *preparationPhaseBudget) ResolveIdentity(ctx context.Context) (identity.Identity, error) {
	return f.i, f.step(ctx, "identity")
}
func (f *preparationPhaseBudget) RecoveryState(ctx context.Context) (artifact.RecoveryProof, error) {
	return f.recovery, f.step(ctx, "recovery")
}
func (f *preparationPhaseBudget) ContextProcessing(ctx context.Context, r authapp.ContextDownloadEvidence, recovery artifact.RecoveryProof) (artifact.DownloadProcessingProof, error) {
	if r.CaptureID != f.record.CaptureID || recovery != f.recovery {
		f.t.Fatal("processing changed original selection")
	}
	return f.processing, f.step(ctx, "processing")
}
func (f *preparationPhaseBudget) CheckDownloadCurrent(ctx context.Context, current identities.CurrentIdentity, scope artifact.DownloadScope) (artifact.DownloadAuthority, error) {
	f.checks++
	if scope != f.a.Scope {
		f.t.Fatal("authority changed original scope")
	}
	if f.authority != nil {
		return f.authority.CheckDownloadCurrent(ctx, current, scope)
	}
	// Fixed identity/catalog/retention facts isolate the real policy cost.
	// Every production current check still evaluates the actual environment.
	environment, err := f.environment.DownloadEnvironment(ctx, f.record, scope.Principal)
	if err != nil {
		return artifact.DownloadAuthority{}, err
	}
	a := f.a
	a.Environment, a.ValidUntil = environment, identity.Earlier(a.ValidUntil, environment.ValidUntil)
	return a, f.step(ctx, "authority")
}
func (f *preparationPhaseBudget) ResolveContextDownload(ctx context.Context, _ artifact.DownloadRouteQuery) (artifact.DownloadRoute, error) {
	return artifact.DownloadRoute{Scope: f.a.Scope, ObservedAt: f.started, ValidUntil: f.until}, f.step(ctx, "route")
}
func (f *preparationPhaseBudget) LookupDownloadKey(ctx context.Context, _ artifact.DownloadKeyQuery) (artifact.DownloadKeyLookup, error) {
	return artifact.DownloadKeyLookup{ObservedAt: f.started, ValidUntil: f.until}, f.step(ctx, "lookup-key")
}
func (f *preparationPhaseBudget) LookupDownload(ctx context.Context, _ string, _ identity.Principal) (artifact.DownloadSession, error) {
	return f.session, f.step(ctx, "lookup")
}
func (f *preparationPhaseBudget) ReserveDownload(ctx context.Context, r evidence.DownloadReservation) (artifact.DownloadSession, error) {
	f.session = r.Session
	return f.session, f.step(ctx, "reserve-session")
}
func (f *preparationPhaseBudget) ObserveDownload(ctx context.Context, _ string, _ artifact.DownloadAuthority, _ *artifact.DownloadPreparation) (artifact.DownloadObservation, error) {
	return artifact.DownloadObservation{Session: f.session, ObservedAt: f.started, ValidUntil: f.until}, f.step(ctx, "observe-session")
}
func (f *preparationPhaseBudget) ContextDownloadPlan(ctx context.Context, scope artifact.DownloadScope) (evidence.ContextDownloadPlan, error) {
	return evidence.ContextDownloadPlan{Allocation: artifact.DownloadAllocation{ID: ownerID(19100), RootID: scope.RootID, ClusterID: scope.ClusterID, NamespaceUID: scope.NamespaceUID, WorkloadUID: scope.WorkloadUID, OutputLimit: 1 << 20, ReadLimit: 128 << 20, SessionLimit: 4, ValidUntil: f.started.Add(time.Minute)}, OutputLimit: 8192, ReadLimit: 16 << 20, RequestLimit: 4, Duration: 30 * time.Second, ObservedAt: f.started, ValidUntil: f.until}, f.step(ctx, "plan")
}
func (f *preparationPhaseBudget) ContextNativeReady(ctx context.Context) (time.Time, error) {
	return f.until, f.step(ctx, "runtime-ready")
}
func (f *preparationPhaseBudget) CurrentWorkerConfiguration(ctx context.Context, _ value.DownloadWorkerProfile) (time.Time, error) {
	return f.until, f.step(ctx, "configuration")
}
func (f *preparationPhaseBudget) ReadContextDownloadSource(ctx context.Context, _ artifact.DownloadAuthority) (evidence.ContextDownloadSource, error) {
	return f.source, f.step(ctx, "source")
}
func (f *preparationPhaseBudget) ReadContextDownloadAttachment(ctx context.Context, id string, _ artifact.DownloadAuthority) (evidence.ContextDownloadAttachment, error) {
	return evidence.ContextDownloadAttachment{SessionID: id, Scope: f.a.Scope, State: artifact.DownloadPreparing, ObservedAt: f.started, ValidUntil: f.until}, f.step(ctx, "attachment")
}
func (f preparationPhaseLedger) ReserveDownloadWorker(ctx context.Context, session, id string, a artifact.DownloadAuthority, profile value.DownloadWorkerProfile) (value.DownloadWorkerIntent, error) {
	f.intent = value.DownloadWorkerIntent{ID: id, SessionID: session, Generation: 1, Profile: profile, Authority: a, CreatedAt: time.Now().UTC().Truncate(time.Microsecond), RunUntil: f.session.Deadline}
	return f.intent, f.step(ctx, "reserve-worker")
}
func (f preparationPhaseLedger) ReadDownloadWorkerIntentReceipt(ctx context.Context, _ value.DownloadWorkerIntent) (audit.Receipt, bool, error) {
	return audit.Receipt{}, false, f.step(ctx, "read-intent-audit")
}
func (f *preparationPhaseBudget) WriteDownloadWorkerIntent(ctx context.Context, i value.DownloadWorkerIntent) (audit.Receipt, error) {
	return audit.Receipt{Key: audit.DownloadWorkerAuditKey(i), Version: "synthetic-version", ETag: "synthetic", Bytes: 1, SHA256: artifact.Digest{1}}, f.step(ctx, "write-intent-audit")
}
func (f *preparationPhaseBudget) AcknowledgeDownloadWorkerIntent(ctx context.Context, _ value.DownloadWorkerIntent, _ audit.Receipt) error {
	return f.step(ctx, "ack-intent-audit")
}
func (f preparationPhaseLedger) ClaimDownloadWorker(ctx context.Context, i value.DownloadWorkerIntent, a artifact.DownloadAuthority) (value.DownloadWorkerLaunch, error) {
	return value.DownloadWorkerLaunch{Intent: i, CheckedAt: time.Now(), Until: a.ValidUntil, MayCreate: true}, f.step(ctx, "claim-worker")
}
func (f preparationPhaseJobs) CreateDownloadWorker(ctx context.Context, launch value.DownloadWorkerLaunch) (value.DownloadWorkerJob, error) {
	f.created = true
	f.job = value.DownloadWorkerJob{IntentID: launch.Intent.ID, UID: ownerID(19101), Spec: artifact.Digest{1}}
	return f.job, f.step(ctx, "create-job")
}
func (f preparationPhaseLedger) RecordDownloadWorkerJob(ctx context.Context, _ value.DownloadWorkerIntent, _ value.DownloadWorkerJob) error {
	f.recorded = true
	return f.step(ctx, "record-job")
}
func (f preparationPhaseJobs) ObserveDownloadWorker(ctx context.Context, i value.DownloadWorkerIntent, job value.DownloadWorkerJob) (value.DownloadWorker, error) {
	if err := f.step(ctx, "observe-job"); err != nil {
		return value.DownloadWorker{}, err
	}
	f.pending = true
	return value.DownloadWorker{}, &evidence.DownloadWorkerPending{Intent: i, Job: job, ObservedAt: time.Now(), ValidUntil: f.until}
}

func newPreparationPhaseBudget(t *testing.T) (*preparationPhaseBudget, evidence.ContextDownloadCoordinator) {
	t.Helper()
	policy := newDownloadPolicyBudgetFixture(t)
	var path artifact.DownloadPath
	for _, p := range policy.source.paths {
		path = p
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	f := &preparationPhaseBudget{downloadPolicyBudgetFixture: policy, t: t, started: now, until: now.Add(5 * time.Second)}
	root, installation, id := policy.source.root, policy.source.installation, ownerID(19102)
	rev := path.WorkerConfiguration
	principal := identity.Principal{Issuer: "https://id.example.test", Subject: "developer", ClientID: "console", Kind: identity.Human}
	f.i = identity.Identity{Principal: principal, Policy: rev, Scopes: []string{"evidence:read", "evidence:download"}, VerifiedAt: now, ValidUntil: f.until}
	e := artifact.ContextExpectation{Registration: artifact.Registration{Location: artifact.Location{ClusterID: path.TargetClusterID, ArtifactID: id, AttemptID: id}, StoreID: path.StoreID, AllocationID: id, PoolRevision: 1, AllocationRevision: 1, NativeLimit: 4096, AnchorAt: now, WriteUntil: now.Add(30 * time.Second), ExpiresAt: now.Add(time.Minute), DeleteBy: now.Add(90 * time.Second)}, CaseID: id, OccurrenceID: id, NodeUID: "node", NodeBootID: id, PodUID: "pod", Namespace: "app", NamespaceUID: "namespace", WorkloadUID: "workload", CollectorVersion: "synthetic", CollectorImageDigest: artifact.Digest{1}, RecipeDigest: artifact.Digest{2}, PlanDigest: artifact.Digest{3}, CaptureUID: id, ActionID: "context", DataClass: "metadata", PurposeRef: "diagnostics", Audience: []artifact.AudienceAssignment{{Kind: "Group", Issuer: principal.Issuer, SubjectID: "team", Role: "workload-maintainer", BasisKind: "AccessBinding", BasisUID: "binding", AssignmentID: id, BasisDigest: artifact.Digest{4}}}, RequestedAgeSeconds: 60, MaximumAgeSeconds: 300, DeletionBudgetSeconds: 30, RetentionRules: []artifact.RetentionRule{{UID: "retention", Generation: 1, Digest: artifact.Digest{5}}}, TriggeredAt: now}
	var copies artifact.Copies
	for n := range copies {
		copies[n] = artifact.CopyReceipt{VersionID: "synthetic", ETag: "synthetic", Bytes: 128, SHA256: artifact.Digest{byte(n + 1)}}
	}
	scope := artifact.DownloadScope{RootID: root, ArtifactID: id, CaptureID: id, ClusterID: path.TargetClusterID, NamespaceUID: e.NamespaceUID, WorkloadUID: e.WorkloadUID, PodUID: e.PodUID, Version: evidence.ContextCopiesDigest(copies), Principal: principal}
	retention := artifact.RetentionProof{RootID: root, ClusterID: scope.ClusterID, NamespaceUID: scope.NamespaceUID, WorkloadUID: scope.WorkloadUID, PodUID: scope.PodUID, Topology: rev, Policy: rev, Selectors: rev, SourceCount: 1, Sources: [2]artifact.RetentionSourceVersion{{ClusterID: scope.ClusterID, ControlNamespaceUID: "control", Epoch: root, Hub: true, ProtectionDigest: artifact.Digest{1}, SnapshotDigest: artifact.Digest{2}, Acceptance: rev}}, ObservedAt: now, ValidUntil: f.until}
	f.a = artifact.DownloadAuthority{Scope: scope, Retention: retention, PermissionEpoch: root, PermissionSequence: 1, ProjectionDigest: artifact.Digest{1}, DecisionDigest: artifact.Digest{2}, IdentityRevision: rev, CheckedAt: now, ValidUntil: f.until, AccessUntil: e.Registration.ExpiresAt, DeleteBy: e.Registration.DeleteBy}
	f.source = evidence.ContextDownloadSource{Scope: scope, Expectation: e, Copies: copies, ObservedAt: now, ValidUntil: f.until}
	f.record = authapp.ContextDownloadEvidence{CaptureID: id, PurposeRef: e.PurposeRef, Version: scope.Version, Audience: e.Audience, Retained: privacy.RetainedArtifact{RootID: root, Registration: e.Registration, Input: privacy.Input{Target: value.Target{ClusterID: scope.ClusterID, NamespaceUID: scope.NamespaceUID, WorkloadUID: scope.WorkloadUID, PodUID: scope.PodUID}, PrivacyClass: "potentialPersonalData", EvidenceType: "context", RequestedSeconds: 60, AnchorAt: now}, OriginPolicies: e.RetentionRules, Effective: privacy.Deadlines{AnchorAt: now, ExpiresAt: e.Registration.ExpiresAt, DeleteBy: e.Registration.DeleteBy}}, ObservedAt: now, ValidUntil: f.until}
	f.recovery = artifact.RecoveryProof{InstallationID: installation, IssuerEpoch: ownerID(19007), Revision: rev, ObservedAt: now, FreshUntil: f.until}
	f.processing = artifact.DownloadProcessingProof{RootID: root, Epoch: root, CaptureID: id, Location: e.Registration.Location, Sequence: 1, StateDigest: artifact.Digest{3}, ObservedAt: now, ValidUntil: f.until}
	observations, err := authapp.NewDownloadPolicyObservations(f, time.Now)
	if err != nil {
		t.Fatal("download policy observations", err)
	}
	f.environment = authapp.CurrentDownloadEnvironment{RootID: root, InstallationID: installation, Policies: observations, Recovery: f, Processing: f, Now: time.Now}
	f.profile = value.DownloadWorkerProfile{Configuration: rev, InstallationID: installation, ClusterID: path.AcquisitionClusterID, Namespace: "workers", NamespaceUID: "workers-uid", ServiceAccount: "worker", ServiceAccountUID: "worker-uid", Image: "synthetic.invalid/worker@sha256:" + strings.Repeat("1", 64), ControlConfig: "control", ControlConfigUID: "control-uid", PriorityClass: "worker", PriorityClassUID: "priority-uid", ControlDigest: artifact.Digest{1}, CPUMillis: 100, MemoryBytes: 64 << 20, MaxRuntime: time.Minute, StoreCredentialSecret: "reader", StoreCredentialSecretUID: ownerID(19103)}
	if !f.a.Valid(now) || !f.source.Valid(now) || !f.record.Retained.Valid() || !f.processing.Valid(now) || !f.recovery.Valid(now) || !f.profile.Valid() {
		t.Fatal("invalid synthetic preparation facts")
	}
	unused := &preparationPhaseUnused{}
	newID := func() string { return ownerID(19104) }
	dispatcher := &evidence.DownloadDispatcher{Ledger: preparationPhaseLedger{preparationPhaseBudget: f}, Jobs: preparationPhaseJobs{preparationPhaseBudget: f}, Audit: f, Acknowledgements: f, CurrentAuthority: f, Profile: f.profile, Now: time.Now}
	runtime, err := evidence.NewContextNativeRuntime(evidence.ContextNativeRuntimeConfig{Serving: f, Profile: f.profile, Configuration: f, Workers: f, Preparation: unused, Dispatcher: dispatcher,
		Sources: f, Authority: f, Audit: unused, Acknowledgements: unused,
		Native: evidence.NativeAttachmentConfig{HubPodUID: id, HubProcessEpoch: id, KeyScope: value.KeyScope{InstallationID: installation, Purpose: "artifact", KeyID: "synthetic"}, Owners: unused, Fences: unused, Registrar: unused, Origins: evidence.NativeOrigins{Operations: unused, Now: time.Now}, PreparationKeys: unused, WindowKeys: unused}, Now: time.Now, NewID: newID})
	if err != nil {
		t.Fatal("runtime composition", err)
	}
	return f, evidence.ContextDownloadCoordinator{RootID: root, InstallationID: installation, Recovery: f, Routes: f, Sources: f, Authority: f, Sessions: f, Plans: f, Runtime: runtime, Now: time.Now, NewID: newID}
}

func TestDownloadPreparationFirstJobFitsOriginalPolicyBudget(t *testing.T) {
	f, coordinator := newPreparationPhaseBudget(t)
	call, cancel := context.WithDeadline(t.Context(), f.until)
	defer cancel()
	out, err := coordinator.PrepareContextDownload(call, f, f.a.Scope.ArtifactID, "original-download-key")
	t.Logf("elapsed=%s original_interval=%s authority_checks=%d policy_reads=%d completed_policy_reads=%d observer=%d probe=%d denied=%d created=%t recorded=%t job_pending=%t continued=%t err=%v", time.Since(f.started), f.until.Sub(f.started), f.checks, f.policyReads, f.policiesOK, f.observer.Load(), f.probe.Load(), f.denied.Load(), f.created, f.recorded, f.pending, out.ContinuePreparation, err)
	t.Logf("production_path=%v", f.steps)
	if err != nil || !out.ContinuePreparation || out.Session.State != artifact.DownloadPreparing || out.Metadata != nil || !f.created || !f.recorded || !f.pending {
		t.Fatal("first acknowledged Job Pending did not fit the original five-second request")
	}
	if f.policyReads != 1 || f.policiesOK != 1 || f.observer.Load() != 14 || f.probe.Load() != 3 || f.denied.Load() != 1 {
		t.Fatal("preparation repeated the protected policy observation", f.policyReads, f.policiesOK, f.observer.Load(), f.probe.Load(), f.denied.Load())
	}
}
