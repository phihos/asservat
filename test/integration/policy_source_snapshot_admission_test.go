//go:build cgo && libpcap

package integration

import (
	"context"
	"slices"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/postgres"
	captureapp "asservat.local/asservat/internal/application/capture"
	planningapp "asservat.local/asservat/internal/application/planning"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	capturevalue "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/identity"
	planvalue "asservat.local/asservat/internal/domain/planning"
	"asservat.local/asservat/internal/domain/privacy"
	"asservat.local/asservat/internal/domain/targets"
	"github.com/jackc/pgx/v5/pgxpool"
)

// This helper performs genuine source-row -> Tick occurrence -> passive
// preview -> shared capture admission. It neither edits a finite admitted row
// nor inserts acceptance/authority by hand. The existing fixture supplies
// synthetic current collector/target facts; these are not native observation or
// clock qualification. Call once per policy within real shared cooldown limits.
type policySourceSnapshotAdmissionFixture struct {
	Accepted   capturevalue.Accepted
	Admission  capturevalue.Admission
	Preview    capturevalue.ContextPreview
	Source     captureapp.PolicySourceState
	Occurrence capturevalue.PolicyOccurrence
}

func admitPolicySourceSnapshotFixture(t *testing.T, ctx context.Context, hub *pgxpool.Pool, admissions *postgres.ContextAdmissions, accepted policySourceAcceptedFixture, original captureapp.PolicySourceAdmission, fresh captureapp.PolicySourceCheck, maximumBytes int64, beforeAdmission ...func(*testing.T, capturevalue.Admission, capturevalue.ContextPreview)) policySourceSnapshotAdmissionFixture {
	t.Helper()
	var out policySourceSnapshotAdmissionFixture
	s := accepted.Scenario
	guards := postgres.EffectTransactionGuards{Recovery: s.recovery.guard, Retention: s.retention.guard}
	ledger, err := postgres.NewPolicySources(ctx, hub, s.a.RootID, fresh.Recovery.InstallationID, guards)
	if err != nil {
		t.Fatal("snapshot source reader", err)
	}
	rows, err := ledger.ListSources(ctx, accepted.Authority.PolicyUID)
	if err != nil {
		t.Fatal("retained original source", err)
	}
	var source *captureapp.PolicySourceState
	for n := range rows {
		if rows[n].Binding.SourceID == original.Permit.Binding.SourceID {
			if source != nil {
				t.Fatal("duplicate original source")
			}
			source = &rows[n]
		}
	}
	if source == nil || source.Target == nil || len(source.Audience) == 0 || source.Binding != original.Permit.Binding {
		t.Fatal("real source lacks immutable107 provenance")
	}
	if maximumBytes < 64<<10 || maximumBytes > artifact.RecordingNativeLimit || maximumBytes > accepted.Compiled.Recorder.Action.MaxBytes {
		t.Fatal("snapshot output exceeds accepted recorder")
	}
	bound, end := context.WithDeadline(ctx, fresh.ValidUntil)
	defer end()
	trigger, err := postgres.NewPolicyTriggers(bound, hub, s.a.RootID, fresh.Recovery.InstallationID)
	if err != nil {
		t.Fatal(err)
	}
	observation := targets.RestartObservation{ClusterID: fresh.Authority.ClusterID, Namespace: source.Target.Request.Namespace, Workload: source.Target.Request.Workload, Pods: []targets.PodRestarts{{UID: source.Binding.PodUID, Name: source.Target.Request.PodName, Restarts: 1, Reason: "Error", ExitCode: 1}}, ObservedAt: time.Now().UTC().Truncate(time.Microsecond)}
	observation.FreshUntil = observation.ObservedAt.Add(5 * time.Second)
	if occurrences, err := trigger.Tick(bound, capturevalue.PolicyTick{Policy: accepted.Compiled, Authority: fresh.Authority, Observation: observation}); err != nil || len(occurrences) != 0 {
		t.Fatal("real snapshot detector baseline", occurrences, err)
	}
	observation.Pods[0].Restarts++
	observation.ObservedAt = time.Now().UTC().Truncate(time.Microsecond)
	observation.FreshUntil = observation.ObservedAt.Add(5 * time.Second)
	occurrences, err := trigger.Tick(bound, capturevalue.PolicyTick{Policy: accepted.Compiled, Authority: fresh.Authority, Observation: observation})
	if err != nil || len(occurrences) != 1 || occurrences[0].TriggeredAt.IsZero() {
		t.Fatal("real original snapshot occurrence/T0", occurrences, err)
	}
	occurrence := occurrences[0]
	current, err := postgres.NewAutomationAuthorities(bound, hub, s.a.RootID, fresh.Recovery.InstallationID)
	if err != nil {
		t.Fatal(err)
	}
	projection, err := current.PolicyAutomationAuthority(bound, fresh.Authority, source.Target.Target())
	if err != nil {
		t.Fatal("current real policy eligibility projection", err)
	}
	retained, err := s.retention.policies(bound)
	if err != nil {
		t.Fatal("current accepted retention sources", err)
	}
	storageReader, err := postgres.NewContextStorageReader(bound, hub, s.a.RootID)
	if err != nil {
		t.Fatal(err)
	}
	storage, err := storageReader.ContextStorage(bound, source.Target.Target())
	if err != nil {
		t.Fatal("current real snapshot allocation", err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	executor := authorization.PolicyExecutorIdentity(fresh.Authority, now, identity.Earlier(fresh.ValidUntil, now.Add(5*time.Second)))
	eligible := authorization.PolicyContextEligibility(executor, fresh.Authority, projection, source.Target.Target(), now)
	if !eligible.Eligible {
		t.Fatal("real snapshot team eligibility", eligible.Reason)
	}
	before, e1 := time.ParseDuration(accepted.Compiled.Recorder.Action.Before)
	after, e2 := time.ParseDuration(accepted.Compiled.Recorder.Action.After)
	actionTimeout, e3 := time.ParseDuration(accepted.Compiled.Recorder.Action.Timeout)
	recipeTimeout, e4 := time.ParseDuration(accepted.Compiled.Recorder.Composition.MaxDuration)
	if e1 != nil || e2 != nil || e3 != nil || e4 != nil {
		t.Fatal("accepted source window")
	}
	deadline := identity.Earlier(now.Add(min(actionTimeout, recipeTimeout)), fresh.Authority.NotAfter).UTC()
	request := artifact.SourceSnapshotRequest{SourceBindingDigest: artifact.Digest(source.Target.BindingDigest), SourceID: source.Binding.SourceID, Fence: source.Binding.Fence, SnapshotID: custodyID(), SourceStartedAt: source.StartedAt.UTC(), SourceHardUntil: source.HardUntil.UTC(), T0: occurrence.TriggeredAt.UTC(), IssuedAt: now, StartBy: identity.Earlier(fresh.ValidUntil, identity.Earlier(now.Add(5*time.Second), source.HardUntil)).UTC(), ProcessingUntil: deadline, Before: before, After: after, MaxBytes: maximumBytes, RequireApproval: fresh.Settings.RequireRecordingApproval}
	resolution, err := privacy.Resolve(retained, privacy.Input{Target: source.Target.Target(), PrivacyClass: "potentialPersonalData", EvidenceType: "packetCapture", RequestedSeconds: accepted.Compiled.RetentionSeconds, AnchorAt: artifact.SourceSnapshotAnchor(request)}, now)
	if err != nil {
		t.Fatal("snapshot source-age retention", err)
	}
	request.ProcessingUntil = identity.Earlier(request.ProcessingUntil, resolution.ExpiresAt).UTC()
	request.StartBy = identity.Earlier(request.StartBy, request.ProcessingUntil.Add(-time.Microsecond)).UTC()
	if !request.Valid() {
		t.Fatal("authored snapshot window cannot fit original processing bounds")
	}
	audience, err := planningapp.SourceAudienceDigest(source.Audience)
	if err != nil || audience != artifact.Digest(source.Binding.AudienceDigest) {
		t.Fatal("real original complete source audience", err)
	}
	selected := &planvalue.SourceSnapshotContext{Request: request, ActionID: source.Binding.ActionID, PolicyUID: source.Binding.PolicyUID, TriggerKind: "policy", ExecutionDigest: artifact.Digest(source.Binding.Scope), RecipeDigest: accepted.Compiled.Recorder.RecipeDigest, SourceAudience: slices.Clone(source.Audience), SourceAudienceDigest: audience, SourceTarget: source.Target}
	eligible.DefaultAudience, err = captureapp.SnapshotAudience(selected, eligible.DefaultAudience)
	if err != nil {
		t.Fatal("real current/original audience intersection", err)
	}
	originalTarget := *source.Target
	observed := targets.SourceSnapshotResolution{Original: originalTarget, Process: targets.PacketSourceObservation{PodUID: source.Binding.PodUID, NodeUID: source.Binding.NodeUID, BootID: source.Binding.BootID, CollectorPodUID: source.Binding.CollectorPodUID, CollectorEpoch: source.Binding.CollectorEpoch, ObservedAt: now, FreshUntil: fresh.ValidUntil}, State: targets.RecorderSourceState{SourceID: source.Binding.SourceID, Fence: source.Binding.Fence, IssuedAt: original.Permit.IssuedAt, LeafUntil: original.Permit.LeafUntil, Credit: original.Permit.Credit, ObservedAt: now, FreshUntil: now.Add(15 * time.Second)}, ReportedAt: now, ReportFreshUntil: now.Add(15 * time.Second), ObservedAt: now, FreshUntil: fresh.ValidUntil}
	if !observed.Valid(now) {
		t.Fatal("explicit synthetic current exact-source report")
	}
	input := s.a.Plan.Input
	input.CaptureID, input.CaseID = custodyID(), custodyID()
	input.Executor = fresh.Authority.Executor
	input.Deadline = request.ProcessingUntil
	input.Target = targets.PodResolution{ExecutionClass: artifact.ContextAPIExecution, Request: source.Target.Request, Pin: source.Target.Pin}
	input.Capability.ExecutionClass = artifact.ContextAPIExecution
	input.Capability.ObservedAt, input.Capability.FreshUntil = now, fresh.ValidUntil
	input.Retention, input.Recorder, input.Snapshot, input.SnapshotSource = resolution, nil, selected, &observed
	plan, err := planningapp.CompileContext(input, now)
	if err != nil {
		t.Fatal("real source snapshot accepted plan", err)
	}
	recovery, err := s.recovery.reader.RecoveryState(bound)
	if err != nil {
		t.Fatal(err)
	}
	a := s.a
	a.Plan, a.Eligibility, a.Storage, a.Recovery = plan, eligible, storage.Binding, recovery
	a.CaseID, a.OccurrenceID, a.IdempotencyKey = input.CaseID, occurrence.ID, occurrence.ID
	a.Registration = artifact.Registration{Location: artifact.Location{ClusterID: source.ClusterID, ArtifactID: custodyID(), AttemptID: custodyID()}, StoreID: storage.Selection.StoreID, AllocationID: storage.Selection.AllocationID, PoolRevision: storage.Selection.PoolRevision, AllocationRevision: storage.Selection.AllocationRevision, NativeLimit: maximumBytes, AnchorAt: resolution.AnchorAt, WriteUntil: request.ProcessingUntil, ExpiresAt: resolution.ExpiresAt, DeleteBy: resolution.DeleteBy}
	p := capturevalue.ContextPreview{ID: custodyID(), AssessmentID: custodyID(), AssessmentRulesDigest: planningapp.SourceSnapshotAssessmentRulesDigest(), RootID: a.RootID, InstallationID: recovery.InstallationID, IssuerEpoch: recovery.IssuerEpoch, CaptureID: input.CaptureID, CaseID: a.CaseID, OccurrenceID: a.OccurrenceID, ArtifactID: a.Registration.Location.ArtifactID, AttemptID: a.Registration.Location.AttemptID, Actor: input.Executor, ExecutionClass: artifact.ContextAPIExecution, Intent: capturevalue.ContextIntent{Snapshot: selected, Target: targets.WorkloadRequest{ClusterID: source.ClusterID, Namespace: source.Target.Request.Namespace.Name, Kind: "Pod", Name: source.Target.Request.PodName}, RequestedSeconds: accepted.Compiled.RetentionSeconds}, Target: source.Target.Request, Pin: source.Target.Pin, Storage: storage.Selection, Retention: capturevalue.ContextRetentionReview{PurposeRef: resolution.PurposeRef, RequestedSeconds: resolution.RequestedSeconds, MaximumSeconds: resolution.MaximumSeconds, DeletionBudgetSeconds: resolution.DeletionBudgetSeconds, Policies: slices.Clone(resolution.Policies)}, Audience: slices.Clone(eligible.DefaultAudience), CanonicalScope: slices.Clone(plan.CanonicalScope), ScopeDigest: plan.ScopeDigest, CreatedAt: now, Deadline: input.Deadline, SelectionUntil: identity.Earlier(now.Add(time.Minute), input.Deadline)}
	if !captureapp.ValidContextPreview(p) {
		t.Fatal("protected snapshot preview structure")
	}
	a.SubmissionDigest = captureapp.ContextRequestDigest(p.ID)
	previews, err := postgres.NewContextPreviews(bound, hub, a.RootID)
	if err != nil {
		t.Fatal(err)
	}
	if err = previews.CreateContextPreview(bound, p); err != nil {
		t.Fatal("persist real snapshot preview", err)
	}
	for _, probe := range beforeAdmission {
		candidate := a
		candidate.Plan.CanonicalScope = slices.Clone(a.Plan.CanonicalScope)
		candidate.Plan.Input.Snapshot = a.Plan.Input.Snapshot.Clone()
		candidate.Plan.Input.Retention.Policies = slices.Clone(a.Plan.Input.Retention.Policies)
		candidate.Eligibility.DefaultAudience = slices.Clone(a.Eligibility.DefaultAudience)
		if a.Plan.Input.SnapshotSource != nil {
			observed := *a.Plan.Input.SnapshotSource
			candidate.Plan.Input.SnapshotSource = &observed
		}
		probe(t, candidate, p.Clone())
	}
	output, err := admissions.AdmitReviewedContext(bound, p.ID, a)
	if err != nil {
		t.Fatal("real source snapshot admission", err)
	}
	if output.Expectation.Snapshot == nil || output.Expectation.Recording != nil || !output.Expectation.Snapshot.T0.Equal(occurrence.TriggeredAt) || !output.Expectation.Registration.AnchorAt.Equal(artifact.SourceSnapshotAnchor(request)) || !slices.Equal(output.Expectation.Audience, eligible.DefaultAudience) {
		t.Fatal("real admission changed source window/executor/audience")
	}
	out = policySourceSnapshotAdmissionFixture{Accepted: output, Admission: a, Preview: p, Source: *source, Occurrence: occurrence}
	return out
}
