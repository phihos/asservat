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

// Genuine manual source Save: current ordinary initiator plus the original
// policy executor, real retained source/preview/admission and no detector Tick
// or policy occurrence row. Target/report/initial identity observations remain
// explicitly synthetic component inputs, not installed authority qualification.
func admitManualRecordingSaveFixture(t *testing.T, ctx context.Context, hub *pgxpool.Pool, admissions *postgres.ContextAdmissions, accepted policySourceAcceptedFixture, original captureapp.PolicySourceAdmission, fresh captureapp.PolicySourceCheck, maximumBytes int64, beforeAdmission ...func(*testing.T, capturevalue.Admission, capturevalue.ContextPreview)) policySourceSnapshotAdmissionFixture {
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
	if !accepted.Compiled.RecordingSaves || accepted.Compiled.Recorder == nil {
		t.Fatal("manual source policy was not reviewed with recordingSaves enabled")
	}
	if maximumBytes < 64<<10 || maximumBytes > artifact.RecordingNativeLimit || maximumBytes > accepted.Compiled.Recorder.Action.MaxBytes {
		t.Fatal("snapshot output exceeds accepted recorder")
	}
	bound, end := context.WithDeadline(ctx, fresh.ValidUntil)
	defer end()
	// The capture correlation identity is not a detector policy_occurrence.
	occurrenceID := custodyID()
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
	initiatorIdentity := manualRecordingSaveInitiator(s.a.Eligibility.VerifiedIdentity)
	initiatorIdentity.VerifiedAt, initiatorIdentity.ValidUntil = now, fresh.ValidUntil
	initiator := authorization.ContextEligibility(initiatorIdentity, projection.Permissions, source.Target.Target(), now)
	if !initiator.Eligible || !initiator.VerifiedIdentity.Valid(now) || initiator.Principal == eligible.Principal {
		t.Fatal("real independent ordinary initiator eligibility", initiator.Reason)
	}
	progress := authorization.CaptureProgressEligibility(initiatorIdentity, projection.Permissions, source.Target.Target(), initiatorIdentity.Principal, now)
	if !progress.Eligible {
		t.Fatal("real current manual initiator progress rights", progress.Reason)
	}
	before, e1 := time.ParseDuration(accepted.Compiled.Recorder.Action.Before)
	_, e2 := time.ParseDuration(accepted.Compiled.Recorder.Action.After)
	actionTimeout, e3 := time.ParseDuration(accepted.Compiled.Recorder.Action.Timeout)
	recipeTimeout, e4 := time.ParseDuration(accepted.Compiled.Recorder.Composition.MaxDuration)
	if e1 != nil || e2 != nil || e3 != nil || e4 != nil {
		t.Fatal("accepted source window")
	}
	deadline := identity.Earlier(now.Add(min(actionTimeout, recipeTimeout)), fresh.Authority.NotAfter).UTC()
	request := artifact.SourceSnapshotRequest{SourceBindingDigest: artifact.Digest(source.Target.BindingDigest), SourceID: source.Binding.SourceID, Fence: source.Binding.Fence, SnapshotID: custodyID(), SourceStartedAt: source.StartedAt.UTC(), SourceHardUntil: source.HardUntil.UTC(), T0: now, IssuedAt: now, StartBy: identity.Earlier(fresh.ValidUntil, identity.Earlier(now.Add(5*time.Second), source.HardUntil)).UTC(), ProcessingUntil: deadline, Before: before, After: 0, MaxBytes: maximumBytes, RequireApproval: fresh.Settings.RequireRecordingApproval}
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
	selected := &planvalue.SourceSnapshotContext{SourceDefinitionDigest: artifact.Digest(source.Binding.ExpectationDigest), Request: request, ActionID: source.Binding.ActionID, PolicyUID: source.Binding.PolicyUID, TriggerKind: "recordingSave", ExecutionDigest: artifact.Digest(source.Binding.Scope), RecipeDigest: accepted.Compiled.Recorder.RecipeDigest, SourceAudience: slices.Clone(source.Audience), SourceAudienceDigest: audience, SourceTarget: source.Target}
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
	selected.RecordingSaveScope, _, err = planningapp.CompileRecordingSaveScope(planningapp.RecordingSaveScopeInput{CaptureID: input.CaptureID, Requester: initiator.Principal, Authority: fresh.Authority, Sources: []planningapp.RecordingSaveScopeSource{{PolicyUID: fresh.Authority.PolicyUID, ExecutionDigest: fresh.Authority.ScopeDigest, Original: originalTarget, ActionID: source.Binding.ActionID, Kind: accepted.Compiled.Recorder.Action.Kind, DefinitionDigest: artifact.Digest(source.Binding.ExpectationDigest), AudienceDigest: audience, ApprovedBefore: before, Before: before, MaxBytes: maximumBytes}}, IncidentPodLimit: 1, FinalizeTimeout: min(actionTimeout, recipeTimeout), CeilingDigest: artifact.Digest(input.Capability.Revision.Digest), RetentionDigest: artifact.Digest(resolution.PolicyRevision.Digest)}, now)
	if err != nil {
		t.Fatal("genuine manual recording-save scope", err)
	}
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
	a.CaseID, a.OccurrenceID, a.IdempotencyKey = input.CaseID, occurrenceID, "manual-source-save-"+custodyID()
	a.RecordingSave = &capturevalue.RecordingSaveAdmission{Policy: accepted.Compiled, Authority: fresh.Authority, Initiator: initiator}
	a.Registration = artifact.Registration{Location: artifact.Location{ClusterID: source.ClusterID, ArtifactID: custodyID(), AttemptID: custodyID()}, StoreID: storage.Selection.StoreID, AllocationID: storage.Selection.AllocationID, PoolRevision: storage.Selection.PoolRevision, AllocationRevision: storage.Selection.AllocationRevision, NativeLimit: maximumBytes, AnchorAt: resolution.AnchorAt, WriteUntil: request.ProcessingUntil, ExpiresAt: resolution.ExpiresAt, DeleteBy: resolution.DeleteBy}
	p := capturevalue.ContextPreview{ID: custodyID(), AssessmentID: custodyID(), AssessmentRulesDigest: planningapp.SourceSnapshotAssessmentRulesDigest(), RootID: a.RootID, InstallationID: recovery.InstallationID, IssuerEpoch: recovery.IssuerEpoch, CaptureID: input.CaptureID, CaseID: a.CaseID, OccurrenceID: a.OccurrenceID, ArtifactID: a.Registration.Location.ArtifactID, AttemptID: a.Registration.Location.AttemptID, Actor: initiator.Principal, ExecutionClass: artifact.ContextAPIExecution, Intent: capturevalue.ContextIntent{Snapshot: selected, Target: targets.WorkloadRequest{ClusterID: source.ClusterID, Namespace: source.Target.Request.Namespace.Name, Kind: "Pod", Name: source.Target.Request.PodName}, RequestedSeconds: accepted.Compiled.RetentionSeconds}, Target: source.Target.Request, Pin: source.Target.Pin, Storage: storage.Selection, Retention: capturevalue.ContextRetentionReview{PurposeRef: resolution.PurposeRef, RequestedSeconds: resolution.RequestedSeconds, MaximumSeconds: resolution.MaximumSeconds, DeletionBudgetSeconds: resolution.DeletionBudgetSeconds, Policies: slices.Clone(resolution.Policies)}, Audience: slices.Clone(eligible.DefaultAudience), CanonicalScope: slices.Clone(plan.CanonicalScope), ScopeDigest: plan.ScopeDigest, CreatedAt: now, Deadline: input.Deadline, SelectionUntil: identity.Earlier(now.Add(time.Minute), input.Deadline)}
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
		manual := *a.RecordingSave
		candidate.RecordingSave = &manual
		candidate.RecordingSave.Initiator.VerifiedIdentity.Groups = slices.Clone(manual.Initiator.VerifiedIdentity.Groups)
		candidate.RecordingSave.Initiator.VerifiedIdentity.Scopes = slices.Clone(manual.Initiator.VerifiedIdentity.Scopes)
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
		t.Fatal("real manual source snapshot admission", err)
	}
	if output.Expectation.Snapshot == nil || output.Expectation.Recording != nil || !output.Expectation.Snapshot.T0.Equal(output.CreatedAt) || !output.Expectation.Registration.AnchorAt.Equal(artifact.SourceSnapshotAnchor(*output.Expectation.Snapshot)) || !slices.Equal(output.Expectation.Audience, eligible.DefaultAudience) {
		t.Fatal("real admission changed source window/executor/audience")
	}
	acceptedPlan, acceptedRegistration, err := planningapp.ReanchorRecordingSave(plan, a.Registration, output.CreatedAt, fresh.Authority.NotAfter)
	if err != nil || *output.Expectation.Snapshot != acceptedPlan.Input.Snapshot.Request || output.Expectation.Registration != acceptedRegistration || !output.Deadline.Equal(acceptedPlan.Input.Deadline) {
		t.Fatal("SQL manual acceptance differs from immutable first T0 contract", err)
	}
	a.Plan, a.Registration = acceptedPlan, acceptedRegistration
	out = policySourceSnapshotAdmissionFixture{Accepted: output, Admission: a, Preview: p, Source: *source}
	return out
}

// Manual fixture principals can collect and inspect their operation progress.
// This does not replace current target permissions or extend identity clocks.
func manualRecordingSaveInitiator(i identity.Identity) identity.Identity {
	if !slices.Contains(i.Scopes, "evidence:read") {
		i.Scopes = append(slices.Clone(i.Scopes), "evidence:read")
	}
	return i
}

func TestManualRecordingSaveInitiatorHasCurrentProgressRights(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	a := policyRecorderOfflineAdmission(t, now)
	owner := a.Eligibility.DefaultAudience[0]
	original := a.Eligibility.VerifiedIdentity
	original.Principal = identity.Principal{Issuer: owner.Issuer, Subject: "developer", ClientID: "browser", Kind: identity.Human}
	original.Groups = []string{owner.SubjectID}
	original.Scopes = []string{"evidence:capture"}
	target := a.Plan.Input.Target.Target()
	p := authorization.Projection{Target: target, Revision: identity.Revision{UID: "permissions", Generation: 1, Digest: artifact.Digest{1}}, ObservedAt: now, FreshUntil: now.Add(5 * time.Second), DeniesComplete: true, DeniesObservedAt: now, DeniesFreshUntil: now.Add(5 * time.Second), Allows: []authorization.CurrentAssignment{{Audience: owner, ObservedAt: now, FreshUntil: now.Add(5 * time.Second)}}}
	if r := authorization.ContextEligibility(original, p, target, now); !r.Eligible {
		t.Fatal("capture-only control cannot collect", r.Reason)
	}
	if r := authorization.CaptureProgressEligibility(original, p, target, original.Principal, now); r.Eligible || r.Reason != "InsufficientScope" {
		t.Fatal("capture-only identity did not reproduce progress denial", r)
	}
	corrected := manualRecordingSaveInitiator(original)
	if corrected.Principal != original.Principal || !corrected.VerifiedAt.Equal(original.VerifiedAt) || !corrected.ValidUntil.Equal(original.ValidUntil) {
		t.Fatal("fixture scope correction changed identity or original clock")
	}
	if r := authorization.CaptureProgressEligibility(corrected, p, target, original.Principal, now); !r.Eligible {
		t.Fatal("manual fixture initiator cannot read its current operation", r.Reason)
	}
	missing := p
	missing.Allows = nil
	if r := authorization.CaptureProgressEligibility(corrected, missing, target, original.Principal, now); r.Eligible {
		t.Fatal("scope correction invented target permission")
	}
	denied := p
	denied.Denies = slices.Clone(p.Allows)
	if r := authorization.CaptureProgressEligibility(corrected, denied, target, original.Principal, now); r.Eligible || r.Reason != "ExplicitDeny" {
		t.Fatal("scope correction bypassed current deny", r)
	}
}
