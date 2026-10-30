package capture

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"slices"
	"sort"
	"time"

	identities "asservat.local/asservat/internal/application/identity"
	compiler "asservat.local/asservat/internal/application/planning"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/identity"
	planvalue "asservat.local/asservat/internal/domain/planning"
	"asservat.local/asservat/internal/domain/targets"
)

// The regional batch preserves every original target and the caller's existing
// deadline. There is no serial-query or live-Pod fallback for grouped selection.
type SourceSnapshotGroupTargets interface {
	ResolveSourceSnapshots(context.Context, []targets.SourceSnapshotTarget) ([]targets.SourceSnapshotResolution, error)
}

func exactRecordingGroupSources(refs []value.RecordingReference, rows []RecordingCandidate) ([]RecordingCandidate, error) {
	if len(refs) < 2 || len(refs) > value.MaxRecordingSaveGroupChildren || len(rows) != len(refs) {
		return nil, value.ErrChanged
	}
	refs = slices.Clone(refs)
	sort.Slice(refs, func(i, j int) bool { return refs[i].SourceID < refs[j].SourceID })
	byID := map[string]RecordingCandidate{}
	for _, row := range rows {
		if _, ok := byID[row.Source.Binding.SourceID]; ok {
			return nil, value.ErrChanged
		}
		byID[row.Source.Binding.SourceID] = row
	}
	out := make([]RecordingCandidate, 0, len(refs))
	seen := map[string]bool{}
	for _, ref := range refs {
		row, ok := byID[ref.SourceID]
		if !ok || row.Source.Target == nil {
			return nil, value.ErrChanged
		}
		source, b := row.Source, row.Source.Binding
		actual := value.RecordingReference{SourceID: b.SourceID, Fence: b.Fence, PolicyUID: b.PolicyUID, PodUID: b.PodUID, ActionID: b.ActionID, BindingDigest: artifact.Digest(source.Target.BindingDigest), ExecutionDigest: artifact.Digest(b.Scope)}
		pair := b.PodUID + "\x00" + b.ActionID
		if actual != ref || ref.PolicyUID != refs[0].PolicyUID || ref.ExecutionDigest != refs[0].ExecutionDigest || seen[pair] || len(out) > 0 && (row.PolicyName != out[0].PolicyName || source.Target.Request.Namespace != out[0].Source.Target.Request.Namespace || source.Target.Request.Workload != out[0].Source.Target.Request.Workload) {
			return nil, value.ErrChanged
		}
		seen[pair] = true
		out = append(out, row)
	}
	return out, nil
}

func (s ContextInvestigation) resolveRecordingGroup(ctx context.Context, rows []RecordingCandidate) ([]targets.SourceSnapshotResolution, error) {
	resolver, ok := s.Targets.(SourceSnapshotGroupTargets)
	if !ok {
		return nil, value.ErrUnavailable
	}
	original := make([]targets.SourceSnapshotTarget, len(rows))
	for n, row := range rows {
		if row.Source.Target == nil {
			return nil, value.ErrChanged
		}
		original[n] = *row.Source.Target
	}
	resolved, err := resolver.ResolveSourceSnapshots(ctx, original)
	if err != nil {
		return nil, err
	}
	if len(resolved) != len(original) {
		return nil, value.ErrChanged
	}
	for n, r := range resolved {
		if r.Original != original[n] || !r.Valid(s.Now()) {
			return nil, value.ErrChanged
		}
	}
	return resolved, nil
}

func (s RecordingSaves) previewRecordingSaveGroup(ctx context.Context, current identities.CurrentIdentity, i identity.Identity, set value.RecordingSelectionSet, refs []value.RecordingReference, request RecordingSavePreviewRequest) (ContextPreviewResult, error) {
	var zero ContextPreviewResult
	store, ok := s.Investigation.Previews.(RecordingSaveGroupPreviewStore)
	if !ok {
		return zero, value.ErrUnavailable
	}
	ids := make([]string, len(refs))
	handles := map[string]string{}
	for n, ref := range refs {
		ids[n] = ref.SourceID
		handles[ref.SourceID] = request.Handles[n]
	}
	rows, err := s.Inventory.Candidates.RecordingSources(ctx, set.Target, ids)
	if err != nil {
		return zero, err
	}
	rows, err = exactRecordingGroupSources(refs, rows)
	if err != nil {
		return zero, err
	}
	policy, err := s.Inventory.Policies.RecordingPolicy(ctx, rows[0].PolicyName, refs[0].PolicyUID)
	if err != nil {
		return zero, err
	}
	a, p := policy.Accepted.Authority, policy.Policy
	pods := map[string]bool{}
	for _, row := range rows {
		pods[row.Source.Binding.PodUID] = true
	}
	if !p.RecordingSaves || a.ScopeDigest != refs[0].ExecutionDigest || len(pods) > recordingSaveIncidentPodCap(p) {
		return zero, value.ErrDenied
	}
	var lineage *value.HistoryLineage
	preferences := map[string]time.Duration{}
	if request.RepeatedFromCaptureID != "" {
		if s.History == nil {
			return zero, value.ErrSettingsUnavailable
		}
		settings, e := s.History.Settings(ctx, current, request.RepeatedFromCaptureID)
		if e != nil {
			return zero, e
		}
		if settings.RecordingSave == nil || settings.RecordingSave.PolicyUID != a.PolicyUID || settings.ClusterID != set.Target.ClusterID || settings.NamespaceUID != set.Target.NamespaceUID || settings.WorkloadUID != set.Target.WorkloadUID {
			return zero, value.ErrInvalid
		}
		lineage = &value.HistoryLineage{CaptureID: settings.CaptureID, ExpiresAt: settings.ExpiresAt}
		for _, window := range settings.RecordingSave.Windows {
			preferences[window.ActionID] = window.Before
		}
	}
	resolved, err := s.Investigation.resolveRecordingGroup(ctx, rows)
	if err != nil {
		return zero, err
	}
	now := s.Inventory.Now().UTC().Truncate(time.Microsecond)
	executor := newPolicyIdentity(ctx, s.Inventory.Accepted, a, identity.Earlier(i.ValidUntil, policy.Accepted.SourceUntil), s.Inventory.Now)
	parts := make([]ContextPreviewResult, len(rows))
	plans := make([]planvalue.ContextPlan, len(rows))
	until := i.ValidUntil
	for n, row := range rows {
		before := request.Before
		if before == 0 && lineage != nil {
			before = preferences[row.Source.Binding.ActionID]
		}
		parts[n], plans[n], err = s.Investigation.prepareSourceSnapshotPreview(ctx, executor, PolicySnapshotSelection{PolicyName: row.PolicyName, Policy: p, Authority: a, Source: row.Source, Target: row.Source.Target.Request, TriggeredAt: now}, &manualSnapshotSelection{Current: current, Before: before, Sharing: request.Sharing, RepeatedFrom: lineage}, false, &resolved[n])
		if err != nil {
			return zero, err
		}
		until = identity.Earlier(until, parts[n].ValidUntil)
	}
	parent := value.ContextPreview{Group: &value.RecordingSaveGroupPreview{Executor: a.Executor, PolicyName: rows[0].PolicyName, PolicyUID: a.PolicyUID, ExecutionDigest: a.ScopeDigest}, ID: s.Investigation.NewID(), RootID: s.Investigation.RootID, InstallationID: s.Investigation.InstallationID, IssuerEpoch: parts[0].Preview.IssuerEpoch, CaptureID: s.Investigation.NewID(), CaseID: s.Investigation.NewID(), AssessmentID: s.Investigation.NewID(), AssessmentRulesDigest: RecordingSaveGroupAssessmentRulesDigest(), Actor: i.Principal, ExecutionClass: artifact.ContextAPIExecution, Storage: parts[0].Preview.Storage, CreatedAt: now, SelectionUntil: now.Add(time.Minute)}
	parent.Target = rows[0].Source.Target.Request
	parent.Target.PodUID, parent.Target.PodName = "", ""
	parent.Intent = value.ContextIntent{Target: targets.WorkloadRequest{ClusterID: set.Target.ClusterID, Namespace: parent.Target.Namespace.Name, Kind: parent.Target.Workload.Kind, Name: parent.Target.Workload.Name}, Sharing: request.Sharing, RepeatedFrom: lineage}
	sources := make([]compiler.RecordingSaveScopeSource, 0, len(rows))
	for n, row := range rows {
		part, plan := parts[n].Preview, plans[n]
		if part.Storage != parent.Storage {
			return zero, value.ErrChanged
		}
		saved := plan.Input.Snapshot
		audience, e := compiler.SourceAudienceDigest(part.Audience)
		if e != nil {
			return zero, e
		}
		ref := value.RecordingReference{SourceID: row.Source.Binding.SourceID, Fence: row.Source.Binding.Fence, PolicyUID: a.PolicyUID, PodUID: row.Source.Binding.PodUID, ActionID: saved.ActionID, BindingDigest: saved.Request.SourceBindingDigest, ExecutionDigest: a.ScopeDigest}
		parent.Group.Children = append(parent.Group.Children, value.RecordingSaveGroupChild{Reference: ref, CaptureID: part.CaptureID, ArtifactID: part.ArtifactID, AttemptID: part.AttemptID, OccurrenceID: part.OccurrenceID, AssessmentID: part.AssessmentID, Request: saved.Request, AudienceDigest: audience, CapabilityRevision: plan.Input.Capability.Revision, Retention: value.RecordingSaveRetentionReview{PurposeRef: part.Retention.PurposeRef, RequestedSeconds: part.Retention.RequestedSeconds, MaximumSeconds: part.Retention.MaximumSeconds, DeletionBudgetSeconds: part.Retention.DeletionBudgetSeconds, PolicyRevision: plan.Input.Retention.PolicyRevision}})
		if parent.Deadline.Before(part.Deadline) {
			parent.Deadline = part.Deadline
		}
		approved, _ := time.ParseDuration(p.Recorder.Action.Before)
		sources = append(sources, compiler.RecordingSaveScopeSource{PolicyUID: a.PolicyUID, ExecutionDigest: a.ScopeDigest, Original: *row.Source.Target, ActionID: saved.ActionID, Kind: p.Recorder.Action.Kind, DefinitionDigest: saved.SourceDefinitionDigest, AudienceDigest: saved.SourceAudienceDigest, ApprovedBefore: approved, Before: saved.Request.Before, MaxBytes: saved.Request.MaxBytes, CeilingDigest: artifact.Digest(plan.Input.Capability.Revision.Digest), RetentionDigest: artifact.Digest(plan.Input.Retention.PolicyRevision.Digest)})
	}
	parent.SelectionUntil = identity.Earlier(parent.SelectionUntil, parent.Deadline)
	actionTimeout, _ := time.ParseDuration(p.Recorder.Action.Timeout)
	recipeTimeout, _ := time.ParseDuration(p.Recorder.Composition.MaxDuration)
	parent.CanonicalScope, parent.ScopeDigest, err = compiler.CompileRecordingSaveScope(compiler.RecordingSaveScopeInput{CaptureID: parent.CaptureID, Requester: i.Principal, Authority: a, Sources: sources, CeilingDigest: sources[0].CeilingDigest, RetentionDigest: sources[0].RetentionDigest, IncidentPodLimit: recordingSaveIncidentPodCap(p), FinalizeTimeout: min(actionTimeout, recipeTimeout)}, s.Inventory.Now())
	if err != nil {
		return zero, err
	}
	metadata := &RecordingSavePreviewMetadata{IncidentPodCap: recordingSaveIncidentPodCap(p)}
	for n := range parts {
		input := plans[n].Input
		input.CaseID = parent.CaseID
		input.Snapshot = input.Snapshot.Clone()
		input.Snapshot.Group = &planvalue.RecordingSaveGroupBinding{ParentCaptureID: parent.CaptureID, SelectionDigest: parent.ScopeDigest, ChildIndex: n, ChildCount: len(parts)}
		input.Snapshot.RecordingSaveScope = slices.Clone(parent.CanonicalScope)
		plans[n], err = compiler.CompileContext(input, s.Inventory.Now())
		if err != nil {
			return zero, err
		}
		assessment, e := compiler.AssessContext(plans[n], parts[n].Preview.AssessmentID, s.Inventory.Now())
		if e != nil {
			return zero, e
		}
		row := parts[n].RecordingSave.Selected[0]
		row.Handle = handles[rows[n].Source.Binding.SourceID]
		metadata.Selected = append(metadata.Selected, row)
		metadata.Windows = append(metadata.Windows, RecordingSaveWindow{Handle: row.Handle, Before: input.Snapshot.Request.Before})
		metadata.Assessments = append(metadata.Assessments, RecordingSaveActionAssessment{ActionID: input.Snapshot.ActionID, PodUID: row.PodUID, Assessment: assessment})
	}
	if err = s.Investigation.preparePreviewReason(ctx, &parent, request.Reason); err != nil {
		return zero, err
	}
	if !ValidContextPreview(parent) || !s.Inventory.Now().Before(until) {
		return zero, value.ErrChanged
	}
	if err = store.CreateRecordingGroupPreview(ctx, parent.Clone()); err != nil {
		return zero, err
	}
	if _, _, err = s.Inventory.authorize(ctx, current, set.Target); err != nil || ctx.Err() != nil || !s.Inventory.Now().Before(until) {
		return zero, value.ErrChanged
	}
	for n, part := range parts {
		selected := plans[n].Input.Snapshot
		target := rows[n].Source.Target.Target()
		initiator := s.Investigation.Eligibility.ContextEligibilityCurrent(ctx, current, target)
		policyCurrent := s.Investigation.Eligibility.ContextEligibilityCurrent(ctx, executor, target)
		audience, e := SnapshotAudience(selected, policyCurrent.DefaultAudience)
		if e != nil || !initiator.Eligible || initiator.Principal != i.Principal || !initiator.VerifiedIdentity.Valid(s.Inventory.Now()) || !policyCurrent.Eligible || policyCurrent.Principal != a.Executor || !policyCurrent.VerifiedIdentity.Valid(s.Inventory.Now()) || !slices.Equal(audience, part.Preview.Audience) || !resolved[n].Valid(s.Inventory.Now()) || !s.Inventory.Now().Before(part.ValidUntil) {
			return zero, value.ErrChanged
		}
		until = identity.Earlier(until, identity.Earlier(initiator.ValidUntil, policyCurrent.ValidUntil))
	}
	assessment, err := aggregateRecordingSaveAssessment(parent, metadata.Assessments, s.Inventory.Now())
	if err != nil {
		return zero, err
	}
	return ContextPreviewResult{RecordingSave: metadata, Preview: parent, Assessment: assessment, CollectorImageDigest: parts[0].CollectorImageDigest, ProjectionDigest: parts[0].ProjectionDigest, ValidUntil: until}, nil
}

func RecordingSaveGroupAssessmentRulesDigest() artifact.Digest {
	return sha256.Sum256([]byte("asservat-recording-save-group-assessment/v1;all-child-incremental-limits;no-new-observation;source-aged-retention"))
}
func aggregateRecordingSaveAssessment(p value.ContextPreview, children []RecordingSaveActionAssessment, now time.Time) (planvalue.ContextAssessment, error) {
	if p.Group == nil || len(children) != len(p.Group.Children) {
		return planvalue.ContextAssessment{}, value.ErrInvalid
	}
	out := planvalue.ContextAssessment{ID: p.AssessmentID, PlanDigest: p.ScopeDigest, RulesDigest: RecordingSaveGroupAssessmentRulesDigest(), GeneratedAt: now, Impact: planvalue.AssessmentImpact{Level: "unknown", HasUnknowns: true, Effects: []string{"nodeCPU", "collectorMemory", "storageIO", "uploadContention"}, Explanation: "Saves existing windows from all selected sources. Each output separately consumes frozen memory, encoding, encryption, storage and upload capacity; no source starts or observation credits are added. Combined overhead is unmeasured. Retention and gaps remain specific to each source."}, Exposure: planvalue.AssessmentExposure{Classification: "potentialPersonalData", Basis: "conservativeMechanism", UnknownContent: true}}
	capabilities := make([]artifact.Digest, 0, len(children))
	for _, child := range children {
		a := child.Assessment
		if a.OutputLimit < 1 || a.OutputLimit > artifact.RecordingNativeLimit {
			return planvalue.ContextAssessment{}, value.ErrInvalid
		}
		out.OutputLimit += a.OutputLimit
		if out.ValidUntil.IsZero() {
			out.ValidUntil = a.ValidUntil
		} else {
			out.ValidUntil = identity.Earlier(out.ValidUntil, a.ValidUntil)
		}
		capabilities = append(capabilities, a.CapabilityDigest)
	}
	raw, _ := json.Marshal(capabilities)
	out.CapabilityDigest = sha256.Sum256(raw)
	return out, nil
}

// requestRecordingSaveGroup refreshes every member before the one atomic parent
// admission. No child preview or independent public admission is created.
func (s ContextInvestigation) requestRecordingSaveGroup(ctx context.Context, current identities.CurrentIdentity, p value.ContextPreview, key string, recovery artifact.RecoveryProof, bounds *value.GroupRequestBounds) (value.Accepted, error) {
	var zero value.Accepted
	if s.RecordingSources == nil || s.RecordingGroups == nil || s.RecordingPolicies == nil || s.PolicyAccepted == nil || p.Group == nil || !p.Current(s.Now()) || p.IssuerEpoch != recovery.IssuerEpoch || p.AssessmentRulesDigest != RecordingSaveGroupAssessmentRulesDigest() {
		return zero, value.ErrUnavailable
	}
	g := p.Group
	refs := make([]value.RecordingReference, len(g.Children))
	ids := make([]string, len(refs))
	for n, c := range g.Children {
		refs[n] = c.Reference
		ids[n] = c.Reference.SourceID
	}
	rows, err := s.RecordingSources.RecordingSources(ctx, authorization.WorkloadTarget{ClusterID: p.Target.ClusterID, NamespaceUID: p.Target.Namespace.UID, WorkloadUID: p.Target.Workload.UID}, ids)
	if err != nil {
		return zero, err
	}
	rows, err = exactRecordingGroupSources(refs, rows)
	if err != nil {
		return zero, err
	}
	policy, err := s.RecordingPolicies.RecordingPolicy(ctx, g.PolicyName, g.PolicyUID)
	if err != nil {
		return zero, err
	}
	a := policy.Accepted.Authority
	pods := map[string]bool{}
	for _, row := range rows {
		pods[row.Source.Binding.PodUID] = true
	}
	if !policy.Policy.RecordingSaves || a.Executor != g.Executor || a.ScopeDigest != g.ExecutionDigest || len(pods) > recordingSaveIncidentPodCap(policy.Policy) {
		return zero, value.ErrDenied
	}
	caller, err := current.ResolveIdentity(ctx)
	if err != nil || !caller.Valid(s.Now()) || caller.Principal != p.Actor {
		return zero, value.ErrDenied
	}
	var original *value.GroupRequestBounds
	if bounds != nil {
		copy := *bounds
		copy.Until = identity.Earlier(copy.Until, caller.ValidUntil).UTC().Truncate(time.Microsecond)
		if copy.Requester != caller.Principal || !copy.Valid(s.Now()) {
			return zero, value.ErrDenied
		}
		original = &copy
	}
	executor := newPolicyIdentity(ctx, s.PolicyAccepted, a, identity.Earlier(caller.ValidUntil, policy.Accepted.SourceUntil), s.Now)
	resolved, err := s.resolveRecordingGroup(ctx, rows)
	if err != nil {
		return zero, err
	}
	t0 := s.Now().UTC().Truncate(time.Microsecond)
	request := value.RecordingSaveGroupAdmission{RequestBounds: original, Preview: p.Clone(), RootID: s.RootID, IdempotencyKey: key, SubmissionDigest: ContextRequestDigest(p.ID), Recovery: recovery}
	facts := make([]contextFacts, len(rows))
	preparedUntil := make([]time.Time, len(rows))
	initiators := make([]authorization.CaptureEligibility, len(rows))
	for n, row := range rows {
		part, plan, e := s.prepareSourceSnapshotPreview(ctx, executor, PolicySnapshotSelection{PolicyName: row.PolicyName, Policy: policy.Policy, Authority: a, Source: row.Source, Target: row.Source.Target.Request, TriggeredAt: t0}, &manualSnapshotSelection{Current: current, Before: g.Children[n].Request.Before, Sharing: p.Intent.Sharing, RepeatedFrom: p.Intent.RepeatedFrom, GroupParent: &p, GroupIndex: n, Prepared: &facts[n], PreparedInitiator: &initiators[n]}, false, &resolved[n])
		if e != nil {
			return zero, e
		}
		preparedUntil[n] = part.ValidUntil
		f := facts[n]
		c := g.Children[n]
		r := artifact.Registration{Location: artifact.Location{ClusterID: p.Target.ClusterID, ArtifactID: c.ArtifactID, AttemptID: c.AttemptID}, StoreID: p.Storage.StoreID, AllocationID: p.Storage.AllocationID, PoolRevision: p.Storage.PoolRevision, AllocationRevision: p.Storage.AllocationRevision, NativeLimit: plan.Input.Snapshot.Request.MaxBytes, AnchorAt: f.retention.AnchorAt, WriteUntil: identity.Earlier(part.Preview.Deadline, f.retention.ExpiresAt), ExpiresAt: f.retention.ExpiresAt, DeleteBy: f.retention.DeleteBy}
		if r.Validate() != nil {
			return zero, value.ErrInvalid
		}
		initiator := initiators[n]
		if !initiator.Eligible || initiator.Principal != p.Actor || !initiator.VerifiedIdentity.Valid(s.Now()) {
			return zero, value.ErrDenied
		}
		child := value.Admission{RecordingSave: &value.RecordingSaveAdmission{Authority: a, Policy: policy.Policy, Initiator: initiator}, RepeatedFrom: p.Intent.RepeatedFrom, Recovery: recovery, RootID: s.RootID, IdempotencyKey: key, SubmissionDigest: request.SubmissionDigest, Plan: plan, Eligibility: f.eligibility, Storage: f.storage.Binding, Registration: r, CaseID: p.CaseID, OccurrenceID: c.OccurrenceID}
		if !ReviewedRecordingSaveGroupChild(p, child) {
			return zero, value.ErrChanged
		}
		request.Children = append(request.Children, child)
	}
	// Earlier members retain their original facts while later blocking reads run.
	for n, f := range facts {
		if !s.factsCurrent(f, s.Now()) || !resolved[n].Valid(s.Now()) || !s.Now().Before(preparedUntil[n]) {
			return zero, value.ErrChanged
		}
		child := &request.Children[n]
		final := s.Eligibility.ContextEligibilityCurrent(ctx, executor, f.target.Target())
		final.DefaultAudience, err = SnapshotAudience(child.Plan.Input.Snapshot, final.DefaultAudience)
		if err != nil || !final.Eligible || final.Principal != g.Executor || !final.VerifiedIdentity.Valid(s.Now()) || !slices.Equal(final.DefaultAudience, f.eligibility.DefaultAudience) {
			return zero, value.ErrChanged
		}
		final.ValidUntil = identity.Earlier(final.ValidUntil, f.eligibility.ValidUntil)
		child.Eligibility = final
		initiator := s.Eligibility.ContextEligibilityCurrent(ctx, current, f.target.Target())
		if !initiator.Eligible || initiator.Principal != p.Actor || !initiator.VerifiedIdentity.Valid(s.Now()) {
			return zero, value.ErrDenied
		}
		initiator.ValidUntil = identity.Earlier(initiator.ValidUntil, child.RecordingSave.Initiator.ValidUntil)
		child.RecordingSave.Initiator = initiator
		if request.RequestBounds != nil {
			request.RequestBounds.Until = identity.Earlier(request.RequestBounds.Until, initiator.VerifiedIdentity.ValidUntil).UTC().Truncate(time.Microsecond)
		}
	}
	if !p.Current(s.Now()) || !recovery.Valid(s.Now()) || ctx.Err() != nil {
		return zero, value.ErrChanged
	}
	if request.RequestBounds != nil && !request.RequestBounds.Valid(s.Now()) {
		return zero, value.ErrDenied
	}
	accepted, err := s.RecordingGroups.AdmitRecordingSaveGroup(ctx, request)
	if err != nil {
		return zero, err
	}
	if !acceptedContext(accepted, request.SubmissionDigest) || accepted.CaptureID != p.CaptureID || accepted.ScopeDigest != p.ScopeDigest {
		return zero, value.ErrUnavailable
	}
	if _, err = s.currentIdentity(ctx, current, caller.Principal, caller.ValidUntil); err != nil || !recovery.Valid(s.Now()) || ctx.Err() != nil {
		return zero, value.ErrDenied
	}
	accepted.MetadataValidUntil = identity.Earlier(accepted.MetadataValidUntil, identity.Earlier(caller.ValidUntil, recovery.FreshUntil))
	for _, until := range preparedUntil {
		accepted.MetadataValidUntil = identity.Earlier(accepted.MetadataValidUntil, until)
	}
	if !s.Now().Before(accepted.MetadataValidUntil) {
		return zero, value.ErrDenied
	}
	if !accepted.Replay {
		draft, e := HistoryDraftFromPreview(p, accepted)
		if e == nil {
			accepted.HistoryParameters = &draft
			accepted.HistorySource = p.Intent.RepeatedFrom
		} else {
			accepted.HistoryUnavailable = true
		}
	}
	return accepted, nil
}
