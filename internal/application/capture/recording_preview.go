package capture

import (
	"context"
	"errors"
	"slices"
	"time"

	auditapp "asservat.local/asservat/internal/application/audit"
	identities "asservat.local/asservat/internal/application/identity"
	compiler "asservat.local/asservat/internal/application/planning"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/domain/planning"
	"asservat.local/asservat/internal/domain/targets"
)

// ContextRecorders answers whether the node collector on a resolved Pod's
// node currently offers the packet recorder (ADR-248). It is a regional
// observation, never authority: acceptance still runs every ordinary check
// and the connector checks the node again before queueing work.
type ContextRecorders interface {
	PacketRecorder(context.Context, targets.PodResolution) error
}

// packetRecorderAvailable reports whether this composition could be recorded
// on the target's node now. Any failure is "not available".
func (s ContextInvestigation) packetRecorderAvailable(ctx context.Context, intent value.ContextIntent, target targets.PodResolution) bool {
	if s.Recorders == nil || intent.Composition == nil || target.ExecutionClass != artifact.ContextAPIExecution {
		return false
	}
	if evidence, err := compiler.RecorderEvidenceType(*intent.Composition); err != nil || evidence != "packetCapture" {
		return false
	}
	mark := time.Now()
	err := s.Recorders.PacketRecorder(ctx, target)
	auditapp.MarkStep(ctx, "p-recorder", mark)
	return err == nil
}

// recordingPlan compiles the accepted context plan of an acceptable
// composition preview: the authored composition with the filter programs
// frozen in the reviewed scope (no filter compiler is consulted again).
func (s ContextInvestigation) recordingPlan(p value.ContextPreview, f contextFacts) (planning.ContextPlan, error) {
	recorder, err := compiler.RecorderContextFromScope(*p.Intent.Composition, p.CanonicalScope)
	if err != nil {
		return planning.ContextPlan{}, err
	}
	return compiler.CompileContext(planning.ContextInput{CaptureID: p.CaptureID, CaseID: p.CaseID, Executor: p.Actor, Deadline: p.Deadline, Target: f.target, Retention: f.retention, Capability: f.capability, Recorder: recorder}, s.Now())
}

// previewRecording is PreviewComposition for a packet composition whose
// target node offers the packet recorder: the ordinary pod-status preview
// facts (capability, retention for the recorder's evidence type, storage,
// processing coverage), then the recorder plan with acceptance nodeRecorder.
// A plan this release cannot record falls back to the ADR-243 refusal.
func (s ContextInvestigation) previewRecording(ctx context.Context, source identities.CurrentIdentity, intent value.ContextIntent, i identity.Identity, recovery artifact.RecoveryProof, target targets.PodResolution, created time.Time) (RecorderPreviewResult, error) {
	var zero RecorderPreviewResult
	f, err := s.facts(ctx, source, i.Principal, intent, target, created, identity.Earlier(i.ValidUntil, recovery.FreshUntil))
	if err != nil {
		return zero, previewFailure("facts", err)
	}
	p := value.ContextPreview{ID: s.NewID(), RootID: s.RootID, InstallationID: s.InstallationID, IssuerEpoch: recovery.IssuerEpoch, CaptureID: s.NewID(), CaseID: s.NewID(), OccurrenceID: s.NewID(), ArtifactID: s.NewID(), AttemptID: s.NewID(), Actor: i.Principal, Intent: intent, Target: target.Request, Pin: target.Pin, Storage: f.storage.Selection, Retention: retentionReview(f.retention), Audience: slices.Clone(f.eligibility.DefaultAudience), CreatedAt: created, Deadline: created.Add(s.Lifetime)}
	p.Intent.Composition = intent.Composition.Clone()
	p.ExecutionClass = target.ExecutionClass
	p.AssessmentID, p.AssessmentRulesDigest = s.NewID(), compiler.RecorderAssessmentRulesDigest()
	required, err := s.requireRecordingApproval(ctx, i.Principal.Issuer)
	if err != nil {
		return zero, previewFailure("approvals", err)
	}
	mark := time.Now()
	plan, err := compiler.CompileRecorder(planning.RecorderInput{CaptureID: p.CaptureID, Executor: p.Actor, Target: target, Composition: *intent.Composition, Retention: f.retention, Deadline: p.Deadline, NodeRecorder: true, RequireApproval: required}, s.Filters, s.Now())
	auditapp.MarkStep(ctx, "p-compile", mark)
	if err != nil {
		return zero, previewFailure("compile", err)
	}
	if !compiler.AcceptableRecorder(plan).Acceptable() {
		return zero, errRecordingNotAcceptable
	}
	p.CanonicalScope, p.ScopeDigest = slices.Clone(plan.CanonicalScope), plan.ScopeDigest
	processingStarted := time.Now()
	coverage, err := s.processingCoverage(ctx, p, f, recovery, i.ValidUntil)
	auditapp.MarkStep(ctx, "p-processing", processingStarted)
	if err != nil {
		return zero, previewFailure("processing", err)
	}
	ctx, coverageEnd := context.WithDeadline(ctx, coverage.FreshUntil)
	defer coverageEnd()
	// The accepted context plan must reproduce the reviewed scope exactly.
	accepted, err := s.recordingPlan(p, f)
	if err != nil || accepted.ScopeDigest != plan.ScopeDigest {
		return zero, previewFailure("compile/accepted", value.ErrInvalid)
	}
	assessment, err := compiler.AssessRecorder(plan, p.AssessmentID, s.Now())
	if err != nil {
		return zero, previewFailure("assessment", err)
	}
	if !ValidContextPreview(p) || !p.Current(s.Now()) {
		return zero, previewFailure("blueprint", value.ErrInvalid)
	}
	if _, err = s.currentIdentity(ctx, source, i.Principal, i.ValidUntil); err != nil || !s.factsCurrent(f, s.Now()) || !coverage.Current(s.Now()) || !recovery.Valid(s.Now()) {
		return zero, previewFailure("before-store/current", value.ErrChanged)
	}
	mark = time.Now()
	err = s.Previews.CreateContextPreview(ctx, p.Clone())
	auditapp.MarkStep(ctx, "p-store", mark)
	if err != nil {
		return zero, previewFailure("store", err)
	}
	current := s.Eligibility.ContextEligibilityCurrent(ctx, source, target.Target())
	if !current.Eligible || current.Target != target.Target() || current.Principal != i.Principal || !current.VerifiedIdentity.Valid(s.Now()) || !i.Valid(s.Now()) || !slices.Equal(current.DefaultAudience, p.Audience) || !s.Now().Before(current.ValidUntil) || !s.factsCurrent(f, s.Now()) || !coverage.Current(s.Now()) || !recovery.Valid(s.Now()) || ctx.Err() != nil || s.Now().Before(created) {
		return zero, previewFailure("after-store/current", value.ErrChanged)
	}
	until := identity.Earlier(i.ValidUntil, recovery.FreshUntil)
	for _, bound := range []time.Time{current.ValidUntil, current.VerifiedIdentity.ValidUntil, f.eligibility.ValidUntil, f.eligibility.VerifiedIdentity.ValidUntil, assessment.ValidUntil, plan.ValidUntil, f.storage.Binding.FreshUntil, coverage.FreshUntil} {
		until = identity.Earlier(until, bound)
	}
	if !s.Now().Before(until) || ctx.Err() != nil {
		return zero, previewFailure("response/current", value.ErrUnavailable)
	}
	return RecorderPreviewResult{Preview: p.Clone(), Plan: plan, Assessment: assessment, ValidUntil: until, Recordable: true}, nil
}

// recordingAssessment checks that the accepted plan still yields the
// reviewed recorder assessment rules.
func (s ContextInvestigation) recordingAssessment(p value.ContextPreview, plan planning.ContextPlan) error {
	rp, err := compiler.RecorderPlanForContext(plan)
	if err != nil {
		return err
	}
	a, err := compiler.AssessRecorder(rp, p.AssessmentID, s.Now())
	if err != nil || a.RulesDigest != p.AssessmentRulesDigest {
		return value.ErrChanged
	}
	return nil
}

// nativeLimit is the registered native bound of an admission: pod status, or
// the interim 8 MiB per recording (ADR-248).
func nativeLimit(recording bool) int64 {
	if recording {
		return artifact.RecordingNativeLimit
	}
	return artifact.MaxContextBytes
}

// recordingCompletionMargin covers the start exchange, the node's gadget
// start and the encrypted upload after the recorded duration (measured on a
// GitHub runner: 0.4 s from queueing to delivery beyond a 10 s recording).
const recordingCompletionMargin = 30 * time.Second

// errRecordingNotAcceptable sends a node-recorder preview back to the ADR-243
// plan-only path: the plan is valid but this release cannot record it.
var errRecordingNotAcceptable = errors.New("recorder plan not acceptable in this release")
