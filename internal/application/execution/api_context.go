package execution

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"time"

	"asservat.local/asservat/internal/application/evidence"
	fleetapp "asservat.local/asservat/internal/application/fleet"
	identities "asservat.local/asservat/internal/application/identity"
	compiler "asservat.local/asservat/internal/application/planning"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/collector"
	value "asservat.local/asservat/internal/domain/execution"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/domain/planning"
	"asservat.local/asservat/internal/domain/privacy"
	"asservat.local/asservat/internal/domain/targets"
)

type APIContextEligibility interface {
	ContextEligibilityCurrent(context.Context, identities.CurrentIdentity, authorization.Target) authorization.CaptureEligibility
}
type APIContextCapability interface {
	ContextCapability(context.Context, authorization.Target) (planning.ContextCapability, error)
}
type APIContextRetention interface {
	Resolve(context.Context, privacy.Input) (privacy.Resolution, error)
}

type APIContextWork struct {
	Accepted     capture.Accepted
	Target       targets.Request
	Actor        identity.Principal
	IntentDigest artifact.Digest
}
type APIExecutionCheck struct {
	Work                  APIContextWork
	Plan                  planning.ContextPlan
	Eligibility           authorization.CaptureEligibility
	Recovery              artifact.RecoveryProof
	Process               value.APIProcessObservation
	CheckedAt, ValidUntil time.Time
}

func (c APIExecutionCheck) Valid(now time.Time) bool {
	w, e := c.Work, c.Work.Accepted.Expectation
	t := c.Plan.Input.Target
	return e.ExecutionClass == artifact.ContextAPIExecution && e.Validate() == nil && w.Accepted.State == capture.IntentAudited && w.Actor == c.Eligibility.Principal && c.Eligibility.VerifiedIdentity.Principal == w.Actor && c.Eligibility.Eligible && c.Eligibility.Target == t.Target() && c.Eligibility.VerifiedIdentity.Valid(now) && now.Before(c.Eligibility.ValidUntil) && compiler.VerifyContextPlan(c.Plan, now) && c.Plan.ScopeDigest == e.PlanDigest && c.Plan.Input.Executor == w.Actor && c.Plan.Input.CaptureID == e.CaptureUID && c.Plan.Input.Deadline.Equal(w.Accepted.Deadline) && t.Request == w.Target && t.Pin == w.Accepted.Pin && c.Process.Valid(now) && c.Process.Binding.ClusterID == e.Registration.Location.ClusterID && c.Process.Binding.ImageDigest == e.CollectorImageDigest && c.Process.Binding.InstallationID == c.Recovery.InstallationID && c.Process.Binding.IssuerEpoch == c.Recovery.IssuerEpoch && c.Recovery.Valid(now) && c.Plan.Input.Retention.Proof.Valid(now) && identity.Fresh(c.CheckedAt, c.ValidUntil, now, 5*time.Second) && !c.ValidUntil.After(c.Eligibility.ValidUntil) && !c.ValidUntil.After(c.Plan.ValidUntil) && !c.ValidUntil.After(c.Process.ValidUntil) && !c.ValidUntil.After(c.Recovery.FreshUntil) && now.Before(e.Registration.WriteUntil) && w.IntentDigest != (artifact.Digest{})
}

// Typed facets share one installed SQL credential and pool (ADR-217). Their
// transaction checks remain; acquisition, audit, publication and unwrap stay
// separate privileges and ports.
type APIExecutionReader interface {
	ReadAPIContextWork(context.Context, string, identity.Identity, artifact.RecoveryProof) (APIContextWork, error)
}
type APIExecutionPreparer interface {
	PrepareAPIExecution(context.Context, APIExecutionCheck) (value.APIExecution, bool, error)
	BindAPIStart(context.Context, APIExecutionCheck, value.APIExecution, value.PreparedStart) (value.APIExecution, error)
}

// PolicyRecordingPreparer is the finite policy-only companion. It atomically
// commits the original API preparation and both observed-input pool debits.
// The runner must not use the ordinary preparation for a sensitive policy action.
// Implementing this port alone does not qualify or enable that acquisition mode.
type PolicyRecordingPreparer interface {
	PreparePolicyRecording(context.Context, APIExecutionCheck, targets.PacketSourceObservation) (value.APIExecution, bool, collector.ObservationPermit, error)
}

type APIExecutionRecorder interface {
	RecordAPIStart(context.Context, APIExecutionCheck, value.APIExecution, value.Disposition) (value.APIExecution, error)
	RecordAPIOutcome(context.Context, value.APIExecution, value.APIProcessObservation) (value.APIExecution, error)
}
type APIStoredCompletionRecorder interface {
	RecordAPIStoredCompletion(context.Context, value.APIExecution, artifact.ContextWriterCompletion, value.APIProcessObservation, artifact.RecoveryProof) (value.APIExecution, error)
}
type APIProcessReader interface {
	ReadAPIProcess(context.Context) (value.APIProcessObservation, error)
}
type APIStartPreparation interface {
	PrepareStart(context.Context, value.PreparationCheck) (value.PreparedStart, error)
	ReadyStart(context.Context, value.Request) (value.Disposition, error)
}

// ObservedAPIStartPreparation checks a start against a complete process
// observation the caller already holds for the same verified work (ADR-173),
// instead of reading the process again. The observation must come from the
// same in-process reader; it is never accepted from a remote party.
type ObservedAPIStartPreparation interface {
	PrepareObservedStart(context.Context, value.PreparationCheck, value.APIProcessObservation) (value.PreparedStart, error)
	ReadyObservedStart(context.Context, value.Request, value.APIProcessObservation) (value.Disposition, error)
}

type APIContextRunner struct {
	Read    APIExecutionReader
	Prepare APIExecutionPreparer
	Record  APIExecutionRecorder
	Process APIProcessReader
	Local   APIStartPreparation
	Starts  StartJournal
	Targets interface {
		ResolvePod(context.Context, targets.Request) (targets.PodResolution, error)
	}
	Eligibility  APIContextEligibility
	Capabilities APIContextCapability
	Retention    APIContextRetention
	Recovery     fleetapp.RecoveryReader
	Output       evidence.ContextProducer
	Collector    ContextCollector
	Now          func() time.Time
}

func APIExecutionDigest(r value.APIExecution) artifact.Digest {
	b, _ := json.Marshal(r)
	return artifact.Digest(sha256.Sum256(b))
}
func (s APIContextRunner) checkObserved(ctx context.Context, current identities.CurrentIdentity, w APIContextWork, original time.Time, capability *planning.ContextCapability, observedRecovery *artifact.RecoveryProof) (APIExecutionCheck, error) {
	var out APIExecutionCheck
	start := s.Now().UTC().Truncate(time.Microsecond)
	t, err := s.Targets.ResolvePod(ctx, w.Target)
	if err != nil {
		return out, apiCheckStep{"ResolvePod", err}
	}
	eligible := s.Eligibility.ContextEligibilityCurrent(ctx, current, t.Target())
	if !eligible.Eligible {
		return out, apiCheckStep{"Eligibility", value.ErrDenied}
	}
	var cap planning.ContextCapability
	if capability != nil {
		cap = *capability
	} else {
		cap, err = s.Capabilities.ContextCapability(ctx, t.Target())
		if err != nil {
			return out, apiCheckStep{"Capability", err}
		}
	}
	e := w.Accepted.Expectation
	// ADR-248: a recording recompiles its accepted recorder plan from the
	// frozen composition and program in the expectation, with the retention
	// of its own evidence type.
	evidenceType := "context"
	var recorder *planning.RecorderContext
	if e.Recording != nil {
		if recorder, err = compiler.RecorderContextFor(e.Recording); err != nil {
			return out, apiCheckStep{"Recording", value.ErrInvalid}
		}
		evidenceType = e.Type().EvidenceType
	}
	retention, err := s.Retention.Resolve(ctx, privacy.Input{Target: t.Target(), PrivacyClass: "potentialPersonalData", EvidenceType: evidenceType, RequestedSeconds: e.RequestedAgeSeconds, AnchorAt: e.Registration.AnchorAt})
	if err != nil {
		return out, apiCheckStep{"Retention", err}
	}
	caseID := e.CaseID
	if recorder != nil {
		caseID = "" // a recorder scope carries no case (ADR-243)
	}
	plan, err := compiler.CompileContext(planning.ContextInput{CaptureID: e.CaptureUID, CaseID: caseID, Executor: w.Actor, Deadline: w.Accepted.Deadline, Target: t, Capability: cap, Retention: retention, Recorder: recorder}, s.Now())
	if err != nil {
		return out, apiCheckStep{"Compile", err}
	}
	var recovery artifact.RecoveryProof
	if observedRecovery != nil {
		recovery = *observedRecovery
	} else {
		recovery, err = s.Recovery.RecoveryState(ctx)
		if err != nil {
			return out, apiCheckStep{"Recovery", err}
		}
	}
	process, err := s.Process.ReadAPIProcess(ctx)
	if err != nil {
		return out, apiCheckStep{"Process", err}
	}
	until := identity.Earlier(original, start.Add(5*time.Second))
	for _, d := range []time.Time{plan.ValidUntil, eligible.ValidUntil, recovery.FreshUntil, process.ValidUntil, e.Registration.WriteUntil} {
		until = identity.Earlier(until, d)
	}
	out = APIExecutionCheck{w, plan, eligible, recovery, process, start, until.UTC().Truncate(time.Microsecond)}
	if err := out.current(ctx, s.Now()); err != nil {
		return APIExecutionCheck{}, err
	}
	return out, nil
}

// current checks the one request-owned observation without renewing any fact.
// Each SQL effect still independently checks its transactional fences; native
// acquisition still checks the exact pinned Pod and the committed start.
func (c APIExecutionCheck) current(ctx context.Context, now time.Time) error {
	if !c.Valid(now) {
		return apiCheckStep{"Current", value.ErrDenied}
	}
	if ctx.Err() != nil {
		return apiCheckStep{"Context", value.ErrDenied}
	}
	if until, ok := ctx.Deadline(); ok && !now.Before(until) {
		return apiCheckStep{"Context", value.ErrDenied}
	}
	return nil
}

func (s APIContextRunner) valid(ctx context.Context, current identities.CurrentIdentity, captureID string) bool {
	return ctx != nil && current != nil && s.Read != nil && s.Prepare != nil && s.Record != nil && s.Process != nil && s.Local != nil && s.Starts != nil && s.Targets != nil && s.Eligibility != nil && s.Capabilities != nil && s.Retention != nil && s.Recovery != nil && s.Output != nil && s.Collector != nil && s.Now != nil && authorization.UUID(captureID)
}

// Execute starts only within the original request-owned identity interval. It
// neither restores a human request after restart nor queues a frozen identity.
func (s APIContextRunner) Execute(ctx context.Context, current identities.CurrentIdentity, captureID string) (ContextResult, error) {
	var zero ContextResult
	if !s.valid(ctx, current, captureID) {
		return zero, executeStep{"start", value.ErrInvalid}
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	i, err := current.ResolveIdentity(ctx)
	if err != nil || !i.Valid(s.Now()) {
		return zero, executeStep{"start", value.ErrDenied}
	}
	original := identity.Earlier(i.ValidUntil, s.Now().Add(5*time.Second))
	startCtx, stop := context.WithDeadline(ctx, original)
	defer stop()
	recovery, err := s.Recovery.RecoveryState(startCtx)
	if err != nil {
		return zero, executeStep{"RecoveryState", err}
	}
	w, err := s.Read.ReadAPIContextWork(startCtx, captureID, i, recovery)
	if err != nil {
		return zero, executeStep{"ReadAPIContextWork", err}
	}
	return s.execute(ctx, current, w, original, nil, nil)
}

// ExecuteObserved consumes the hub start's own already-read prelude. These are
// local service values, never caller or regional wire authority. The caller
// must retain the original narrowed context; no input is refreshed or cached.
func (s APIContextRunner) ExecuteObserved(ctx context.Context, current identities.CurrentIdentity, caller identity.Identity, w APIContextWork, capability planning.ContextCapability, recovery artifact.RecoveryProof) (ContextResult, error) {
	if !s.valid(ctx, current, w.Accepted.CaptureID) {
		return ContextResult{}, executeStep{"start", value.ErrInvalid}
	}
	now := s.Now()
	original, bounded := ctx.Deadline()
	if !bounded || original.After(now.Add(5*time.Second)) || ctx.Err() != nil || !now.Before(original) || !caller.Valid(now) || w.Actor != caller.Principal || w.Accepted.CaptureID != w.Accepted.Expectation.CaptureUID || !capability.Valid(now) || !recovery.Valid(now) {
		return ContextResult{}, executeStep{"start", value.ErrDenied}
	}
	for _, until := range []time.Time{caller.ValidUntil, capability.FreshUntil, recovery.FreshUntil} {
		original = identity.Earlier(original, until)
	}
	return s.execute(ctx, current, w, original, &capability, &recovery)
}

func (s APIContextRunner) execute(ctx context.Context, current identities.CurrentIdentity, w APIContextWork, original time.Time, capability *planning.ContextCapability, recovery *artifact.RecoveryProof) (ContextResult, error) {
	var zero ContextResult
	startCtx, stop := context.WithDeadline(ctx, original)
	defer stop()
	check, err := s.checkObserved(startCtx, current, w, original, capability, recovery)
	if err != nil {
		// The check only reads; nothing was prepared or started. The runner
		// never inspects a dependency's error: the composing start classifies
		// a temporary unavailability from the fixed Check step (ADR-250).
		return zero, executeStep{"Check", err}
	}
	r, mayCreate, err := s.Prepare.PrepareAPIExecution(startCtx, check)
	if err != nil {
		return zero, executeStep{"PrepareAPIExecution[" + check.limit(original, s.Now()) + "]", err}
	}
	if !r.Valid() || r.Process != check.Process.Binding || r.ExpectationDigest != evidence.ContextExpectationDigest(w.Accepted.Expectation) {
		return zero, executeStep{"PrepareAPIExecution", value.ErrConflict}
	}
	if r.Phase != "prepared" {
		return ContextResult{State: "AlreadyStarted"}, nil
	}
	// Only the positively acknowledged first SQL preparation may create keys.
	// Existing prepared state cannot distinguish an active owner from a lost or
	// uncertain provider effect. It never permits another wrapping attempt.
	if !mayCreate {
		return ContextResult{State: "Indeterminate"}, value.ErrPreparationUncertain
	}
	startCtx, stopPreparation := context.WithDeadline(startCtx, r.Binding.NotAfter)
	defer stopPreparation()
	if startCtx.Err() != nil || !s.Now().Before(r.Binding.NotAfter) {
		return ContextResult{State: "Indeterminate"}, value.ErrExpired
	}
	if r.WriterProtocol != artifact.ContextWriterProtocol {
		return zero, executeStep{"PrepareAPIExecution", value.ErrUnavailable}
	}
	completionRecorder, ok := s.Record.(APIStoredCompletionRecorder)
	if !ok {
		return zero, executeStep{"PrepareAPIExecution", value.ErrUnavailable}
	}
	prepared, err := s.Output.PrepareContext(startCtx, w.Accepted.Expectation)
	if err != nil {
		return zero, executeStep{"PrepareContext", err}
	}
	if prepared == nil {
		return zero, executeStep{"PrepareContext", value.ErrUnavailable}
	}
	defer prepared.Close()
	closer, ok := prepared.(evidence.StoredContextCloser)
	if !ok {
		return zero, executeStep{"PrepareContext", value.ErrUnavailable}
	}
	if err := check.current(startCtx, s.Now()); err != nil {
		return zero, executeStep{"PrepareContext", err}
	}
	c := value.PreparationCheck{Binding: r.Binding, CheckedAt: check.CheckedAt, ValidUntil: identity.Earlier(check.ValidUntil, r.Binding.NotAfter), MayCreate: mayCreate}
	object, err := s.Local.PrepareStart(startCtx, c)
	if err != nil {
		return zero, executeStep{"PrepareStart", err}
	}
	r, err = s.Prepare.BindAPIStart(startCtx, check, r, object)
	if err != nil {
		return zero, executeStep{"BindAPIStart", err}
	}
	request := value.Request{Binding: r.Binding, ObjectUID: r.ObjectUID, CheckedAt: c.CheckedAt, ValidUntil: c.ValidUntil}
	ready, err := s.Local.ReadyStart(startCtx, request)
	if err != nil {
		return zero, executeStep{"ReadyStart", err}
	}
	if ready.MayStart || ready.ObjectUID != r.ObjectUID {
		return zero, executeStep{"ReadyStart", value.ErrDenied}
	}
	if ready.Phase == value.StartCommitted {
		return ContextResult{State: "AlreadyStarted"}, nil
	}
	// Capacity waits consume the same observation's original interval. They do
	// not trigger another provider graph or authorize a replacement target.
	if err := check.current(startCtx, s.Now()); err != nil {
		return zero, executeStep{"ReadyStart", err}
	}
	if check.Process.Binding != r.Process {
		return zero, executeStep{"ReadyStart", value.ErrConflict}
	}
	d, err := s.Starts.ConsumeStart(startCtx, request)
	if err != nil {
		return ContextResult{State: "Indeterminate"}, err
	}
	if !d.MayStart {
		return ContextResult{State: "AlreadyStarted"}, nil
	}
	if d.ObjectUID != r.ObjectUID || d.Phase != value.StartCommitted || !d.CommittedAt.Before(d.ValidUntil) || d.ValidUntil.After(request.ValidUntil) || !s.Now().Before(d.ValidUntil) {
		return ContextResult{State: "Indeterminate"}, value.ErrDenied
	}
	r, err = s.Record.RecordAPIStart(startCtx, check, r, d)
	if err != nil {
		return ContextResult{State: "Indeterminate"}, err
	}
	if startCtx.Err() != nil || !s.Now().Before(d.ValidUntil) {
		return ContextResult{State: "Indeterminate"}, value.ErrExpired
	}
	result := r
	if w.Accepted.Expectation.Recording != nil {
		// ADR-248: the node records for the accepted duration; the SQL
		// execution stays started until a later collect exchange records
		// the stored completion (CollectRecording). Only a start the region
		// refused is recorded as failed now.
		recorder, ok := prepared.(evidence.ContextRecorder)
		if !ok {
			return zero, executeStep{"StartRecording", value.ErrUnavailable}
		}
		queued, err := recorder.StartRecording(ctx, w.Accepted.Pin, r.StartedAt, d.ValidUntil)
		if err == nil && !queued.IsZero() && queued.Before(d.ValidUntil) && !queued.Before(r.StartedAt) {
			return ContextResult{State: "Recording"}, nil
		}
		result.CompletedAt, result.Phase = s.Now().UTC().Truncate(time.Microsecond), "captureFailed"
		if err == nil {
			err = value.ErrUnavailable
		}
		return s.finishAcquisition(ctx, w, prepared, closer, completionRecorder, result, err)
	}
	if acquirer, ok := prepared.(evidence.ContextAcquirer); ok {
		// ADR-171: capture and store happen where the plaintext is. Only the
		// acquisition instant and the copy receipts return here.
		acquired, copies, acquireErr := acquirer.AcquireContext(ctx, w.Accepted.Pin, r.StartedAt, d.ValidUntil)
		err = acquireErr
		result.CompletedAt = s.Now().UTC().Truncate(time.Microsecond)
		switch {
		case err == nil && !acquired.IsZero() && acquired.Before(d.ValidUntil) && copies.Validate(w.Accepted.Expectation.Registration) == nil:
			result.AcquiredAt, result.Copies, result.Phase = acquired, copies, "stored"
		case err == nil || errors.Is(err, evidence.ErrContextStoreUnconfirmed):
			result.AcquiredAt, result.Phase = acquired, "storeUnconfirmed"
			if err == nil {
				err = value.ErrUnavailable
			}
		default:
			result.CompletedAt, result.Phase = acquired, captureFailurePhase(err)
			if acquired.IsZero() {
				result.CompletedAt = s.Now().UTC().Truncate(time.Microsecond)
			}
		}
		return s.finishAcquisition(ctx, w, prepared, closer, completionRecorder, result, err)
	}
	captureCtx, end := context.WithDeadline(startCtx, d.ValidUntil)
	native, err := s.Collector.Capture(captureCtx, w.Accepted.Pin)
	acquired := s.Now().UTC().Truncate(time.Microsecond)
	captureErr := captureCtx.Err()
	end()
	defer clear(native)
	result.CompletedAt = acquired
	result.Phase = captureFailurePhase(err)
	if err == nil && captureErr == nil && acquired.Before(d.ValidUntil) && len(native) > 0 && len(native) <= artifact.MaxContextBytes {
		result.AcquiredAt = acquired
		result.Copies, err = prepared.StoreContext(ctx, native, r.StartedAt, acquired)
		result.CompletedAt = s.Now().UTC().Truncate(time.Microsecond)
		result.Phase = "stored"
		if err != nil || result.Copies.Validate(w.Accepted.Expectation.Registration) != nil {
			result.Phase = "storeUnconfirmed"
			result.Copies = artifact.Copies{}
			if err == nil {
				err = value.ErrUnavailable
			}
		}
	} else if err == nil {
		if captureErr != nil {
			err = captureErr
		} else {
			err = value.ErrExpired
		}
	}
	return s.finishAcquisition(ctx, w, prepared, closer, completionRecorder, result, err)
}

// finishAcquisition records the stored completion or the failed outcome with a
// current process proof; it is shared by the local and ADR-171 paths.
func (s APIContextRunner) finishAcquisition(ctx context.Context, w APIContextWork, prepared evidence.PreparedContext, closer evidence.StoredContextCloser, completionRecorder APIStoredCompletionRecorder, result value.APIExecution, err error) (ContextResult, error) {
	process, proofErr := s.Process.ReadAPIProcess(ctx)
	if proofErr != nil {
		return ContextResult{State: "Indeterminate"}, proofErr
	}
	var recordErr error
	if result.Phase == "stored" {
		completion, closeErr := closer.CompleteStored()
		if closeErr != nil || completion.Copies != result.Copies || !completion.Valid(w.Accepted.Expectation.Registration) {
			return ContextResult{State: "Indeterminate"}, value.ErrUnavailable
		}
		result.CompletedAt = completion.StoredAt
		currentRecovery, recoveryErr := s.Recovery.RecoveryState(ctx)
		if recoveryErr != nil {
			return ContextResult{State: "Indeterminate"}, recoveryErr
		}
		_, recordErr = completionRecorder.RecordAPIStoredCompletion(ctx, result, completion, process, currentRecovery)
	} else {
		prepared.Close()
		_, recordErr = s.Record.RecordAPIOutcome(ctx, result, process)
	}
	if recordErr != nil {
		return ContextResult{State: "Indeterminate"}, recordErr
	}
	if err != nil {
		return ContextResult{State: "Indeterminate"}, err
	}
	return ContextResult{State: "StoredPendingVerification", Copies: result.Copies}, nil
}

// executeStep names the call before a failed execution, for operator
// diagnostics; its class is the wrapped error.
type executeStep struct {
	step string
	err  error
}

func (e executeStep) Error() string { return "api context execution " + e.step }
func (e executeStep) Unwrap() error { return e.err }
func (e executeStep) FixedStep() string {
	var inner interface{ FixedStep() string }
	if errors.As(e.err, &inner) {
		return e.step + "/" + inner.FixedStep()
	}
	return e.step
}

// captureFailurePhase records why a started capture produced no output: the
// pinned Pod is gone or Kubernetes denied the read; anything else is generic.
func captureFailurePhase(err error) string {
	switch {
	case errors.Is(err, targets.ErrChanged):
		return "targetGone"
	case errors.Is(err, targets.ErrDenied):
		return "denied"
	}
	return "captureFailed"
}
