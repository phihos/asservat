package execution

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	access "asservat.local/asservat/internal/application/authorization"
	"asservat.local/asservat/internal/application/evidence"
	identities "asservat.local/asservat/internal/application/identity"
	compiler "asservat.local/asservat/internal/application/planning"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/configuration"
	value "asservat.local/asservat/internal/domain/execution"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/domain/planning"
	"asservat.local/asservat/internal/domain/privacy"
	"asservat.local/asservat/internal/domain/targets"
)

type apiRunnerFixture struct {
	*contextExecutionFixture
	work      APIContextWork
	target    targets.PodResolution
	cap       planning.ContextCapability
	retention privacy.Resolution
	recovery  artifact.RecoveryProof
	process   value.APIProcessBinding
	actor     identity.Identity
	mu        sync.Mutex
	record    value.APIExecution
}

func (f *apiRunnerFixture) Resolve(ctx context.Context, _ string) (identity.Identity, error) {
	i := f.actor
	if f.prepares.Load() > 0 {
		if f.mode == "revoked-after-keys" {
			i.Groups = nil
		}
		if f.mode == "expired-after-keys" {
			return i, identity.ErrDenied
		}
	}
	if ctx.Err() != nil {
		return i, ctx.Err()
	}
	return i, nil
}
func (f *apiRunnerFixture) Permissions(ctx context.Context, t authorization.Target) (authorization.Projection, error) {
	if f.mode == "eligibility-denied" {
		return authorization.Projection{}, value.ErrDenied
	}
	return authorization.Projection{Target: t, Revision: identity.Revision{UID: "permissions", Generation: 1, Digest: [32]byte{1}}, ObservedAt: f.now, FreshUntil: f.now.Add(5 * time.Second), DeniesObservedAt: f.now, DeniesFreshUntil: f.now.Add(5 * time.Second), DeniesComplete: true, Allows: []authorization.CurrentAssignment{{Audience: f.work.Accepted.Expectation.Audience[0], ObservedAt: f.now, FreshUntil: f.now.Add(5 * time.Second)}}}, nil
}
func (f *apiRunnerFixture) ReadAPIContextWork(context.Context, string, identity.Identity, artifact.RecoveryProof) (APIContextWork, error) {
	return f.work, nil
}
func (f *apiRunnerFixture) ResolvePod(context.Context, targets.Request) (targets.PodResolution, error) {
	if f.mode == "replacement-pod" && f.prepares.Load() > 0 {
		return targets.PodResolution{}, targets.ErrChanged
	}
	switch f.mode {
	case "target-unavailable":
		return targets.PodResolution{}, targets.ErrUnavailable
	case "target-denied":
		return targets.PodResolution{}, targets.ErrDenied
	case "target-changed":
		return targets.PodResolution{}, targets.ErrChanged
	case "target-private":
		return targets.PodResolution{}, uninspectableError{}
	}
	return f.target, nil
}

// The runner never marks a check failure itself: it keeps the dependency's
// error under the fixed Check step. A composer classifies it, so only a
// temporary unavailability counts as not started; a denial (target or
// eligibility) or a changed target keeps its class. A lost preparation reply
// is never marked not started.
func TestAPIContextRunnerLeavesCheckClassificationToTheComposer(t *testing.T) {
	for mode, want := range map[string]bool{"target-unavailable": true, "target-denied": false, "target-changed": false, "eligibility-denied": false} {
		t.Run(mode, func(t *testing.T) {
			f, s, current := apiRunner(t)
			f.mode = mode
			_, err := s.Execute(t.Context(), current, f.work.Accepted.CaptureID)
			var fixed interface{ FixedStep() string }
			if err == nil || errors.Is(err, value.ErrNotStarted) || !errors.As(err, &fixed) || !strings.HasPrefix(fixed.FixedStep(), "Check") || TemporarilyUnavailable(err) != want || f.captures.Load() != 0 {
				t.Fatal("check classification", err, want)
			}
		})
	}
	f, s, current := apiRunner(t)
	f.mode = "lost-preparation-reply"
	_, err := s.Execute(t.Context(), current, f.work.Accepted.CaptureID)
	if err == nil || errors.Is(err, value.ErrNotStarted) {
		t.Fatal("a possibly committed preparation was marked not started", err)
	}
}

// The runner must not inspect a dependency's private error (diagnostics
// contract); a check failure passes it through unexamined.
type uninspectableError struct{}

func (uninspectableError) Error() string { panic("rendered") }
func (uninspectableError) Unwrap() error { panic("unwrapped") }
func (uninspectableError) Is(error) bool { panic("inspected") }

func TestAPIContextRunnerDoesNotInspectCheckErrors(t *testing.T) {
	f, s, current := apiRunner(t)
	f.mode = "target-private"
	_, err := s.Execute(t.Context(), current, f.work.Accepted.CaptureID)
	var step executeStep
	if !errors.As(err, &step) || step.step != "Check" {
		t.Fatal("private check failure lost its fixed step")
	}
}
func (f *apiRunnerFixture) ContextCapability(context.Context, authorization.Target) (planning.ContextCapability, error) {
	return f.cap, nil
}
func (f *apiRunnerFixture) ResolveRetention(context.Context, privacy.Input) (privacy.Resolution, error) {
	return f.retention, nil
}

type apiFixtureRetention struct{ f *apiRunnerFixture }

func (r apiFixtureRetention) Resolve(ctx context.Context, i privacy.Input) (privacy.Resolution, error) {
	return r.f.ResolveRetention(ctx, i)
}
func (f *apiRunnerFixture) RecoveryState(context.Context) (artifact.RecoveryProof, error) {
	return f.recovery, nil
}
func (f *apiRunnerFixture) ReadAPIProcess(context.Context) (value.APIProcessObservation, error) {
	p := f.process
	if f.mode == "restarted-process" && f.prepares.Load() > 0 {
		p.ProcessEpoch = contextID(80)
	}
	return value.APIProcessObservation{Binding: p, CheckedAt: f.now, ValidUntil: f.now.Add(5 * time.Second)}, nil
}
func (f *apiRunnerFixture) PrepareAPIExecution(_ context.Context, c APIExecutionCheck) (value.APIExecution, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !c.Valid(f.now) {
		return value.APIExecution{}, false, value.ErrDenied
	}
	first := f.record.Phase == ""
	if first {
		b := f.resolved.Start.Binding
		b.ExecutionClass = artifact.ContextAPIExecution
		b.NodeUID = ""
		b.NodeBootID = ""
		b.ExecutorPodUID = f.process.PodUID
		b.ExecutorAccountUID = f.process.AccountUID
		b.CollectorEpoch = f.process.ProcessEpoch
		b.ScopeDigest = f.work.Accepted.ScopeDigest
		b.NotBefore = c.CheckedAt
		b.NotAfter = c.ValidUntil
		f.record = value.APIExecution{WriterProtocol: artifact.ContextWriterProtocol, RootID: contextID(41), Binding: b, Process: f.process, ExpectationDigest: evidence.ContextExpectationDigest(f.work.Accepted.Expectation), Phase: "prepared"}
	}
	if f.mode == "legacy-writer-protocol" {
		f.record.WriterProtocol = ""
	}
	if f.mode == "lost-preparation-reply" && first {
		return value.APIExecution{}, false, value.ErrUnavailable
	}
	return f.record, first, nil
}
func (f *apiRunnerFixture) BindAPIStart(_ context.Context, _ APIExecutionCheck, _ value.APIExecution, p value.PreparedStart) (value.APIExecution, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.record.ObjectUID != "" && f.record.ObjectUID != p.ObjectUID {
		return value.APIExecution{}, value.ErrConflict
	}
	f.record.ObjectUID = p.ObjectUID
	return f.record, nil
}
func (f *apiRunnerFixture) PrepareStart(_ context.Context, c value.PreparationCheck) (value.PreparedStart, error) {
	if f.mode == "restarted-process" {
		// A restarted regional process loses the exact live exchange. It cannot
		// answer this operation with a replacement process or inherit its work.
		return value.PreparedStart{}, context.Canceled
	}
	if f.mode == "lost-create-reply" && c.MayCreate {
		return value.PreparedStart{}, value.ErrUnavailable
	}
	return value.PreparedStart{ObjectUID: f.resolved.Start.ObjectUID, ResourceVersion: "1"}, nil
}
func (f *apiRunnerFixture) Capture(ctx context.Context, pin artifact.PinnedPod) ([]byte, error) {
	if f.mode == "replacement-pod" {
		// The native collector rechecks the pinned Pod/controller at acquisition;
		// a new full runner observation is not needed to prevent substitution.
		return nil, targets.ErrChanged
	}
	return f.contextExecutionFixture.Capture(ctx, pin)
}
func (f *apiRunnerFixture) ReadyStart(ctx context.Context, r value.Request) (value.Disposition, error) {
	return f.LookupStart(ctx, r)
}
func (f *apiRunnerFixture) RecordAPIStart(_ context.Context, _ APIExecutionCheck, _ value.APIExecution, d value.Disposition) (value.APIExecution, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.mode == "lost-start-record-reply" {
		return value.APIExecution{}, value.ErrUnavailable
	}
	if f.record.Phase != "prepared" {
		return value.APIExecution{}, value.ErrConflict
	}
	f.record.Phase = "started"
	f.record.StartedAt = d.CommittedAt
	if f.mode == "expired-start-record-reply" {
		f.now = f.now.Add(6 * time.Second)
	}
	return f.record, nil
}
func (f *apiRunnerFixture) RecordAPIOutcome(_ context.Context, r value.APIExecution, p value.APIProcessObservation) (value.APIExecution, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.mode == "lost-acquire-reply" {
		// The exchange that lost the acquisition reply cannot record either.
		return value.APIExecution{}, value.ErrUnavailable
	}
	if !r.Valid() || p.Binding != r.Process {
		return value.APIExecution{}, value.ErrDenied
	}
	f.record = r
	return r, nil
}
func (f *apiRunnerFixture) RecordAPIStoredCompletion(ctx context.Context, r value.APIExecution, c artifact.ContextWriterCompletion, p value.APIProcessObservation, recovery artifact.RecoveryProof) (value.APIExecution, error) {
	if f.closes.Load() < 1 || c.Copies != r.Copies || !c.Valid(f.work.Accepted.Expectation.Registration) || !recovery.Valid(f.now) {
		return value.APIExecution{}, value.ErrDenied
	}
	return f.RecordAPIOutcome(ctx, r, p)
}
func apiRunner(t *testing.T) (*apiRunnerFixture, APIContextRunner, identities.CurrentIdentity) {
	t.Helper()
	base, _ := executionFixture()
	f := &apiRunnerFixture{contextExecutionFixture: base}
	e := base.resolved.Expectation
	e.ExecutionClass = artifact.ContextAPIExecution
	e.NodeUID = ""
	e.NodeBootID = ""
	pin := base.resolved.Pin
	pin.NodeName = ""
	pin.ControllerUID = e.WorkloadUID
	rev := identity.Revision{UID: contextID(40), Generation: 1, Digest: [32]byte{40}}
	f.target = targets.PodResolution{ExecutionClass: artifact.ContextAPIExecution, Request: targets.Request{ClusterID: e.Registration.Location.ClusterID, Namespace: configuration.NamespaceRef{Name: e.Namespace, UID: e.NamespaceUID}, Workload: configuration.WorkloadRef{Kind: "StatefulSet", Name: "api", UID: e.WorkloadUID}, PodName: pin.Name, PodUID: e.PodUID}, Pin: pin, PodResourceVersion: "1", WorkloadResourceVersion: "1", ObservedAt: f.now, FreshUntil: f.now.Add(5 * time.Second)}
	f.actor = identity.Identity{Principal: identity.Principal{Issuer: e.Audience[0].Issuer, Subject: "dev", ClientID: "console", Kind: identity.Human}, Policy: rev, Scopes: []string{"evidence:capture", "evidence:read"}, Groups: []string{"team"}, VerifiedAt: f.now, ValidUntil: f.now.Add(5 * time.Second)}
	f.cap = planning.ContextCapability{ExecutionClass: artifact.ContextAPIExecution, Enabled: true, Revision: rev, CollectorVersion: e.CollectorVersion, CollectorImageDigest: e.CollectorImageDigest, ProjectionDigest: compiler.ProjectionDigest(), ObservedAt: f.now, FreshUntil: f.now.Add(5 * time.Second)}
	proof := artifact.RetentionProof{RootID: contextID(41), ClusterID: f.target.Target().ClusterID, NamespaceUID: e.NamespaceUID, WorkloadUID: e.WorkloadUID, PodUID: e.PodUID, Topology: rev, Policy: rev, Selectors: rev, SourceCount: 1, ObservedAt: f.now, ValidUntil: f.now.Add(5 * time.Second), Sources: [2]artifact.RetentionSourceVersion{{ClusterID: f.target.Target().ClusterID, ControlNamespaceUID: contextID(42), Epoch: contextID(43), Hub: true, ProtectionDigest: artifact.Digest{1}, SnapshotDigest: artifact.Digest{2}, Acceptance: rev}}}
	f.retention = privacy.Resolution{Target: f.target.Target(), PolicyRevision: rev, PurposeRef: e.PurposeRef, PrivacyClass: "potentialPersonalData", EvidenceType: "context", RequestedSeconds: e.RequestedAgeSeconds, MaximumSeconds: e.MaximumAgeSeconds, DeletionBudgetSeconds: e.DeletionBudgetSeconds, Policies: e.RetentionRules, Deadlines: privacy.Deadlines{AnchorAt: e.Registration.AnchorAt, ExpiresAt: e.Registration.ExpiresAt, DeleteBy: e.Registration.DeleteBy}, ValidUntil: f.now.Add(5 * time.Second), Proof: proof}
	f.recovery = artifact.RecoveryProof{InstallationID: contextID(44), IssuerEpoch: base.receiver.IssuerEpoch, Revision: rev, ObservedAt: f.now, FreshUntil: f.now.Add(5 * time.Second)}
	f.process = value.APIProcessBinding{InstallationID: f.recovery.InstallationID, ClusterID: f.target.Target().ClusterID, IssuerEpoch: f.recovery.IssuerEpoch, NamespaceUID: contextID(45), AccountUID: contextID(46), PodUID: contextID(47), ProcessEpoch: contextID(48), StartupDigest: artifact.Digest{1}, ImageDigest: e.CollectorImageDigest}
	plan, err := compiler.CompileContext(planning.ContextInput{CaptureID: e.CaptureUID, CaseID: e.CaseID, Executor: f.actor.Principal, Deadline: e.Registration.WriteUntil, Target: f.target, Retention: f.retention, Capability: f.cap}, f.now)
	if err != nil {
		t.Fatal(err)
	}
	e.PlanDigest = plan.ScopeDigest
	e.RecipeDigest = plan.RecipeDigest
	f.work = APIContextWork{Accepted: capture.Accepted{CaptureID: e.CaptureUID, State: capture.IntentAudited, ScopeDigest: e.PlanDigest, Expectation: e, Pin: pin, CreatedAt: f.now, Deadline: e.Registration.WriteUntil}, Target: f.target.Request, Actor: f.actor.Principal, IntentDigest: artifact.Digest{1}}
	svc := APIContextRunner{Read: f, Prepare: f, Record: f, Process: f, Local: f, Starts: f, Targets: f, Eligibility: access.Evaluator{Permissions: f, Now: func() time.Time { return f.now }}, Capabilities: f, Retention: apiFixtureRetention{f}, Recovery: f, Output: f, Collector: f, Now: func() time.Time { return f.now }}
	source, _, err := identities.NewBearerRequest(context.Background(), f, "synthetic-token", svc.Now)
	if err != nil {
		t.Fatal(err)
	}
	return f, svc, source
}
func TestAPIContextRunnerOneEffectAndClosedKeys(t *testing.T) {
	f, s, current := apiRunner(t)
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			out, err := s.Execute(context.Background(), current, f.work.Accepted.CaptureID)
			if !(errors.Is(err, value.ErrPreparationUncertain) && out.State == "Indeterminate") && (err != nil || out.State != "StoredPendingVerification" && out.State != "AlreadyStarted") {
				t.Errorf("%s %v", out.State, err)
			}
		})
	}
	wg.Wait()
	if f.captures.Load() != 1 || f.stores.Load() != 1 || f.prepares.Load() != 1 || f.prepares.Load() != f.closes.Load() || f.record.Phase != "stored" {
		t.Fatal("repeated effect or keys retained", f.captures.Load(), f.stores.Load(), f.record.Phase)
	}
}
func TestAPIContextRunnerBlockingOrUncertainBoundaryDoesNotReacquire(t *testing.T) {
	for _, mode := range []string{"legacy-writer-protocol", "replacement-pod", "restarted-process", "lost-preparation-reply", "lost-create-reply", "lost-start-reply", "lost-start-record-reply", "expired-start-record-reply"} {
		t.Run(mode, func(t *testing.T) {
			f, s, current := apiRunner(t)
			f.mode = mode
			_, err := s.Execute(context.Background(), current, f.work.Accepted.CaptureID)
			if err == nil || f.captures.Load() != 0 || f.stores.Load() != 0 || f.prepares.Load() != f.closes.Load() {
				t.Fatal("uncertain/stale authority acquired", err)
			}
		})
	}
}

func TestAPIContextRunnerNextOperationObservesIdentityChange(t *testing.T) {
	for _, mode := range []string{"revoked-after-keys", "expired-after-keys"} {
		t.Run(mode, func(t *testing.T) {
			f, s, current := apiRunner(t)
			f.mode = mode
			out, err := s.Execute(t.Context(), current, f.work.Accepted.CaptureID)
			if err != nil || out.State != "StoredPendingVerification" || f.captures.Load() != 1 || f.stores.Load() != 1 {
				t.Fatal("unobserved external change invalidated a live original observation", out, err)
			}
			// Both a new deny and an unavailable identity source are observed by
			// the next operation. Neither can resurrect an old request or effect.
			_, err = s.Execute(t.Context(), current, f.work.Accepted.CaptureID)
			if !errors.Is(err, value.ErrDenied) || f.prepares.Load() != 1 || f.captures.Load() != 1 || f.stores.Load() != 1 || f.prepares.Load() != f.closes.Load() {
				t.Fatal("next request reused identity or replayed effects", err)
			}
		})
	}
}
func TestAPIContextRunnerFailureIsImmutableSpentOutcome(t *testing.T) {
	for _, mode := range []string{"capture", "oversize", "write"} {
		t.Run(mode, func(t *testing.T) {
			f, s, current := apiRunner(t)
			f.mode = mode
			_, err := s.Execute(context.Background(), current, f.work.Accepted.CaptureID)
			if err == nil || !f.spent.Load() {
				t.Fatal("failure was not spent", err)
			}
			before := f.captures.Load()
			out, err := s.Execute(context.Background(), current, f.work.Accepted.CaptureID)
			if err != nil || out.State != "AlreadyStarted" || f.captures.Load() != before {
				t.Fatal("repeated failed acquisition", err)
			}
		})
	}
}

// acquiringOutput simulates ADR-171's regional output: capture and store in
// one place, returning only the instant and copies to the runner.
type acquiringOutput struct{ f *apiRunnerFixture }

func (o acquiringOutput) PrepareContext(ctx context.Context, e artifact.ContextExpectation) (evidence.PreparedContext, error) {
	p, err := o.f.PrepareContext(ctx, e)
	if err != nil {
		return nil, err
	}
	return &acquiringPrepared{StoredContextCloser: p.(evidence.StoredContextCloser), f: o.f}, nil
}

type acquiringPrepared struct {
	evidence.StoredContextCloser
	f *apiRunnerFixture
}

func (p *acquiringPrepared) AcquireContext(ctx context.Context, pin artifact.PinnedPod, started, until time.Time) (time.Time, artifact.Copies, error) {
	native, err := p.f.Capture(ctx, pin)
	if err != nil {
		return time.Time{}, artifact.Copies{}, value.ErrExpired
	}
	acquired := p.f.now
	copies, err := p.StoreContext(ctx, native, started, acquired)
	if err != nil {
		return acquired, artifact.Copies{}, errors.Join(evidence.ErrContextStoreUnconfirmed, err)
	}
	return acquired, copies, nil
}

type refusingCollector struct{ t *testing.T }

func (c refusingCollector) Capture(context.Context, artifact.PinnedPod) ([]byte, error) {
	c.t.Error("runner captured locally despite an acquiring output")
	return nil, value.ErrUnavailable
}

func TestAPIContextRunnerAcquiringOutputCapturesAtTheOutput(t *testing.T) {
	f, s, current := apiRunner(t)
	s.Output, s.Collector = acquiringOutput{f}, refusingCollector{t}
	out, err := s.Execute(context.Background(), current, f.work.Accepted.CaptureID)
	if err != nil || out.State != "StoredPendingVerification" || f.captures.Load() != 1 || f.stores.Load() != 1 || f.record.Phase != "stored" || f.prepares.Load() != f.closes.Load() {
		t.Fatal("acquiring output", out.State, err, f.record.Phase)
	}
	for mode, phase := range map[string]string{"capture": "captureFailed", "write": "storeUnconfirmed"} {
		f, s, current := apiRunner(t)
		f.mode = mode
		s.Output, s.Collector = acquiringOutput{f}, refusingCollector{t}
		if _, err := s.Execute(context.Background(), current, f.work.Accepted.CaptureID); err == nil || !f.spent.Load() || f.record.Phase != phase {
			t.Fatal("acquisition failure not spent with its phase", mode, err, f.record.Phase)
		}
	}
}

// lostReplyPrepared is a regional output whose region captured and committed
// the copies, but whose reply never reached the hub: either the acquisition
// reply or the later CompleteStored reply is lost on the exchange.
type lostReplyPrepared struct {
	*acquiringPrepared
	mode string
}

func (p lostReplyPrepared) AcquireContext(ctx context.Context, pin artifact.PinnedPod, started, until time.Time) (time.Time, artifact.Copies, error) {
	acquired, copies, err := p.acquiringPrepared.AcquireContext(ctx, pin, started, until)
	if err == nil && p.mode == "lost-acquire-reply" {
		return time.Time{}, artifact.Copies{}, value.ErrUnavailable
	}
	return acquired, copies, err
}
func (p lostReplyPrepared) CompleteStored() (artifact.ContextWriterCompletion, error) {
	if _, err := p.acquiringPrepared.CompleteStored(); err != nil || p.mode == "lost-complete-reply" {
		return artifact.ContextWriterCompletion{}, value.ErrUnavailable
	}
	return p.acquiringPrepared.CompleteStored()
}

type lostReplyOutput struct {
	f    *apiRunnerFixture
	mode string
}

func (o lostReplyOutput) PrepareContext(ctx context.Context, e artifact.ContextExpectation) (evidence.PreparedContext, error) {
	p, err := acquiringOutput{o.f}.PrepareContext(ctx, e)
	if err != nil {
		return nil, err
	}
	return lostReplyPrepared{acquiringPrepared: p.(*acquiringPrepared), mode: o.mode}, nil
}

// ADR-223: a committed regional artifact whose reply is lost is not imported
// and never collected again. SQL keeps the durable "started" phase, which
// progress reports as Running until the deadline observer marks it
// Indeterminate (TestAPIExecutionUnrecordedOutcomeEndsIndeterminateAfterDeadline).
func TestAPIContextRunnerLostRegionalReplyNeverReacquires(t *testing.T) {
	for _, mode := range []string{"lost-complete-reply", "lost-acquire-reply"} {
		t.Run(mode, func(t *testing.T) {
			f, s, current := apiRunner(t)
			s.Output, s.Collector = lostReplyOutput{f, mode}, refusingCollector{t}
			if mode == "lost-acquire-reply" {
				f.mode = mode
			}
			out, err := s.Execute(t.Context(), current, f.work.Accepted.CaptureID)
			if err == nil || out.State != "Indeterminate" || f.captures.Load() != 1 || f.stores.Load() != 1 || f.record.Phase != "started" {
				t.Fatal("lost reply", out.State, err, f.captures.Load(), f.stores.Load(), f.record.Phase)
			}
			for range 3 {
				out, err = s.Execute(t.Context(), current, f.work.Accepted.CaptureID)
				if err != nil || out.State != "AlreadyStarted" || f.captures.Load() != 1 || f.stores.Load() != 1 || f.record.Phase != "started" {
					t.Fatal("retry repeated collection or rewrote the outcome", out.State, err, f.record.Phase)
				}
			}
		})
	}
}

func TestCaptureFailurePhaseRecordsTheCause(t *testing.T) {
	for err, want := range map[error]string{
		fmt.Errorf("pod gone: %w", targets.ErrChanged): "targetGone",
		fmt.Errorf("forbidden: %w", targets.ErrDenied): "denied",
		value.ErrUnavailable:                           "captureFailed",
		nil:                                            "captureFailed",
	} {
		if got := captureFailurePhase(err); got != want {
			t.Fatal(err, got, want)
		}
	}
}

func TestPolicyRawRunnerRequiresSameWorkSourceBeforePreparation(t *testing.T) {
	f, s, current := apiRunner(t)
	f.work.Actor = authorization.PolicyPrincipal("11111111-1111-4111-8111-111111111111", "policy")
	f.work.Accepted.Expectation.Recording = &artifact.Recording{Filter: &artifact.RecordingFilter{Expression: "tcp[13] & 2 != 0"}}
	_, err := s.execute(t.Context(), current, f.work, f.now.Add(5*time.Second), nil, nil)
	var step apiCheckStep
	if err == nil || !errors.As(err, &step) || step.step != "ResolvePacketSource" || f.prepares.Load() != 0 || f.captures.Load() != 0 {
		t.Fatal("unsupported exact source reached preparation/acquisition", err, f.prepares.Load(), f.captures.Load())
	}
}
