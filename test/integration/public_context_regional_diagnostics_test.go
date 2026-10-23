package integration

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	authapp "asservat.local/asservat/internal/application/authorization"
	"asservat.local/asservat/internal/application/evidence"
	executionapp "asservat.local/asservat/internal/application/execution"
	fleetapp "asservat.local/asservat/internal/application/fleet"
	identities "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	executionvalue "asservat.local/asservat/internal/domain/execution"
	fleetvalue "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/domain/planning"
	"asservat.local/asservat/internal/domain/privacy"
	"asservat.local/asservat/internal/domain/targets"
)

// This extension observes only the original regional verifier/runner calls.
// It stores closed codes, never errors or work/identity values. No clocks,
// extra reads, retry, deadline change or replacement prepared handle is added.
func journeyRegionalCode(err error) uint8 {
	switch err {
	case executionvalue.ErrInvalid, fleetvalue.ErrInvalid:
		return 10
	case executionvalue.ErrDenied, fleetvalue.ErrDenied, targets.ErrDenied:
		return 3
	case executionvalue.ErrUnavailable, fleetvalue.ErrUnavailable:
		return 11
	case executionvalue.ErrConflict:
		return 12
	case executionvalue.ErrPreparationUncertain:
		return 13
	case contracts.ErrAPIContextProtocol:
		return 14
	case targets.ErrChanged:
		return 4
	}
	return journeyDiagnosticError(err)
}
func journeyRegionalReason(err error) string {
	return journeyDiagnosticReason(journeyRegionalCode(err))
}

type publicJourneyVerifierDiagnostics struct {
	source fleetapp.APIContextWorkVerifier
	trace  *publicJourneyDiagnostics
}

func (s *publicJourneyDiagnostics) RegionalVerifier(in fleetapp.APIContextWorkVerifier) fleetapp.APIContextWorkVerifier {
	if in == nil {
		return nil
	}
	return publicJourneyVerifierDiagnostics{in, s}
}
func (s publicJourneyVerifierDiagnostics) VerifyAPIContextWork(c context.Context, body []byte, receiver fleetvalue.APIContextReceiver) (fleetvalue.AuthenticatedAPIContextWork, error) {
	v, e := s.source.VerifyAPIContextWork(c, body, receiver)
	s.trace.record(journeyRegionalVerify, journeyRegionalCode(e))
	return v, e
}

type publicJourneyRunnerDiagnostics struct {
	in    executionapp.APIContextRunner
	trace *publicJourneyDiagnostics
}

// The optional completion facet remains optional. Embedding it delegates the
// untouched post-collection call; absence still fails the original type check.
type publicJourneyRunnerStoredDiagnostics struct {
	*publicJourneyRunnerDiagnostics
	executionapp.APIStoredCompletionRecorder
}

func (s *publicJourneyDiagnostics) Runner(in executionapp.APIContextRunner) executionapp.APIContextRunner {
	p := &publicJourneyRunnerDiagnostics{in, s}
	if in.Read != nil {
		in.Read = p
	}
	if in.Recovery != nil {
		in.Recovery = p
	}
	if in.Targets != nil {
		in.Targets = p
	}
	if in.Eligibility != nil {
		in.Eligibility = p
	}
	if in.Capabilities != nil {
		in.Capabilities = p
	}
	if in.Retention != nil {
		in.Retention = p
	}
	if in.Process != nil {
		in.Process = p
	}
	if in.Prepare != nil {
		in.Prepare = p
	}
	if in.Output != nil {
		in.Output = p
	}
	if in.Local != nil {
		in.Local = p
	}
	if in.Starts != nil {
		in.Starts = p
	}
	if in.Record != nil {
		in.Record = p
		if stored, ok := p.in.Record.(executionapp.APIStoredCompletionRecorder); ok {
			in.Record = publicJourneyRunnerStoredDiagnostics{p, stored}
		}
	}
	return in
}
func (s *publicJourneyRunnerDiagnostics) RecoveryState(c context.Context) (artifact.RecoveryProof, error) {
	v, e := s.in.Recovery.RecoveryState(c)
	s.trace.record(journeyRunnerRecovery, journeyRegionalCode(e))
	return v, e
}
func (s *publicJourneyRunnerDiagnostics) ReadAPIContextWork(c context.Context, id string, i identity.Identity, r artifact.RecoveryProof) (executionapp.APIContextWork, error) {
	v, e := s.in.Read.ReadAPIContextWork(c, id, i, r)
	s.trace.record(journeyRunnerRead, journeyRegionalCode(e))
	return v, e
}
func (s *publicJourneyRunnerDiagnostics) ResolvePod(c context.Context, r targets.Request) (targets.PodResolution, error) {
	v, e := s.in.Targets.ResolvePod(c, r)
	s.trace.record(journeyRunnerTarget, journeyRegionalCode(e))
	return v, e
}
func (s *publicJourneyRunnerDiagnostics) ContextEligibilityCurrent(c context.Context, i identities.CurrentIdentity, t authorization.Target) authorization.CaptureEligibility {
	if i != nil {
		i = journeyEligibilityCurrentDiagnostics{i, s.trace}
	}
	v := s.in.Eligibility.ContextEligibilityCurrent(c, i, t)
	s.trace.record(journeyRunnerEligibility, journeyEligibilityCode(v))
	return v
}
func (s *publicJourneyRunnerDiagnostics) ContextCapability(c context.Context, t authorization.Target) (planning.ContextCapability, error) {
	v, e := s.in.Capabilities.ContextCapability(c, t)
	s.trace.record(journeyRunnerCapability, journeyRegionalCode(e))
	return v, e
}
func (s *publicJourneyRunnerDiagnostics) Resolve(c context.Context, in privacy.Input) (privacy.Resolution, error) {
	v, e := s.in.Retention.Resolve(c, in)
	s.trace.record(journeyRunnerRetention, journeyRegionalCode(e))
	return v, e
}
func (s *publicJourneyRunnerDiagnostics) ReadAPIProcess(c context.Context) (executionvalue.APIProcessObservation, error) {
	v, e := s.in.Process.ReadAPIProcess(c)
	s.trace.record(journeyRunnerProcess, journeyRegionalCode(e))
	return v, e
}
func (s *publicJourneyRunnerDiagnostics) PrepareAPIExecution(c context.Context, in executionapp.APIExecutionCheck) (executionvalue.APIExecution, bool, error) {
	v, may, e := s.in.Prepare.PrepareAPIExecution(c, in)
	s.trace.record(journeyRunnerPrepare, journeyRegionalCode(e))
	return v, may, e
}
func (s *publicJourneyRunnerDiagnostics) PrepareContext(c context.Context, in artifact.ContextExpectation) (evidence.PreparedContext, error) {
	v, e := s.in.Output.PrepareContext(c, in)
	s.trace.record(journeyRunnerKeys, journeyRegionalCode(e))
	return v, e
}
func (s *publicJourneyRunnerDiagnostics) PrepareStart(c context.Context, in executionvalue.PreparationCheck) (executionvalue.PreparedStart, error) {
	v, e := s.in.Local.PrepareStart(c, in)
	s.trace.record(journeyRunnerLocalPrepare, journeyRegionalCode(e))
	return v, e
}
func (s *publicJourneyRunnerDiagnostics) BindAPIStart(c context.Context, in executionapp.APIExecutionCheck, r executionvalue.APIExecution, start executionvalue.PreparedStart) (executionvalue.APIExecution, error) {
	v, e := s.in.Prepare.BindAPIStart(c, in, r, start)
	s.trace.record(journeyRunnerBind, journeyRegionalCode(e))
	return v, e
}
func (s *publicJourneyRunnerDiagnostics) ReadyStart(c context.Context, in executionvalue.Request) (executionvalue.Disposition, error) {
	v, e := s.in.Local.ReadyStart(c, in)
	s.trace.record(journeyRunnerReady, journeyRegionalCode(e))
	return v, e
}
func (s *publicJourneyRunnerDiagnostics) ConsumeStart(c context.Context, in executionvalue.Request) (executionvalue.Disposition, error) {
	v, e := s.in.Starts.ConsumeStart(c, in)
	s.trace.record(journeyRunnerConsume, journeyRegionalCode(e))
	return v, e
}
func (s *publicJourneyRunnerDiagnostics) LookupStart(c context.Context, in executionvalue.Request) (executionvalue.Disposition, error) {
	return s.in.Starts.LookupStart(c, in)
}
func (s *publicJourneyRunnerDiagnostics) RecordAPIStart(c context.Context, in executionapp.APIExecutionCheck, r executionvalue.APIExecution, d executionvalue.Disposition) (executionvalue.APIExecution, error) {
	v, e := s.in.Record.RecordAPIStart(c, in, r, d)
	s.trace.record(journeyRunnerRecord, journeyRegionalCode(e))
	return v, e
}
func (s *publicJourneyRunnerDiagnostics) RecordAPIOutcome(c context.Context, r executionvalue.APIExecution, p executionvalue.APIProcessObservation) (executionvalue.APIExecution, error) {
	return s.in.Record.RecordAPIOutcome(c, r, p)
}

type journeyDiagnosticVerifier func(context.Context, []byte, fleetvalue.APIContextReceiver) (fleetvalue.AuthenticatedAPIContextWork, error)

func (f journeyDiagnosticVerifier) VerifyAPIContextWork(c context.Context, b []byte, r fleetvalue.APIContextReceiver) (fleetvalue.AuthenticatedAPIContextWork, error) {
	return f(c, b, r)
}

type journeyDiagnosticRunnerIdentity func(context.Context) (identity.Identity, error)

func (f journeyDiagnosticRunnerIdentity) ResolveIdentity(c context.Context) (identity.Identity, error) {
	return f(c)
}

// Every unused port embeds a nil interface and will panic if the actual runner
// improperly advances after the first refusing read. No fake success pipeline.
type journeyDiagnosticRunnerSources struct {
	executionapp.APIExecutionPreparer
	executionapp.APIExecutionRecorder
	executionapp.APIProcessReader
	executionapp.APIStartPreparation
	executionapp.StartJournal
	executionapp.APIContextEligibility
	executionapp.APIContextCapability
	executionapp.APIContextRetention
	evidence.ContextProducer
	executionapp.ContextCollector
	read     func(context.Context, string, identity.Identity, artifact.RecoveryProof) (executionapp.APIContextWork, error)
	recovery func(context.Context) (artifact.RecoveryProof, error)
	target   func(context.Context, targets.Request) (targets.PodResolution, error)
}

func (s *journeyDiagnosticRunnerSources) ReadAPIContextWork(c context.Context, id string, i identity.Identity, r artifact.RecoveryProof) (executionapp.APIContextWork, error) {
	return s.read(c, id, i, r)
}
func (s *journeyDiagnosticRunnerSources) RecoveryState(c context.Context) (artifact.RecoveryProof, error) {
	return s.recovery(c)
}
func (s *journeyDiagnosticRunnerSources) ResolvePod(c context.Context, r targets.Request) (targets.PodResolution, error) {
	return s.target(c, r)
}

type journeyDiagnosticOptionalRecord struct {
	executionapp.APIExecutionRecorder
	executionapp.APIStoredCompletionRecorder
}
type journeyDiagnosticPrepared struct{ evidence.StoredContextCloser }
type journeyDiagnosticProducer func(context.Context, artifact.ContextExpectation) (evidence.PreparedContext, error)

func (f journeyDiagnosticProducer) PrepareContext(c context.Context, e artifact.ContextExpectation) (evidence.PreparedContext, error) {
	return f(c, e)
}

func TestPublicJourneyDiagnosticsOriginalRegionalVerifier(t *testing.T) {
	for _, failure := range []bool{false, true} {
		t.Run(map[bool]string{false: "success", true: "private-refusal"}[failure], func(t *testing.T) {
			trace := &publicJourneyDiagnostics{}
			body := []byte("original-private-payload")
			receiver := fleetvalue.APIContextReceiver{}
			expected := fleetvalue.AuthenticatedAPIContextWork{ValidUntil: time.Unix(123, 0)}
			private := &journeyDiagnosticPrivateError{}
			var original error
			if failure {
				original = private
			}
			calls := 0
			source := journeyDiagnosticVerifier(func(c context.Context, b []byte, r fleetvalue.APIContextReceiver) (fleetvalue.AuthenticatedAPIContextWork, error) {
				calls++
				if c != t.Context() || &b[0] != &body[0] || r != receiver {
					t.Fatal("changed original verifier input")
				}
				return expected, original
			})
			v, e := trace.RegionalVerifier(source).VerifyAPIContextWork(t.Context(), body, receiver)
			if !reflect.DeepEqual(v, expected) || e != original || calls != 1 || trace.calls[journeyRegionalVerify] != 1 {
				t.Fatal("verifier delegation changed")
			}
			if failure && (trace.first != journeyRegionalVerify+1 || trace.reasons[journeyRegionalVerify] != 9) {
				t.Fatal("private failure not retained as closed code")
			}
			if journeyRegionalReason(original) != map[bool]string{false: "none", true: "unknown-refusal"}[failure] {
				t.Fatal("exchange error not safely classified")
			}
		})
	}
}
func TestPublicJourneyDiagnosticsOriginalRegionalRunner(t *testing.T) {
	for _, stopAt := range []string{"read", "target"} {
		t.Run(stopAt, func(t *testing.T) {
			now := time.Now().UTC()
			actor := identity.Identity{Principal: identity.Principal{Issuer: "https://fixture.invalid", Subject: "developer", ClientID: "console", Kind: identity.Human}, Policy: identity.Revision{UID: "policy", Generation: 1, Digest: [32]byte{1}}, VerifiedAt: now, ValidUntil: now.Add(5 * time.Second)}
			if !actor.Valid(now) {
				t.Fatal("invalid identity fixture")
			}
			trace := &publicJourneyDiagnostics{}
			private := &journeyDiagnosticPrivateError{}
			type key struct{}
			ctx, cancel := context.WithDeadline(context.WithValue(t.Context(), key{}, "original"), actor.ValidUntil)
			defer cancel()
			check := func(c context.Context) {
				t.Helper()
				d, ok := c.Deadline()
				if c.Value(key{}) != "original" || !ok || !d.Equal(actor.ValidUntil) {
					t.Fatal("runner context/interval changed")
				}
			}
			id := "00000000-0000-4000-8000-000000000001"
			target := targets.Request{ClusterID: "original-cluster"}
			var readContext context.Context
			f := &journeyDiagnosticRunnerSources{}
			f.recovery = func(c context.Context) (artifact.RecoveryProof, error) {
				check(c)
				readContext = c
				return artifact.RecoveryProof{}, nil
			}
			f.read = func(c context.Context, got string, i identity.Identity, r artifact.RecoveryProof) (executionapp.APIContextWork, error) {
				check(c)
				if c != readContext || got != id || !reflect.DeepEqual(i, actor) || r != (artifact.RecoveryProof{}) {
					t.Fatal("original read input changed")
				}
				if stopAt == "read" {
					return executionapp.APIContextWork{}, private
				}
				return executionapp.APIContextWork{Target: target}, nil
			}
			f.target = func(c context.Context, r targets.Request) (targets.PodResolution, error) {
				check(c)
				if r != target {
					t.Fatal("original target input changed")
				}
				// The runner derives a context for each phase; the original
				// deadline, values and caller cancellation must reach both.
				cancel()
				if c.Err() != context.Canceled || readContext.Err() != context.Canceled {
					t.Fatal("original caller cancellation lost")
				}
				return targets.PodResolution{}, private
			}
			runner := executionapp.APIContextRunner{Read: f, Prepare: f, Record: f, Process: f, Local: f, Starts: f, Targets: f, Eligibility: f, Capabilities: f, Retention: f, Recovery: f, Output: f, Collector: f, Now: func() time.Time { return now }}
			identityCalls := 0
			result, e := trace.Runner(runner).Execute(ctx, journeyDiagnosticRunnerIdentity(func(c context.Context) (identity.Identity, error) { check(c); identityCalls++; return actor, nil }), id)
			expectedStage := journeyRunnerRead
			if stopAt == "target" {
				expectedStage = journeyRunnerTarget
			}
			// The runner's fixed-step wrapper must retain this exact private
			// cause, not erase it or require an unwrapped top-level error.
			if !errors.Is(e, private) || !reflect.DeepEqual(result, executionapp.ContextResult{}) || identityCalls != 1 || trace.first != expectedStage+1 || trace.reasons[expectedStage] != 9 || trace.calls[journeyRunnerRecovery] != 1 || trace.calls[journeyRunnerRead] != 1 || trace.calls[journeyRunnerPrepare] != 0 || trace.calls[journeyRunnerKeys] != 0 {
				t.Fatal("actual runner changed original stopping behavior")
			}
			if (trace.calls[journeyRunnerTarget] == 1) != (stopAt == "target") {
				t.Fatal("target invoked after read refusal")
			}
			trace.Report(t)
		})
	}
}
func TestPublicJourneyDiagnosticsRegionalFacetPreservation(t *testing.T) {
	trace := &publicJourneyDiagnostics{}
	if !reflect.DeepEqual(trace.Runner(executionapp.APIContextRunner{}), executionapp.APIContextRunner{}) || trace.RegionalVerifier(nil) != nil {
		t.Fatal("nil port became available")
	}
	plain := &journeyDiagnosticRunnerSources{}
	if _, ok := trace.Runner(executionapp.APIContextRunner{Record: plain}).Record.(executionapp.APIStoredCompletionRecorder); ok {
		t.Fatal("invented optional completion facet")
	}
	optional := journeyDiagnosticOptionalRecord{}
	if _, ok := trace.Runner(executionapp.APIContextRunner{Record: optional}).Record.(executionapp.APIStoredCompletionRecorder); !ok {
		t.Fatal("lost optional completion facet")
	}
	prepared := &journeyDiagnosticPrepared{}
	calls := 0
	producer := journeyDiagnosticProducer(func(c context.Context, e artifact.ContextExpectation) (evidence.PreparedContext, error) {
		calls++
		if c != t.Context() {
			t.Fatal("key preparation context replaced")
		}
		return prepared, nil
	})
	got, e := trace.Runner(executionapp.APIContextRunner{Output: producer}).Output.PrepareContext(t.Context(), artifact.ContextExpectation{})
	if e != nil || got != prepared || calls != 1 {
		t.Fatal("prepared one-use handle was replaced")
	}
	if _, ok := got.(evidence.StoredContextCloser); !ok {
		t.Fatal("lost prepared completion facet")
	}
}

// Whitelist the actual evaluator's deciding reason. Unknown strings never enter
// the recorder or logs; the returned eligibility remains exactly unchanged.
func journeyEligibilityCode(v authorization.CaptureEligibility) uint8 {
	if v.Eligible {
		return 0
	}
	switch v.Reason {
	case "AuthorityUnavailable":
		return 20
	case "IdentityUnavailable":
		return 21
	case "PermissionUnavailable":
		return 22
	case "InvalidRequest":
		return 23
	case "ExplicitDeny":
		return 24
	case "InsufficientScope":
		return 25
	case "NoEntitlement":
		return 26
	case "NoEvidenceAudience":
		return 27
	case "AudienceOverflow":
		return 28
	default:
		return 3
	}
}

type journeyEligibilityCurrentDiagnostics struct {
	source identities.CurrentIdentity
	trace  *publicJourneyDiagnostics
}

func (s journeyEligibilityCurrentDiagnostics) ResolveIdentity(c context.Context) (identity.Identity, error) {
	v, e := s.source.ResolveIdentity(c)
	s.trace.record(journeyRunnerEligibilityIdentity, journeyRegionalCode(e))
	// These are the original completed delegate's context flags, never a later
	// wall-clock inference or an extra identity/permission read.
	state := c.Err()
	s.trace.mu.Lock()
	if !s.trace.stopped {
		if state == context.Canceled {
			s.trace.identityCanceled++
		}
		if state == context.DeadlineExceeded {
			s.trace.identityDeadline++
		}
	}
	s.trace.mu.Unlock()
	return v, e
}

type journeyDiagnosticPermissions func(context.Context, authorization.Target) (authorization.Projection, error)

func (f journeyDiagnosticPermissions) Permissions(c context.Context, t authorization.Target) (authorization.Projection, error) {
	return f(c, t)
}

func TestPublicJourneyDiagnosticsOriginalEligibility(t *testing.T) {
	for _, mode := range []string{"success", "first-identity", "permission", "final-identity", "canceled-identity", "nil-identity"} {
		t.Run(mode, func(t *testing.T) {
			now := time.Now().UTC()
			actor := identity.Identity{Principal: identity.Principal{Issuer: "https://fixture.invalid", Subject: "developer", ClientID: "console", Kind: identity.Human}, Policy: identity.Revision{UID: "policy", Generation: 1, Digest: [32]byte{1}}, Scopes: []string{"evidence:capture"}, VerifiedAt: now, ValidUntil: now.Add(5 * time.Second)}
			target := authorization.Target{ClusterID: "00000000-0000-4000-8000-000000000001", NamespaceUID: "namespace", WorkloadUID: "workload", PodUID: "pod"}
			projection := authorization.Projection{Target: target, Revision: identity.Revision{UID: "permissions", Generation: 1, Digest: [32]byte{2}}, ObservedAt: now, FreshUntil: actor.ValidUntil, DeniesComplete: true, DeniesObservedAt: now, DeniesFreshUntil: actor.ValidUntil, Allows: []authorization.CurrentAssignment{{Audience: artifact.AudienceAssignment{Kind: "User", Issuer: actor.Principal.Issuer, SubjectID: actor.Principal.Subject, Role: "workload-maintainer", BasisKind: "AccessBinding", BasisUID: "binding", AssignmentID: "00000000-0000-4000-8000-000000000002", BasisDigest: artifact.Digest{3}}, ObservedAt: now, FreshUntil: actor.ValidUntil}}}
			trace := &publicJourneyDiagnostics{}
			private := &journeyDiagnosticPrivateError{}
			type marker struct{}
			ctx, cancel := context.WithDeadline(context.WithValue(t.Context(), marker{}, "original"), actor.ValidUntil)
			defer cancel()
			identityCalls, permissionCalls := 0, 0
			var originalContext context.Context
			check := func(c context.Context) {
				t.Helper()
				d, ok := c.Deadline()
				if c.Value(marker{}) != "original" || !ok || !d.Equal(actor.ValidUntil) {
					t.Fatal("original evaluator context changed")
				}
				if originalContext == nil {
					originalContext = c
				} else if c != originalContext {
					t.Fatal("original evaluator delegate context replaced")
				}
			}
			var current identities.CurrentIdentity = journeyDiagnosticRunnerIdentity(func(c context.Context) (identity.Identity, error) {
				check(c)
				identityCalls++
				if mode == "first-identity" || mode == "final-identity" && identityCalls == 2 {
					return actor, private
				}
				if mode == "canceled-identity" {
					cancel()
					return actor, context.Canceled
				}
				return actor, nil
			})
			if mode == "nil-identity" {
				current = nil
			}
			evaluator := authapp.Evaluator{Permissions: journeyDiagnosticPermissions(func(c context.Context, tgt authorization.Target) (authorization.Projection, error) {
				check(c)
				permissionCalls++
				if tgt != target {
					t.Fatal("target replaced")
				}
				if mode == "permission" {
					return projection, private
				}
				return projection, nil
			}), Now: func() time.Time { return now }}
			decorated := trace.Runner(executionapp.APIContextRunner{Eligibility: evaluator}).Eligibility
			got := decorated.ContextEligibilityCurrent(ctx, current, target)
			reason, wantCode, wantIdentity, wantPermission := "Eligible", uint8(0), 2, 1
			switch mode {
			case "first-identity":
				reason, wantCode, wantIdentity, wantPermission = "IdentityUnavailable", 21, 1, 0
			case "permission":
				reason, wantCode, wantIdentity, wantPermission = "PermissionUnavailable", 22, 1, 1
			case "final-identity":
				reason, wantCode = "AuthorityUnavailable", 20
			case "canceled-identity":
				reason, wantCode, wantIdentity, wantPermission = "IdentityUnavailable", 21, 1, 0
			case "nil-identity":
				reason, wantCode, wantIdentity, wantPermission = "AuthorityUnavailable", 20, 0, 0
			}
			if got.Reason != reason || got.Eligible != (mode == "success") || identityCalls != wantIdentity || permissionCalls != wantPermission || trace.calls[journeyRunnerEligibilityIdentity] != uint32(wantIdentity) || trace.calls[journeyRunnerEligibility] != 1 || trace.reasons[journeyRunnerEligibility] != wantCode {
				t.Fatal("actual evaluator decision or original dispatch changed")
			}
			if mode == "success" && !reflect.DeepEqual(got, authorization.ContextEligibility(actor, projection, target, now)) {
				t.Fatal("successful evaluator result changed")
			}
			if mode == "first-identity" || mode == "final-identity" {
				if trace.reasons[journeyRunnerEligibilityIdentity] != 9 {
					t.Fatal("private identity error escaped closed code")
				}
			}
			if (trace.identityCanceled == 1) != (mode == "canceled-identity") || trace.identityDeadline != 0 {
				t.Fatal("original context cancellation flags changed")
			}
			trace.Report(t)
		})
	}
	if code := journeyEligibilityCode(authorization.CaptureEligibility{Result: authorization.Result{Reason: "private arbitrary reason"}}); code != 3 || journeyDiagnosticReason(code) != "denied" {
		t.Fatal("unrecognized reason retained")
	}
}
