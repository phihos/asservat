package execution

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/application/evidence"
	identities "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/execution"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/domain/planning"
	"asservat.local/asservat/internal/domain/privacy"
	"asservat.local/asservat/internal/domain/targets"
)

// These are counts of real runner port calls, not a model of provider latency.
// The actual evaluator still resolves identity and evaluates the permission
// projection. SQL/provider ports are the existing explicitly synthetic fixture.
type apiObservationReads struct {
	*apiRunnerFixture
	eligibility                                                   APIContextEligibility
	targets, eligibilityReads, capabilities, retention, processes int
	processUntil                                                  time.Time
}

func (p *apiObservationReads) ResolvePod(ctx context.Context, r targets.Request) (targets.PodResolution, error) {
	p.targets++
	return p.apiRunnerFixture.ResolvePod(ctx, r)
}
func (p *apiObservationReads) ContextEligibilityCurrent(ctx context.Context, current identities.CurrentIdentity, target authorization.Target) authorization.CaptureEligibility {
	p.eligibilityReads++
	return p.eligibility.ContextEligibilityCurrent(ctx, current, target)
}
func (p *apiObservationReads) ContextCapability(ctx context.Context, target authorization.Target) (planning.ContextCapability, error) {
	p.capabilities++
	return p.apiRunnerFixture.ContextCapability(ctx, target)
}
func (p *apiObservationReads) ReadAPIProcess(ctx context.Context) (value.APIProcessObservation, error) {
	p.processes++
	out, err := p.apiRunnerFixture.ReadAPIProcess(ctx)
	if !p.processUntil.IsZero() {
		out.ValidUntil = p.processUntil
	}
	return out, err
}

type apiObservationBoundary struct {
	*apiRunnerFixture
	wrapped, ready func(context.Context)
	checks         []APIExecutionCheck
	local          int
	bindError      error
	changeProcess  bool
}

func (b *apiObservationBoundary) PrepareContext(ctx context.Context, e artifact.ContextExpectation) (evidence.PreparedContext, error) {
	p, err := b.apiRunnerFixture.PrepareContext(ctx, e)
	if b.wrapped != nil {
		b.wrapped(ctx)
	}
	return p, err
}
func (b *apiObservationBoundary) PrepareStart(ctx context.Context, c value.PreparationCheck) (value.PreparedStart, error) {
	b.local++
	return b.apiRunnerFixture.PrepareStart(ctx, c)
}
func (b *apiObservationBoundary) ReadyStart(ctx context.Context, r value.Request) (value.Disposition, error) {
	d, err := b.apiRunnerFixture.ReadyStart(ctx, r)
	if b.ready != nil {
		b.ready(ctx)
	}
	return d, err
}
func (b *apiObservationBoundary) PrepareAPIExecution(ctx context.Context, c APIExecutionCheck) (value.APIExecution, bool, error) {
	b.checks = append(b.checks, c)
	return b.apiRunnerFixture.PrepareAPIExecution(ctx, c)
}
func (b *apiObservationBoundary) BindAPIStart(ctx context.Context, c APIExecutionCheck, r value.APIExecution, p value.PreparedStart) (value.APIExecution, error) {
	b.checks = append(b.checks, c)
	if b.bindError != nil {
		return value.APIExecution{}, b.bindError
	}
	out, err := b.apiRunnerFixture.BindAPIStart(ctx, c, r, p)
	if b.changeProcess {
		out.Process.ProcessEpoch = contextID(99)
	}
	return out, err
}
func (b *apiObservationBoundary) RecordAPIStart(ctx context.Context, c APIExecutionCheck, r value.APIExecution, d value.Disposition) (value.APIExecution, error) {
	b.checks = append(b.checks, c)
	return b.apiRunnerFixture.RecordAPIStart(ctx, c, r, d)
}

func observedRunner(t *testing.T) (*apiRunnerFixture, APIContextRunner, identities.CurrentIdentity, *apiObservationReads, *apiObservationBoundary) {
	t.Helper()
	f, s, current := apiRunner(t)
	p := &apiObservationReads{apiRunnerFixture: f, eligibility: s.Eligibility}
	b := &apiObservationBoundary{apiRunnerFixture: f}
	s.Targets, s.Eligibility, s.Capabilities, s.Retention, s.Process = p, p, p, apiObservationRetention{p}, p
	s.Prepare, s.Record, s.Local, s.Output = b, b, b, b
	return f, s, current, p, b
}

func TestAPIContextObservationRetainsBoundsAfterBlockingEffects(t *testing.T) {
	for _, boundary := range []string{"wrapping", "readiness"} {
		for _, bound := range []string{"caller", "target", "capability", "retention", "recovery", "process", "parent", "cancellation"} {
			t.Run(boundary+"/"+bound, func(t *testing.T) {
				f, s, current, p, b := observedRunner(t)
				original := f.now
				until := original.Add(time.Second)
				ctx, cancel := context.WithDeadline(t.Context(), original.Add(5*time.Second))
				defer cancel()
				switch bound {
				case "caller":
					f.actor.ValidUntil = until
				case "target":
					f.target.FreshUntil = until
				case "capability":
					f.cap.FreshUntil = until
				case "retention":
					f.retention.ValidUntil = until
					f.retention.Proof.ValidUntil = until
				case "recovery":
					f.recovery.FreshUntil = until
				case "process":
					p.processUntil = until
				case "parent":
					var stop context.CancelFunc
					ctx, stop = context.WithDeadline(ctx, until)
					defer stop()
				}
				wait := func(context.Context) {
					if bound == "cancellation" {
						cancel()
					} else {
						f.now = until
					}
				}
				if boundary == "wrapping" {
					b.wrapped = wait
				} else {
					b.ready = wait
				}
				_, err := s.Execute(ctx, current, f.work.Accepted.CaptureID)
				want := "PrepareContext"
				if boundary == "readiness" {
					want = "ReadyStart"
				}
				var step interface{ FixedStep() string }
				if err == nil || !errors.As(err, &step) || (step.FixedStep() != want+"/Current" && step.FixedStep() != want+"/Context") || f.record.Phase != "prepared" || f.prepares.Load() != 1 || f.closes.Load() != 1 || f.consumes.Load() != 0 || f.captures.Load() != 0 || f.stores.Load() != 0 {
					t.Fatal("blocking effect escaped original bound", err, f.record.Phase, f.prepares.Load(), f.closes.Load())
				}
				if p.targets != 1 || p.eligibilityReads != 1 || p.capabilities != 1 || p.retention != 1 || p.processes != 1 {
					t.Fatal("expiry refreshed an observation", p)
				}
				if boundary == "wrapping" && b.local != 0 {
					t.Fatal("expired wrapping reached local prepare")
				}
			})
		}
	}
}

func TestAPIContextObservationRetainsSQLEffectChecks(t *testing.T) {
	for _, mode := range []string{"same-observation", "fenced-bind", "changed-returned-process"} {
		t.Run(mode, func(t *testing.T) {
			f, s, current, p, b := observedRunner(t)
			if mode == "fenced-bind" {
				b.bindError = value.ErrDenied
			}
			b.changeProcess = mode == "changed-returned-process"
			out, err := s.Execute(t.Context(), current, f.work.Accepted.CaptureID)
			if mode == "same-observation" {
				if err != nil || out.State != "StoredPendingVerification" || len(b.checks) != 3 {
					t.Fatal("effect sequence", out, err, len(b.checks))
				}
				for _, c := range b.checks[1:] {
					if !reflect.DeepEqual(c, b.checks[0]) {
						t.Fatal("effect refreshed or replaced the checked operation")
					}
				}
			} else if err == nil || f.consumes.Load() != 0 || f.captures.Load() != 0 || f.stores.Load() != 0 || f.record.Phase != "prepared" || f.prepares.Load() != f.closes.Load() {
				t.Fatal("failed SQL effect or changed process permitted start", err)
			}
			if p.targets != 1 || p.eligibilityReads != 1 || p.capabilities != 1 || p.retention != 1 {
				t.Fatal("SQL effect forced another provider graph")
			}
		})
	}
}

func TestAPIContextObservedPreludeKeepsExactInputs(t *testing.T) {
	for _, mode := range []string{"valid-short-parent", "valid-short-caller", "actor", "client", "capture", "target", "pin", "capability", "recovery-incarnation", "caller-expired", "capability-expired", "recovery-expired", "scope", "cancelled", "unbounded"} {
		t.Run(mode, func(t *testing.T) {
			f, s, current, p, b := observedRunner(t)
			caller, w, capability, recovery := f.actor, f.work, f.cap, f.recovery
			until := f.now.Add(5 * time.Second)
			if mode == "valid-short-parent" {
				until = f.now.Add(2 * time.Second)
			}
			ctx, cancel := context.WithDeadline(t.Context(), until)
			defer cancel()
			switch mode {
			case "valid-short-caller":
				caller.ValidUntil = f.now.Add(2 * time.Second)
			case "actor":
				caller.Principal.Subject = "other"
			case "client":
				caller.Principal.ClientID = "other"
			case "capture":
				w.Accepted.CaptureID = contextID(99)
			case "target":
				w.Target.PodUID = contextID(99)
			case "pin":
				w.Accepted.Pin.UID = contextID(99)
			case "capability":
				capability.CollectorImageDigest = artifact.Digest{99}
			case "recovery-incarnation":
				recovery.IssuerEpoch = contextID(99)
			case "caller-expired":
				caller.ValidUntil = f.now
			case "capability-expired":
				capability.FreshUntil = f.now
			case "recovery-expired":
				recovery.FreshUntil = f.now
			case "scope":
				f.actor.Scopes = []string{"evidence:read"}
			case "cancelled":
				cancel()
			case "unbounded":
				ctx = t.Context()
			}
			// Stop at the first preparation without granting a synthetic row/effect.
			s.Prepare = observationRefusingPreparation{b}
			_, err := s.ExecuteObserved(ctx, current, caller, w, capability, recovery)
			if strings.HasPrefix(mode, "valid-") {
				if !errors.Is(err, value.ErrUnavailable) || len(b.checks) != 1 || p.capabilities != 0 {
					t.Fatal("observed prelude was reread or refused", err, len(b.checks), p.capabilities)
				}
				want := identity.Earlier(until, caller.ValidUntil)
				if !b.checks[0].ValidUntil.Equal(want) {
					t.Fatal("handoff extended original deadline", b.checks[0].ValidUntil, want)
				}
			} else if err == nil || len(b.checks) != 0 {
				t.Fatal("invalid observed handoff reached SQL preparation", mode, err, len(b.checks))
			}
			if f.prepares.Load() != 0 || f.consumes.Load() != 0 || f.captures.Load() != 0 {
				t.Fatal("prelude test reached an effect")
			}
		})
	}
}

type observationRefusingPreparation struct{ *apiObservationBoundary }

func (p observationRefusingPreparation) PrepareAPIExecution(_ context.Context, c APIExecutionCheck) (value.APIExecution, bool, error) {
	p.checks = append(p.checks, c)
	return value.APIExecution{}, false, value.ErrUnavailable
}

type apiObservationRetention struct{ p *apiObservationReads }

func (r apiObservationRetention) Resolve(ctx context.Context, in privacy.Input) (privacy.Resolution, error) {
	r.p.retention++
	return r.p.ResolveRetention(ctx, in)
}

// The entire successful runner, including the post-acquisition process read,
// owns one start observation. Later effects keep the original SQL guards;
// an extra target/eligibility/capability/retention observation is not required.
func TestAPIContextRunnerOneRequestObservation(t *testing.T) {
	f, runner, current := apiRunner(t)
	p := &apiObservationReads{apiRunnerFixture: f, eligibility: runner.Eligibility}
	runner.Targets, runner.Eligibility, runner.Capabilities, runner.Retention, runner.Process = p, p, p, apiObservationRetention{p}, p
	ctx, cancel := context.WithDeadline(t.Context(), f.now.Add(5*time.Second))
	defer cancel()
	out, err := runner.Execute(ctx, current, f.work.Accepted.CaptureID)
	if err != nil || out.State != "StoredPendingVerification" || f.captures.Load() != 1 || f.stores.Load() != 1 || f.prepares.Load() != f.closes.Load() {
		t.Fatal("fixture did not complete the real runner", out.State, err)
	}
	if p.targets != 1 || p.eligibilityReads != 1 || p.capabilities != 1 || p.retention != 1 || p.processes != 2 {
		t.Fatalf("one request repeated authority observations: target=%d eligibility=%d capability=%d retention=%d process=%d (includes final completion proof)", p.targets, p.eligibilityReads, p.capabilities, p.retention, p.processes)
	}
	if !f.record.Binding.NotAfter.Equal(f.now.Add(5*time.Second)) || f.record.Phase != "stored" || f.record.Copies == (artifact.Copies{}) {
		t.Fatal("request observation changed its original interval or completion", f.record.Binding.NotAfter, f.record.Phase)
	}
}
