package execution

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	identities "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/execution"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/domain/planning"
	"asservat.local/asservat/internal/domain/privacy"
	"asservat.local/asservat/internal/domain/targets"
)

type apiCheckPrivateError struct{}

func (apiCheckPrivateError) Error() string     { return "private-provider-host-token" }
func (apiCheckPrivateError) FixedStep() string { return "private-provider-host-token" }
func (apiCheckPrivateError) Unwrap() error     { return value.ErrUnavailable }

type apiCheckProbe struct {
	*apiRunnerFixture
	t           *testing.T
	eligibility APIContextEligibility
	until       time.Time
	cancel      context.CancelFunc
	fail        string
	failure     error
	check       int
	failCheck   int
	calls       []string
}

func (p *apiCheckProbe) visit(ctx context.Context, stage string) error {
	p.t.Helper()
	p.calls = append(p.calls, stage)
	if until, ok := ctx.Deadline(); !ok || !until.Equal(p.until) {
		p.t.Fatal("check changed the original caller deadline", stage)
	}
	if p.fail == stage && (p.check == p.failCheck || stage == "ReadAPIContextWork") {
		return p.failure
	}
	return nil
}
func (p *apiCheckProbe) ReadAPIContextWork(ctx context.Context, id string, i identity.Identity, r artifact.RecoveryProof) (APIContextWork, error) {
	if err := p.visit(ctx, "ReadAPIContextWork"); err != nil {
		return APIContextWork{}, err
	}
	return p.apiRunnerFixture.ReadAPIContextWork(ctx, id, i, r)
}
func (p *apiCheckProbe) ResolvePod(ctx context.Context, r targets.Request) (targets.PodResolution, error) {
	p.check++
	if err := p.visit(ctx, "ResolvePod"); err != nil {
		return targets.PodResolution{}, err
	}
	return p.apiRunnerFixture.ResolvePod(ctx, r)
}
func (p *apiCheckProbe) ContextEligibilityCurrent(ctx context.Context, current identities.CurrentIdentity, t authorization.Target) authorization.CaptureEligibility {
	if p.visit(ctx, "Eligibility") != nil {
		return authorization.CaptureEligibility{}
	}
	return p.eligibility.ContextEligibilityCurrent(ctx, current, t)
}
func (p *apiCheckProbe) ContextCapability(ctx context.Context, target authorization.Target) (planning.ContextCapability, error) {
	if err := p.visit(ctx, "Capability"); err != nil {
		return planning.ContextCapability{}, err
	}
	out, err := p.apiRunnerFixture.ContextCapability(ctx, target)
	if p.fail == "Compile" && p.check == p.failCheck {
		out.Enabled = false
	}
	return out, err
}
func (p *apiCheckProbe) RecoveryState(ctx context.Context) (artifact.RecoveryProof, error) {
	stage := "Recovery"
	if p.check == 0 {
		stage = "InitialRecovery"
	}
	if err := p.visit(ctx, stage); err != nil {
		return artifact.RecoveryProof{}, err
	}
	return p.apiRunnerFixture.RecoveryState(ctx)
}
func (p *apiCheckProbe) ReadAPIProcess(ctx context.Context) (value.APIProcessObservation, error) {
	if err := p.visit(ctx, "Process"); err != nil {
		return value.APIProcessObservation{}, err
	}
	out, err := p.apiRunnerFixture.ReadAPIProcess(ctx)
	if p.check == p.failCheck {
		switch p.fail {
		case "Current":
			out.Binding.PodUID = ""
		case "Context":
			p.cancel()
		}
	}
	return out, err
}

type apiCheckRetention struct{ p *apiCheckProbe }

func (r apiCheckRetention) Resolve(ctx context.Context, in privacy.Input) (privacy.Resolution, error) {
	if err := r.p.visit(ctx, "Retention"); err != nil {
		return privacy.Resolution{}, err
	}
	return r.p.apiRunnerFixture.ResolveRetention(ctx, in)
}

func apiCheckDiagnosticRunner(t *testing.T, fail string, failure error, check int) (*apiCheckProbe, APIContextRunner, identities.CurrentIdentity, context.Context) {
	t.Helper()
	f, runner, current := apiRunner(t)
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	t.Cleanup(cancel)
	until, _ := ctx.Deadline()
	p := &apiCheckProbe{apiRunnerFixture: f, t: t, eligibility: runner.Eligibility, until: until, cancel: cancel, fail: fail, failure: failure, failCheck: check}
	runner.Read, runner.Targets, runner.Eligibility, runner.Capabilities, runner.Retention, runner.Recovery, runner.Process = p, p, p, p, apiCheckRetention{p}, p, p
	return p, runner, current, ctx
}

func TestAPIContextCheckDiagnosticsSeparateReadsWithoutEffects(t *testing.T) {
	order := []string{"InitialRecovery", "ReadAPIContextWork", "ResolvePod", "Eligibility", "Capability", "Retention", "Recovery", "Process"}
	for _, tc := range []struct {
		stage, want string
		reads       int
		failure     error
		class       error
	}{
		{"ReadAPIContextWork", "ReadAPIContextWork", 2, value.ErrUnavailable, value.ErrUnavailable},
		{"ResolvePod", "Check/ResolvePod", 3, apiCheckPrivateError{}, value.ErrUnavailable},
		{"ResolvePod", "Check/ResolvePod", 3, context.DeadlineExceeded, context.DeadlineExceeded},
		{"ResolvePod", "Check/ResolvePod", 3, context.Canceled, context.Canceled},
		{"Eligibility", "Check/Eligibility", 4, value.ErrDenied, value.ErrDenied},
		{"Capability", "Check/Capability", 5, apiCheckPrivateError{}, value.ErrUnavailable},
		{"Retention", "Check/Retention", 6, apiCheckPrivateError{}, value.ErrUnavailable},
		{"Compile", "Check/Compile", 6, nil, planning.ErrInvalid},
		{"Recovery", "Check/Recovery", 7, apiCheckPrivateError{}, value.ErrUnavailable},
		{"Process", "Check/Process", 8, apiCheckPrivateError{}, value.ErrUnavailable},
		{"Current", "Check/Current", 8, nil, value.ErrDenied},
		{"Context", "Check/Context", 8, nil, value.ErrDenied},
	} {
		t.Run(tc.stage, func(t *testing.T) {
			p, runner, current, ctx := apiCheckDiagnosticRunner(t, tc.stage, tc.failure, 1)
			_, err := runner.Execute(ctx, current, p.work.Accepted.CaptureID)
			if !errors.Is(err, tc.class) || tc.failure != nil && tc.stage != "Eligibility" && !errors.Is(err, tc.failure) {
				t.Fatal("diagnostic changed the failure chain")
			}
			if !slices.Equal(p.calls, order[:tc.reads]) {
				t.Fatal("diagnostic changed read order or short circuit", p.calls)
			}
			if p.record.Phase != "" || p.prepares.Load() != 0 || p.consumes.Load() != 0 || p.captures.Load() != 0 || p.stores.Load() != 0 {
				t.Fatal("failed current check reached a preparation or acquisition effect")
			}
			var step interface{ FixedStep() string }
			if !errors.As(err, &step) || step.FixedStep() != tc.want || strings.Contains(err.Error(), "private-") {
				t.Fatalf("failure not localized to its closed check stage: got %v, want %s", err, tc.want)
			}
		})
	}
}

func TestAPIContextCheckDiagnosticsRetainLaterEffectBoundary(t *testing.T) {
	for _, tc := range []struct {
		check int
		want  string
	}{
		{2, "PrepareContext/Context"},
		{3, "ReadyStart/Context"},
	} {
		t.Run(tc.want, func(t *testing.T) {
			p, runner, current, ctx := apiCheckDiagnosticRunner(t, "", nil, 0)
			boundary := &apiObservationBoundary{apiRunnerFixture: p.apiRunnerFixture}
			if tc.check == 2 {
				boundary.wrapped = func(context.Context) { p.cancel() }
			} else {
				boundary.ready = func(context.Context) { p.cancel() }
			}
			runner.Output, runner.Local = boundary, boundary
			_, err := runner.Execute(ctx, current, p.work.Accepted.CaptureID)
			if !errors.Is(err, value.ErrDenied) || p.check != 1 || p.record.Phase != "prepared" || p.prepares.Load() != 1 || p.closes.Load() != 1 || p.consumes.Load() != 0 || p.captures.Load() != 0 || p.stores.Load() != 0 {
				t.Fatal("later check changed preparation ownership or allowed acquisition")
			}
			var step interface{ FixedStep() string }
			if !errors.As(err, &step) || step.FixedStep() != tc.want {
				t.Fatal("later check lost its original effect boundary", err)
			}
		})
	}
}
