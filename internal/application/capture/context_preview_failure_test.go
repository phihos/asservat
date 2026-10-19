package capture

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	identities "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/planning"
	"asservat.local/asservat/internal/domain/privacy"
	"asservat.local/asservat/internal/domain/targets"
)

type failedPreviewPort struct {
	*investigationFixture
	err error
}

func (p failedPreviewPort) ResolveWorkload(c context.Context, r targets.WorkloadRequest) (targets.PodResolution, error) {
	return targets.PodResolution{}, p.err
}
func (p failedPreviewPort) ContextCapability(context.Context, authorization.Target) (planning.ContextCapability, error) {
	return planning.ContextCapability{}, p.err
}
func (p failedPreviewPort) Resolve(context.Context, privacy.Input) (privacy.Resolution, error) {
	return privacy.Resolution{}, p.err
}
func (p failedPreviewPort) ContextStorage(context.Context, authorization.Target) (ContextStorageObservation, error) {
	return ContextStorageObservation{}, p.err
}
func (p failedPreviewPort) RecoveryState(context.Context) (artifact.RecoveryProof, error) {
	return artifact.RecoveryProof{}, p.err
}
func (p failedPreviewPort) CreateContextPreview(context.Context, value.ContextPreview) error {
	return p.err
}

type failedPreviewEligibility string

func (e failedPreviewEligibility) ContextEligibilityCurrent(context.Context, identities.CurrentIdentity, authorization.Target) authorization.CaptureEligibility {
	return authorization.CaptureEligibility{Result: authorization.Result{Reason: string(e)}}
}

type untrustedPreviewError struct{ error }

func (untrustedPreviewError) FixedStep() string { return "private-provider-token-and-target" }
func (e untrustedPreviewError) Unwrap() error   { return e.error }

func TestContextPreviewFailureReportsFixedDependencyAndPreservesCause(t *testing.T) {
	for _, stage := range []string{"recovery", "target", "facts/capability", "facts/retention", "facts/storage", "processing/read", "store"} {
		t.Run(stage, func(t *testing.T) {
			f := newInvestigationFixture()
			ctx := t.Context()
			cause := errors.New("private-provider-token-and-target")
			port := failedPreviewPort{investigationFixture: f, err: untrustedPreviewError{fmt.Errorf("%w: %w", value.ErrUnavailable, cause)}}
			switch stage {
			case "recovery":
				f.svc.Recovery = port
			case "target":
				f.svc.Targets = port
			case "facts/capability":
				f.svc.Capabilities = port
			case "facts/retention":
				f.svc.Retention = port
			case "facts/storage":
				f.svc.Storage = port
			case "processing/read":
				f.svc.Processing = &coverageReadFixture{f: f, err: port.err}
			case "store":
				f.svc.Previews = port
			}
			var reports []string
			f.svc.ReportPreviewFailure = func(step string) { reports = append(reports, step) }
			_, err := f.svc.Preview(ctx, f.source(t, ctx), f.intent())
			want := stage
			if stage == "facts/retention" {
				want += "/other" // not a privacy-domain error class
			}
			var step interface{ FixedStep() string }
			if !errors.Is(err, value.ErrUnavailable) || !errors.Is(err, cause) || !errors.As(err, &step) || step.FixedStep() != want || !slices.Equal(reports, []string{want}) {
				t.Fatalf("lost exact private stage or original cause: reports=%v, error=%v", reports, err)
			}
			if strings.Contains(err.Error(), "private-") || len(f.previews) != 0 || f.admissions.Load() != 0 {
				t.Fatal("diagnostic leaked dependency text or performed a later effect")
			}
		})
	}
}

func TestContextPreviewFailureDoesNotTrustEligibilityReason(t *testing.T) {
	for reason, want := range map[string]string{"PermissionUnavailable": "facts/eligibility/permission", "ExplicitDeny": "facts/eligibility/deny", "private-target": "facts/eligibility"} {
		t.Run(reason, func(t *testing.T) {
			f := newInvestigationFixture()
			f.svc.Eligibility = failedPreviewEligibility(reason)
			var reports []string
			f.svc.ReportPreviewFailure = func(step string) { reports = append(reports, step) }
			_, err := f.svc.Preview(t.Context(), f.source(t, t.Context()), f.intent())
			if !errors.Is(err, value.ErrDenied) || !slices.Equal(reports, []string{want}) {
				t.Fatalf("eligibility classification changed: %v %v", reports, err)
			}
		})
	}
}

func TestContextPreviewFailureReportsExpiryAfterDraftWithoutUndoingIt(t *testing.T) {
	f := newInvestigationFixture()
	f.afterStore = func() { f.now = f.now.Add(6 * time.Second) }
	var reports []string
	f.svc.ReportPreviewFailure = func(step string) { reports = append(reports, step) }
	_, err := f.svc.Preview(t.Context(), f.source(t, t.Context()), f.intent())
	if !errors.Is(err, value.ErrChanged) || !slices.Equal(reports, []string{"after-store/current"}) || len(f.previews) != 1 || f.admissions.Load() != 0 {
		t.Fatalf("late draft changed original semantics: reports=%v, error=%v", reports, err)
	}
}

func TestContextPreviewSuccessDoesNotReportFailure(t *testing.T) {
	f := newInvestigationFixture()
	f.svc.ReportPreviewFailure = func(string) { t.Fatal("successful preview reported a refusal") }
	f.preview(t)
}

func TestRetentionFailureClassesAreClosed(t *testing.T) {
	for err, want := range map[error]string{privacy.ErrInvalid: "invalid", privacy.ErrConflict: "conflict", privacy.ErrExpired: "expired", privacy.ErrUnavailable: "unavailable", errors.New("private"): "other"} {
		if got := retentionFailure(fmt.Errorf("wrapped: %w", err)); got != want {
			t.Fatalf("%v: %q", err, got)
		}
	}
}
