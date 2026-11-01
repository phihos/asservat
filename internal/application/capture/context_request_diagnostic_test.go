package capture

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/capture"
)

type requestDiagnosticStorageError struct {
	cause error
	reads int
	until time.Time
}

func (s *requestDiagnosticStorageError) ContextStorage(ctx context.Context, _ authorization.Target) (ContextStorageObservation, error) {
	s.reads++
	s.until, _ = ctx.Deadline()
	return ContextStorageObservation{}, s.cause
}

func TestContextRequestReportsOwnedStorageReadFailureWithoutChangingPreview(t *testing.T) {
	for _, operation := range []string{"request", "preview"} {
		t.Run(operation, func(t *testing.T) {
			f := newInvestigationFixture()
			p := f.preview(t)
			cause := errors.New("private-provider-token-and-target")
			storage := &requestDiagnosticStorageError{cause: untrustedPreviewError{fmt.Errorf("%w: %w", value.ErrUnavailable, cause)}}
			f.svc.Storage = storage
			var reports []string
			f.svc.ReportPreviewFailure = func(stage string) { reports = append(reports, stage) }
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			defer cancel()
			originalUntil, _ := ctx.Deadline()
			source := f.source(t, ctx)
			var err error
			want := "request/facts/storage/read"
			if operation == "request" {
				_, err = f.svc.Request(ctx, source, p.ID, "original")
			} else {
				_, err = f.svc.Preview(ctx, source, f.intent())
				want = "facts/storage"
			}
			var step interface{ FixedStep() string }
			if !errors.Is(err, value.ErrUnavailable) || !errors.Is(err, cause) ||
				!errors.As(err, &step) || step.FixedStep() != "facts/storage" || !slices.Equal(reports, []string{want}) {
				t.Fatalf("lost original cause or closed stage: error=%v reports=%v", err, reports)
			}
			if strings.Contains(err.Error(), "private-") || strings.Contains(strings.Join(reports, ","), "private-") {
				t.Fatal("diagnostic copied dependency text")
			}
			if storage.reads != 1 || storage.until.IsZero() || storage.until.After(originalUntil) ||
				f.admissions.Load() != 0 || len(f.accepted) != 0 || len(f.previews) != 1 {
				t.Fatal("diagnostic added I/O, widened the caller or allowed an effect", storage.reads, storage.until)
			}
		})
	}
}

func TestContextRequestChangedDiagnosticIsNotDuplicated(t *testing.T) {
	f := newInvestigationFixture()
	p := f.preview(t)
	f.target.Pin.ControllerUID = "replacement-controller"
	var reports []string
	f.svc.ReportPreviewFailure = func(stage string) { reports = append(reports, stage) }
	_, err := f.svc.Request(t.Context(), f.source(t, t.Context()), p.ID, "original")
	if !errors.Is(err, value.ErrChanged) || !slices.Equal(reports, []string{"request/changed/target"}) ||
		f.admissions.Load() != 0 || len(f.accepted) != 0 {
		t.Fatal("changed-review reporting or refusal changed", err, reports)
	}
}

func TestContextPreviewStorageMarginStageRemainsUnchanged(t *testing.T) {
	f := newInvestigationFixture()
	f.store.Binding.FreshUntil = f.now.Add(50 * time.Millisecond)
	var reports []string
	f.svc.ReportPreviewFailure = func(stage string) { reports = append(reports, stage) }
	_, err := f.svc.Preview(t.Context(), f.source(t, t.Context()), f.intent())
	var step interface{ FixedStep() string }
	if !errors.Is(err, value.ErrUnavailable) || !errors.As(err, &step) || step.FixedStep() != "facts/storage" ||
		!slices.Equal(reports, []string{"facts/storage"}) || len(f.previews) != 0 || f.admissions.Load() != 0 {
		t.Fatal("private request margin marker changed preview semantics", err, reports)
	}
}

type requestStorageReadMarker struct {
	error
	stage string
}

func (e requestStorageReadMarker) Unwrap() error              { return e.error }
func (e requestStorageReadMarker) ContextStorageRead() string { return e.stage }

func TestContextRequestStorageReadDetailsAreClosed(t *testing.T) {
	for _, detail := range []string{
		"transaction", "observation",
		"observation/shape", "observation/pool", "observation/allocation", "observation/source",
		"observation/capacity", "observation/control", "observation/selection",
		"query/no-row", "query/deadline", "query/canceled", "query/unavailable",
		"clock/no-row", "clock/deadline", "clock/canceled", "clock/unavailable",
		"", "private-provider-token", "query/sql-42501", "query/unavailable/private",
	} {
		t.Run(detail, func(t *testing.T) {
			f := newInvestigationFixture()
			p := f.preview(t)
			cause := errors.New("private-provider-token-and-target")
			f.svc.Storage = &requestDiagnosticStorageError{cause: requestStorageReadMarker{
				error: untrustedPreviewError{fmt.Errorf("%w: %w", value.ErrUnavailable, cause)}, stage: detail}}
			var reports []string
			f.svc.ReportPreviewFailure = func(stage string) { reports = append(reports, stage) }
			_, err := f.svc.Request(t.Context(), f.source(t, t.Context()), p.ID, "original")
			want := "request/facts/storage/read"
			switch detail {
			case "", "private-provider-token", "query/sql-42501", "query/unavailable/private":
			default:
				want += "/" + detail
			}
			if !errors.Is(err, value.ErrUnavailable) || !errors.Is(err, cause) || !slices.Equal(reports, []string{want}) {
				t.Fatal("storage detail changed cause or escaped its closed vocabulary", err, reports)
			}
			if f.admissions.Load() != 0 || len(f.accepted) != 0 {
				t.Fatal("storage diagnostic allowed admission")
			}
		})
	}
}

func TestContextRequestStoragePredicateRetainsChangedRefusal(t *testing.T) {
	f := newInvestigationFixture()
	p := f.preview(t)
	storage := &requestDiagnosticStorageError{cause: requestStorageReadMarker{error: value.ErrChanged, stage: "observation/capacity"}}
	f.svc.Storage = storage
	var reports []string
	f.svc.ReportPreviewFailure = func(stage string) { reports = append(reports, stage) }
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	until, _ := ctx.Deadline()
	_, err := f.svc.Request(ctx, f.source(t, ctx), p.ID, "original-storage-refusal")
	if !errors.Is(err, value.ErrChanged) || !slices.Equal(reports, []string{"request/facts/storage/read/observation/capacity"}) ||
		storage.reads != 1 || storage.until.IsZero() || storage.until.After(until) || f.admissions.Load() != 0 || len(f.accepted) != 0 || len(f.previews) != 1 {
		t.Fatal("storage predicate changed original refusal, bounds or effects", err, reports, storage.reads)
	}
}
