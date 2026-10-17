package capture

import (
	"context"
	"errors"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/capture"
)

// Synthetic coverage is explicit and used only by this application fixture.
func (f *investigationFixture) ContextProcessingCoverage(_ context.Context, r value.ProcessingCoverageRequest, _ artifact.RecoveryProof) (value.ProcessingCoverage, error) {
	return value.ProcessingCoverage{Request: r, ObservedAt: f.now, FreshUntil: f.now.Add(5 * time.Second)}, nil
}

type coverageReadFixture struct {
	f     *investigationFixture
	err   error
	calls int
	after func(*value.ProcessingCoverage)
}

func (r *coverageReadFixture) ContextProcessingCoverage(ctx context.Context, in value.ProcessingCoverageRequest, recovery artifact.RecoveryProof) (value.ProcessingCoverage, error) {
	r.calls++
	o, _ := r.f.ContextProcessingCoverage(ctx, in, recovery)
	if r.after != nil {
		r.after(&o)
	}
	return o, r.err
}

func TestContextProcessingCoveragePrecedesPreviewAndAdmission(t *testing.T) {
	for _, preview := range []bool{true, false} {
		name := "new-admission"
		if preview {
			name = "preview"
		}
		t.Run(name, func(t *testing.T) {
			f := newInvestigationFixture()
			ctx := t.Context()
			source := f.source(t, ctx)
			reader := &coverageReadFixture{f: f}
			f.svc.Processing = reader
			var id string
			if !preview {
				p, e := f.svc.Preview(ctx, source, f.intent())
				if e != nil {
					t.Fatal(e)
				}
				id = p.Preview.ID
			}
			reader.err = value.ErrProcessingCoverage
			var err error
			if preview {
				_, err = f.svc.Preview(ctx, source, f.intent())
			} else {
				_, err = f.svc.Request(ctx, source, id, "same-original-key")
			}
			if !errors.Is(err, value.ErrProcessingCoverage) || f.admissions.Load() != 0 || len(f.accepted) != 0 || preview && len(f.previews) != 0 {
				t.Fatal("known short coverage reached draft/admission", err)
			}
			if !preview && f.previews[id].Intent.RequestedSeconds != 60 {
				t.Fatal("caller retention was silently shortened")
			}
		})
	}
}

func TestContextProcessingCoveragePreservesPassiveAcceptedReplay(t *testing.T) {
	f := newInvestigationFixture()
	ctx := t.Context()
	source := f.source(t, ctx)
	r := &coverageReadFixture{f: f}
	f.svc.Processing = r
	p, err := f.svc.Preview(ctx, source, f.intent())
	if err != nil {
		t.Fatal(err)
	}
	a, err := f.svc.Request(ctx, source, p.Preview.ID, "original")
	if err != nil {
		t.Fatal(err)
	}
	calls := r.calls
	r.err = value.ErrUnavailable
	b, err := f.svc.Request(ctx, source, p.Preview.ID, "original")
	if err != nil || !b.Replay || b.CaptureID != a.CaptureID || r.calls != calls || f.admissions.Load() != 1 {
		t.Fatal("historical replay attempted fresh processing admission", err)
	}
}

func TestContextProcessingCoverageRejectsMissingChangedLateAndCancelledRead(t *testing.T) {
	for _, name := range []string{"missing", "changed-target", "late", "cancelled"} {
		t.Run(name, func(t *testing.T) {
			f := newInvestigationFixture()
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			source := f.source(t, ctx)
			r := &coverageReadFixture{f: f}
			f.svc.Processing = r
			switch name {
			case "missing":
				f.svc.Processing = nil
			case "changed-target":
				r.after = func(o *value.ProcessingCoverage) { o.Request.Target.PodUID = "another-pod" }
			case "late":
				r.after = func(o *value.ProcessingCoverage) { f.now = o.FreshUntil }
			case "cancelled":
				r.after = func(*value.ProcessingCoverage) { cancel() }
			}
			_, err := f.svc.Preview(ctx, source, f.intent())
			if !errors.Is(err, value.ErrUnavailable) || len(f.previews) != 0 || f.admissions.Load() != 0 {
				t.Fatal("invalid coverage read reached a draft", err)
			}
		})
	}
}

func TestContextProcessingCoverageExpiredIdentityMasksKnownLimitation(t *testing.T) {
	f := newInvestigationFixture()
	ctx := t.Context()
	source := f.source(t, ctx)
	reader := &coverageReadFixture{f: f, err: value.ErrProcessingCoverage, after: func(o *value.ProcessingCoverage) { f.now = o.FreshUntil }}
	f.svc.Processing = reader
	_, err := f.svc.Preview(ctx, source, f.intent())
	if !errors.Is(err, value.ErrUnavailable) || errors.Is(err, value.ErrProcessingCoverage) || len(f.previews) != 0 || f.admissions.Load() != 0 {
		t.Fatal("expired identity disclosed known current coverage", err)
	}
}
