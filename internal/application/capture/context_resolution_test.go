package capture

import (
	"context"
	"errors"
	"testing"
	"time"

	value "asservat.local/asservat/internal/domain/capture"
)

type resolutionFunc func(context.Context, value.ReplayQuery) (value.ContextRequestDisposition, error)

func (f resolutionFunc) ResolveOrCloseContextRequest(c context.Context, q value.ReplayQuery) (value.ContextRequestDisposition, error) {
	return f(c, q)
}

func TestResolveContextRequestWorksWithoutAcquisitionComposition(t *testing.T) {
	f := newInvestigationFixture()
	p := f.preview(t)
	f.svc.Targets = nil
	f.svc.Capabilities = nil
	f.svc.Retention = nil
	f.svc.Storage = nil
	f.svc.Previews = nil
	f.svc.Admission = nil
	got, err := f.svc.ResolveContextRequest(context.Background(), f.source(t, context.Background()), p.ID, "original")
	if err != nil || got.State != value.RequestClosed || got.Accepted != nil || !got.Valid(f.now) {
		t.Fatal("passive closure requires acquisition", err)
	}
}
func TestResolveContextRequestAcceptedReturnsOriginalOperation(t *testing.T) {
	f := newInvestigationFixture()
	p := f.preview(t)
	a, err := f.request(t, p, "original")
	if err != nil {
		t.Fatal(err)
	}
	f.now = f.now.Add(2 * time.Minute)
	f.missing = true
	f.cap.Enabled = false
	got, err := f.svc.ResolveContextRequest(context.Background(), f.source(t, context.Background()), p.ID, "original")
	if err != nil || got.State != value.RequestAccepted || got.Accepted == nil || got.Accepted.CaptureID != a.CaptureID || got.Accepted.Expectation.Registration != a.Expectation.Registration || f.admissions.Load() != 1 {
		t.Fatal("resolution replaced accepted work", err)
	}
}
func TestResolveContextRequestUnknownClosureRemainsUnresolved(t *testing.T) {
	f := newInvestigationFixture()
	p := f.preview(t)
	f.svc.Resolution = resolutionFunc(func(c context.Context, q value.ReplayQuery) (value.ContextRequestDisposition, error) {
		_, err := f.ResolveOrCloseContextRequest(c, q)
		if err != nil {
			return value.ContextRequestDisposition{}, err
		}
		return value.ContextRequestDisposition{}, value.ErrUnavailable
	})
	got, err := f.svc.ResolveContextRequest(context.Background(), f.source(t, context.Background()), p.ID, "original")
	if !errors.Is(err, value.ErrUnavailable) || got.State != "" || got.Accepted != nil {
		t.Fatal("unknown closure claimed non-admission", err)
	}
	f.svc.Resolution = f
	got, err = f.svc.ResolveContextRequest(context.Background(), f.source(t, context.Background()), p.ID, "original")
	if err != nil || got.State != value.RequestClosed {
		t.Fatal("same original closure cannot resolve", err)
	}
}
func TestResolveContextRequestRetainsOriginalPermissionDeadlineThroughIdentity(t *testing.T) {
	f := newInvestigationFixture()
	p := f.preview(t)
	until := f.now.Add(time.Millisecond)
	f.svc.Resolution = resolutionFunc(func(c context.Context, q value.ReplayQuery) (value.ContextRequestDisposition, error) {
		f.now = f.now.Add(2 * time.Millisecond)
		return value.ContextRequestDisposition{State: value.RequestClosed, ValidUntil: until}, nil
	})
	got, err := f.svc.ResolveContextRequest(context.Background(), f.source(t, context.Background()), p.ID, "original")
	if err == nil || got.State != "" {
		t.Fatal("expired permission disclosed terminal resolution")
	}
}
func TestResolveContextRequestRejectsMalformedDisposition(t *testing.T) {
	for _, state := range []value.ContextRequestDisposition{
		{State: value.RequestClosed},
		{State: value.RequestAccepted, ValidUntil: time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)},
		{State: value.RequestClosed, Accepted: &value.Accepted{}, ValidUntil: time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)},
	} {
		f := newInvestigationFixture()
		p := f.preview(t)
		f.svc.Resolution = resolutionFunc(func(context.Context, value.ReplayQuery) (value.ContextRequestDisposition, error) { return state, nil })
		if got, err := f.svc.ResolveContextRequest(context.Background(), f.source(t, context.Background()), p.ID, "original"); err == nil || got.State != "" {
			t.Fatal("invalid terminal disposition accepted")
		}
	}
}

func TestResolveContextRequestNeedsReadScopeButNotCaptureScope(t *testing.T) {
	f := newInvestigationFixture()
	p := f.preview(t)
	a, err := f.request(t, p, "original")
	if err != nil {
		t.Fatal(err)
	}
	f.identityChange = "scopes" // fresh request has evidence:read only
	got, err := f.svc.ResolveContextRequest(context.Background(), f.source(t, context.Background()), p.ID, "original")
	if err != nil || got.State != value.RequestAccepted || got.Accepted.CaptureID != a.CaptureID {
		t.Fatal("capture scope unnecessarily required", err)
	}
}
