package evidence

import (
	"context"
	"errors"
	"slices"
	"testing"

	identities "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
)

type rawUseProbe struct {
	steps *[]string
	err   error
	uses  []authorization.GrantUse
	ids   []string
	scope artifact.DownloadScope
}

func (p *rawUseProbe) ReserveRawResult(_ context.Context, current identities.CurrentIdentity, scope artifact.DownloadScope, useID string, use authorization.GrantUse) error {
	if current == nil {
		return artifact.ErrInvalid
	}
	*p.steps = append(*p.steps, "reserve")
	p.scope = scope
	p.ids, p.uses = append(p.ids, useID), append(p.uses, use)
	return p.err
}

type rawCaller struct{ identity.Identity }

func (c rawCaller) ResolveIdentity(context.Context) (identity.Identity, error) {
	return c.Identity, nil
}

// rawDownloadRequest turns the synthetic request into a raw packet capture.
func rawDownloadRequest(t *testing.T, r *ContextDownloadRequest) {
	t.Helper()
	e := &r.Expectation
	e.ExecutionClass = artifact.ContextNodeExecution
	e.NativeType, e.DataClass = artifact.RawPCAPNGArtifact, "raw"
	e.NodeUID, e.NodeBootID = "synthetic-node-uid", e.CaptureUID
	e.ActionID = "a0123456789abcdef01234567"
	e.Registration.NativeLimit = artifact.RecordingNativeLimit
	e.Recording = &artifact.Recording{Kind: "packetCapture", Profile: "rawPackets", Composition: []byte("{}"), DurationMillis: 10_000, MaxBytes: 1 << 20, Snaplen: 96, RequireApproval: true}
	if err := e.Validate(); err != nil || !e.ServedClass() {
		t.Fatal("invalid raw fixture", err)
	}
}

// ADR-279: every raw batch reserves one grant use under its batch ID before
// the batch begins or any byte is read; a refusal or a missing port stops it.
func TestContextDownloadRawBatchReservesGrantUse(t *testing.T) {
	f, w, r := downloadWorkerTest(t)
	rawDownloadRequest(t, &r)
	p := &rawUseProbe{steps: &f.calls}
	w.RawResults = p
	caller := rawCaller{}
	check := func(ctx context.Context) (artifact.DownloadAuthority, error) { return w.current(ctx, "synthetic", r) }
	if _, err := w.prepareChecked(context.Background(), caller, r, check, nil); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(f.calls[:3], []string{"authority", "reserve", "begin"}) || len(p.uses) != 1 || p.ids[0] != f.i.Batch.ID || p.scope != r.Scope ||
		p.uses[0] != (authorization.GrantUse{Operation: authorization.GrantDownloadOperation, Operations: 1}) {
		t.Fatal("preparation reservation", f.calls, p.ids, p.uses)
	}
	f.calls = nil
	selection := DownloadSelection{Offset: 2, Length: 7, Partial: true}
	if _, err := w.beginChecked(context.Background(), caller, r, artifact.DownloadContent, selection, check); err != nil {
		t.Fatal(err)
	}
	if len(p.uses) != 2 || p.uses[1] != (authorization.GrantUse{Operation: authorization.GrantDownloadOperation, Bytes: 7}) || p.ids[1] != f.i.Batch.ID {
		t.Fatal("content reservation", p.uses)
	}
	for _, name := range []string{"exhausted", "no-port", "bearer"} {
		t.Run(name, func(t *testing.T) {
			f, w, r := downloadWorkerTest(t)
			rawDownloadRequest(t, &r)
			p := &rawUseProbe{steps: &f.calls}
			w.RawResults = p
			var err error
			switch name {
			case "exhausted":
				p.err = authorization.ErrGrantPoolExhausted
				_, err = w.prepareChecked(context.Background(), rawCaller{}, r, func(ctx context.Context) (artifact.DownloadAuthority, error) { return w.current(ctx, "synthetic", r) }, nil)
				if !errors.Is(err, authorization.ErrGrantPoolExhausted) {
					t.Fatal("exhausted pool", err)
				}
			case "no-port":
				w.RawResults = nil
				_, err = w.prepareChecked(context.Background(), rawCaller{}, r, func(ctx context.Context) (artifact.DownloadAuthority, error) { return w.current(ctx, "synthetic", r) }, nil)
			case "bearer":
				_, err = w.Prepare(context.Background(), "synthetic", r)
			}
			if err == nil || slices.Contains(f.calls, "begin") || slices.Contains(f.calls, "native") {
				t.Fatal("raw batch without a reserved use", err, f.calls)
			}
		})
	}
	// Metadata never consults the grant.
	f, w, r = downloadWorkerTest(t)
	p = &rawUseProbe{steps: &f.calls}
	w.RawResults = p
	if _, err := w.Prepare(context.Background(), "synthetic", r); err != nil || len(p.uses) != 0 {
		t.Fatal("metadata reserved a grant use", err)
	}
}

// A raw response charges each window's bytes under its window ID before the
// window's intent audit or any read; a refusal delivers nothing more.
func TestResponseTransferRawWindowsReserveGrantUse(t *testing.T) {
	f, service, req := newResponseTransferFixture(t, artifact.DownloadWindowBytes+17)
	f.format = artifact.RawPCAPNGFormat
	steps := []string{}
	p := &rawUseProbe{steps: &steps}
	service.RawResults = p
	if e := service.Transfer(context.Background(), f, req, f, f); e != nil {
		t.Fatal(e)
	}
	if len(p.uses) != 2 || p.uses[0].Bytes != artifact.DownloadWindowBytes || p.uses[1].Bytes != 17 || p.uses[0].Operation != authorization.GrantDownloadOperation || p.ids[1] != f.w.ID || p.ids[0] == p.ids[1] || f.emitted != f.size {
		t.Fatal("window reservations", p.ids, p.uses)
	}
	f, service, req = newResponseTransferFixture(t, artifact.DownloadWindowBytes+17)
	f.format = artifact.RawPCAPNGFormat
	p = &rawUseProbe{steps: &steps, err: authorization.ErrGrantPoolExhausted}
	service.RawResults = p
	if e := service.Transfer(context.Background(), f, req, f, f); !errors.Is(e, authorization.ErrGrantPoolExhausted) || f.emitted != 0 || f.intents != 0 {
		t.Fatal("exhausted pool delivered", e, f.emitted, f.intents)
	}
	f, service, req = newResponseTransferFixture(t, 17)
	f.format = artifact.RawPCAPNGFormat
	if e := service.Transfer(context.Background(), f, req, f, f); e == nil || f.emitted != 0 || f.begins != 0 {
		t.Fatal("raw response without the grant port", e)
	}
}
