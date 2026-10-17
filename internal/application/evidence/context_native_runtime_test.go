package evidence

import (
	"asservat.local/asservat/internal/domain/artifact"
	"context"
	"testing"
	"time"
)

type contextAttachmentFixture struct {
	f     *downloadResultFixture
	value ContextDownloadAttachment
	reads int
}

func (f *contextAttachmentFixture) ReadContextDownloadAttachment(ctx context.Context, _ string, a artifact.DownloadAuthority) (ContextDownloadAttachment, error) {
	f.reads++
	out := f.value
	out.ObservedAt = f.f.now
	out.ValidUntil = a.ValidUntil
	return out, ctx.Err()
}
func warmContextRuntimeFixture(t *testing.T) (*downloadResultFixture, *contextAttachmentFixture, *ContextNativeRuntime, artifact.NativeDownloadMetadata) {
	t.Helper()
	f, cfg, _ := newDownloadResultFixture(t)
	p := nativeLeaseFixture().Operation.Path
	p.TargetClusterID = f.a.Scope.ClusterID
	p.StoreID = f.a.Environment.StoreID
	p.AcquisitionClusterID = f.enrollment.Worker.Intent.Profile.ClusterID
	p.ConnectorClusterID = p.AcquisitionClusterID
	p.WorkerConfiguration = f.enrollment.Worker.Intent.Profile.Configuration
	f.a.Environment.Path = p
	f.a.Environment.Region = p.AcquisitionRegion
	f.a.Environment.Processing = artifact.DownloadProcessingProof{RootID: f.a.Scope.RootID, Epoch: f.a.Scope.RootID, CaptureID: f.a.Scope.CaptureID, Location: f.a.Environment.Location, Sequence: 1, StateDigest: artifact.Digest{21}, ObservedAt: f.now, ValidUntil: f.a.ValidUntil}
	f.enrollment.Worker.Intent.Authority = f.a
	f.s.StopProtocol = artifact.DownloadStopProtocol
	f.s.State = artifact.DownloadReady
	prep := artifact.DownloadPreparation{SessionID: f.s.ID, BatchID: "30000000-0000-4000-8000-000000000001", Generation: 1}
	observed := ContextDownloadAttachment{SessionID: f.s.ID, Scope: f.s.Scope, State: f.s.State, Found: true, Intent: f.enrollment.Worker.Intent, Worker: &f.enrollment.Worker, Enrollment: &f.enrollment, MetadataAttempted: true, Preparation: &prep, NativeTransitions: 4, ObservedAt: f.now, ValidUntil: f.a.ValidUntil}
	if !f.a.Environment.CurrentValid(f.now) || !observed.Valid(f.now) || !f.s.Valid() {
		t.Fatal("synthetic current runtime fixture invalid")
	}
	lookup := &contextAttachmentFixture{f: f, value: observed}
	runtime := &ContextNativeRuntime{config: ContextNativeRuntimeConfig{Authority: f, Dispatcher: &DownloadDispatcher{}, Workers: lookup, Profile: f.enrollment.Worker.Intent.Profile, Now: func() time.Time { return f.now }}, metadata: newContextNativeMetadata(func() time.Time { return f.now })}
	t.Cleanup(runtime.Close)
	key, e := contextMetadataKey(f.s, observed, f.a)
	if e != nil {
		t.Fatal(e)
	}
	m := contextDownloadMetadata(cfg.Request, []byte("synthetic context"))
	m.ReadUntil, m.DeleteBy = f.a.AccessUntil, f.a.DeleteBy
	// Only this test substitutes an authenticated positive regional observation.
	// Production fills the same cache through actual RemoteContextSource.
	_, release, e := runtime.metadata.get(context.Background(), key, true, false, func(context.Context) (artifact.NativeDownloadMetadata, error) { return m, nil })
	if e != nil {
		t.Fatal(e)
	}
	release()
	return f, lookup, runtime, m
}
func TestContextRuntimeWarmPollStillChecksCurrentAuthorityAndSQL(t *testing.T) {
	f, sql, r, m := warmContextRuntimeFixture(t)
	for i := 0; i < 40; i++ {
		out, found, e := r.ReadPreparedContextDownload(context.Background(), f, f.s)
		if e != nil || !found || out.Native != m {
			t.Fatal("warm metadata", i, e)
		}
	}
	if sql.reads != 80 || sql.value.NativeTransitions != 4 {
		t.Fatal("poll bypassed SQL or spent native credits", sql.reads)
	}
	f.failure = "current-authority"
	if _, found, e := r.ReadPreparedContextDownload(context.Background(), f, f.s); e == nil || found {
		t.Fatal("cached fact bypassed revoked authority")
	}
}
func TestContextRuntimeKnownUnjoinedOwnerDoesNotAdvertiseReady(t *testing.T) {
	for _, mode := range []string{"unjoined", "expired-response", "exhausted", "active-stream"} {
		t.Run(mode, func(t *testing.T) {
			f, sql, r, _ := warmContextRuntimeFixture(t)
			switch mode {
			case "unjoined":
				sql.value.NativeBusy = true
			case "expired-response":
				sql.value.ResponseBusy = true
				sql.value.NativeUncertain = true
			case "exhausted":
				sql.value.NativeTransitions = 2
			case "active-stream":
				sql.value.NativeBusy = true
				sql.value.ResponseBusy = true
				sql.value.State = artifact.DownloadStreaming
				f.s.State = artifact.DownloadStreaming
			}
			_, found, e := r.ReadPreparedContextDownload(context.Background(), f, f.s)
			if mode == "active-stream" {
				if e != nil || !found {
					t.Fatal("warm streaming metadata lost", e)
				}
			} else if e == nil || found {
				t.Fatal("unavailable content advertised", mode)
			}
		})
	}
}
func TestContextRuntimeWarmFactsRespectCurrentRetentionAndPath(t *testing.T) {
	f, _, r, m := warmContextRuntimeFixture(t)
	f.a.AccessUntil = f.now.Add(10 * time.Second)
	f.a.DeleteBy = f.now.Add(30 * time.Second)
	got, ok, e := r.ReadPreparedContextDownload(context.Background(), f, f.s)
	if e != nil || !ok || got.Native.ReadUntil != f.a.AccessUntil || got.Native.DeleteBy != f.a.DeleteBy || got.Native.SHA256 != m.SHA256 {
		t.Fatal("current retention not intersected", e)
	}
	f.a.Environment.Path.ID = "30000000-0000-4000-8000-000000000011"
	if _, found, e := r.ReadPreparedContextDownload(context.Background(), f, f.s); e == nil || found {
		t.Fatal("cached fact crossed accepted path")
	}
}
