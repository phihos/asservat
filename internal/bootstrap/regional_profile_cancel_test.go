package bootstrap

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/collector"
	"asservat.local/asservat/internal/domain/execution"
	"asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/planning"
	"github.com/google/pprof/profile"
)

func (q *profileQueue) EnqueueProfileCancel(_ context.Context, _, _, _ string, _ time.Time) (collector.Work, error) {
	return collector.Work{}, nil
}
func TestProfileStopFencesLateStartAndNeedsJoinedResult(t *testing.T) {
	for _, beforeStart := range []bool{true, false} {
		t.Run(map[bool]string{true: "before-dispatch", false: "after-dispatch"}[beforeStart], func(t *testing.T) {
			h, q, reader, e, endpoint, now := profileHolderFixture(t)
			stop := collector.ProfileStop{RootID: e.CaptureUID, ClusterID: e.Registration.Location.ClusterID, CaptureID: e.CaptureUID, AttemptID: e.Registration.Location.AttemptID, WriterPodUID: e.CaptureUID, WriterEpoch: e.CaptureUID, ExpectationDigest: evidence.ContextExpectationDigest(e), WriteUntil: e.Registration.WriteUntil}
			p := h.PrepareProfile(&objectstore.PreparedArtifact{}, e)
			if !beforeStart {
				if _, err := p.StartProfile(context.Background(), reader.plan.Pin, now, now.Add(time.Second), endpoint); err != nil {
					t.Fatal(err)
				}
			}
			if err := h.CancelProfile(context.Background(), stop); err != nil {
				t.Fatal(err)
			}
			work := fleet.APIContextWork{CaptureID: e.CaptureUID, AttemptID: e.Registration.Location.AttemptID, ExpectationDigest: stop.ExpectationDigest}
			if beforeStart {
				if _, err := p.StartProfile(context.Background(), reader.plan.Pin, now, now.Add(time.Second), endpoint); err == nil || len(q.profiles) != 0 {
					t.Fatal("late start followed stop")
				}
			} else {
				if out, err := h.Collect(work); err != nil || out.State != evidence.RecordingPending {
					t.Fatal("enqueue claimed joined", out, err)
				}
				r := collector.ProfileResult{WorkID: q.profiles[0].ID, CaptureID: e.CaptureUID, ExpectationDigest: stop.ExpectationDigest, EndpointDigest: e.Profile.EndpointDigest, Failure: collector.ReasonCaptureFailed, Outcome: execution.GoProfileOutcome{Format: artifact.PprofFormat, StartedAt: now, CompletedAt: now, MayHaveStarted: true}}
				if err := h.DeliverProfile(context.Background(), q.node, r, bytes.NewReader(nil)); err != nil {
					t.Fatal(err)
				}
			}
			out, err := h.Collect(work)
			if err != nil || out.State != evidence.RecordingCancelled || out.ProfileCancellation == nil || out.ProfileCancellation.MayHaveStarted == beforeStart || !out.Valid(e.Registration) {
				t.Fatal("typed joined result", out, err)
			}
			if err := h.CancelProfile(context.Background(), stop); err != nil {
				t.Fatal("idempotent stop", err)
			}
			wrong := stop
			wrong.WriterEpoch = "22222222-2222-4222-8222-222222222222"
			if err := h.CancelProfile(context.Background(), wrong); err == nil {
				t.Fatal("replacement writer inherited stop")
			}
		})
	}
}

func TestProfileStopJoinsRealWriterAndKeepsUncertainBackendEffects(t *testing.T) {
	h, q, reader, e, endpoint, now := profileHolderFixture(t)
	_, _, _, x := sourceSnapshotPipelineFixture(t, nil)
	base := snapshotExpected(t, x)
	base.CaptureUID, base.PodUID, base.NamespaceUID = e.CaptureUID, e.PodUID, e.NamespaceUID
	base.ActionID = "a0123456789abcdef01234567"
	base.NativeType, base.DataClass, base.Profile = artifact.PprofArtifact, "raw", e.Profile.Clone()
	base.Snapshot, base.SourceSnapshotManifest, base.Lifecycle = nil, nil, nil
	base.Registration.Location = e.Registration.Location
	base.TriggeredAt = now
	base.Registration.AnchorAt = now
	base.Registration.WriteUntil = now.Add(time.Minute)
	base.Registration.ExpiresAt = now.Add(120 * time.Second)
	base.Registration.DeleteBy = now.Add(180 * time.Second)
	base.Registration.NativeLimit = 64 << 10
	base.Profile.MaxBytes = 64 << 10
	var frozen planning.ProfileContext
	if err := json.Unmarshal(base.Profile.Composition, &frozen); err != nil {
		t.Fatal(err)
	}
	frozen.Endpoints[0].Request.NativeLimit = 64 << 10
	base.Profile.Composition, _ = json.Marshal(frozen)
	// Small native test output exercises the actual prepared writer without a multipart fixture.
	if err := base.Validate(); err != nil {
		t.Fatal("profile writer fixture", err)
	}
	entered, release := make(chan struct{}), make(chan struct{})
	defer close(release)
	prepared := preparedSnapshot(t, base, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(entered)
		<-release
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	e = base
	endpoint.NativeLimit = 64 << 10
	reader.plan.NativeLimit = 64 << 10
	output := h.PrepareProfile(prepared, e)
	if _, err := output.StartProfile(t.Context(), reader.plan.Pin, now, now.Add(time.Second), endpoint); err != nil {
		t.Fatal(err)
	}
	stop := collector.ProfileStop{RootID: e.CaptureUID, ClusterID: e.Registration.Location.ClusterID, CaptureID: e.CaptureUID, AttemptID: e.Registration.Location.AttemptID, WriterPodUID: e.CaptureUID, WriterEpoch: e.CaptureUID, ExpectationDigest: evidence.ContextExpectationDigest(e), WriteUntil: e.Registration.WriteUntil}
	var native bytes.Buffer
	sample := &profile.Profile{SampleType: []*profile.ValueType{{Type: "alloc_objects", Unit: "count"}}, Sample: []*profile.Sample{{Value: []int64{1}}}}
	if err := sample.Write(&native); err != nil {
		t.Fatal(err)
	}
	result := collector.ProfileResult{WorkID: q.profiles[0].ID, CaptureID: e.CaptureUID, ExpectationDigest: stop.ExpectationDigest, EndpointDigest: e.Profile.EndpointDigest, Outcome: execution.GoProfileOutcome{Format: artifact.PprofFormat, StartedAt: now, CompletedAt: now, MayHaveStarted: true, ResponseComplete: true, NativeBytes: int64(native.Len())}}
	done := make(chan error, 1)
	go func() {
		done <- h.DeliverProfile(t.Context(), q.node, result, bytes.NewReader(native.Bytes()))
	}()
	select {
	case <-entered:
	case err := <-done:
		t.Fatal("profile writer returned before backend", err)
	case <-time.After(5 * time.Second):
		t.Fatal("profile writer did not reach backend")
	}
	work := fleet.APIContextWork{CaptureID: e.CaptureUID, AttemptID: e.Registration.Location.AttemptID, ExpectationDigest: stop.ExpectationDigest}
	if out, err := h.Collect(work); err != nil || out.State != evidence.RecordingPending {
		t.Fatal("inflight writer claimed completion", out, err)
	}
	if err := h.CancelProfile(t.Context(), stop); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("unknown backend response became storage success")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("cancelled writer did not join")
	}
	out, err := h.Collect(work)
	if err != nil || out.State != evidence.RecordingCancelled || out.ProfileCancellation == nil || !out.ProfileCancellation.MayHaveStarted || h.storing != 0 {
		t.Fatal("writer join lost cancellation or reservation", out, h.storing, err)
	}
}
