package contextstart

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/execution"
	"asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/targets"
)

type fakeRecorderOutput struct {
	started int
	err     error
}

func (o *fakeRecorderOutput) StoreContext(context.Context, []byte, time.Time, time.Time) (artifact.Copies, error) {
	return artifact.Copies{}, value.ErrUnavailable
}
func (o *fakeRecorderOutput) Close() {}
func (o *fakeRecorderOutput) StartRecording(_ context.Context, _ artifact.PinnedPod, started, _ time.Time) (time.Time, error) {
	o.started++
	return started, o.err
}

type fakeRecordings struct{ seen []fleet.APIContextWork }

func (r *fakeRecordings) Collect(w fleet.APIContextWork) (evidence.RecordingCollection, error) {
	r.seen = append(r.seen, w)
	return evidence.RecordingCollection{State: evidence.RecordingPending}, nil
}

// ADR-248: start-recording needs the committed start and the exact resolved
// pin, runs once, and collect-recording answers only for a session that
// prepared nothing and consumed no start.
func TestRegionalSessionStartsAndCollectsRecordings(t *testing.T) {
	w := workFixture().Work
	now := time.Now().UTC().Truncate(time.Microsecond)
	op := func(method string, body any) contracts.APIContextOperation {
		b, _ := json.Marshal(body)
		return contracts.APIContextOperation{Format: contracts.APIContextExchangeFormat, Sequence: 1, Method: method, Body: b}
	}
	local := (&countingLocal{}).local()
	pin := artifact.PinnedPod{Namespace: "app", NamespaceUID: "ns", Name: "web", UID: w.Target.PodUID}
	out := &fakeRecorderOutput{}
	s := &regionalSession{local: local, work: w, prepared: out, resolved: &targets.PodResolution{Pin: pin}}
	req := acquireRequest{Pin: pin, Started: now, Until: now.Add(time.Second)}
	if _, err := s.handle(context.Background(), op(opStartRecording, req)); !errors.Is(err, value.ErrDenied) || out.started != 0 {
		t.Fatal("a recording started without a committed start", err)
	}
	s.consumed = &value.Disposition{MayStart: true, Phase: value.StartCommitted, ValidUntil: now.Add(2 * time.Second)}
	other := req
	other.Pin.UID = "another-pod"
	if _, err := s.handle(context.Background(), op(opStartRecording, other)); !errors.Is(err, value.ErrDenied) {
		t.Fatal("a recording started for another pin", err)
	}
	got, err := s.handle(context.Background(), op(opStartRecording, req))
	if err != nil || got.(recordingReply).Queued != now || out.started != 1 {
		t.Fatal(got, err)
	}
	if _, err := s.handle(context.Background(), op(opStartRecording, req)); !errors.Is(err, value.ErrDenied) || out.started != 1 {
		t.Fatal("a second recording start", err)
	}
	// A collect session prepares nothing and consumes no start.
	if _, err := s.handle(context.Background(), op(opCollect, struct{}{})); err == nil {
		t.Fatal("collect answered in a start session")
	}
	recordings := &fakeRecordings{}
	local.Recordings = recordings
	collect := &regionalSession{local: local, work: w}
	c, err := collect.handle(context.Background(), op(opCollect, struct{}{}))
	if err != nil || c.(evidence.RecordingCollection).State != evidence.RecordingPending || len(recordings.seen) != 1 || recordings.seen[0].CaptureID != w.CaptureID {
		t.Fatal(c, err)
	}
	local.Recordings = nil
	if _, err := (&regionalSession{local: local, work: w}).handle(context.Background(), op(opCollect, struct{}{})); err == nil {
		t.Fatal("collect answered without a recording holder")
	}
}
