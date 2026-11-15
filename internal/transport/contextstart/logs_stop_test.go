package contextstart

import (
	"testing"
	"time"

	app "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/collector"
)

func TestLogsRestrictiveStopNeedsNoNodeQueue(t *testing.T) {
	w, receiver := sourceStreamWorkFixture()
	now := w.IssuedAt()
	stop := collector.RecordingStop{RootID: w.Channel.RootID, ClusterID: w.Channel.Connector.Binding.ClusterID, CaptureID: "44444444-4444-4444-8444-444444444444", AttemptID: "55555555-5555-4555-8555-555555555555", WriterPodUID: w.Channel.Executor.PodUID, WriterEpoch: w.Channel.Executor.ProcessEpoch, ExpectationDigest: artifact.Digest{5}, WriteUntil: now.Add(time.Minute)}
	request := app.SourceWork{Channel: w.Channel, StopRecording: &stop, StopIssuedAt: now, NotAfter: w.NotAfter}
	if !request.Valid(time.Now()) {
		t.Fatal("invalid accepted restrictive fixture")
	}
	called := &sourceRecordingCanceller{}
	local := &SourceLocal{Recordings: called}
	payload, err := encodeSourceWork(request, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	reply, err := applySourceWork(t.Context(), receiver, payload, local, time.Now)
	if err != nil || reply.State != "queued" || called.calls != 1 || !called.last.Equal(stop) {
		t.Fatal("authenticated restrictive recording Stop required a node queue", err, reply.State, called.calls)
	}
	if payload, err = encodeSourceWork(w, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := applySourceWork(t.Context(), receiver, payload, local, time.Now); err == nil || called.calls != 1 {
		t.Fatal("node-free restrictive route enabled source arming")
	}
}
