package contextstart

import (
	"context"
	"testing"
	"time"

	app "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/collector"
	"asservat.local/asservat/internal/domain/fleet"
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
	local := &SourceLocal{Recordings: called, Verifier: sourceWorkVerifierFunc(func(context.Context, []byte, fleet.APIContextReceiver) (app.AuthenticatedSourceWork, error) {
		return app.AuthenticatedSourceWork{Work: request, KeyID: "synthetic", TrustRevision: workFixture().TrustRevision, VerifiedAt: request.IssuedAt(), ValidUntil: request.NotAfter}, nil
	})}
	reply, err := applySourceWork(t.Context(), receiver, nil, local, time.Now)
	if err != nil || reply.State != "queued" || called.calls != 1 || !called.last.Equal(stop) {
		t.Fatal("authenticated restrictive recording Stop required a node queue", err, reply.State, called.calls)
	}
	request = w
	if _, err := applySourceWork(t.Context(), receiver, nil, local, time.Now); err == nil || called.calls != 1 {
		t.Fatal("node-free restrictive route enabled source arming")
	}
}
