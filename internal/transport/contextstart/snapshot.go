package contextstart

import (
	"context"
	"time"

	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/domain/collector"
	value "asservat.local/asservat/internal/domain/execution"
)

const opStartSourceSnapshot = "start-source-snapshot"

var _ evidence.SourceSnapshotRecorder = (*remoteOutput)(nil)

func (o *remoteOutput) StartSourceSnapshot(ctx context.Context, s collector.SourceSnapshot) (time.Time, error) {
	var reply recordingReply
	err := o.h.call(ctx, opStartSourceSnapshot, s, &reply)
	return reply.Queued, err
}
func (s *regionalSession) startSourceSnapshot(ctx context.Context, raw []byte) (any, error) {
	var x collector.SourceSnapshot
	if err := decodeOperationBody(raw, &x); err != nil {
		return nil, err
	}
	recorder, ok := s.prepared.(evidence.SourceSnapshotRecorder)
	d := s.consumed
	if x.WriterPodUID != s.work.Channel.Executor.PodUID || x.WriterEpoch != s.work.Channel.Executor.ProcessEpoch || x.AttemptID != s.work.AttemptID || s.snapshotTarget == nil || !s.snapshotTarget.Valid(s.local.Now()) || x.Binding.NodeUID != s.snapshotTarget.Original.NodeUID || x.Binding.BootID != s.snapshotTarget.Original.BootID || x.Binding.CollectorPodUID != s.snapshotTarget.Original.CollectorPodUID || x.Binding.CollectorEpoch != s.snapshotTarget.Original.CollectorEpoch || x.Binding.SourceID != s.snapshotTarget.Original.SourceID || x.Binding.Fence != s.snapshotTarget.Original.Fence || x.Request.SourceBindingDigest != s.snapshotTarget.Original.BindingDigest || s.acquired || !ok || s.expectation == nil || s.expectation.Snapshot == nil || d == nil || !d.MayStart || d.Phase != value.StartCommitted || !x.Valid() || x.CaptureID != s.work.CaptureID || x.ExpectationDigest != [32]byte(s.work.ExpectationDigest) || !s.expectation.Snapshot.Equal(x.Request) || !s.local.Now().Before(x.Request.StartBy) {
		return nil, value.ErrDenied
	}
	if !s.local.Now().Before(d.ValidUntil) {
		return nil, value.ErrExpired
	}
	cutoff := d.ValidUntil
	if s.snapshotTarget.FreshUntil.Before(cutoff) {
		cutoff = s.snapshotTarget.FreshUntil
	}
	committed, cancel := context.WithDeadline(ctx, cutoff)
	defer cancel()
	s.acquired = true
	queued, err := recorder.StartSourceSnapshot(committed, x)
	if err != nil {
		return nil, err
	}
	return recordingReply{Queued: queued}, nil
}
