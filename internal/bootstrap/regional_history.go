package bootstrap

import (
	"asservat.local/asservat/internal/adapters/objectstore"
	fleetapp "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/identity"
	"context"
	"time"
)

// This adapter is installed only behind the separate history signed-work
// handler. The current native receiver proves epoch; this immutable pin merely
// prevents mixing another local execution process into a completion.
type regionalHistoryObjects struct {
	objects              objectstore.HistoryObjects
	root, cluster, epoch string
	now                  func() time.Time
}

func (r regionalHistoryObjects) ExecuteHistory(ctx context.Context, a capture.HistoryOperationAuthority, b capture.HistoryCiphertexts, c artifact.Copies) (fleetapp.HistoryReply, error) {
	var out fleetapp.HistoryReply
	e := a.Expectation
	if ctx == nil || ctx.Err() != nil || r.now == nil || !a.Valid(r.now()) || e.RootID != r.root || e.Registration.Location.ClusterID != r.cluster || a.ExecutorEpoch != r.epoch || !authorization.UUID(r.epoch) {
		return out, artifact.ErrInvalid
	}
	call, cancel := context.WithDeadline(ctx, a.NotAfter)
	defer cancel()
	switch a.Operation {
	case "write":
		digest, err := capture.HistoryCiphertextsDigest(b)
		if err != nil || digest != a.BundleDigest {
			return out, artifact.ErrIntegrity
		}
		copies, err := r.objects.Write(call, e, b)
		if err != nil {
			return out, err
		}
		if call.Err() != nil || !a.Valid(r.now()) {
			return out, identity.ErrUnavailable
		}
		completion := capture.HistoryWriterCompletion{RootID: e.RootID, CaptureID: e.CaptureID, AttemptID: e.Registration.Location.AttemptID, OperationID: a.RequestID, ProcessEpoch: r.epoch, ExpectationDigest: capture.HistoryExpectationDigest(e), CopiesDigest: capture.HistoryCopiesDigest(copies), CompletedAt: r.now().UTC(), NotAfter: a.NotAfter}
		if !completion.Valid(e) {
			return out, artifact.ErrIntegrity
		}
		out.Copies, out.WriterCompletion = copies, &completion
	case "read":
		if c.Validate(e.Registration) != nil || capture.HistoryCopiesDigest(c) != a.CopiesDigest {
			return out, artifact.ErrIntegrity
		}
		bundle, err := r.objects.Read(call, e, c)
		if err != nil {
			return out, err
		}
		if call.Err() != nil || !a.Valid(r.now()) {
			bundle.Clear()
			return out, identity.ErrUnavailable
		}
		out.Bundle, out.Copies = bundle, c
	case "purge":
		if !fleetapp.HistoryCopiesMatch(a, c) {
			return out, artifact.ErrIntegrity
		}
		if err := r.objects.Purge(call, e); err != nil {
			return out, err
		}
		if call.Err() != nil || !a.Valid(r.now()) {
			return out, identity.ErrUnavailable
		}
		completion := capture.HistoryDeleteCompletion{RootID: e.RootID, CaptureID: e.CaptureID, AttemptID: e.Registration.Location.AttemptID, OperationID: a.RequestID, ProcessEpoch: r.epoch, ExpectationDigest: capture.HistoryExpectationDigest(e), CopiesDigest: a.CopiesDigest, DeletionFence: a.DeletionFence, CompletedAt: r.now().UTC(), NotAfter: a.NotAfter}
		if !completion.Valid(a) {
			return out, artifact.ErrIntegrity
		}
		out.DeleteCompletion = &completion
	default:
		return out, artifact.ErrInvalid
	}
	return out, nil
}
