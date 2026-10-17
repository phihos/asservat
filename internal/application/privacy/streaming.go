package privacy

import (
	"context"
	"crypto/sha256"
	"hash"

	"asservat.local/asservat/internal/domain/artifact"
)

// StreamingJournal is the SQL journal facet (ADR-166).
type StreamingJournal interface {
	AdvanceStreaming(context.Context, artifact.StreamingPlan, artifact.StreamingStep) (artifact.StreamingState, bool, error)
}

// MultipartObjects is the object-store facet. Each call is a single attempt.
type MultipartObjects interface {
	CreateUpload(context.Context, artifact.Location) (string, error)
	UploadPart(context.Context, artifact.Location, string, artifact.StreamingPart, []byte) (string, error)
	CompleteUpload(context.Context, artifact.Location, string, []artifact.StreamingPart, int64, artifact.Digest) (artifact.CopyReceipt, error)
	AbortUpload(context.Context, artifact.Location, string) error
	UploadAbsent(context.Context, artifact.Location, string) (bool, error)
	VerifyStreaming(context.Context, artifact.Location, artifact.CopyReceipt, int64) error
}

// StreamingWriter turns one ciphertext data stream into sequential journaled
// 8 MiB parts. A remote request starts only after its claim committed fresh;
// any failure leaves the journal and charges for cleanup and never retries.
// The caller's context carries the original acquisition and WriteUntil bound.
type StreamingWriter struct {
	plan    artifact.StreamingPlan
	journal StreamingJournal
	objects MultipartObjects
	upload  string
	buffer  []byte
	sum     hash.Hash
	size    int64
	parts   []artifact.StreamingPart
	failed  bool
}

func NewStreamingWriter(ctx context.Context, plan artifact.StreamingPlan, journal StreamingJournal, objects MultipartObjects) (*StreamingWriter, error) {
	if ctx == nil || plan.Validate() != nil || journal == nil || objects == nil {
		return nil, artifact.ErrInvalid
	}
	_, fresh, err := journal.AdvanceStreaming(ctx, plan, artifact.StreamingStep{Kind: artifact.StreamClaimCreate})
	if err != nil {
		return nil, err
	}
	if !fresh {
		return nil, ErrUnavailable // a spent create is never repeated
	}
	upload, err := objects.CreateUpload(ctx, plan.Registration.Location)
	if err != nil {
		return nil, ErrUnavailable
	}
	if _, _, err = journal.AdvanceStreaming(ctx, plan, artifact.StreamingStep{Kind: artifact.StreamUpload, UploadID: upload}); err != nil {
		return nil, err
	}
	return &StreamingWriter{plan: plan, journal: journal, objects: objects, upload: upload, buffer: make([]byte, 0, artifact.StreamingPartBytes), sum: sha256.New()}, nil
}

// Write buffers ciphertext and uploads each full part in order.
func (w *StreamingWriter) Write(ctx context.Context, p []byte) error {
	if w == nil || w.failed {
		return ErrUnavailable
	}
	for len(p) > 0 {
		n := min(len(p), int(artifact.StreamingPartBytes)-len(w.buffer))
		w.buffer = append(w.buffer, p[:n]...)
		p = p[n:]
		if int64(len(w.buffer)) == artifact.StreamingPartBytes {
			if err := w.flush(ctx); err != nil {
				return err
			}
		}
	}
	return nil
}

func (w *StreamingWriter) flush(ctx context.Context) error {
	if len(w.buffer) == 0 {
		return nil
	}
	if w.size+int64(len(w.buffer)) > w.plan.TemporaryBytes() {
		w.failed = true
		return artifact.ErrLimit
	}
	part := artifact.StreamingPart{Number: len(w.parts) + 1, Bytes: int64(len(w.buffer)), SHA256: sha256.Sum256(w.buffer)}
	_, fresh, err := w.journal.AdvanceStreaming(ctx, w.plan, artifact.StreamingStep{Kind: artifact.StreamClaimPart, Part: part})
	if err != nil || !fresh {
		w.failed = true
		if err == nil {
			err = ErrUnavailable
		}
		return err
	}
	etag, err := w.objects.UploadPart(ctx, w.plan.Registration.Location, w.upload, part, w.buffer)
	if err != nil {
		w.failed = true
		return ErrUnavailable
	}
	part.ETag = etag
	if _, _, err = w.journal.AdvanceStreaming(ctx, w.plan, artifact.StreamingStep{Kind: artifact.StreamAckPart, Part: part}); err != nil {
		w.failed = true
		return err
	}
	w.sum.Write(w.buffer)
	w.size += part.Bytes
	w.parts = append(w.parts, part)
	clear(w.buffer)
	w.buffer = w.buffer[:0]
	return nil
}

// Finish uploads the last part, completes create-only, records the receipt and
// verifies the complete ciphertext before returning it for StoreCopies.
func (w *StreamingWriter) Finish(ctx context.Context) (artifact.CopyReceipt, error) {
	var zero artifact.CopyReceipt
	if w == nil || w.failed {
		return zero, ErrUnavailable
	}
	if err := w.flush(ctx); err != nil {
		return zero, err
	}
	w.failed = true // no further writes after Finish, whatever its outcome
	if len(w.parts) == 0 {
		return zero, artifact.ErrInvalid
	}
	var digest artifact.Digest
	copy(digest[:], w.sum.Sum(nil))
	_, fresh, err := w.journal.AdvanceStreaming(ctx, w.plan, artifact.StreamingStep{Kind: artifact.StreamClaimComplete, Bytes: w.size, SHA256: digest})
	if err != nil || !fresh {
		if err == nil {
			err = ErrUnavailable
		}
		return zero, err
	}
	loc := w.plan.Registration.Location
	receipt, err := w.objects.CompleteUpload(ctx, loc, w.upload, w.parts, w.size, digest)
	if err != nil || receipt.Bytes != w.size || receipt.SHA256 != digest {
		return zero, ErrUnavailable // uncertain completion: reconcile, never repeat
	}
	if _, _, err = w.journal.AdvanceStreaming(ctx, w.plan, artifact.StreamingStep{Kind: artifact.StreamAckComplete, Receipt: receipt}); err != nil {
		return zero, err
	}
	if err = w.objects.VerifyStreaming(ctx, loc, receipt, w.plan.Registration.Limits()[0]); err != nil {
		return zero, err
	}
	return receipt, nil
}

// ReleaseStreaming releases the temporary multipart charge after a verified
// receipt or after aborting an upload whose completion was never spent. Both
// require a later inventory showing no open upload. An uncertain completion
// keeps its charge until reconciliation or the attempt's own deletion.
func ReleaseStreaming(ctx context.Context, plan artifact.StreamingPlan, state artifact.StreamingState, journal StreamingJournal, objects MultipartObjects) error {
	if ctx == nil || journal == nil || objects == nil || state.Validate(plan) != nil || !state.ReleasedAt.IsZero() {
		return artifact.ErrInvalid
	}
	loc := plan.Registration.Location
	aborted := state.Receipt == nil
	switch {
	case state.Receipt != nil:
	case !state.CompleteSpent && state.UploadID != "":
		if err := objects.AbortUpload(ctx, loc, state.UploadID); err != nil {
			return ErrUnavailable
		}
	default:
		return ErrUnavailable // unknown create or uncertain completion stays charged
	}
	absent, err := objects.UploadAbsent(ctx, loc, state.UploadID)
	if err != nil || !absent {
		return ErrUnavailable
	}
	_, _, err = journal.AdvanceStreaming(ctx, plan, artifact.StreamingStep{Kind: artifact.StreamRelease, Aborted: aborted})
	return err
}
