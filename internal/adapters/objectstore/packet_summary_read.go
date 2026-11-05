package objectstore

import (
	"context"
	"errors"
	"io"
	"slices"
	"time"

	"asservat.local/asservat/internal/adapters/objectstore/manifest"
	app "asservat.local/asservat/internal/application/audit"
	"asservat.local/asservat/internal/application/evidence"
	value "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/identity"
)

// ServePacketSummaries installs the closed regional metadata views of metadata and raw PCAPNG.
func (r *ContextProjectionReader) ServePacketSummaries(summarize evidence.PacketSummarizer) {
	if r != nil {
		r.packets = summarize
	}
}

func (r *ContextProjectionReader) readPacketSummary(ctx context.Context, source evidence.NativeContextSource, scope value.ContextProjectionScope, keys evidence.KeyOpener, until time.Time) (value.ProjectionResult, error) {
	var zero value.ProjectionResult
	if r.store == nil || r.packets == nil || ctx == nil || ctx.Err() != nil || keys == nil || !scope.Valid() || !source.Valid(scope.Version) {
		return zero, value.ErrUnavailable
	}
	deadline, ok := ctx.Deadline()
	if !ok || deadline.After(until) || deadline.After(time.Now().Add(identity.EvidenceReadRequestWindow)) || !time.Now().Before(deadline) {
		return zero, value.ErrUnavailable
	}
	source.Expectation.Audience = slices.Clone(source.Expectation.Audience)
	source.Expectation.RetentionRules = slices.Clone(source.Expectation.RetentionRules)
	source.Expectation.SourceSnapshotManifest = source.Expectation.SourceSnapshotManifest.Clone()
	source.Expectation.Recording = source.Expectation.Recording.Clone()
	if source.Expectation.Snapshot != nil {
		source.Expectation.Snapshot = source.Expectation.Snapshot.Clone()
	}
	if source.Expectation.Lifecycle != nil {
		lifecycle := *source.Expectation.Lifecycle
		lifecycle.GapReasons = slices.Clone(lifecycle.GapReasons)
		source.Expectation.Lifecycle = &lifecycle
	}
	timed := &timedKeyOpener{inner: keys}
	verifier, err := NewContextVerifier(r.store, timed)
	if err != nil {
		return zero, value.ErrUnavailable
	}
	started := time.Now()
	opened, err := verifier.openNative(ctx, ctx, source.Expectation, source.Copies, minDeadline(deadline, source.Expectation.Registration.ExpiresAt))
	if err != nil || ctx.Err() != nil {
		if opened != nil {
			opened.Close()
		}
		return zero, &readRefusal{value.ErrUnavailable, err}
	}
	result, err := evidence.ReadPacketSummary(ctx, opened, source, scope, checkedPacketSummarizer(verifier.contracts, r.packets))
	app.MarkDuration(ctx, "object-decrypt", time.Since(started)-timed.total())
	if err != nil || ctx.Err() != nil || !time.Now().Before(deadline) {
		result.Clear()
		return zero, &readRefusal{value.ErrUnavailable, readStage(ctx, "parse", errors.Join(value.ErrUnavailable, err))}
	}
	return result, nil
}

// The canonical check observes the same complete stream as the extractor.
// It remains independently mandatory before any result or size refusal.
func checkedPacketSummarizer(contracts *manifest.Validator, summarize evidence.PacketSummarizer) evidence.PacketSummarizer {
	return func(ctx context.Context, source io.Reader, e artifact.ContextExpectation, from, until time.Time) (value.PacketSummary, error) {
		var zero value.PacketSummary
		if contracts == nil || summarize == nil {
			return zero, value.ErrUnavailable
		}
		check, err := contracts.NativeCheck(e, manifest.ContextManifest{StartedAt: from, CompletedAt: until})
		if err != nil {
			return zero, value.ErrUnavailable
		}
		reader := &syscallCheckedReader{source: source, check: check}
		result, err := summarize(ctx, reader, e, from, until)
		if errors.Is(err, value.ErrRecordTooLarge) {
			if _, drainErr := io.Copy(io.Discard, reader); drainErr != nil {
				err = drainErr
			}
		}
		checkErr := check.Close()
		if reader.failed || checkErr != nil {
			clear(result.Conversations)
			return zero, value.ErrUnavailable
		}
		return result, err
	}
}
