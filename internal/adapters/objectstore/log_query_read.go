package objectstore

import (
	"context"
	"errors"
	"slices"
	"time"

	app "asservat.local/asservat/internal/application/audit"
	"asservat.local/asservat/internal/application/evidence"
	value "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/identity"
)

// ServeLogQueries installs the separately authorized saved-log view.
func (r *ContextProjectionReader) ServeLogQueries(f evidence.LogQuerier) {
	if r != nil {
		r.queryLogs = f
	}
}

func (r *ContextProjectionReader) readLogQuery(ctx context.Context, source evidence.NativeContextSource, scope value.ContextProjectionScope, keys evidence.KeyOpener, until time.Time) (value.ProjectionResult, error) {
	var zero value.ProjectionResult
	if r.store == nil || r.queryLogs == nil || ctx == nil || ctx.Err() != nil || keys == nil || !scope.Valid() || !source.Valid(scope.Version) {
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
	source.Expectation.Logs = source.Expectation.Logs.Clone()
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
	// The installed callback performs the canonical full-source walk and binds
	// the accepted header and actual fetch interval in that same parse. Native
	// publication retains its independent mandatory checker.
	result, err := evidence.ReadLogQuery(ctx, opened, source, scope, r.queryLogs)
	app.MarkDuration(ctx, "object-decrypt", time.Since(started)-timed.total())
	if err != nil || ctx.Err() != nil || !time.Now().Before(deadline) {
		result.Clear()
		return zero, &readRefusal{value.ErrUnavailable, readStage(ctx, "parse", errors.Join(value.ErrUnavailable, err))}
	}
	return result, nil
}
