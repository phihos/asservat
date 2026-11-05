package objectstore

import (
	"context"
	"errors"
	"slices"
	"time"

	"asservat.local/asservat/internal/adapters/objectstore/manifest"
	app "asservat.local/asservat/internal/application/audit"
	"asservat.local/asservat/internal/application/evidence"
	value "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/identity"
)

// ServeSyscallQueries installs the separately authorized recorded-argument view.
func (r *ContextProjectionReader) ServeSyscallQueries(f evidence.SyscallQuerier) {
	if r != nil {
		r.querySyscalls = f
	}
}

func (r *ContextProjectionReader) readSyscallQuery(ctx context.Context, source evidence.NativeContextSource, scope value.ContextProjectionScope, keys evidence.KeyOpener, until time.Time) (value.ProjectionResult, error) {
	var zero value.ProjectionResult
	if r.store == nil || r.querySyscalls == nil || ctx == nil || ctx.Err() != nil || keys == nil || !scope.Valid() || !source.Valid(scope.Version) {
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
	result, err := evidence.ReadSyscallQuery(ctx, opened, source, scope, checkedSyscallQuerier(verifier.contracts, r.querySyscalls))
	app.MarkDuration(ctx, "object-decrypt", time.Since(started)-timed.total())
	if err != nil || ctx.Err() != nil || !time.Now().Before(deadline) {
		result.Clear()
		return zero, &readRefusal{value.ErrUnavailable, readStage(ctx, "parse", errors.Join(value.ErrUnavailable, err))}
	}
	return result, nil
}

func checkedSyscallQuerier(contracts *manifest.Validator, f evidence.SyscallQuerier) evidence.SyscallQuerier {
	return evidence.SyscallQuerier(checkedSyscallProjector(contracts, evidence.SyscallProjector(f)))
}
