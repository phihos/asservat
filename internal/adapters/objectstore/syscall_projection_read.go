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

// ServeSyscallProjections installs only the closed, regional metadata views.
// Native argument bytes remain inside this reader and its fixed parser.
func (r *ContextProjectionReader) ServeSyscallProjections(project evidence.SyscallProjector) {
	if r != nil {
		r.syscalls = project
	}
}

func (r *ContextProjectionReader) readSyscallProjection(ctx context.Context, source evidence.NativeContextSource, scope value.ContextProjectionScope, keys evidence.KeyOpener, until time.Time) (value.ProjectionResult, error) {
	var zero value.ProjectionResult
	if r.store == nil || r.syscalls == nil || ctx == nil || ctx.Err() != nil || keys == nil || !scope.Valid() || !source.Valid(scope.Version) {
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
	result, err := evidence.ReadSyscallProjection(ctx, opened, source, scope, checkedSyscallProjector(verifier.contracts, r.syscalls))
	app.MarkDuration(ctx, "object-decrypt", time.Since(started)-timed.total())
	if err != nil || ctx.Err() != nil || !time.Now().Before(deadline) {
		result.Clear()
		return zero, &readRefusal{value.ErrUnavailable, readStage(ctx, "parse", errors.Join(value.ErrUnavailable, err))}
	}
	return result, nil
}

// The canonical format check and fixed extractor consume the same stream, so
// no additional object read or key unwrap is introduced. The manifest interval
// binds raw header/footer times; published source provenance stays unchanged.
func checkedSyscallProjector(contracts *manifest.Validator, project evidence.SyscallProjector) evidence.SyscallProjector {
	return func(ctx context.Context, source io.Reader, e artifact.ContextExpectation, from, until time.Time, selection value.SyscallSelection, version artifact.Digest) (value.ProjectionResult, error) {
		var zero value.ProjectionResult
		if contracts == nil || project == nil {
			return zero, value.ErrUnavailable
		}
		check, err := contracts.NativeCheck(e, manifest.ContextManifest{StartedAt: from, CompletedAt: until})
		if err != nil {
			return zero, value.ErrUnavailable
		}
		reader := &syscallCheckedReader{source: source, check: check}
		result, err := project(ctx, reader, e, from, until, selection, version)
		if errors.Is(err, value.ErrInvalidCursor) {
			_, drainErr := io.Copy(io.Discard, reader)
			if drainErr != nil {
				err = drainErr
			}
		}
		checkErr := check.Close()
		if reader.failed || checkErr != nil {
			result.Clear()
			return zero, value.ErrUnavailable
		}
		return result, err
	}
}

type syscallCheckedReader struct {
	source io.Reader
	check  manifest.NativeCheck
	failed bool
}

func (r *syscallCheckedReader) Read(p []byte) (int, error) {
	if r.failed {
		return 0, value.ErrUnavailable
	}
	n, err := r.source.Read(p)
	if n > 0 {
		if checkErr := r.check.Write(p[:n]); checkErr != nil {
			clear(p[:n])
			r.failed = true
			return 0, checkErr
		}
	}
	if err != nil && err != io.EOF {
		r.failed = true
	}
	return n, err
}
