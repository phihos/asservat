package evidence

import (
	query "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
	"context"
	"io"
	"testing"
	"time"
)

type rawSyscallCloseSource struct {
	*syscallSourceFixture
	closes      int
	cancelClose context.CancelFunc
}

func (s *rawSyscallCloseSource) Close() {
	s.closes++
	s.syscallSourceFixture.Close()
	if s.cancelClose != nil {
		s.cancelClose()
	}
}
func rawSyscallReadFixture(t *testing.T) (NativeContextSource, query.ContextProjectionScope, *rawSyscallCloseSource) {
	t.Helper()
	source, scope, opened := syscallProjectionFixture(t, true, query.SyscallEventsView)
	scope.Syscalls.View, scope.DisplayVersion, scope.RawGrantID = query.SyscallQueryView, query.SyscallQueryDisplayVersion, scope.RootID
	return source, scope, &rawSyscallCloseSource{syscallSourceFixture: opened}
}
func consumeRawSyscallPage(ctx context.Context, r io.Reader, e artifact.ContextExpectation, from, until time.Time, selection query.SyscallSelection, version artifact.Digest) (query.ProjectionResult, error) {
	if _, err := io.Copy(io.Discard, r); err != nil {
		return query.ProjectionResult{}, err
	}
	duration := uint64(0)
	event := artifact.RawArgumentEvent{Identity: artifact.ArgumentIdentity{PodUID: e.PodUID, ProcessRef: "synthetic-process", ThreadRef: "synthetic-thread"}, Syscall: "write", ABI: "x86_64", Timestamp: from.Format(time.RFC3339Nano), DurationNS: &duration, Outcome: "success", Arguments: []artifact.ArgumentValue{{Name: "count", Value: "decimal:18446744073709551615"}, {Name: "buffer", Value: "base64:"}}}
	return query.ProjectionResult{SyscallQuery: &query.SyscallArgumentPage{Version: version, Events: []artifact.RawArgumentEvent{event}, TotalMatching: 1, SyscallRecordCounts: query.SyscallRecordCounts{RecordCount: 1}}}, nil
}
func TestRawSyscallQueryAuthenticatesAndClosesBeforeResult(t *testing.T) {
	for _, mode := range []string{"complete", "partial", "missing-final", "changed-final", "cancel-read", "cancel-close", "wrong-window", "cursor", "cursor-missing-final", "too-large", "too-large-canceled-close"} {
		t.Run(mode, func(t *testing.T) {
			source, scope, opened := rawSyscallReadFixture(t)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			callback := SyscallQuerier(consumeRawSyscallPage)
			switch mode {
			case "partial":
				callback = func(ctx context.Context, r io.Reader, e artifact.ContextExpectation, a, b time.Time, s query.SyscallSelection, v artifact.Digest) (query.ProjectionResult, error) {
					return consumeRawSyscallPage(ctx, emptySyscallReader{}, e, a, b, s, v)
				}
			case "missing-final", "cursor-missing-final":
				opened.noFinal = true
			case "changed-final":
				opened.afterRead = func() { opened.metadata.SHA256[0] ^= 1 }
			case "cancel-read":
				opened.afterRead = cancel
			case "cancel-close", "too-large-canceled-close":
				opened.cancelClose = cancel
			case "wrong-window":
				callback = func(ctx context.Context, r io.Reader, e artifact.ContextExpectation, a, b time.Time, s query.SyscallSelection, v artifact.Digest) (query.ProjectionResult, error) {
					out, err := consumeRawSyscallPage(ctx, r, e, a, b, s, v)
					if err == nil {
						out.SyscallQuery.Events[0].Timestamp = b.Add(time.Second).Format(time.RFC3339Nano)
					}
					return out, err
				}
			}
			if mode == "cursor" || mode == "cursor-missing-final" {
				callback = func(context.Context, io.Reader, artifact.ContextExpectation, time.Time, time.Time, query.SyscallSelection, artifact.Digest) (query.ProjectionResult, error) {
					return query.ProjectionResult{}, query.ErrInvalidCursor
				}
			}
			if mode == "too-large" || mode == "too-large-canceled-close" {
				callback = func(context.Context, io.Reader, artifact.ContextExpectation, time.Time, time.Time, query.SyscallSelection, artifact.Digest) (query.ProjectionResult, error) {
					return query.ProjectionResult{}, query.ErrRecordTooLarge
				}
			}
			out, err := ReadSyscallQuery(ctx, opened, source, scope, callback)
			switch mode {
			case "complete":
				if err != nil || out.SyscallQuery == nil || !out.Valid(scope) || opened.offset != opened.metadata.Size {
					t.Fatal("authenticated result", err)
				}
			case "cursor":
				if err != nil || !out.InvalidCursor || out.SyscallQuery != nil || opened.offset != opened.metadata.Size {
					t.Fatal("cursor before EOF", err)
				}
			case "too-large":
				if err != nil || !out.TooLarge || out.SyscallQuery != nil || opened.offset != opened.metadata.Size {
					t.Fatal("size before EOF", err)
				}
			default:
				if err == nil || out.SyscallQuery != nil || out.InvalidCursor || out.TooLarge {
					t.Fatal("fault disclosed prefix/refusal", mode, err)
				}
			}
			if opened.closes != 1 {
				t.Fatal("source close count", opened.closes)
			}
		})
	}
}

type emptySyscallReader struct{}

func (emptySyscallReader) Read([]byte) (int, error) { return 0, io.EOF }
