package evidence

import (
	"bytes"
	"context"
	"io"
	"testing"
	"time"

	query "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
)

type syscallSourceFixture struct {
	*summarySourceFixture
	from, until time.Time
}

func (s *syscallSourceFixture) CaptureWindow() (time.Time, time.Time) { return s.from, s.until }

func syscallProjectionFixture(t *testing.T, raw bool, view query.SyscallView) (NativeContextSource, query.ContextProjectionScope, *syscallSourceFixture) {
	t.Helper()
	source, scope, _, _ := httpHeaderPageFixture(t)
	e := &source.Expectation
	e.NativeType, e.DataClass = artifact.SyscallRecordsArtifact, "metadata"
	e.Recording = &artifact.Recording{Kind: "syscallTrace", Profile: "metadata", Composition: []byte("{}"), DurationMillis: 1000, MaxBytes: artifact.RecordingNativeLimit, Snaplen: artifact.RecordingSyscallSnaplen, Syscalls: &artifact.RecordingSyscalls{Names: []string{"write"}, MaxEvents: 100, MaxEventsPerSecond: 100, MaxTrackedThreads: 16}}
	if raw {
		e.NativeType, e.DataClass = artifact.SyscallArgumentsArtifact, "raw"
		e.Recording.Profile, e.Recording.Snaplen = "arguments", 0
		e.Recording.Arguments = &artifact.RecordingArguments{ProgramDigest: artifact.Digest{1}, DefinitionDigest: artifact.Digest{2}, AccountingRule: artifact.Digest{3}, MaxProbeBytes: 256, MaxBytesPerEvent: 128, MaxBytesPerSecond: 1024}
	}
	scope.NativeType, scope.SourceFormat, scope.DisplayVersion = e.NativeType, e.Type().Format, view.DisplayVersion()
	scope.Headers = query.HTTPHeaderWindow{}
	selection, err := query.NormalizeSyscallSelection(scope.CaseID, scope.ArtifactID, view, "", 100, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	scope.Syscalls = selection.Window()
	if !scope.Valid() || !source.Valid(scope.Version) {
		t.Fatal("synthetic syscall scope/source invalid", e.Validate())
	}
	opened := &syscallSourceFixture{summarySourceFixture: &summarySourceFixture{metadata: expectedNativeMetadata(source, 2*artifact.DeliveryBytes+17, artifact.Digest{1})}, from: e.TriggeredAt, until: e.TriggeredAt.Add(time.Second)}
	return source, scope, opened
}

func consumeSyscallProjection(ctx context.Context, r io.Reader, e artifact.ContextExpectation, from, until time.Time, selection query.SyscallSelection, version artifact.Digest) (query.ProjectionResult, error) {
	if _, err := io.Copy(io.Discard, r); err != nil {
		return query.ProjectionResult{}, err
	}
	counts := query.SyscallRecordCounts{RecordCount: 1}
	if selection.View == query.SyscallSummaryView {
		return query.ProjectionResult{SyscallSummary: &query.SyscallSummaryPage{Version: version, Total: 1, Rows: []query.SyscallCount{{Syscall: "write", Count: 1}}, SyscallRecordCounts: counts}}, nil
	}
	event := artifact.SyscallMetadataEvent{Identity: artifact.SyscallMetadataIdentity{PodUID: e.PodUID, ProcessRef: "synthetic-process", ThreadRef: "synthetic-thread"}, Syscall: "write", ABI: "x86_64", Timestamp: from.Format(time.RFC3339Nano), Outcome: "success"}
	return query.ProjectionResult{SyscallEvents: &query.SyscallEventPage{Version: version, TotalMatching: 1, Events: []artifact.SyscallMetadataEvent{event}, SyscallRecordCounts: counts}}, nil
}

func TestReadSyscallProjectionStreamsBothSourceClassesAndViews(t *testing.T) {
	for _, raw := range []bool{false, true} {
		for _, view := range []query.SyscallView{query.SyscallSummaryView, query.SyscallEventsView} {
			source, scope, opened := syscallProjectionFixture(t, raw, view)
			result, err := ReadSyscallProjection(t.Context(), opened, source, scope, consumeSyscallProjection)
			if err != nil || !result.Valid(scope) || !opened.closed || opened.offset != opened.metadata.Size || opened.reads < 2 || opened.maximum > artifact.DeliveryBytes {
				t.Fatal(raw, view, err, opened)
			}
			if !bytes.Equal(opened.returned, make([]byte, len(opened.returned))) {
				t.Fatal("retained native bytes")
			}
		}
	}
}

func TestReadSyscallProjectionRefusesUnauthenticatedOrPartialResults(t *testing.T) {
	for _, mode := range []string{"wrong-format", "wrong-class", "wrong-version", "accepted-limit", "missing-window", "reversed-window", "missing-final", "short", "canceled", "partial-projector", "swallowed-error", "wrong-view", "wrong-event-window", "invalid-cursor-missing-final"} {
		t.Run(mode, func(t *testing.T) {
			source, scope, opened := syscallProjectionFixture(t, true, query.SyscallSummaryView)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			project := SyscallProjector(consumeSyscallProjection)
			switch mode {
			case "wrong-format":
				opened.metadata.Format = artifact.SyscallRecordsFormat
			case "wrong-class":
				source.Expectation.DataClass = "metadata"
			case "wrong-version":
				scope.Version[0] ^= 1
			case "accepted-limit":
				opened.metadata.Size = source.Expectation.Registration.NativeLimit + 1
			case "missing-window":
				opened.from = time.Time{}
			case "reversed-window":
				opened.until = opened.from.Add(-time.Second)
			case "missing-final":
				opened.noFinal = true
			case "short":
				opened.short = true
			case "canceled":
				opened.afterRead = cancel
			case "partial-projector":
				project = func(ctx context.Context, r io.Reader, e artifact.ContextExpectation, from, until time.Time, selection query.SyscallSelection, version artifact.Digest) (query.ProjectionResult, error) {
					return consumeSyscallProjection(ctx, bytes.NewReader(nil), e, from, until, selection, version)
				}
			case "swallowed-error":
				opened.noFinal = true
				project = func(ctx context.Context, r io.Reader, e artifact.ContextExpectation, from, until time.Time, selection query.SyscallSelection, version artifact.Digest) (query.ProjectionResult, error) {
					_, _ = io.Copy(io.Discard, r)
					return consumeSyscallProjection(ctx, bytes.NewReader(nil), e, from, until, selection, version)
				}
			case "wrong-view":
				project = func(ctx context.Context, r io.Reader, e artifact.ContextExpectation, from, until time.Time, selection query.SyscallSelection, version artifact.Digest) (query.ProjectionResult, error) {
					selection.View = query.SyscallEventsView
					return consumeSyscallProjection(ctx, r, e, from, until, selection, version)
				}
			case "wrong-event-window":
				scope.Syscalls.View, scope.DisplayVersion = query.SyscallEventsView, query.SyscallEventsView.DisplayVersion()
				project = func(ctx context.Context, r io.Reader, e artifact.ContextExpectation, from, until time.Time, selection query.SyscallSelection, version artifact.Digest) (query.ProjectionResult, error) {
					result, err := consumeSyscallProjection(ctx, r, e, from, until, selection, version)
					result.SyscallEvents.Events[0].Timestamp = until.Add(time.Second).Format(time.RFC3339Nano)
					return result, err
				}
			case "invalid-cursor-missing-final":
				opened.noFinal = true
				project = func(context.Context, io.Reader, artifact.ContextExpectation, time.Time, time.Time, query.SyscallSelection, artifact.Digest) (query.ProjectionResult, error) {
					return query.ProjectionResult{}, query.ErrInvalidCursor
				}
			}
			result, err := ReadSyscallProjection(ctx, opened, source, scope, project)
			if err == nil || result.SyscallSummary != nil || result.SyscallEvents != nil || result.InvalidCursor || !opened.closed {
				t.Fatal("refusal retained output", err, opened.closed)
			}
		})
	}
}

func TestReadSyscallProjectionAuthenticatesBeforeCursorRefusal(t *testing.T) {
	source, scope, opened := syscallProjectionFixture(t, false, query.SyscallSummaryView)
	project := func(context.Context, io.Reader, artifact.ContextExpectation, time.Time, time.Time, query.SyscallSelection, artifact.Digest) (query.ProjectionResult, error) {
		return query.ProjectionResult{}, query.ErrInvalidCursor
	}
	result, err := ReadSyscallProjection(t.Context(), opened, source, scope, project)
	if err != nil || !result.InvalidCursor || opened.offset != opened.metadata.Size || !opened.closed {
		t.Fatal("cursor refusal skipped final authentication", result, err)
	}
}

// Include a full context-batch allowance for commit/manifest reads beyond
// the encrypted native frame/index ceiling.
func TestSyscallProjectionReadFitsTwoQueryUnits(t *testing.T) {
	for _, name := range []string{artifact.SyscallRecordsArtifact, artifact.SyscallArgumentsArtifact} {
		typ, ok := artifact.LookupNativeType(name)
		work := NativeWindowReadWork(typ) + query.ContextBatchReadWork
		unit := int64(query.ContextMaxReadBatches * query.ContextBatchReadWork)
		if !ok || typ.DownloadLimit() != artifact.RecordingNativeLimit || work <= unit || work > query.SyscallProjectionQueryUnits*unit {
			t.Fatal("syscall query funding", name, work, unit)
		}
	}
}
