package syscalls

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
)

const projectionCredential = "synthetic-password-only-for-test"

func argumentProjectionFixture(t *testing.T) (artifact.ContextExpectation, time.Time, time.Time, [][]byte) {
	t.Helper()
	from := time.Date(2026, 11, 3, 10, 0, 0, 0, time.UTC)
	until := from.Add(time.Second)
	defs, err := ArgumentDefinitions([]string{"read", "write"}, true, 128)
	if err != nil {
		t.Fatal(err)
	}
	program, rule := artifact.Digest{1}, artifact.Digest{2}
	definition := artifact.Digest(ArgumentDefinitionDigest(defs))
	e := artifact.ContextExpectation{PodUID: "pod", NativeType: artifact.SyscallArgumentsArtifact, Recording: &artifact.Recording{MaxBytes: artifact.RecordingNativeLimit, Syscalls: &artifact.RecordingSyscalls{Names: []string{"read", "write"}, MaxEvents: 100}, Arguments: &artifact.RecordingArguments{ProgramDigest: program, DefinitionDigest: definition, AccountingRule: rule, MaxBytesPerEvent: 128, MaxProbeBytes: 512, MaxBytesPerSecond: 1 << 20, CaptureBuffers: true}}}
	header := ArgumentHeader{Record: "header", Format: ArgumentNativeFormat, PodUID: e.PodUID, NodeUID: "node", CollectorPodUID: "collector", SessionID: "session", Fence: "fence", BootID: "boot", SourceEpoch: "epoch", EngineDigest: hex.EncodeToString(program[:]), DefinitionDigest: hex.EncodeToString(definition[:]), AccountingRule: hex.EncodeToString(rule[:]), Decoder: ArgumentDecoderVersion, ABI: ABI, StartedAt: from}
	var lines [][]byte
	appendLine := func(v any) {
		line, err := AppendArgumentLine(nil, v)
		if err != nil {
			t.Fatal(err)
		}
		lines = append(lines, line)
	}
	appendLine(header)
	for _, mode := range []string{"success", "error", "unmatched", "unfinished"} {
		enter := argumentProbe(EventEnter, 1, 10, 100)
		enter.Memory.Data = []byte(projectionCredential)
		exit := argumentProbe(EventExit, 1, 10, 100)
		exit.Memory = nil
		call := ArgumentCall{Entry: &enter, Exit: &exit}
		switch mode {
		case "error":
			exit.Event.Ret = -2
		case "unmatched":
			exit.Event.Number = 0
			call.Entry = nil
		case "unfinished":
			call.Exit = nil
		}
		ev, err := ArgumentEvent(call, header, from, defs)
		if err != nil {
			t.Fatal(err)
		}
		appendLine(ArgumentEventLine{Record: "event", Event: ev})
	}
	observedEvents, observedBytes := uint64(24), uint64(4096)
	appendLine(ArgumentFooter{Record: "footer", EndedAt: until, Outcome: "completed", Retained: 4, PairGaps: 2, LostSamples: 7, CoverageUnknown: true, ObservedEvents: &observedEvents, ObservedBytes: &observedBytes})
	return e, from, until, lines
}

func syscallProjectionSelection(t *testing.T, view analysis.SyscallView, cursor string, limit int, names []string, errors bool) analysis.SyscallSelection {
	t.Helper()
	s, err := analysis.NormalizeSyscallSelection(eventCase, eventArtifact, view, cursor, limit, names, errors)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestApprovedArgumentProjectionUsesFixedMetadataAndFullCounts(t *testing.T) {
	e, from, until, lines := argumentProjectionFixture(t)
	raw, version := bytes.Join(lines, nil), artifact.Digest{1}
	if !bytes.Contains(raw, []byte(base64.StdEncoding.EncodeToString([]byte(projectionCredential)))) {
		t.Fatal("fixture has no sensitive raw buffer")
	}
	s := syscallProjectionSelection(t, analysis.SyscallSummaryView, "", 1, nil, false)
	r, err := ProjectSyscalls(t.Context(), bytes.NewReader(raw), e, from, until, s, version)
	if err != nil || r.SyscallSummary == nil || r.SyscallSummary.Total != 2 || r.SyscallSummary.Rows[0].Syscall != "read" || r.SyscallSummary.RecordCount != 4 || r.SyscallSummary.UnmatchedEvents != 1 || r.SyscallSummary.UnfinishedEvents != 1 || r.SyscallSummary.UnknownEvents != 0 {
		t.Fatal(r, err)
	}
	s = syscallProjectionSelection(t, analysis.SyscallSummaryView, r.SyscallSummary.Next(s, version), 100, nil, false)
	r, err = ProjectSyscalls(t.Context(), bytes.NewReader(raw), e, from, until, s, version)
	if err != nil || len(r.SyscallSummary.Rows) != 1 || r.SyscallSummary.Rows[0] != (analysis.SyscallCount{Syscall: "write", Count: 3, Errors: 1, PairedCount: 2, TotalDurationNS: 2}) || r.SyscallSummary.Next(s, version) != "" {
		t.Fatal(r, err)
	}
	s = syscallProjectionSelection(t, analysis.SyscallEventsView, "", 100, []string{"write"}, true)
	r, err = ProjectSyscalls(t.Context(), bytes.NewReader(raw), e, from, until, s, version)
	if err != nil || r.SyscallEvents == nil || r.SyscallEvents.TotalMatching != 1 || len(r.SyscallEvents.Events) != 1 || r.SyscallEvents.Events[0].Errno != "ENOENT" || r.SyscallEvents.RecordCount != 4 || !r.SyscallEvents.Valid(s, version, e.PodUID, from, until) {
		t.Fatal(r, err)
	}
	body, _ := json.Marshal(r)
	for _, secret := range []string{projectionCredential, base64.StdEncoding.EncodeToString([]byte(projectionCredential)), "arguments", "decimal:", "buffer", "LostSamples", "coverage_unknown"} {
		if bytes.Contains(body, []byte(secret)) {
			t.Fatal("raw or misleading acquisition value escaped", secret)
		}
	}
	// Filters cannot lower full-file counts, make loss assumptions or cause
	// a source with a valid empty display selection to be discarded.
	s = syscallProjectionSelection(t, analysis.SyscallEventsView, "", 100, []string{"not-observed"}, false)
	r, err = ProjectSyscalls(t.Context(), bytes.NewReader(raw), e, from, until, s, version)
	if err != nil || r.SyscallEvents.RecordCount != 4 || r.SyscallEvents.TotalMatching != 0 || len(r.SyscallEvents.Events) != 0 {
		t.Fatal(r, err)
	}
}

func TestArgumentProjectionRejectsMalformedTailForBothViews(t *testing.T) {
	e, from, until, lines := argumentProjectionFixture(t)
	good, version := bytes.Join(lines, nil), artifact.Digest{1}
	bad := map[string][]byte{
		"missing-footer":         bytes.Join(lines[:len(lines)-1], nil),
		"partial-footer":         good[:len(good)-1],
		"extra-record":           append(bytes.Clone(good), lines[1]...),
		"unknown-tail":           append(bytes.Clone(good), []byte("invalid\n")...),
		"duplicate-footer":       append(bytes.Clone(good), lines[len(lines)-1]...),
		"bad-retained":           bytes.ReplaceAll(good, []byte(`"retained":4`), []byte(`"retained":3`)),
		"invented-complete-loss": bytes.ReplaceAll(good, []byte(`"coverage_unknown":true`), []byte(`"coverage_unknown":false`)),
		"null-event-duration":    bytes.Replace(good, []byte(`"duration_ns":1`), []byte(`"duration_ns":null`), 1),
		"bad-argument":           bytes.ReplaceAll(good, []byte("base64:"), []byte("invalid:")),
		"bad-header-window":      bytes.ReplaceAll(good, []byte(`2026-11-03T10:00:00Z`), []byte(`2026-11-03T09:00:00Z`)),
		"bad-footer-window":      bytes.ReplaceAll(good, []byte(`2026-11-03T10:00:01Z`), []byte(`2026-11-03T10:00:00.9Z`)),
		"wrong-pod":              bytes.ReplaceAll(good, []byte(`"pod_uid":"pod"`), []byte(`"pod_uid":"other"`)),
		"wrong-source-ref":       bytes.ReplaceAll(good, []byte(`@boot@epoch`), []byte(`@boot@other`)),
		"wrong-pin":              bytes.ReplaceAll(good, []byte(hex.EncodeToString(e.Recording.Arguments.ProgramDigest[:])), []byte(strings.Repeat("f", 64))),
		"reordered":              bytes.Join([][]byte{lines[1], lines[0], bytes.Join(lines[2:], nil)}, nil),
		"duplicate-member":       bytes.Replace(good, []byte(`"outcome":"success"`), []byte(`"outcome":"success","outcome":"success"`), 1),
	}
	for name, raw := range bad {
		t.Run(name, func(t *testing.T) {
			for _, view := range []analysis.SyscallView{analysis.SyscallSummaryView, analysis.SyscallEventsView} {
				s := syscallProjectionSelection(t, view, "", 1, nil, false)
				r, err := ProjectSyscalls(t.Context(), bytes.NewReader(raw), e, from, until, s, version)
				if err == nil || r.SyscallSummary != nil || r.SyscallEvents != nil {
					t.Fatal("successful prefix escaped malformed source", view, r, err)
				}
			}
		})
	}
	// This private read path must not loosen original publication authority.
	if _, err := NewArgumentCheck(e, artifact.ArgumentSourceProvenance{}); err == nil {
		t.Fatal("publication accepted absent original immutable source facts")
	}
}

func TestApprovedSyscallProjectionBoundsAndDoesNotSkipContinuation(t *testing.T) {
	e, from, until, lines := argumentProjectionFixture(t)
	good, version := bytes.Join(lines, nil), artifact.Digest{1}
	s := syscallProjectionSelection(t, analysis.SyscallEventsView, "", 1, nil, false)
	r, err := ProjectSyscalls(t.Context(), bytes.NewReader(good), e, from, until, s, version)
	if err != nil || len(r.SyscallEvents.Events) != 1 {
		t.Fatal(r, err)
	}
	s = syscallProjectionSelection(t, analysis.SyscallEventsView, r.SyscallEvents.Next(s, version), 1, nil, false)
	r, err = ProjectSyscalls(t.Context(), bytes.NewReader(good), e, from, until, s, version)
	if err != nil || r.SyscallEvents.Events[0].Outcome != "error" {
		t.Fatal("continuation lost native order", r, err)
	}
	if _, err := ProjectSyscalls(t.Context(), forbiddenMetadataRead{}, e, from, until, s, artifact.Digest{2}); !errors.Is(err, analysis.ErrInvalidCursor) {
		t.Fatal("stale version reached source", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := ProjectSyscalls(ctx, bytes.NewReader(good), e, from, until, s, version); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err := ProjectSyscalls(t.Context(), &summaryErrorReader{data: good}, e, from, until, s, version); err == nil {
		t.Fatal("incomplete authenticated reader accepted")
	}
	e.Recording.MaxBytes = int64(len(good) - 1)
	if _, err := ProjectSyscalls(t.Context(), bytes.NewReader(good), e, from, until, s, version); !errors.Is(err, artifact.ErrLimit) {
		t.Fatal("native byte cap ignored", err)
	}
}

func TestApprovedMetadataSummaryPagesAndByteBound(t *testing.T) {
	raw, at := summaryNative(t)
	e, version := artifact.ContextExpectation{PodUID: "pod", NativeType: artifact.SyscallRecordsArtifact}, artifact.Digest{1}
	s := syscallProjectionSelection(t, analysis.SyscallSummaryView, "", 1, nil, false)
	r, err := ProjectSyscalls(t.Context(), bytes.NewReader(raw), e, at, at, s, version)
	if err != nil || r.SyscallSummary == nil || r.SyscallSummary.Rows[0].Syscall != "read" || r.SyscallSummary.Total != 2 {
		t.Fatal(r, err)
	}
	s = syscallProjectionSelection(t, analysis.SyscallSummaryView, r.SyscallSummary.Next(s, version), 100, nil, false)
	r, err = ProjectSyscalls(t.Context(), bytes.NewReader(raw), e, at, at, s, version)
	if err != nil || r.SyscallSummary.Rows[0].Syscall != "write" || r.SyscallSummary.Next(s, version) != "" {
		t.Fatal(r, err)
	}
	// Escaped control characters can expand a legal 64-character name to
	// several hundred bytes; enforce encoded bytes as well as row count.
	var many []byte
	for i := range 100 {
		event := event{Identity: identity{ProcessRef: "p", ThreadRef: "t", PodUID: "pod"}, Syscall: strings.Repeat("\x00", 63) + string(rune(i+1)), ABI: ABI, Timestamp: at.Format(time.RFC3339Nano), Outcome: "success"}
		line, _ := json.Marshal(event)
		many = append(append(many, line...), '\n')
	}
	s = syscallProjectionSelection(t, analysis.SyscallSummaryView, "", 100, nil, false)
	r, err = ProjectSyscalls(t.Context(), bytes.NewReader(many), e, at, at, s, version)
	if err != nil || len(r.SyscallSummary.Rows) == 0 || len(r.SyscallSummary.Rows) >= 100 || r.SyscallSummary.Total != 100 {
		t.Fatal(r, err)
	}
	body, _ := json.Marshal(r.SyscallSummary)
	if len(body) > analysis.ContextResultBytes || r.SyscallSummary.Next(s, version) == "" {
		t.Fatal("unbounded or non-continuable summary", len(body))
	}
	firstOmitted := len(r.SyscallSummary.Rows)
	s = syscallProjectionSelection(t, analysis.SyscallSummaryView, r.SyscallSummary.Next(s, version), 100, nil, false)
	r, err = ProjectSyscalls(t.Context(), bytes.NewReader(many), e, at, at, s, version)
	if err != nil || r.SyscallSummary.Start != firstOmitted || r.SyscallSummary.Rows[0].Syscall != strings.Repeat("\x00", 63)+string(rune(firstOmitted+1)) {
		t.Fatal("summary skipped a row", r, err)
	}
}
