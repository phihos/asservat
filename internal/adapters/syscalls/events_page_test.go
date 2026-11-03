package syscalls

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
)

const eventCase = "00000000-0000-4000-8000-000000000080"
const eventArtifact = "00000000-0000-4000-8000-000000000081"

func TestMetadataPagesFilterAndContinueNativeOrder(t *testing.T) {
	data, at := summaryNative(t)
	version := artifact.Digest{1}
	s, err := analysis.NormalizeSyscallSelection(eventCase, eventArtifact, analysis.SyscallEventsView, "", 1, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	p, err := ReadMetadataPage(context.Background(), bytes.NewReader(data), "pod", at, at, s, version)
	if err != nil || p.TotalMatching != 5 || len(p.Events) != 1 || p.RecordCount != 5 || p.UnmatchedEvents != 1 || p.UnfinishedEvents != 1 || p.UnknownEvents != 1 {
		t.Fatal(p, err)
	}
	cursor := p.Next(s, version)
	next, err := analysis.NormalizeSyscallSelection(eventCase, eventArtifact, analysis.SyscallEventsView, cursor, 2, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	p, err = ReadMetadataPage(context.Background(), bytes.NewReader(data), "pod", at, at, next, version)
	if err != nil || len(p.Events) != 2 || p.Events[0].Outcome != "error" || p.Events[1].Outcome != "unmatched" {
		t.Fatal(p, err)
	}
	filtered, _ := analysis.NormalizeSyscallSelection(eventCase, eventArtifact, analysis.SyscallEventsView, "", 0, []string{"write"}, true)
	p, err = ReadMetadataPage(context.Background(), bytes.NewReader(data), "pod", at, at, filtered, version)
	if err != nil || p.TotalMatching != 1 || len(p.Events) != 1 || p.Events[0].Errno != "ENOENT" || p.Next(filtered, version) != "" || p.RecordCount != 5 {
		t.Fatal(p, err)
	}
}

type forbiddenMetadataRead struct{}

func (forbiddenMetadataRead) Read([]byte) (int, error) {
	panic("stale display cursor caused a source read")
}
func TestMetadataPageRefusesMalformedTailAndStaleCursor(t *testing.T) {
	data, at := summaryNative(t)
	version := artifact.Digest{1}
	s, _ := analysis.NormalizeSyscallSelection(eventCase, eventArtifact, analysis.SyscallEventsView, "", 1, nil, false)
	for _, input := range [][]byte{append(bytes.Clone(data), []byte("invalid\n")...), data[:len(data)-1]} {
		p, err := ReadMetadataPage(context.Background(), bytes.NewReader(input), "pod", at, at, s, version)
		if err == nil || len(p.Events) != 0 {
			t.Fatal("successful prefix escaped invalid tail", p, err)
		}
	}
	cursor := s.Cursor(1, version)
	next, _ := analysis.NormalizeSyscallSelection(eventCase, eventArtifact, analysis.SyscallEventsView, cursor, 1, nil, false)
	if _, err := ReadMetadataPage(context.Background(), forbiddenMetadataRead{}, "pod", at, at, next, artifact.Digest{2}); err != analysis.ErrInvalidCursor {
		t.Fatal(err)
	}
	beyond, _ := analysis.NormalizeSyscallSelection(eventCase, eventArtifact, analysis.SyscallEventsView, s.Cursor(5, version), 1, nil, false)
	if _, err := ReadMetadataPage(context.Background(), bytes.NewReader(data), "pod", at, at, beyond, version); err != analysis.ErrInvalidCursor {
		t.Fatal(err)
	}
}

func TestMetadataPagesBoundBytesWithoutSkippingRecords(t *testing.T) {
	at := time.Date(2026, 11, 3, 0, 0, 0, 0, time.UTC)
	version := artifact.Digest{1}
	var data []byte
	for i := 0; i < 100; i++ {
		e := event{Identity: identity{ProcessRef: strings.Repeat("p", 125) + fmt.Sprintf("%03d", i), ThreadRef: strings.Repeat("t", 128), PodUID: "pod"}, Syscall: strings.Repeat("w", 64), ABI: strings.Repeat("a", 32), Timestamp: at.Format(time.RFC3339Nano), Outcome: "error", Errno: strings.Repeat("e", 32)}
		b, _ := json.Marshal(e)
		data = append(data, b...)
		data = append(data, '\n')
	}
	s, _ := analysis.NormalizeSyscallSelection(eventCase, eventArtifact, analysis.SyscallEventsView, "", 100, nil, false)
	p, err := ReadMetadataPage(context.Background(), bytes.NewReader(data), "pod", at, at, s, version)
	if err != nil || len(p.Events) == 0 || len(p.Events) >= 100 || p.TotalMatching != 100 {
		t.Fatal(p, err)
	}
	body, _ := json.Marshal(p)
	if len(body) > analysis.ContextResultBytes {
		t.Fatal("oversize page", len(body))
	}
	count := len(p.Events)
	if !strings.HasSuffix(p.Events[count-1].Identity.ProcessRef, fmt.Sprintf("%03d", count-1)) {
		t.Fatal("non-prefix page")
	}
	next, _ := analysis.NormalizeSyscallSelection(eventCase, eventArtifact, analysis.SyscallEventsView, p.Next(s, version), 100, nil, false)
	p, err = ReadMetadataPage(context.Background(), bytes.NewReader(data), "pod", at, at, next, version)
	if err != nil || !strings.HasSuffix(p.Events[0].Identity.ProcessRef, fmt.Sprintf("%03d", count)) {
		t.Fatal("pagination skipped a record", p, err)
	}
}
