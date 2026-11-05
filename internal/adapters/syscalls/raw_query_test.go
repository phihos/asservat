package syscalls

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"testing"

	"asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
)

func TestRawSyscallQueryCopiesWholeRecordedValuesAndFilters(t *testing.T) {
	e, from, until, lines := argumentProjectionFixture(t)
	raw := bytes.Join(lines, nil)
	version := artifact.Digest{1}
	s := syscallProjectionSelection(t, analysis.SyscallQueryView, "", 1, nil, false)
	result, err := QuerySyscallArguments(t.Context(), bytes.NewReader(raw), e, from, until, s, version)
	var original ArgumentEventLine
	if json.Unmarshal(lines[1], &original) != nil {
		t.Fatal("fixture")
	}
	if err != nil || result.SyscallQuery == nil || result.SyscallQuery.RecordCount != 4 || result.SyscallQuery.TotalMatching != 4 || len(result.SyscallQuery.Events) != 1 {
		t.Fatal("raw page", err)
	}
	got, _ := json.Marshal(result.SyscallQuery.Events[0])
	want, _ := json.Marshal(original.Event)
	if !bytes.Equal(got, want) || !bytes.Contains(got, []byte(base64.StdEncoding.EncodeToString([]byte(projectionCredential)))) {
		t.Fatal("recorded values changed")
	}
	next := result.SyscallQuery.Next(s, version)
	s = syscallProjectionSelection(t, analysis.SyscallQueryView, next, 100, nil, false)
	result, err = QuerySyscallArguments(t.Context(), bytes.NewReader(raw), e, from, until, s, version)
	if err != nil || len(result.SyscallQuery.Events) != 3 || result.SyscallQuery.Events[0].Outcome != "error" || result.SyscallQuery.Events[1].Outcome != "unmatched" || result.SyscallQuery.Next(s, version) != "" {
		t.Fatal("native continuation", err)
	}
	s = syscallProjectionSelection(t, analysis.SyscallQueryView, "", 100, []string{"write"}, true)
	result, err = QuerySyscallArguments(t.Context(), bytes.NewReader(raw), e, from, until, s, version)
	if err != nil || result.SyscallQuery.TotalMatching != 1 || result.SyscallQuery.RecordCount != 4 || result.SyscallQuery.Events[0].Errno != "ENOENT" {
		t.Fatal("display filter changed fullcounts", err)
	}
	s = syscallProjectionSelection(t, analysis.SyscallQueryView, "", 100, []string{"absent"}, false)
	result, err = QuerySyscallArguments(t.Context(), bytes.NewReader(raw), e, from, until, s, version)
	if err != nil || result.SyscallQuery.Events == nil || len(result.SyscallQuery.Events) != 0 || result.SyscallQuery.RecordCount != 4 {
		t.Fatal("empty filtered file", err)
	}
}

func TestRawSyscallQueryPageFullNeverSkipsInvalidTail(t *testing.T) {
	e, from, until, lines := argumentProjectionFixture(t)
	good := bytes.Join(lines, nil)
	s := syscallProjectionSelection(t, analysis.SyscallQueryView, "", 1, nil, false)
	for name, raw := range map[string][]byte{
		"missing-footer": bytes.Join(lines[:len(lines)-1], nil), "partial-footer": good[:len(good)-1], "extra-tail": append(bytes.Clone(good), []byte("bad\n")...), "retained": bytes.ReplaceAll(good, []byte(`"retained":4`), []byte(`"retained":3`)), "wrong-window": bytes.ReplaceAll(good, []byte(`2026-11-03T10:00:01Z`), []byte(`2026-11-03T10:00:00.9Z`)),
		"last-argument": bytes.Join([][]byte{lines[0], lines[1], lines[2], lines[3], bytes.ReplaceAll(lines[4], []byte("base64:"), []byte("hex:")), lines[5]}, nil),
	} {
		t.Run(name, func(t *testing.T) {
			result, err := QuerySyscallArguments(t.Context(), bytes.NewReader(raw), e, from, until, s, artifact.Digest{1})
			if err == nil || result.SyscallQuery != nil {
				t.Fatal("pagefull hid malformed tail", err)
			}
		})
	}
	ctx, cancel := context.WithCancel(t.Context())
	reader := &rawCancelReader{reader: bytes.NewReader(good), cancel: cancel}
	result, err := QuerySyscallArguments(ctx, reader, e, from, until, s, artifact.Digest{1})
	if !errors.Is(err, context.Canceled) || result.SyscallQuery != nil {
		t.Fatal("cancellation disclosed prefix", err)
	}
}

type rawCancelReader struct {
	reader io.Reader
	cancel context.CancelFunc
}

func (r *rawCancelReader) Read(p []byte) (int, error) {
	n, err := r.reader.Read(p)
	r.cancel()
	return n, err
}

func TestRawSyscallQueryWholeEventByteLimitAndContinuation(t *testing.T) {
	e, from, until, lines := argumentProjectionFixture(t)
	e.Recording.Syscalls.MaxEvents = 100
	var base ArgumentEventLine
	if json.Unmarshal(lines[1], &base) != nil {
		t.Fatal("event")
	}
	var body bytes.Buffer
	body.Write(lines[0])
	for n := 0; n < 100; n++ {
		event := base
		event.Event.Arguments = append([]artifact.ArgumentValue(nil), base.Event.Arguments...)
		event.Event.Arguments[0].Value = "decimal:" + strconv.Itoa(n)
		encoded, _ := AppendArgumentLine(nil, event)
		body.Write(encoded)
	}
	var footer ArgumentFooter
	_ = json.Unmarshal(lines[len(lines)-1], &footer)
	footer.Retained = 100
	encoded, _ := AppendArgumentLine(nil, footer)
	body.Write(encoded)
	version := artifact.Digest{1}
	cursor := ""
	seen := 0
	for {
		s := syscallProjectionSelection(t, analysis.SyscallQueryView, cursor, 100, nil, false)
		result, err := QuerySyscallArguments(t.Context(), bytes.NewReader(body.Bytes()), e, from, until, s, version)
		if err != nil || result.SyscallQuery == nil {
			t.Fatal(err)
		}
		page := result.SyscallQuery
		b, _ := json.Marshal(page)
		if len(b) > analysis.SyscallQueryPageBytes || len(page.Events) == 0 || len(page.Events) >= 100 || page.TotalMatching != 100 || page.RecordCount != 100 {
			t.Fatal("page bound/count", len(b), len(page.Events))
		}
		for _, event := range page.Events {
			if event.Arguments[0].Value != "decimal:"+strconv.Itoa(seen) {
				t.Fatal("skipped whole event", seen)
			}
			seen++
		}
		cursor = page.Next(s, version)
		if cursor == "" {
			break
		}
	}
	if seen != 100 {
		t.Fatal("lost records", seen)
	}
}
