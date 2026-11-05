package logs

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"io"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
)

func queryLogFixture(t *testing.T, body []byte) ([]byte, artifact.ContextExpectation, time.Time, time.Time) {
	t.Helper()
	now := time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)
	e := artifact.ContextExpectation{DataClass: "raw", ActionID: "a0123456789abcdef01234567", Registration: artifact.Registration{NativeLimit: 1 << 20}, NativeType: artifact.LogsArtifact, PodUID: "10000000-0000-4000-8000-000000000002", TriggeredAt: now, Logs: &artifact.LogCapture{ActionID: "a0123456789abcdef01234567", BeforeMillis: 60000, TimeoutMillis: 10000, Streams: "combined", MaxNativeBytes: 1 << 20}}
	start, end, err := e.Logs.Window(now)
	if err != nil {
		t.Fatal(err)
	}
	var native bytes.Buffer
	encoder, err := NewEncoder(t.Context(), &native, artifact.LogHeader{Record: "header", Format: artifact.LogFormat, PodUID: e.PodUID, WindowStart: start, WindowEnd: end, Origins: 1}, e.Logs.MaxNativeBytes)
	if err != nil {
		t.Fatal(err)
	}
	if err = encoder.BeginOrigin(artifact.LogOrigin{Record: "origin", OriginID: 0, ContainerKind: "regular", ContainerName: "app", Source: "current", Stream: "combined"}); err != nil {
		t.Fatal(err)
	}
	if _, err = encoder.Write(body); err != nil {
		t.Fatal(err)
	}
	fetchStart, fetchEnd := now.Add(time.Second), now.Add(2*time.Second)
	if err = encoder.EndOrigin(artifact.LogCoverage{FetchOutcome: "complete", FetchStartedAt: &fetchStart, FetchFinishedAt: &fetchEnd, Gaps: []string{"rotationUnknown"}}); err != nil {
		t.Fatal(err)
	}
	if err = encoder.Close(); err != nil {
		t.Fatal(err)
	}
	return native.Bytes(), e, now, now.Add(3 * time.Second)
}

func TestLogQueriesReconstructLongEmptyAndInvalidBytesAcrossPages(t *testing.T) {
	body := append(bytes.Repeat([]byte{'&'}, 5000), 0xff, '\n', '\n', 0, 'x')
	native, expected, from, until := queryLogFixture(t, body)
	var cursor string
	var reconstructed []byte
	for pages := 0; ; pages++ {
		if pages > 20 {
			t.Fatal("nonprogressing cursor")
		}
		selection, err := analysis.NormalizeLogSelection("10000000-0000-4000-8000-000000000001", expected.PodUID, cursor, 1)
		if err != nil {
			t.Fatal(err)
		}
		reader := bytes.NewReader(native)
		out, err := QueryLogs(t.Context(), reader, expected, from, until, selection, artifact.Digest{1})
		if err != nil || out.Logs == nil || reader.Len() != 0 {
			t.Fatal("page failed or skipped full EOF", err, reader.Len())
		}
		for _, row := range out.Logs.Entries {
			b, err := base64.StdEncoding.Strict().DecodeString(row.Data)
			if err != nil {
				t.Fatal(err)
			}
			reconstructed = append(reconstructed, b...)
			clear(b)
		}
		cursor = out.Logs.Next(selection, artifact.Digest{1})
		out.Clear()
		if cursor == "" {
			break
		}
	}
	if !bytes.Equal(reconstructed, body) {
		t.Fatal("lost/duplicated bytes, empty line or invalid UTF-8")
	}
}

func TestLogQueryBadTailOverridesPageAndCursorRefusal(t *testing.T) {
	native, expected, from, until := queryLogFixture(t, bytes.Repeat([]byte{'&'}, 18000))
	selection, _ := analysis.NormalizeLogSelection("10000000-0000-4000-8000-000000000001", expected.PodUID, "", 100)
	out, err := QueryLogs(t.Context(), bytes.NewReader(native), expected, from, until, selection, artifact.Digest{1})
	if err != nil || out.Logs == nil || !out.Logs.HasNext || !out.Logs.ValidShape(selection, artifact.Digest{1}, expected.PodUID) {
		t.Fatal("escaped display budget did not stop a valid prefix", err)
	}
	out.Clear()
	bad := append(append([]byte{}, native...), []byte("{}\n")...)
	for _, mismatch := range []bool{false, true} {
		s := selection
		if mismatch {
			cursor := s.Cursor(0, 1024, artifact.Digest{2})
			s, _ = analysis.NormalizeLogSelection(s.CaseID, s.ArtifactID, cursor, 1)
		}
		out, err = QueryLogs(t.Context(), bytes.NewReader(bad), expected, from, until, s, artifact.Digest{1})
		if err == nil || errors.Is(err, analysis.ErrInvalidCursor) || out.Logs != nil {
			t.Fatal("bad tail was hidden by a full page or cursor", err)
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	out, err = QueryLogs(ctx, bytes.NewReader(native), expected, from, until, selection, artifact.Digest{1})
	if err == nil || out.Logs != nil {
		t.Fatal("cancelled page escaped")
	}
	out, err = QueryLogs(t.Context(), io.MultiReader(bytes.NewReader(native), &logQueryFault{}), expected, from, until, selection, artifact.Digest{1})
	if err == nil || out.Logs != nil {
		t.Fatal("failed source tail escaped")
	}
}

type logQueryFault struct{}

func (*logQueryFault) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }

func TestLogQueryRequiresExactRawExpectationAndFinalFetchInterval(t *testing.T) {
	native, expected, from, until := queryLogFixture(t, bytes.Repeat([]byte{'&'}, 18000))
	selection, _ := analysis.NormalizeLogSelection("10000000-0000-4000-8000-000000000001", expected.PodUID, "", 100)
	for _, mode := range []string{"class", "action", "cap"} {
		e := expected
		switch mode {
		case "class":
			e.DataClass = "metadata"
		case "action":
			e.ActionID = "different"
		case "cap":
			e.Registration.NativeLimit--
		}
		out, err := QueryLogs(t.Context(), bytes.NewReader(native), e, from, until, selection, artifact.Digest{1})
		if err == nil || out.Logs != nil {
			t.Errorf("accepted mismatched %s", mode)
		}
	}
	late := bytes.Replace(native, []byte(from.Add(2*time.Second).Format(time.RFC3339Nano)), []byte(from.Add(4*time.Second).Format(time.RFC3339Nano)), 1)
	for _, mismatch := range []bool{false, true} {
		s := selection
		if mismatch {
			s, _ = analysis.NormalizeLogSelection(s.CaseID, s.ArtifactID, s.Cursor(0, 1024, artifact.Digest{2}), 1)
		}
		out, err := QueryLogs(t.Context(), bytes.NewReader(late), expected, from, until, s, artifact.Digest{1})
		if err == nil || errors.Is(err, analysis.ErrInvalidCursor) || out.Logs != nil {
			t.Fatal("late fetch bypassed full-page or cursor checks", err)
		}
	}
}
