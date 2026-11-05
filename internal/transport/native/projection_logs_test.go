package native

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"reflect"
	"testing"
	"time"

	query "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
)

func logsResultFixture(t *testing.T) (query.ContextProjectionScope, query.ProjectionResult) {
	t.Helper()
	s := resultScope()
	selection, err := query.NormalizeLogSelection(s.CaseID, s.ArtifactID, "", 10)
	if err != nil {
		t.Fatal(err)
	}
	s.NativeType, s.SourceFormat, s.DisplayVersion = artifact.LogsArtifact, artifact.LogFormat, query.LogQueryDisplayVersion
	s.SourceProjectionDigest, s.Selection = artifact.Digest{}, query.LineSelection{}
	s.Logs, s.RawGrantID = query.LogWindow{Limit: selection.Limit}, s.CaseID
	now := time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)
	restarts := uint32(0)
	runtime := "containerd://original"
	page := query.LogPage{Version: s.Version, PodUID: s.PodUID, WindowStart: now, WindowEnd: now.Add(time.Second), OriginCount: 1, CompleteOrigins: 1, GappedOrigins: 1, UnknownTimestampOrigins: 1, TotalFragments: 1, SourceBytes: 3, Entries: []query.LogEntry{{Origin: artifact.LogOrigin{Record: "origin", ContainerKind: "regular", ContainerName: "app", Source: "current", Stream: "combined", RuntimeID: &runtime, RestartCount: &restarts}, Line: 1, EndLine: true, Data: base64.StdEncoding.EncodeToString([]byte{0xff, 0, '\n'})}}}
	r := query.ProjectionResult{Logs: &page}
	if !s.Valid() || !r.Valid(s) {
		t.Fatal("invalid logs fixture", s, r)
	}
	return s, r
}

func TestLogsProjectionCodecPreservesBytesProvenanceAndRefusals(t *testing.T) {
	s, result := logsResultFixture(t)
	for _, r := range []query.ProjectionResult{result, {InvalidCursor: true}, {TooLarge: true}} {
		body, err := encodeProjectionResult(r, s)
		if err != nil || len(body) > query.ContextResultBytes {
			t.Fatal("encode", err)
		}
		back, err := decodeProjectionResult(body, s)
		if err != nil || !reflect.DeepEqual(back, r) {
			t.Fatal("logs codec changed exact result", err, string(body))
		}
	}
}

func TestLogsProjectionCodecRejectsChangedScopeAndMalformedPayload(t *testing.T) {
	s, result := logsResultFixture(t)
	body, err := encodeProjectionResult(result, s)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"version", "pod", "selection", "metadata", "missing-grant"} {
		t.Run(name, func(t *testing.T) {
			other := s
			switch name {
			case "version":
				other.Version[0]++
			case "pod":
				other.PodUID = "other"
			case "selection":
				other.Logs.Fragment = 1
				other.Logs.Binding = "0123456789abcdef0123456789abcdef"
			case "metadata":
				other = resultScope()
			case "missing-grant":
				other.RawGrantID = ""
			}
			if _, err := decodeProjectionResult(body, other); err == nil {
				t.Fatal("accepted changed scope")
			}
		})
	}
	var nullReply logProjectionReply
	if err := json.Unmarshal(body, &nullReply); err != nil {
		t.Fatal(err)
	}
	nullReply.Logs.Entries = nil
	nullEntries, err := json.Marshal(nullReply)
	if err != nil {
		t.Fatal(err)
	}
	versionJSON, _ := json.Marshal(s.Version)
	duplicate := append(bytes.Clone(body[:len(body)-1]), []byte(`,"Version":`)...)
	duplicate = append(duplicate, versionJSON...)
	duplicate = append(duplicate, '}')
	for name, bad := range map[string][]byte{
		"null": []byte(`null`), "empty": []byte(`{}`),
		"null-entries":      nullEntries,
		"noncanonical":      append([]byte(" "), body...),
		"extra-result":      append(bytes.Clone(body[:len(body)-1]), []byte(`,"Summary":{}}`)...),
		"duplicate":         duplicate,
		"both-refusals":     []byte(`{"InvalidCursor":true,"TooLarge":true}`),
		"page-with-refusal": append(bytes.Clone(body[:len(body)-1]), []byte(`,"InvalidCursor":true}`)...),
		"oversized":         bytes.Repeat([]byte("x"), query.ContextResultBytes+1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeProjectionResult(bad, s); err == nil {
				t.Fatal("accepted malformed logs reply")
			}
		})
	}
	result.PodStatus = query.PodStatusProjection{PodUID: s.PodUID}
	if _, err := encodeProjectionResult(result, s); err == nil {
		t.Fatal("encoded mixed result")
	}
}
