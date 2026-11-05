package native

import (
	query "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
	"encoding/json"
	"reflect"
	"testing"
	"time"
)

func TestRawSyscallProjectionCodecPreservesValuesAndExactScope(t *testing.T) {
	scope, _ := syscallResultFixture(t, artifact.SyscallArgumentsArtifact, query.SyscallEventsView)
	selection, e := query.NormalizeSyscallSelection(scope.CaseID, scope.ArtifactID, query.SyscallQueryView, "", 1, nil, false)
	if e != nil {
		t.Fatal(e)
	}
	scope.Syscalls = selection.Window()
	scope.DisplayVersion = query.SyscallQueryDisplayVersion
	scope.RawGrantID = scope.CaseID
	duration := uint64(0)
	page := query.SyscallArgumentPage{Version: scope.Version, TotalMatching: 1, SyscallRecordCounts: query.SyscallRecordCounts{RecordCount: 1}, Events: []artifact.RawArgumentEvent{{Identity: artifact.ArgumentIdentity{ProcessRef: "p:10:11@boot@epoch", ThreadRef: "t:12:13@boot@epoch", PodUID: scope.PodUID}, Syscall: "write", ABI: "x86_64", Timestamp: time.Date(2026, 11, 5, 10, 0, 0, 0, time.UTC).Format(time.RFC3339Nano), Outcome: "success", DurationNS: &duration, Arguments: []artifact.ArgumentValue{{Name: "fd", Value: "decimal:0"}, {Name: "buffer", Value: "base64:"}}}}}
	result := query.ProjectionResult{SyscallQuery: &page}
	body, e := encodeProjectionResult(result, scope)
	if e != nil {
		t.Fatal(e)
	}
	got, e := decodeProjectionResult(body, scope)
	if e != nil || !reflect.DeepEqual(got, result) {
		t.Fatal("raw page codec changed zero/empty values", e)
	}
	for _, mode := range []string{"metadata", "wrong-version", "wrong-pod", "malformed-value", "extra-result"} {
		t.Run(mode, func(t *testing.T) {
			other := scope
			payload := body
			switch mode {
			case "metadata":
				other.Syscalls.View = query.SyscallEventsView
				other.DisplayVersion = query.SyscallEventsDisplayVersion
				other.RawGrantID = ""
			case "wrong-version":
				other.Version[0]++
			case "wrong-pod":
				other.PodUID = "other"
			default:
				var wire syscallProjectionReply
				if e = json.Unmarshal(body, &wire); e != nil {
					t.Fatal(e)
				}
				if mode == "malformed-value" {
					wire.Query.Events[0].Arguments[0].Value = "hex:0"
				} else {
					wire.Events = &query.SyscallEventPage{}
				}
				payload, _ = json.Marshal(wire)
			}
			if _, e = decodeProjectionResult(payload, other); e == nil {
				t.Fatal("raw codec accepted changed source/output")
			}
		})
	}
}
