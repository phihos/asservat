package native

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
	query "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
)

func syscallResultFixture(t *testing.T, source string, view query.SyscallView) (query.ContextProjectionScope, query.ProjectionResult) {
	t.Helper()
	s := resultScope()
	selection, err := query.NormalizeSyscallSelection(s.CaseID, s.ArtifactID, view, "", 100, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	s.NativeType, s.DisplayVersion, s.SourceProjectionDigest = source, view.DisplayVersion(), artifact.Digest{}
	s.SourceFormat = artifact.SyscallRecordsFormat
	if source == artifact.SyscallArgumentsArtifact {
		s.SourceFormat = artifact.SyscallArgumentsFormat
	}
	s.Selection, s.Syscalls = query.LineSelection{}, selection.Window()
	stats := query.SyscallRecordCounts{RecordCount: 1}
	var r query.ProjectionResult
	if view == query.SyscallSummaryView {
		r.SyscallSummary = &query.SyscallSummaryPage{Version: s.Version, Total: 1, Rows: []query.SyscallCount{{Syscall: "write", Count: 1, PairedCount: 1, TotalDurationNS: 5}}, SyscallRecordCounts: stats}
	} else {
		duration := uint64(5)
		r.SyscallEvents = &query.SyscallEventPage{Version: s.Version, TotalMatching: 1, Events: []artifact.SyscallMetadataEvent{{Identity: artifact.SyscallMetadataIdentity{ProcessRef: "p:10:11@boot@epoch", ThreadRef: "t:12:13@boot@epoch", PodUID: s.PodUID}, Syscall: "write", ABI: "x86_64", Timestamp: time.Date(2026, 11, 3, 10, 0, 0, 0, time.UTC).Format(time.RFC3339Nano), DurationNS: &duration, Outcome: "success"}}, SyscallRecordCounts: stats}
	}
	if !s.Valid() || !r.Valid(s) {
		t.Fatal("invalid syscall result fixture", s, r)
	}
	return s, r
}

func TestSyscallProjectionPayloadRoundTripsExactSourceAndView(t *testing.T) {
	for _, source := range []string{artifact.SyscallRecordsArtifact, artifact.SyscallArgumentsArtifact} {
		for _, view := range []query.SyscallView{query.SyscallSummaryView, query.SyscallEventsView} {
			t.Run(source+"/"+string(view), func(t *testing.T) {
				s, result := syscallResultFixture(t, source, view)
				body, err := encodeProjectionResult(result, s)
				if err != nil || len(body) > query.ContextResultBytes {
					t.Fatal("bounded reply refused", err, len(body))
				}
				back, err := decodeProjectionResult(body, s)
				if err != nil || !reflect.DeepEqual(back, result) {
					t.Fatal("fixed metadata changed", back, err)
				}
				frame, err := nativeControl(contracts.NativeMetadataFrame, contracts.NativeMetadata{Format: contracts.NativeExchangeFormat, Nonce: strings.Repeat("n", 64), Metadata: body})
				if err != nil || len(frame.Payload) > contracts.NativeControlBytes {
					t.Fatal("bounded reply does not fit native envelope", err)
				}
				for _, change := range []string{"source", "view", "version", "display", "pod"} {
					other := s
					switch change {
					case "source":
						other.NativeType, other.SourceFormat = artifact.SyscallRecordsArtifact, artifact.SyscallRecordsFormat
						if source == artifact.SyscallRecordsArtifact {
							other.NativeType, other.SourceFormat = artifact.SyscallArgumentsArtifact, artifact.SyscallArgumentsFormat
						}
					case "view":
						other.Syscalls.View = query.SyscallSummaryView
						if view == query.SyscallSummaryView {
							other.Syscalls.View = query.SyscallEventsView
						}
						other.DisplayVersion = other.Syscalls.View.DisplayVersion()
					case "version":
						other.Version = artifact.Digest{2}
					case "display":
						other.DisplayVersion = query.ContextDisplayVersion
					case "pod":
						if view == query.SyscallSummaryView {
							continue // summary contains no independently assertable Pod field
						}
						other.PodUID = "other-pod"
					}
					if _, err := decodeProjectionResult(body, other); err == nil {
						t.Fatal("reply crossed source scope", change)
					}
				}
				if _, err := decodeProjectionResult(body, resultScope()); err == nil {
					t.Fatal("syscall reply substituted for historical pod-status")
				}
			})
		}
	}
}

func TestSyscallProjectionPayloadClosedRefusalsAndNulls(t *testing.T) {
	for _, source := range []string{artifact.SyscallRecordsArtifact, artifact.SyscallArgumentsArtifact} {
		for _, view := range []query.SyscallView{query.SyscallSummaryView, query.SyscallEventsView} {
			s, result := syscallResultFixture(t, source, view)
			for _, refusal := range []query.ProjectionResult{{InvalidCursor: true}, {TooLarge: true}} {
				body, err := encodeProjectionResult(refusal, s)
				if err != nil {
					t.Fatal(err)
				}
				back, err := decodeProjectionResult(body, s)
				if err != nil || !reflect.DeepEqual(back, refusal) {
					t.Fatal("refusal lost exclusivity", back, err)
				}
			}
			body, err := encodeProjectionResult(result, s)
			if err != nil {
				t.Fatal(err)
			}
			versionJSON, _ := json.Marshal(s.Version)
			for name, malformed := range map[string][]byte{
				"null":             []byte(`null`),
				"empty":            []byte(`{}`),
				"null-version":     bytes.Replace(body, append([]byte(`"Version":`), versionJSON...), []byte(`"Version":null`), 1),
				"noncanonical":     append([]byte(" "), body...),
				"unknown-member":   append(bytes.Clone(body[:len(body)-1]), []byte(`,"Arguments":["secret"]}`)...),
				"duplicate-member": append(bytes.Clone(body[:len(body)-1]), []byte(`,"View":"`+string(view)+`"}`)...),
				"page-and-refusal": append(bytes.Clone(body[:len(body)-1]), []byte(`,"InvalidCursor":true}`)...),
				"oversized":        append(bytes.Repeat([]byte(" "), query.ContextResultBytes), body...),
			} {
				if _, err := decodeProjectionResult(malformed, s); err == nil {
					t.Fatal("accepted malformed syscall result", source, view, name)
				}
			}
			reply := syscallProjectionReply{NativeType: source, View: view, Version: s.Version}
			for _, mutate := range []func(*syscallProjectionReply){
				func(r *syscallProjectionReply) { r.InvalidCursor, r.TooLarge = true, true },
				func(r *syscallProjectionReply) {
					_, summary := syscallResultFixture(t, source, query.SyscallSummaryView)
					_, events := syscallResultFixture(t, source, query.SyscallEventsView)
					r.Summary, r.Events = summary.SyscallSummary, events.SyscallEvents
				},
				func(r *syscallProjectionReply) {
					if view == query.SyscallSummaryView {
						r.Summary = &query.SyscallSummaryPage{Version: s.Version}
					} else {
						r.Events = &query.SyscallEventPage{Version: s.Version}
					}
				},
			} {
				changed := reply
				mutate(&changed)
				malformed, _ := json.Marshal(changed)
				if _, err := decodeProjectionResult(malformed, s); err == nil {
					t.Fatal("accepted mixed refusal/view or null rows", string(malformed))
				}
			}
			for _, invalid := range []query.ProjectionResult{{}, {InvalidCursor: true, TooLarge: true}, {SyscallSummary: result.SyscallSummary, SyscallEvents: result.SyscallEvents, InvalidCursor: true}} {
				if _, err := encodeProjectionResult(invalid, s); err == nil {
					t.Fatal("encoded an invalid result union")
				}
			}
		}
	}
}

func TestSyscallProjectionPayloadNeverTrimsOversizedSelectedPage(t *testing.T) {
	for _, view := range []query.SyscallView{query.SyscallSummaryView, query.SyscallEventsView} {
		s, result := syscallResultFixture(t, artifact.SyscallArgumentsArtifact, view)
		if view == query.SyscallSummaryView {
			result.SyscallSummary.Rows = nil
			result.SyscallSummary.Total, result.SyscallSummary.RecordCount = 100, 100
			for i := range 100 {
				result.SyscallSummary.Rows = append(result.SyscallSummary.Rows, query.SyscallCount{Syscall: strings.Repeat("\x00", 63) + string(rune(i+1)), Count: 1})
			}
		} else {
			row := result.SyscallEvents.Events[0]
			row.Identity.ProcessRef, row.Identity.ThreadRef = strings.Repeat("\x00", 128), strings.Repeat("\x00", 128)
			result.SyscallEvents.Events = nil
			result.SyscallEvents.TotalMatching, result.SyscallEvents.RecordCount = 100, 100
			for range 100 {
				result.SyscallEvents.Events = append(result.SyscallEvents.Events, row)
			}
		}
		if !result.Valid(s) {
			t.Fatal("oversized fixture is structurally invalid")
		}
		if body, err := encodeProjectionResult(result, s); err == nil || body != nil {
			t.Fatal("oversized selected page silently trimmed/emitted", view, err, len(body))
		}
		reply := syscallProjectionReply{NativeType: s.NativeType, View: view, Version: s.Version, Summary: result.SyscallSummary, Events: result.SyscallEvents}
		body, _ := json.Marshal(reply)
		if len(body) <= query.ContextResultBytes {
			t.Fatal("fixture does not exceed wire bound")
		}
		if _, err := decodeProjectionResult(body, s); err == nil {
			t.Fatal("oversized received reply accepted")
		}
		if view == query.SyscallSummaryView && len(result.SyscallSummary.Rows) != 100 || view == query.SyscallEventsView && len(result.SyscallEvents.Events) != 100 {
			t.Fatal("codec mutated selected prefix")
		}
	}
}

func TestSyscallProjectionPayloadAllowsExplicitEmptyLists(t *testing.T) {
	for _, view := range []query.SyscallView{query.SyscallSummaryView, query.SyscallEventsView} {
		s, result := syscallResultFixture(t, artifact.SyscallRecordsArtifact, view)
		if view == query.SyscallSummaryView {
			result.SyscallSummary = &query.SyscallSummaryPage{Version: s.Version, Rows: []query.SyscallCount{}}
		} else {
			result.SyscallEvents = &query.SyscallEventPage{Version: s.Version, Events: []artifact.SyscallMetadataEvent{}}
		}
		body, err := encodeProjectionResult(result, s)
		if err != nil {
			t.Fatal("explicit empty display refused", err)
		}
		if back, err := decodeProjectionResult(body, s); err != nil || !reflect.DeepEqual(back, result) {
			t.Fatal("empty display changed", back, err)
		}
	}
}

func TestSyscallProjectionPayloadBoundIncludesReplyEnvelope(t *testing.T) {
	s, result := syscallResultFixture(t, artifact.SyscallArgumentsArtifact, query.SyscallEventsView)
	row := result.SyscallEvents.Events[0]
	row.Identity.ProcessRef, row.Identity.ThreadRef = strings.Repeat("x", 110), strings.Repeat("y", 110)
	result.SyscallEvents.Events = nil
	result.SyscallEvents.TotalMatching, result.SyscallEvents.RecordCount = 63, 63
	for range 63 {
		result.SyscallEvents.Events = append(result.SyscallEvents.Events, row)
	}
	page, _ := json.Marshal(result.SyscallEvents)
	reply, _ := json.Marshal(syscallProjectionReply{NativeType: s.NativeType, View: s.Syscalls.View, Version: s.Version, Events: result.SyscallEvents})
	if len(page) > query.ContextResultBytes || len(reply) <= query.ContextResultBytes || !result.Valid(s) {
		t.Fatalf("fixture must cross only the reply boundary: page=%d reply=%d", len(page), len(reply))
	}
	if body, err := encodeProjectionResult(result, s); err == nil || body != nil {
		t.Fatal("inner page bound incorrectly used for complete reply", err)
	}
}
