package presentation

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"

	analysisapp "asservat.local/asservat/internal/application/analysis"
	value "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/identity"
)

func (f *bridgeFixture) ResolveSyscallProjectionRoute(context.Context, string, string, identity.Identity, artifact.RecoveryProof) (value.ContextProjectionCandidate, error) {
	c := f.a.Scope.Candidate()
	c.Syscalls = value.SyscallWindow{}
	return c, nil
}
func syscallBridge(t *testing.T, kind string, view value.SyscallView) (*AuditedOperations, *bridgeFixture, *presentationAuditGate, *projectionAuditTarget) {
	t.Helper()
	s, f, g, p := bridgeAuditFixture(t)
	source, _ := value.LookupProjectionSourceFor(kind, view.DisplayVersion())
	selection, _ := value.NormalizeSyscallSelection(bridgeID, bridgeID, view, "", 2, nil, false)
	f.a.Scope.NativeType, f.a.Scope.SourceFormat, f.a.Scope.DisplayVersion, f.a.Scope.SourceProjectionDigest = source.NativeType, source.Format, source.DisplayVersion, source.ProjectionDigest
	f.a.Scope.Selection, f.a.Scope.Syscalls = value.LineSelection{}, selection.Window()
	f.p.Profile.Worker.MemoryBytes, f.p.Profile.Worker.WorkerTransientBytes = value.SyscallProjectionWorkerBytes, value.SyscallProjectionWorkerBytes
	f.s.SyscallRoutes = f
	reads, _ := f.s.SyscallQueries()
	adapter, e := NewContextProjectionOperations(f.s, f.s.Results)
	if e == nil {
		p.adapter, e = adapter.WithSyscalls(reads)
	}
	if e != nil {
		t.Fatal(e)
	}
	counts := value.SyscallRecordCounts{RecordCount: 3, UnknownEvents: 1}
	if view == value.SyscallSummaryView {
		f.result = &value.ProjectionResult{SyscallSummary: &value.SyscallSummaryPage{Version: f.a.Scope.Version, Total: 3, Rows: []value.SyscallCount{{Syscall: "close", Count: 1}, {Syscall: "read", Count: 1}}, SyscallRecordCounts: counts}}
	} else {
		event := artifact.SyscallMetadataEvent{Identity: artifact.SyscallMetadataIdentity{PodUID: f.a.Scope.PodUID, ProcessRef: "process", ThreadRef: "thread"}, Syscall: "read", ABI: "x86_64", Timestamp: f.now.Format("2006-01-02T15:04:05.999999999Z07:00"), Outcome: "unknown"}
		f.result = &value.ProjectionResult{SyscallEvents: &value.SyscallEventPage{Version: f.a.Scope.Version, TotalMatching: 3, Events: []artifact.SyscallMetadataEvent{event, event}, SyscallRecordCounts: counts}}
	}
	return s, f, g, p
}
func syscallInput(cursor string) []byte {
	b, _ := json.Marshal(SyscallOperationInput{CaseID: bridgeID, ArtifactID: bridgeID, Cursor: cursor, Limit: 2})
	return b
}

func TestSavedSyscallToolsAreOptIn(t *testing.T) {
	_, f, _, p := bridgeAuditFixture(t)
	for _, name := range []string{"get_syscall_summary", "get_syscall_events"} {
		if p.adapter.serves(name) || slices.Contains(p.adapter.toolNames(), name) {
			t.Fatal("uncomposed syscall tool enabled")
		}
	}
	if _, ok := f.s.SyscallQueries(); ok {
		t.Fatal("route implicitly enabled")
	}
}
func TestSavedSyscallAuditedPendingAndPollBothSourcesAndViews(t *testing.T) {
	for _, kind := range []string{artifact.SyscallRecordsArtifact, artifact.SyscallArgumentsArtifact} {
		for _, view := range []value.SyscallView{value.SyscallSummaryView, value.SyscallEventsView} {
			t.Run(kind+"/"+string(view), func(t *testing.T) {
				s, f, g, p := syscallBridge(t, kind, view)
				tool := "get_syscall_" + string(view)
				f.ready = false
				pending, e := s.Call(t.Context(), f, tool, syscallInput(""))
				if e != nil {
					t.Fatal("pending", e)
				}
				if s.contracts.ValidateOutput(tool, pending.Body) != nil || f.admissions != 1 || f.starts != 1 || f.reads != 0 || g.intents[0].InputFormat != "context-query-input/v1" {
					t.Fatal("pending binding")
				}
				if e = pending.Close(context.Background()); e != nil {
					t.Fatal(e)
				}
				f.ready = true
				ready, e := s.Call(t.Context(), f, "get_query_result", bridgePoll(f.q.ID))
				if e != nil {
					var stage interface{ FixedStep() string }
					if errors.As(e, &stage) {
						t.Fatal("poll", stage.FixedStep(), e)
					}
					t.Fatal("poll", e)
				}
				defer ready.Close(context.Background())
				var out struct {
					DataClass string `json:"data_class"`
					Data      struct {
						Tool   string `json:"tool_name"`
						Result struct {
							DataClass string  `json:"data_class"`
							Next      *string `json:"next_cursor"`
							Data      struct {
								Kind     string `json:"kind"`
								Coverage struct {
									Dropped *uint64 `json:"dropped_events"`
									Unknown uint64  `json:"unknown_events"`
									Records uint64  `json:"record_count"`
								} `json:"coverage"`
							} `json:"data"`
						} `json:"result"`
					} `json:"data"`
				}
				if json.Unmarshal(ready.Body, &out) != nil || out.DataClass != "extract" || out.Data.Tool != tool || out.Data.Result.DataClass != "extract" || out.Data.Result.Next == nil || out.Data.Result.Data.Coverage.Dropped != nil || out.Data.Result.Data.Coverage.Unknown != 1 || out.Data.Result.Data.Coverage.Records != 3 {
					t.Fatalf("bounded syscall envelope: %s", ready.Body)
				}
				if s.contracts.ValidateOutput("get_query_result", ready.Body) != nil || f.reads != 1 || f.starts != 1 || p.last.delivery.Tool() != tool || p.last.delivery.Association().Syscalls != f.q.Scope.Syscalls || ready.CheckDisclosure(t.Context()) != nil {
					t.Fatal("poll lost ownership")
				}
			})
		}
	}
}
func TestSavedSyscallInvocationRejectsChangesAndMixedLegacyInput(t *testing.T) {
	for _, mode := range []string{"names", "errors", "cursor", "limit", "artifact", "mixed"} {
		t.Run(mode, func(t *testing.T) {
			s, f, _, p := syscallBridge(t, artifact.SyscallArgumentsArtifact, value.SyscallEventsView)
			p.mutate = func(call *OperationCall, raw *json.RawMessage) {
				var in SyscallOperationInput
				_ = json.Unmarshal(*raw, &in)
				switch mode {
				case "names":
					in.Names = []string{"write"}
				case "errors":
					in.ErrorsOnly = true
				case "cursor":
					in.Cursor = "1:" + strings.Repeat("a", 32)
				case "limit":
					in.Limit = 1
				case "artifact":
					in.ArtifactID = f.next()
				case "mixed":
					request := value.SyscallQueryRequest{CaseID: bridgeID, ArtifactID: bridgeID, Selection: f.a.Scope.Syscalls}
					if call.queryInvocation.CheckInput(t.Context(), analysisapp.ContextQueryInput{Syscalls: request, QueryID: bridgeID}) == nil {
						t.Fatal("mixed query accepted")
					}
					call.queryInvocation = nil
				}
				*raw, _ = json.Marshal(in)
			}
			out, e := s.Call(t.Context(), f, "get_syscall_events", syscallInput(""))
			if e == nil || len(out.Body) != 0 || f.admissions+f.starts+f.reads != 0 {
				t.Fatal("changed input dispatched", e)
			}
		})
	}
}

func TestSavedSyscallPublicResponseBoundsPrefixAndCursor(t *testing.T) {
	s, f, _, _ := syscallBridge(t, artifact.SyscallArgumentsArtifact, value.SyscallEventsView)
	f.a.Scope.Syscalls.Limit = 100
	e := f.result.SyscallEvents.Events[0]
	e.Identity.ProcessRef, e.Identity.ThreadRef = strings.Repeat("<", 128), strings.Repeat("<", 128)
	f.result.SyscallEvents.Events = make([]artifact.SyscallMetadataEvent, 100)
	for i := range f.result.SyscallEvents.Events {
		f.result.SyscallEvents.Events[i] = e
	}
	f.result.SyscallEvents.TotalMatching, f.result.SyscallEvents.RecordCount = 100, 100
	// The coordinator independently rejects >24KiB worker results. Use a
	// structurally valid worker prefix that fits there, then verify the public
	// nested envelope may shorten it further without dropping a row.
	for {
		b, _ := json.Marshal(f.result.SyscallEvents)
		if len(b) < value.ContextResultBytes {
			break
		}
		f.result.SyscallEvents.Events = f.result.SyscallEvents.Events[:len(f.result.SyscallEvents.Events)-1]
	}
	input, _ := json.Marshal(SyscallOperationInput{CaseID: bridgeID, ArtifactID: bridgeID, Limit: 100})
	out, err := s.Call(t.Context(), f, "get_syscall_events", input)
	if err != nil {
		var stage interface{ FixedStep() string }
		if errors.As(err, &stage) {
			t.Fatal(stage.FixedStep(), err)
		}
		t.Fatal(err)
	}
	defer out.Close(context.Background())
	var result struct {
		Next string `json:"next_cursor"`
		Data struct {
			Events []artifact.SyscallMetadataEvent `json:"events"`
		} `json:"data"`
	}
	if json.Unmarshal(out.Body, &result) != nil || len(out.Body) > value.ContextResultBytes || len(result.Data.Events) == 0 || len(result.Data.Events) > len(f.result.SyscallEvents.Events) {
		t.Fatal("invalid public prefix")
	}
	next, err := value.NormalizeSyscallSelection(bridgeID, bridgeID, value.SyscallEventsView, result.Next, 100, nil, false)
	if err != nil || next.Start != len(result.Data.Events) || !next.Matches(f.a.Scope.Version) {
		t.Fatal("cursor skipped a row", next, err)
	}
}

func TestSavedSyscallEmptyFilterKeepsRecordedCountsAndUnknownCoverage(t *testing.T) {
	s, f, _, _ := syscallBridge(t, artifact.SyscallArgumentsArtifact, value.SyscallEventsView)
	f.a.Scope.Syscalls.Names[0], f.a.Scope.Syscalls.NameCount = "write", 1
	f.result.SyscallEvents.Events = []artifact.SyscallMetadataEvent{}
	f.result.SyscallEvents.TotalMatching = 0
	input, _ := json.Marshal(SyscallOperationInput{CaseID: bridgeID, ArtifactID: bridgeID, Limit: 2, Names: []string{"write"}})
	out, err := s.Call(t.Context(), f, "get_syscall_events", input)
	if err != nil {
		t.Fatal(err)
	}
	defer out.Close(context.Background())
	var page struct {
		Next *string `json:"next_cursor"`
		Data struct {
			Events   []artifact.SyscallMetadataEvent `json:"events"`
			Coverage struct {
				Records   uint64  `json:"record_count"`
				Dropped   *uint64 `json:"dropped_events"`
				Truncated *bool   `json:"truncated"`
				Unknown   uint64  `json:"unknown_events"`
			} `json:"coverage"`
		} `json:"data"`
	}
	if json.Unmarshal(out.Body, &page) != nil || page.Next != nil || page.Data.Events == nil || len(page.Data.Events) != 0 || page.Data.Coverage.Records != 3 || page.Data.Coverage.Unknown != 1 || page.Data.Coverage.Dropped != nil || page.Data.Coverage.Truncated != nil {
		t.Fatalf("empty display invented coverage: %s", out.Body)
	}
}

func TestSavedSyscallMalformedCursorRefusesBeforeEvidence(t *testing.T) {
	s, f, g, _ := syscallBridge(t, artifact.SyscallRecordsArtifact, value.SyscallSummaryView)
	out, err := s.Call(t.Context(), f, "get_syscall_summary", syscallInput("malformed"))
	if err != nil {
		t.Fatal(err)
	}
	defer out.Close(context.Background())
	var reply struct {
		Status string           `json:"status"`
		Data   OperationFailure `json:"data"`
	}
	if json.Unmarshal(out.Body, &reply) != nil || reply.Status != "error" || reply.Data.Code != "InvalidCursor" || f.admissions+f.reads+f.starts != 0 || len(g.outcomes) != 1 || g.outcomes[0].Effect != "none" {
		t.Fatal("malformed continuation accessed evidence")
	}
}
