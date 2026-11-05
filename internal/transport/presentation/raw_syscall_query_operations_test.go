package presentation

import (
	identities "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/contracts"
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	value "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
)

type missingSyscallApproval struct{}

func (missingSyscallApproval) Error() string                         { return "approval required" }
func (missingSyscallApproval) RawSyscallQueryApprovalRequired() bool { return true }

type syscallMissingAuthority struct{ *bridgeFixture }

func (f syscallMissingAuthority) ResolveProjectionCurrent(context.Context, identities.CurrentIdentity, value.ContextProjectionCandidate) (value.ContextProjectionAuthority, error) {
	return value.ContextProjectionAuthority{}, missingSyscallApproval{}
}

func TestRawSyscallQueryMissingApprovalRemedyHasNoEffects(t *testing.T) {
	s, f, audit, input := rawSyscallBridgeFixture(t, 1)
	f.s.Results.Authority = syscallMissingAuthority{f}
	reads, _ := f.s.RawSyscallQueries()
	adapter, err := NewContextProjectionOperations(f.s, f.s.Results)
	if err == nil {
		adapter, err = adapter.WithRawSyscallQueries(reads)
	}
	if err != nil {
		t.Fatal(err)
	}
	// Replace the already configured adapter with the actual missing-proof path.
	s.inner.(*projectionAuditTarget).adapter = adapter
	var request map[string]any
	if json.Unmarshal(input, &request) != nil {
		t.Fatal("fixture input")
	}
	delete(request, "grant_id")
	input, _ = json.Marshal(request)
	reply, err := s.Call(t.Context(), f, "syscall_query", input)
	if err != nil {
		t.Fatal("approval remedy", err)
	}
	defer reply.Close(context.Background())
	var out struct {
		Status string `json:"status"`
		Data   struct {
			Code string `json:"code"`
			Role string `json:"responsible_role"`
		} `json:"data"`
	}
	if json.Unmarshal(reply.Body, &out) != nil || out.Status != "error" || out.Data.Code != "RawApprovalRequired" || out.Data.Role != "approver" || f.admissions+f.starts+f.batches+f.reads != 0 || len(audit.outcomes) != 1 || audit.outcomes[0].Effect != "none" {
		t.Fatalf("missing approval caused effects or lost its remedy: %s", reply.Body)
	}
}

func TestRawSyscallQueryRejectsWrongSourceAndMalformedPaidResults(t *testing.T) {
	for _, name := range []string{"version", "pod", "noncanonical-buffer", "truncated-scalar", "metadata-result"} {
		t.Run(name, func(t *testing.T) {
			s, f, _, input := rawSyscallBridgeFixture(t, 1)
			f.ready = true
			event := artifact.RawArgumentEvent{Identity: artifact.ArgumentIdentity{PodUID: f.a.Scope.PodUID, ProcessRef: "process", ThreadRef: "thread"}, Syscall: "write", ABI: "x86_64", Timestamp: f.now.Format(time.RFC3339Nano), Outcome: "unfinished", Arguments: []artifact.ArgumentValue{{Name: "buffer", Value: "base64:c2VjcmV0"}}}
			page := &value.SyscallArgumentPage{Version: f.a.Scope.Version, TotalMatching: 1, Events: []artifact.RawArgumentEvent{event}, SyscallRecordCounts: value.SyscallRecordCounts{RecordCount: 1, UnfinishedEvents: 1}}
			f.result = &value.ProjectionResult{SyscallQuery: page}
			switch name {
			case "version":
				page.Version[0] ^= 1
			case "pod":
				page.Events[0].Identity.PodUID = "another-pod"
			case "noncanonical-buffer":
				page.Events[0].Arguments[0].Value = "base64:c2VjcmV0\n"
			case "truncated-scalar":
				page.Events[0].Arguments = []artifact.ArgumentValue{{Name: "fd", Value: "decimal:0", Truncated: true}}
			case "metadata-result":
				f.result = &value.ProjectionResult{PodStatus: bridgeProjection(f.now)}
			}
			reply, err := s.Call(t.Context(), f, "syscall_query", input)
			if len(reply.Body) != 0 {
				defer reply.Close(context.Background())
				var out struct {
					Status string `json:"status"`
				}
				if json.Unmarshal(reply.Body, &out) != nil || out.Status != "error" || strings.Contains(string(reply.Body), "c2VjcmV0") {
					t.Fatalf("invalid paid result escaped: %s", reply.Body)
				}
			} else if err == nil {
				t.Fatal("missing refusal")
			}
			if f.reads != 1 || f.lastRead == nil || !f.lastRead.closed {
				t.Fatal("paid invalid result was not joined", f.reads)
			}
		})
	}
}

func rawSyscallBridgeFixture(t *testing.T, limit int) (*AuditedOperations, *bridgeFixture, *presentationAuditGate, []byte) {
	t.Helper()
	s, f, audit, target := bridgeAuditFixture(t)
	f.ready = false
	source, ok := value.LookupProjectionSourceFor(artifact.SyscallArgumentsArtifact, value.SyscallQueryDisplayVersion)
	if !ok {
		t.Fatal("raw syscall source unavailable")
	}
	selection, err := value.NormalizeSyscallSelection(bridgeID, bridgeID, value.SyscallQueryView, "", limit, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	f.a.Scope.NativeType, f.a.Scope.SourceFormat, f.a.Scope.DisplayVersion = source.NativeType, source.Format, source.DisplayVersion
	f.a.Scope.SourceProjectionDigest, f.a.Scope.Selection = source.ProjectionDigest, value.LineSelection{}
	f.a.Scope.Syscalls, f.a.Scope.RawGrantID = selection.Window(), f.next()
	f.a.Grant = value.ContextQueryGrant{ParentID: f.a.Scope.RawGrantID, ChildID: f.next()}
	f.p.Profile.Worker.MemoryBytes, f.p.Profile.Worker.WorkerTransientBytes = value.SyscallQueryWorkerBytes, value.SyscallQueryWorkerBytes
	f.s.SyscallRoutes, f.s.Results.Ledger = f, newPacketBridgePort(f)
	reads, _ := f.s.RawSyscallQueries()
	adapter, err := NewContextProjectionOperations(f.s, f.s.Results)
	if err == nil {
		target.adapter, err = adapter.WithRawSyscallQueries(reads)
	}
	if err != nil {
		t.Fatal(err)
	}
	input, _ := json.Marshal(map[string]any{"case_id": bridgeID, "artifact_id": bridgeID, "grant_id": f.a.Scope.RawGrantID, "idempotency_key": "original-raw-call-page", "limit": limit})
	return s, f, audit, input
}

func TestRawSyscallQueryActualAuditedBeginReplayAndPoll(t *testing.T) {
	s, f, audit, input := rawSyscallBridgeFixture(t, 1)
	first, err := s.Call(t.Context(), f, "syscall_query", input)
	if err != nil {
		t.Fatal("raw query must reach its actual audited admission", err)
	}
	if err = first.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	replay, err := s.Call(t.Context(), f, "syscall_query", input)
	if err != nil {
		t.Fatal("same-key replay", err)
	}
	if err = replay.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if f.admissions != 1 || f.starts != 1 || f.reads != 0 || f.polls != 0 || len(audit.outcomes) != 2 || audit.outcomes[1].Effect != "none" {
		t.Fatal("raw replay repeated work or disclosure", f.admissions, f.starts, f.reads, f.polls)
	}
	f.ready = true
	event := artifact.RawArgumentEvent{Identity: artifact.ArgumentIdentity{PodUID: f.a.Scope.PodUID, ProcessRef: "process", ThreadRef: "thread"}, Syscall: "write", ABI: "x86_64", Timestamp: f.now.Format(time.RFC3339Nano), Outcome: "unfinished", Arguments: []artifact.ArgumentValue{{Name: "fd", Value: "decimal:0"}, {Name: "buffer", Value: "base64:"}}}
	f.result = &value.ProjectionResult{SyscallQuery: &value.SyscallArgumentPage{Version: f.a.Scope.Version, TotalMatching: 2, Events: []artifact.RawArgumentEvent{event}, SyscallRecordCounts: value.SyscallRecordCounts{RecordCount: 2, UnfinishedEvents: 2}}}
	page, err := s.Call(t.Context(), f, "get_query_result", bridgePoll(f.q.ID))
	if err != nil {
		t.Fatal("raw poll", err)
	}
	defer page.Close(context.Background())
	var out struct {
		DataClass string `json:"data_class"`
		Truncated bool   `json:"truncated"`
		Data      struct {
			Result struct {
				DataClass string  `json:"data_class"`
				Truncated bool    `json:"truncated"`
				Cursor    *string `json:"next_cursor"`
				Data      struct {
					Events []artifact.RawArgumentEvent `json:"events"`
					Kind   string                      `json:"kind"`
				} `json:"data"`
			} `json:"result"`
		} `json:"data"`
	}
	if json.Unmarshal(page.Body, &out) != nil || out.DataClass != "raw" || out.Truncated || out.Data.Result.DataClass != "raw" || !out.Data.Result.Truncated || out.Data.Result.Cursor == nil || out.Data.Result.Data.Kind != "syscallQuery" || len(out.Data.Result.Data.Events) != 1 || out.Data.Result.Data.Events[0].Arguments[0].Value != "decimal:0" || out.Data.Result.Data.Events[0].Arguments[1].Value != "base64:" {
		t.Fatalf("raw nested reply lost classification, whole-event cursor or recorded values: %s", page.Body)
	}
}

// Conservative hostile structured metadata is wider than the qualified native
// engine's identity grammar. This proves encoded wrapper bounds, not native
// acquisition of this shape or a million-record source.
func TestRawSyscallQueryMaximumAdmittedPageFitsDirectAndNested(t *testing.T) {
	for _, nested := range []bool{false, true} {
		t.Run(map[bool]string{false: "direct", true: "nested"}[nested], func(t *testing.T) {
			s, f, _, input := rawSyscallBridgeFixture(t, 100)
			duration := uint64(time.Minute)
			event := artifact.RawArgumentEvent{Identity: artifact.ArgumentIdentity{PodUID: f.a.Scope.PodUID, ProcessRef: strings.Repeat("<", 128), ThreadRef: strings.Repeat(">", 128)}, Syscall: strings.Repeat("<", 64), ABI: "x86_64", Timestamp: f.now.Format(time.RFC3339Nano), DurationNS: &duration, Outcome: "error", Errno: strings.Repeat("<", 32), Arguments: []artifact.ArgumentValue{{Name: "fd", Value: "decimal:-2147483648"}, {Name: "count", Value: "decimal:18446744073709551615"}, {Name: "offset", Value: "decimal:-9223372036854775808"}, {Name: "flags", Value: "decimal:4294967295"}, {Name: "mode", Value: "decimal:4294967295"}, {Name: "buffer", Value: "base64:" + base64.StdEncoding.EncodeToString([]byte(strings.Repeat("x", 128))), Truncated: true}}}
			if !event.WellFormed() {
				t.Fatal("maximal closed event invalid")
			}
			page := value.SyscallArgumentPage{Version: f.a.Scope.Version, TotalMatching: 1_000_000, Events: []artifact.RawArgumentEvent{}, SyscallRecordCounts: value.SyscallRecordCounts{RecordCount: 1_000_000}}
			for len(page.Events) < 100 {
				page.Events = append(page.Events, event)
				if page.EncodedSize() > value.SyscallQueryPageBytes {
					page.Events = page.Events[:len(page.Events)-1]
					break
				}
			}
			selected := f.a.Scope.Syscalls.Selection(f.a.Scope.CaseID, f.a.Scope.ArtifactID)
			if len(page.Events) < 2 || !page.ValidShape(selected, f.a.Scope.Version, f.a.Scope.PodUID) {
				t.Fatal("invalid bounded page", len(page.Events), page.EncodedSize())
			}
			admitted := len(page.Events)
			f.result = &value.ProjectionResult{SyscallQuery: &page}
			f.ready = !nested
			reply, err := s.Call(t.Context(), f, "syscall_query", input)
			if err != nil {
				t.Fatal("begin", err)
			}
			if nested {
				if err = reply.Close(context.Background()); err != nil {
					t.Fatal(err)
				}
				f.ready = true
				reply, err = s.Call(t.Context(), f, "get_query_result", bridgePoll(f.q.ID))
			}
			if err != nil {
				t.Fatal("paid maximum page", err)
			}
			defer reply.Close(context.Background())
			if len(reply.Body) > contracts.InvestigationOutputLimit {
				t.Fatal("public envelope too large", len(reply.Body))
			}
			var envelope map[string]json.RawMessage
			if json.Unmarshal(reply.Body, &envelope) != nil {
				t.Fatal("bad reply")
			}
			if nested {
				var data struct {
					Result map[string]json.RawMessage `json:"result"`
				}
				if json.Unmarshal(envelope["data"], &data) != nil {
					t.Fatal("bad nested reply")
				}
				envelope = data.Result
			}
			var data struct {
				Events []artifact.RawArgumentEvent `json:"events"`
			}
			var cursor string
			var hint string
			if json.Unmarshal(envelope["data"], &data) != nil || len(data.Events) != admitted || json.Unmarshal(envelope["next_cursor"], &cursor) != nil || cursor == "" || json.Unmarshal(envelope["narrowing_hint"], &hint) != nil || hint == "" {
				t.Fatal("admitted rows or continuation lost", admitted, len(data.Events))
			}
			t.Logf("private=%d rows=%d complete public=%d nested=%t", page.EncodedSize(), admitted, len(reply.Body), nested)
		})
	}
}
