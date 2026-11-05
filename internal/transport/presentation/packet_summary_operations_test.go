package presentation

import (
	analysisapp "asservat.local/asservat/internal/application/analysis"
	value "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"testing"
)

func packetSummaryBridge(t *testing.T) (*AuditedOperations, *bridgeFixture, *presentationAuditGate, *projectionAuditTarget) {
	t.Helper()
	s, f, g, p := bridgeAuditFixture(t)
	f.a.Scope.NativeType, f.a.Scope.SourceFormat, f.a.Scope.DisplayVersion = artifact.PCAPNGArtifact, artifact.PCAPNGFormat, value.PacketSummaryDisplayVersion
	f.a.Scope.SourceProjectionDigest, f.a.Scope.Selection = artifact.Digest{}, value.LineSelection{}
	f.p.Profile.Worker.MemoryBytes, f.p.Profile.Worker.WorkerTransientBytes = value.PacketSummaryWorkerBytes, value.PacketSummaryWorkerBytes
	f.s.PacketRoutes = f
	reads, ok := f.s.PacketSummaries()
	if !ok {
		t.Fatal("typed packet summary route missing")
	}
	adapter, err := NewContextProjectionOperations(f.s, f.s.Results)
	if err == nil {
		p.adapter, err = adapter.WithPacketSummaries(reads)
	}
	if err != nil {
		t.Fatal(err)
	}
	f.result = &value.ProjectionResult{PacketSummary: &value.PacketSummary{CaptureMode: "networkHeaders", DropReporting: "unavailable", Conversations: []value.PacketConversation{}}}
	return s, f, g, p
}

func TestPacketSummaryAuditedSelectionBindsExactSavedArtifact(t *testing.T) {
	s, f, _, p := packetSummaryBridge(t)
	var checked bool
	p.mutate = func(call *OperationCall, raw *json.RawMessage) {
		input := analysisapp.ContextQueryInput{Packet: value.PacketSummaryRequest{CaseID: bridgeID, ArtifactID: bridgeID}}
		if err := call.queryInvocation.CheckInput(t.Context(), input); err != nil {
			t.Fatal("exact saved-packet invocation was not bound", err)
		}
		checked = true
		input.QueryID = bridgeID
		if err := call.queryInvocation.CheckInput(t.Context(), input); err == nil {
			t.Fatal("packet request mixed with polling identity")
		}
		input.QueryID = ""
		input.Packet.ArtifactID = "00000000-0000-4000-8000-000000000099"
		if err := call.queryInvocation.CheckInput(t.Context(), input); err == nil {
			t.Fatal("changed packet artifact accepted")
		}
	}
	_, _ = s.Call(t.Context(), f, "get_pcap_summary", bridgeInput())
	if !checked {
		t.Fatal("saved packet operation never reached audited invocation")
	}
}

func TestPacketSummaryPendingReadyKeepsOriginalSourceAndAudit(t *testing.T) {
	s, f, g, p := packetSummaryBridge(t)
	f.ready = false
	first, err := s.Call(t.Context(), f, "get_pcap_summary", bridgeInput())
	if err != nil {
		t.Fatalf("begin %v %#v admissions=%d starts=%d reads=%d intents=%d", err, err, f.admissions, f.starts, f.reads, len(g.intents))
	}
	if s.contracts.ValidateOutput("get_pcap_summary", first.Body) != nil || f.admissions != 1 || f.starts != 1 || f.reads != 0 || g.intents[0].InputFormat != "context-query-input/v1" {
		t.Fatal("packet summary admission/audit missing")
	}
	_ = first.Close(context.Background())
	f.ready = true
	ready, err := s.Call(t.Context(), f, "get_query_result", bridgePoll(f.q.ID))
	if err != nil {
		t.Fatal("poll", err)
	}
	defer ready.Close(context.Background())
	var out struct {
		DataClass string `json:"data_class"`
		Data      struct {
			Tool   string `json:"tool_name"`
			Result struct {
				Data     value.PacketSummary `json:"data"`
				Warnings []string            `json:"warnings"`
			}
		}
	}
	if json.Unmarshal(ready.Body, &out) != nil || out.DataClass != "extract" || out.Data.Tool != "get_pcap_summary" || !out.Data.Result.Data.Valid() || len(out.Data.Result.Warnings) != 1 {
		t.Fatalf("closed packet output %s", ready.Body)
	}
	if s.contracts.ValidateOutput("get_query_result", ready.Body) != nil || f.reads != 1 || f.starts != 1 || p.last.delivery.Tool() != "get_pcap_summary" {
		t.Fatal("packet poll replaced admitted source")
	}
}

func TestPacketSummaryRequiresExplicitServiceAndClosedInput(t *testing.T) {
	_, f, _, p := bridgeAuditFixture(t)
	if p.adapter.serves("get_pcap_summary") || slices.Contains(p.adapter.toolNames(), "get_pcap_summary") {
		t.Fatal("packet source enabled without protected service")
	}
	wire := p.adapter.contracts
	for _, raw := range []string{
		`{"case_id":"00000000-0000-4000-8000-000000000001","artifact_id":"00000000-0000-4000-8000-000000000002","filter":"tcp"}`,
		`{"case_id":"00000000-0000-4000-8000-000000000001","artifact_id":"00000000-0000-4000-8000-000000000002","url":"http://127.0.0.1"}`,
	} {
		if wire.ValidateInput("get_pcap_summary", []byte(raw)) == nil {
			t.Fatal("free packet query input accepted")
		}
	}
	if f.admissions != 0 || f.starts != 0 || f.reads != 0 {
		t.Fatal("disabled packet service performed work")
	}
}

// Exercise populated producer shapes through the same audited ready-poll
// consumer as the installed worker. An empty summary cannot reveal endpoint,
// counter, truncation or complete-envelope budget mismatches.
func TestPacketSummaryPopulatedReadyPollFitsCanonicalEnvelope(t *testing.T) {
	for _, reporting := range []string{"unavailable", "captureExclusions", "snapshotOutputLimit"} {
		t.Run(reporting, func(t *testing.T) {
			s, f, _, _ := packetSummaryBridge(t)
			f.ready = false
			first, err := s.Call(t.Context(), f, "get_pcap_summary", bridgeInput())
			if err != nil {
				t.Fatal(err)
			}
			if err := first.Close(context.Background()); err != nil {
				t.Fatal(err)
			}
			summary := value.PacketSummary{CaptureMode: "networkHeaders", Packets: value.PacketSummaryMaxCount,
				DropReporting: reporting, ConversationsTotal: value.PacketSummaryMaxAggregates, ConversationsTruncated: true,
				Conversations: make([]value.PacketConversation, value.PacketSummaryMaxConversations)}
			if reporting != "unavailable" {
				drops := value.PacketSummaryMaxCount
				summary.Drops = &drops
			}
			for n := range summary.Conversations {
				summary.Conversations[n] = value.PacketConversation{
					Source:      fmt.Sprintf("[ffff:ffff:ffff:ffff:ffff:ffff:ffff:%x]:65535", n),
					Destination: "[ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff]:65535", Protocol: "TCP",
					Packets: value.PacketSummaryMaxCount / 1000,
				}
			}
			slices.SortFunc(summary.Conversations, func(a, b value.PacketConversation) int {
				if value.PacketConversationBefore(a, b) {
					return -1
				}
				return 1
			})
			if !summary.Valid() {
				t.Fatal("invalid producer fixture")
			}
			f.result, f.ready = &value.ProjectionResult{PacketSummary: &summary}, true
			ready, err := s.Call(t.Context(), f, "get_query_result", bridgePoll(f.q.ID))
			if err != nil {
				t.Fatal("populated ready transition", err)
			}
			defer ready.Close(context.Background())
			if err := s.contracts.ValidateOutput("get_query_result", ready.Body); err != nil {
				t.Fatal("canonical complete poll envelope", err)
			}
			var out struct {
				Data struct {
					Result struct {
						Data value.PacketSummary `json:"data"`
					} `json:"result"`
				} `json:"data"`
			}
			if json.Unmarshal(ready.Body, &out) != nil || !out.Data.Result.Data.Valid() || out.Data.Result.Data.DropReporting != reporting ||
				(out.Data.Result.Data.Drops == nil) != (summary.Drops == nil) || len(out.Data.Result.Data.Conversations) != 100 ||
				out.Data.Result.Data.ConversationsTotal != value.PacketSummaryMaxAggregates || !out.Data.Result.Data.ConversationsTruncated {
				t.Fatal("ready poll changed bounded producer result")
			}
		})
	}
}
