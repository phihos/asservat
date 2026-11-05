package presentation

import (
	"context"
	"encoding/json"
	"testing"

	value "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/identity"
)

type rawPacketBridgeRoutes struct{ *bridgeFixture }

func (r rawPacketBridgeRoutes) ResolvePacketProjectionRoute(context.Context, string, string, identity.Identity, artifact.RecoveryProof) (value.ContextProjectionCandidate, error) {
	return r.a.Scope.Candidate(), nil
}

func rawPacketSummaryBridge(t *testing.T, unclassified int64) (*AuditedOperations, *bridgeFixture) {
	t.Helper()
	s, f, _, p := packetSummaryBridge(t)
	f.a.Scope.NativeType, f.a.Scope.SourceFormat, f.a.Scope.DisplayVersion = artifact.RawPCAPNGArtifact, artifact.RawPCAPNGFormat, value.RawPacketSummaryDisplayVersion
	f.s.PacketRoutes = rawPacketBridgeRoutes{f}
	reads, ok := f.s.PacketSummaries()
	if !ok {
		t.Fatal("raw packet summary route missing")
	}
	adapter, err := NewContextProjectionOperations(f.s, f.s.Results)
	if err == nil {
		p.adapter, err = adapter.WithPacketSummaries(reads)
	}
	if err != nil {
		t.Fatal(err)
	}
	summary := &value.PacketSummary{CaptureMode: "rawPackets", Packets: 5, UnclassifiedPackets: &unclassified,
		DropReporting: "unavailable", Conversations: []value.PacketConversation{}}
	if classified := summary.Packets - unclassified; classified > 0 {
		summary.ConversationsTotal = 1
		summary.Conversations = append(summary.Conversations, value.PacketConversation{Source: "192.0.2.1:40000", Destination: "192.0.2.2:443", Protocol: "TCP", Packets: classified})
	}
	f.result = &value.ProjectionResult{PacketSummary: summary}
	return s, f
}

func TestRawPacketSummaryAuditedReadyPollPreservesCoverage(t *testing.T) {
	for _, unclassified := range []int64{0, 2, 5} {
		t.Run(string(rune('0'+unclassified)), func(t *testing.T) {
			s, f := rawPacketSummaryBridge(t, unclassified)
			f.ready = false
			pending, err := s.Call(t.Context(), f, "get_pcap_summary", bridgeInput())
			if err != nil {
				t.Fatal("raw begin", err)
			}
			if err := pending.Close(context.Background()); err != nil {
				t.Fatal(err)
			}
			f.ready = true
			ready, err := s.Call(t.Context(), f, "get_query_result", bridgePoll(f.q.ID))
			if err != nil {
				t.Fatal("raw ready", err)
			}
			defer ready.Close(context.Background())
			if s.contracts.ValidateOutput("get_query_result", ready.Body) != nil || f.reads != 1 || f.starts != 1 || f.admissions != 1 {
				t.Fatal("raw poll lost canonical audited read")
			}
			var out struct {
				Data struct {
					Tool   string `json:"tool_name"`
					Result struct {
						DataClass string              `json:"data_class"`
						Data      value.PacketSummary `json:"data"`
					} `json:"result"`
				} `json:"data"`
			}
			if json.Unmarshal(ready.Body, &out) != nil || out.Data.Tool != "get_pcap_summary" || out.Data.Result.DataClass != "extract" ||
				!out.Data.Result.Data.Valid() || out.Data.Result.Data.CaptureMode != "rawPackets" ||
				out.Data.Result.Data.UnclassifiedPackets == nil || *out.Data.Result.Data.UnclassifiedPackets != unclassified || out.Data.Result.Data.Packets != 5 {
				t.Fatal("raw prefix coverage was changed or omitted")
			}
		})
	}
}

func TestRawPacketSummaryAuditedDeliveryRejectsMetadataResult(t *testing.T) {
	s, f := rawPacketSummaryBridge(t, 0)
	f.result.PacketSummary.CaptureMode, f.result.PacketSummary.UnclassifiedPackets = "networkHeaders", nil
	if reply, err := s.Call(t.Context(), f, "get_pcap_summary", bridgeInput()); err == nil || len(reply.Body) != 0 || f.reads != 1 {
		t.Fatal("raw source delivered the wrong approved model", err, f.reads)
	}
}
