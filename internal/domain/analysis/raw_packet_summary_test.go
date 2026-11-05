package analysis

import (
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"bytes"
	"encoding/json"
	"testing"
)

func TestRawPacketSummaryCountsUnclassifiedRecords(t *testing.T) {
	var summary PacketSummary
	if err := json.Unmarshal([]byte(`{"capture_mode":"rawPackets","packets":3,"drops":null,"drop_reporting":"unavailable","unclassified_packets":2,"conversations":[{"source":"192.0.2.1:1","destination":"192.0.2.2:2","protocol":"TCP","packets":1}],"conversations_total":1,"conversations_truncated":false}`), &summary); err != nil {
		t.Fatal(err)
	}
	if !summary.Valid() {
		t.Fatal("closed raw aggregate with explicit unclassified records refused")
	}
	scope := packetProjectionScope()
	scope.NativeType, scope.SourceFormat, scope.DisplayVersion = artifact.RawPCAPNGArtifact, artifact.RawPCAPNGFormat, "approved-raw-pcap-summary/v1"
	if !scope.Valid() || !(ProjectionResult{PacketSummary: &summary}).Valid(scope) {
		t.Fatal("exact raw summary scope/result refused")
	}
	if (ProjectionResult{PacketSummary: &summary}).Valid(packetProjectionScope()) {
		t.Fatal("raw result accepted for metadata source")
	}
}

func TestRawPacketSummaryModeCountsAndCloneRemainClosed(t *testing.T) {
	unknown := int64(1)
	original := PacketSummary{CaptureMode: "rawPackets", Packets: 1, UnclassifiedPackets: &unknown, DropReporting: "unavailable", Conversations: []PacketConversation{}}
	if !original.Valid() {
		t.Fatal("all-unclassified source refused")
	}
	cloned := ClonePacketSummary(original)
	*cloned.UnclassifiedPackets = 0
	if *original.UnclassifiedPackets != 1 || cloned.Valid() {
		t.Fatal("clone aliases raw count or invents classification")
	}
	for _, n := range []int64{-1, 2} {
		bad := ClonePacketSummary(original)
		bad.UnclassifiedPackets = &n
		if bad.Valid() {
			t.Fatal("invalid unclassified count", n)
		}
	}
	bad := ClonePacketSummary(original)
	bad.UnclassifiedPackets = nil
	if bad.Valid() {
		t.Fatal("raw unknown classification implied zero")
	}
	metadata := PacketSummary{CaptureMode: "networkHeaders", DropReporting: "unavailable", Conversations: []PacketConversation{}}
	b, _ := json.Marshal(metadata)
	if string(b) != `{"capture_mode":"networkHeaders","packets":0,"drops":null,"drop_reporting":"unavailable","conversations":[],"conversations_total":0,"conversations_truncated":false}` {
		t.Fatal("legacy metadata bytes changed")
	}
	metadata.UnclassifiedPackets = new(int64)
	if metadata.Valid() {
		t.Fatal("metadata accepted raw-only field")
	}
	zero := ClonePacketSummary(original)
	zero.Packets = 0
	*zero.UnclassifiedPackets = 0
	b, _ = json.Marshal(zero)
	if !zero.Valid() || !bytes.Contains(b, []byte(`"unclassified_packets":0`)) {
		t.Fatal("raw explicit zero omitted")
	}
	source, ok := LookupProjectionSource(artifact.RawPCAPNGArtifact)
	if !ok || source.ReadOperation() != authorization.ReadPacketSummary || source.OutputClass() != "extract" || source.DataClass != "raw" || source.NativeLimit != artifact.RecordingNativeLimit {
		t.Fatal("raw source authority/class widened", source)
	}
	if _, ok := LookupProjectionSourceFor(artifact.RawPCAPNGArtifact, PacketSummaryDisplayVersion); ok {
		t.Fatal("metadata version admitted raw")
	}
}
