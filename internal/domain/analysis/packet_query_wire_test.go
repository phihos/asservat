package analysis_test

import (
	"asservat.local/asservat/internal/contracts"
	q "asservat.local/asservat/internal/domain/analysis"
	"encoding/json"
	"testing"
)

func TestPacketQueryPrimitiveEncodedSizeAgreesWithWire(t *testing.T) {
	for _, flag := range []bool{false, true} {
		zero := uint32(0)
		text := "2001:db8::1"
		r := q.PacketQueryResult{CaptureMode: "rawPackets", Fields: []q.PacketQueryField{q.PacketIndex, q.PacketSourceAddress}, Rows: [][]q.PacketQueryCell{{{Number: &zero}, {Text: &text}}, {{}, {}}}, ScannedBytes: 123456, ScannedPackets: 2, OutputLimitReached: flag}
		wire := contracts.PacketQueryPage{CaptureMode: r.CaptureMode, Fields: []string{"packet_index", "source_address"}, Rows: [][]contracts.PacketQueryCell{{{Number: &zero}, {Text: &text}}, {{}, {}}}, ScannedBytes: r.ScannedBytes, ScannedPackets: r.ScannedPackets, OutputLimitReached: flag}
		b, err := json.Marshal(wire)
		if err != nil || r.EncodedSize() != len(b) {
			t.Fatalf("page budget mismatch: got%d wire%d %s %v", r.EncodedSize(), len(b), b, err)
		}
	}
}
