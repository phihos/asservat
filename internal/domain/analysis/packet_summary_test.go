package analysis

import (
	"fmt"
	"testing"
)

func TestPacketSummaryClosedNumericShapeAndClone(t *testing.T) {
	drops := int64(2)
	original := PacketSummary{CaptureMode: "networkHeaders", Packets: 3, Drops: &drops, DropReporting: "captureExclusions", Conversations: []PacketConversation{{Source: "192.0.2.1:40000", Destination: "192.0.2.2:80", Protocol: "TCP", Packets: 3}}, ConversationsTotal: 1}
	if !original.Valid() {
		t.Fatal("valid closed summary refused")
	}
	copy := ClonePacketSummary(original)
	copy.Conversations[0].Packets = 2
	*copy.Drops = 9
	if original.Conversations[0].Packets != 3 || *original.Drops != 2 {
		t.Fatal("clone aliases result")
	}
	for _, mode := range []string{"raw", "missing-rows", "fake-zero", "unknown-reported", "negative", "hostname", "zone", "mapped", "wrong-protocol", "bad-port", "wrong-total", "wrong-truncation", "sum", "zero-row", "ranking", "duplicate"} {
		t.Run(mode, func(t *testing.T) {
			r := ClonePacketSummary(original)
			switch mode {
			case "raw":
				r.CaptureMode = "rawPackets"
			case "missing-rows":
				r.Conversations = nil
			case "fake-zero":
				r.Drops = nil
			case "unknown-reported":
				r.DropReporting = "unavailable"
			case "negative":
				*r.Drops = -1
			case "hostname":
				r.Conversations[0].Source = "app.internal:80"
			case "zone":
				r.Conversations[0].Source = "[fe80::1%eth0]:80"
			case "mapped":
				r.Conversations[0].Source = "[::ffff:192.0.2.1]:80"
			case "wrong-protocol":
				r.Conversations[0].Protocol = "HTTP"
			case "bad-port":
				r.Conversations[0].Destination = "192.0.2.2:65536"
			case "wrong-total":
				r.ConversationsTotal = 2
			case "wrong-truncation":
				r.ConversationsTruncated = true
			case "sum":
				r.Conversations[0].Packets = 2
			case "zero-row":
				r.Conversations[0].Packets = 0
			case "ranking":
				r.ConversationsTotal = 2
				r.Conversations[0].Packets = 1
				r.Conversations = append(r.Conversations, PacketConversation{Source: "192.0.2.2:2", Destination: "192.0.2.1:1", Protocol: "UDP", Packets: 2})
			case "duplicate":
				r.Conversations = append(r.Conversations, r.Conversations[0])
				r.ConversationsTotal = 2
				r.Packets = 6
			}
			if r.Valid() {
				t.Fatal("invalid summary accepted")
			}
		})
	}
	empty := PacketSummary{CaptureMode: "networkHeaders", DropReporting: "unavailable", Conversations: []PacketConversation{}}
	if !empty.Valid() {
		t.Fatal("honest unknown empty summary refused")
	}
}
func TestPacketSummaryBoundedPrefixAndRequest(t *testing.T) {
	r := PacketSummary{CaptureMode: "networkHeaders", Packets: 16384, DropReporting: "unavailable", ConversationsTotal: 16384, ConversationsTruncated: true}
	for i := 0; i < 100; i++ {
		r.Conversations = append(r.Conversations, PacketConversation{Source: fmt.Sprintf("192.0.2.1:%04d", 1000+i), Destination: "[2001:db8::1]:80", Protocol: "TCP", Packets: 1})
	}
	if !r.Valid() {
		t.Fatal("bounded prefix refused")
	}
	r.ConversationsTotal = PacketSummaryMaxAggregates + 1
	if r.Valid() {
		t.Fatal("aggregate work cap widened")
	}
	if !(PacketSummaryRequest{CaseID: "11111111-1111-4111-8111-111111111111", ArtifactID: "22222222-2222-4222-8222-222222222222"}).Valid() || (PacketSummaryRequest{}).Valid() {
		t.Fatal("request identity")
	}
}
