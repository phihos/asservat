package packets

import (
	"encoding/json"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"strings"
	"testing"
)

func TestLivePacketUsesPinnedDirectionAndQualifiedHeadersOnly(t *testing.T) {
	projector := NewLiveProjector()
	ip := ip4(layers.IPProtocolTCP)
	tcp := &layers.TCP{SrcPort: 1234, DstPort: 8080, SYN: true, Window: 1024}
	_ = tcp.SetNetworkLayerForChecksum(ip)
	raw := frame(t, eth(layers.EthernetTypeIPv4), ip, tcp, gopacket.Payload(marker))
	out, ok := projector.Metadata(raw, uint32(len(raw)), true, false)
	if !ok || out.RemoteIP != "192.0.2.2" || out.RemotePort != 8080 || out.Direction != "egress" || out.PID != nil || out.PeerUID != nil {
		t.Fatal(out, ok)
	}
	encoded, _ := json.Marshal(out)
	if strings.Contains(string(encoded), marker) {
		t.Fatal("application bytes retained")
	}
	if len(projector.decoder.tcp.Payload) != 0 || len(projector.decoder.eth.Contents) != 0 {
		t.Fatal("source frame retained after projection")
	}
	in, ok := projector.Metadata(raw, uint32(len(raw)), true, true)
	if !ok || in.RemoteIP != "192.0.2.1" || in.RemotePort != 1234 || in.Direction != "ingress" {
		t.Fatal(in, ok)
	}
	if _, ok = projector.Metadata(raw, uint32(len(raw)), false, false); ok {
		t.Fatal("remote endpoint guessed without direction")
	}
	if _, ok = projector.Metadata(raw[:13], uint32(len(raw)), true, false); ok {
		t.Fatal("incomplete Ethernet interpreted")
	}
}
