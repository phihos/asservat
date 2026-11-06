package packets

import (
	v "asservat.local/asservat/internal/domain/live"
	"github.com/gopacket/gopacket/layers"
)

// LiveMetadata reuses the qualified header decoder. No application bytes,
// options, DNS, process strings or guessed remote endpoint are retained. Input
// and CPU/scan credit must be charged before invoking it, independently of rows.
type LiveProjector struct{ decoder *decoder }

func NewLiveProjector() *LiveProjector { return &LiveProjector{decoder: newDecoder()} }
func (p *LiveProjector) Metadata(frame []byte, wire uint32, directionKnown, ingress bool) (v.PacketFields, bool) {
	if !directionKnown || wire > 1048576 || int(wire) < len(frame) {
		return v.PacketFields{}, false
	}
	if p == nil || p.decoder == nil {
		return v.PacketFields{}, false
	}
	d := p.decoder
	defer func() {
		d.eth = layers.Ethernet{}
		d.ip4 = layers.IPv4{}
		d.ip6 = layers.IPv6{}
		d.tcp = layers.TCP{}
		d.udp = layers.UDP{}
		d.icmp4 = layers.ICMPv4{}
		d.icmp6 = layers.ICMPv6{}
	}()
	if _, reason := d.headerLength(frame); reason != DropNone {
		return v.PacketFields{}, false
	}
	out := v.PacketFields{Direction: "egress", WireBytes: int(wire)}
	if ingress {
		out.Direction = "ingress"
	}
	switch d.decoded[1] {
	case layers.LayerTypeIPv4:
		out.RemoteIP = d.ip4.DstIP.String()
		if ingress {
			out.RemoteIP = d.ip4.SrcIP.String()
		}
	case layers.LayerTypeIPv6:
		out.RemoteIP = d.ip6.DstIP.String()
		if ingress {
			out.RemoteIP = d.ip6.SrcIP.String()
		}
	default:
		return v.PacketFields{}, false
	}
	switch d.decoded[2] {
	case layers.LayerTypeTCP:
		out.Protocol = "TCP"
		out.RemotePort = int(d.tcp.DstPort)
		if ingress {
			out.RemotePort = int(d.tcp.SrcPort)
		}
	case layers.LayerTypeUDP:
		out.Protocol = "UDP"
		out.RemotePort = int(d.udp.DstPort)
		if ingress {
			out.RemotePort = int(d.udp.SrcPort)
		}
	case layers.LayerTypeICMPv4, layers.LayerTypeICMPv6:
		out.Protocol = "ICMP"
	default:
		return v.PacketFields{}, false
	}
	return out, true
}
