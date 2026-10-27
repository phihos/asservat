// Package packets holds the user-space packet steps of a networkHeaders
// capture (ADR-248): the hub-compiled classic BPF filter run on each frame,
// truncation to the end of the transport header, PCAPNG writing and the
// verifier's headers-only recheck. Decoding uses the maintained gopacket
// layers; this package parses no protocol itself. The kernel side is
// Inspektor Gadget's published tcpdump gadget (internal/adapters/gadget).
package packets

import (
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

// Snaplen is the gadget's capture length for networkHeaders: Ethernet (14)
// plus the largest IPv4 header (60) plus the largest TCP header (60). Every
// frame the sanitizer can accept fits; IPv6 (40 + 60) needs less.
const Snaplen = 14 + 60 + 60

// Drop is why a frame was not retained. The counters of a capture name each.
type Drop string

const (
	DropNone        Drop = ""
	DropFiltered    Drop = "filtered"
	DropUnsupported Drop = "unsupported" // not Ethernet + IPv4/IPv6 + TCP/UDP/ICMP
	DropFragment    Drop = "fragment"    // IPv4 fragment
	DropExtension   Drop = "extension"   // IPv6 extension header
	DropMalformed   Drop = "malformed"   // a header the decoder could not read
)

// decoder decodes one frame into its fixed layer slots; it is not safe for
// concurrent use, so each capture and each verification owns one.
type decoder struct {
	eth     layers.Ethernet
	ip4     layers.IPv4
	ip6     layers.IPv6
	tcp     layers.TCP
	udp     layers.UDP
	icmp4   layers.ICMPv4
	icmp6   layers.ICMPv6
	parser  *gopacket.DecodingLayerParser
	decoded []gopacket.LayerType
}

func newDecoder() *decoder {
	d := &decoder{decoded: make([]gopacket.LayerType, 0, 4)}
	d.parser = gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &d.eth, &d.ip4, &d.ip6, &d.tcp, &d.udp, &d.icmp4, &d.icmp6)
	d.parser.IgnoreUnsupported = true
	return d
}

// headerLength returns how many leading bytes of frame are Ethernet, IP and
// transport headers, or why the frame is not retained. Only Ethernet II with
// an unfragmented IPv4 packet (options allowed: they are header fields) or an
// IPv6 packet without extension headers, carrying TCP, UDP, ICMP or ICMPv6,
// is accepted. ICMP keeps its fixed header only: an error message's quoted
// datagram is payload.
func (d *decoder) headerLength(frame []byte) (int, Drop) {
	d.decoded = d.decoded[:0]
	if err := d.parser.DecodeLayers(frame, &d.decoded); err != nil {
		return 0, DropMalformed
	}
	if len(d.decoded) < 2 || d.decoded[0] != layers.LayerTypeEthernet {
		return 0, DropUnsupported
	}
	n := len(d.eth.Contents)
	switch d.decoded[1] {
	case layers.LayerTypeIPv4:
		if d.ip4.Flags&layers.IPv4MoreFragments != 0 || d.ip4.FragOffset != 0 {
			return 0, DropFragment
		}
		n += len(d.ip4.Contents)
	case layers.LayerTypeIPv6:
		switch d.ip6.NextHeader {
		case layers.IPProtocolTCP, layers.IPProtocolUDP, layers.IPProtocolICMPv6:
		default:
			return 0, DropExtension
		}
		n += len(d.ip6.Contents)
	default:
		return 0, DropUnsupported
	}
	if len(d.decoded) != 3 {
		return 0, DropUnsupported
	}
	switch d.decoded[2] {
	case layers.LayerTypeTCP:
		n += len(d.tcp.Contents)
	case layers.LayerTypeUDP:
		n += len(d.udp.Contents)
	case layers.LayerTypeICMPv4:
		if d.decoded[1] != layers.LayerTypeIPv4 {
			return 0, DropUnsupported
		}
		n += len(d.icmp4.Contents)
	case layers.LayerTypeICMPv6:
		if d.decoded[1] != layers.LayerTypeIPv6 {
			return 0, DropUnsupported
		}
		n += len(d.icmp6.Contents)
	default:
		return 0, DropUnsupported
	}
	if n > len(frame) || n > Snaplen {
		return 0, DropMalformed
	}
	return n, DropNone
}
