package packets

import (
	"bytes"
	"encoding/json"
	"errors"
	"net"
	"os"
	"testing"
	"time"

	value "asservat.local/asservat/internal/domain/planning"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

const marker = "SYNTHETIC-PAYLOAD-MARKER-ONLY"

var (
	srcMAC = net.HardwareAddr{0, 1, 2, 3, 4, 5}
	dstMAC = net.HardwareAddr{0, 1, 2, 3, 4, 6}
)

func frame(t *testing.T, ls ...gopacket.SerializableLayer) []byte {
	t.Helper()
	b := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(b, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, ls...); err != nil {
		t.Fatal(err)
	}
	return append([]byte(nil), b.Bytes()...)
}

func eth(t layers.EthernetType) *layers.Ethernet {
	return &layers.Ethernet{SrcMAC: srcMAC, DstMAC: dstMAC, EthernetType: t}
}

func ip4(p layers.IPProtocol) *layers.IPv4 {
	return &layers.IPv4{Version: 4, TTL: 64, Protocol: p, SrcIP: net.IP{192, 0, 2, 1}, DstIP: net.IP{192, 0, 2, 2}}
}

func ip6(p layers.IPProtocol) *layers.IPv6 {
	return &layers.IPv6{Version: 6, HopLimit: 64, NextHeader: p, SrcIP: net.ParseIP("2001:db8::1"), DstIP: net.ParseIP("2001:db8::2")}
}

func tcp4(t *testing.T, opts bool) []byte {
	ip := ip4(layers.IPProtocolTCP)
	tc := &layers.TCP{SrcPort: 40000, DstPort: 80, Seq: 1, SYN: false, ACK: true, PSH: true, Window: 512}
	if opts {
		tc.Options = []layers.TCPOption{{OptionType: layers.TCPOptionKindTimestamps, OptionLength: 10, OptionData: make([]byte, 8)}, {OptionType: layers.TCPOptionKindNop}, {OptionType: layers.TCPOptionKindNop}}
	}
	_ = tc.SetNetworkLayerForChecksum(ip)
	return frame(t, eth(layers.EthernetTypeIPv4), ip, tc, gopacket.Payload(bytes.Repeat([]byte(marker), 8)))
}

func corpus(t *testing.T) map[string][]byte {
	t.Helper()
	ip := ip6(layers.IPProtocolUDP)
	u := &layers.UDP{SrcPort: 5353, DstPort: 53}
	_ = u.SetNetworkLayerForChecksum(ip)
	frag := ip4(layers.IPProtocolUDP)
	frag.Flags = layers.IPv4MoreFragments
	u4 := &layers.UDP{SrcPort: 1, DstPort: 2}
	_ = u4.SetNetworkLayerForChecksum(frag)
	hop := ip6(layers.IPProtocolIPv6HopByHop)
	icmp6 := ip6(layers.IPProtocolICMPv6)
	vip := ip4(layers.IPProtocolUDP)
	vu := &layers.UDP{SrcPort: 1, DstPort: 2}
	_ = vu.SetNetworkLayerForChecksum(vip)
	echo6 := &layers.ICMPv6{TypeCode: layers.CreateICMPv6TypeCode(layers.ICMPv6TypeEchoRequest, 0)}
	_ = echo6.SetNetworkLayerForChecksum(icmp6)
	return map[string][]byte{
		"tcp4":     tcp4(t, false),
		"tcp4opts": tcp4(t, true),
		"udp6":     frame(t, eth(layers.EthernetTypeIPv6), ip, u, gopacket.Payload(marker)),
		"icmp4": frame(t, eth(layers.EthernetTypeIPv4), ip4(layers.IPProtocolICMPv4),
			&layers.ICMPv4{TypeCode: layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoRequest, 0), Id: 7, Seq: 1}, gopacket.Payload(marker)),
		"icmp6":    frame(t, eth(layers.EthernetTypeIPv6), icmp6, echo6, gopacket.Payload(marker)),
		"fragment": frame(t, eth(layers.EthernetTypeIPv4), frag, u4, gopacket.Payload(marker)),
		"hopbyhop": frame(t, eth(layers.EthernetTypeIPv6), hop, &layers.IPv6HopByHop{Options: []*layers.IPv6HopByHopOption{{OptionType: 1, OptionLength: 4, OptionData: []byte{0, 0, 0, 0}}}}, gopacket.Payload(marker)),
		"arp": frame(t, eth(layers.EthernetTypeARP), &layers.ARP{AddrType: layers.LinkTypeEthernet, Protocol: layers.EthernetTypeIPv4, HwAddressSize: 6, ProtAddressSize: 4, Operation: 1,
			SourceHwAddress: srcMAC, SourceProtAddress: []byte{192, 0, 2, 1}, DstHwAddress: make([]byte, 6), DstProtAddress: []byte{192, 0, 2, 2}}),
		"vlan":  frame(t, eth(layers.EthernetTypeDot1Q), &layers.Dot1Q{VLANIdentifier: 5, Type: layers.EthernetTypeIPv4}, vip, vu, gopacket.Payload(marker)),
		"gre":   frame(t, eth(layers.EthernetTypeIPv4), ip4(layers.IPProtocolGRE), gopacket.Payload(marker)),
		"short": {0, 1, 2},
	}
}

func TestHeaderLengthKeepsOnlyHeaders(t *testing.T) {
	d := newDecoder()
	want := map[string]struct {
		n    int
		drop Drop
	}{
		"tcp4": {14 + 20 + 20, DropNone}, "tcp4opts": {14 + 20 + 32, DropNone}, "udp6": {14 + 40 + 8, DropNone},
		"icmp4": {14 + 20 + 8, DropNone}, "icmp6": {14 + 40 + 4, DropNone},
		"fragment": {0, DropFragment}, "hopbyhop": {0, DropExtension}, "arp": {0, DropUnsupported}, "vlan": {0, DropUnsupported},
		"gre": {0, DropUnsupported}, "short": {0, DropMalformed},
	}
	for name, f := range corpus(t) {
		n, drop := d.headerLength(f)
		if w := want[name]; n != w.n || drop != w.drop {
			t.Errorf("%s: got %d %q, want %d %q", name, n, drop, w.n, w.drop)
		}
		if drop == DropNone && bytes.Contains(f[:n], []byte(marker)) {
			t.Errorf("%s: retained bytes contain the payload marker", name)
		}
	}
	// The gadget's snapshot length always covers an accepted frame.
	if n, drop := d.headerLength(tcp4(t, true)[:Snaplen]); drop != DropNone || n != 66 {
		t.Fatal(n, drop)
	}
}

type corpusEntry struct {
	Filter       string
	Packet       []byte
	Instructions []struct {
		Op     uint16
		Jt, Jf uint8
		K      uint32
	}
	Want bool
}

// The feasibility corpus (libpcap 1.11.0 programs, each verdict confirmed by
// the VM kernel's BPF_PROG_TEST_RUN) must give the same verdict in the
// node's user-space evaluator.
func TestFilterMatchesKernelVerdicts(t *testing.T) {
	b, err := os.ReadFile("../pcap/testdata/feasibility-filter-programs.json")
	if err != nil {
		t.Fatal(err)
	}
	var entries []corpusEntry
	if err := json.Unmarshal(b, &entries); err != nil || len(entries) != 11 {
		t.Fatal(err, len(entries))
	}
	for _, e := range entries {
		program := make([]value.BPFInstruction, len(e.Instructions))
		for i, ins := range e.Instructions {
			program[i] = value.BPFInstruction{Code: ins.Op, Jt: ins.Jt, Jf: ins.Jf, K: ins.K}
		}
		f, err := NewFilter(program)
		if err != nil {
			t.Fatalf("%s: %v", e.Filter, err)
		}
		if got := f.Match(e.Packet, len(e.Packet)); got != e.Want {
			t.Errorf("%s: got %t want %t", e.Filter, got, e.Want)
		}
	}
}

func TestFilterLengthUsesWireLength(t *testing.T) {
	// libpcap "greater 1000": ld len; jge #1000; ret #65535; ret #0.
	program := []value.BPFInstruction{{Code: 0x80}, {Code: 0x35, Jt: 0, Jf: 1, K: 1000}, {Code: 0x06, K: 65535}, {Code: 0x06}}
	f, err := NewFilter(program)
	if err != nil {
		t.Fatal(err)
	}
	short := make([]byte, 60)
	if !f.Match(short, 1500) || f.Match(short, 60) {
		t.Fatal("len must be the wire length")
	}
	for _, bad := range [][]value.BPFInstruction{{{Code: 0x81}, {Code: 0x06}}, {{Code: 0x84}, {Code: 0x06}}, {{Code: 0xff}}, {{Code: 0x20, K: 0xfffff000 + 4}, {Code: 0x06}}} {
		if _, err := NewFilter(bad); !errors.Is(err, ErrFilterUnsupported) {
			t.Errorf("%v accepted", bad)
		}
	}
	if f, err := NewFilter(nil); err != nil || !f.Match(short, 60) {
		t.Fatal("an empty program accepts every frame")
	}
}

func TestRecorderWritesHeadersOnlyWithinLimit(t *testing.T) {
	start := time.Unix(1_800_000_000, 0).UTC()
	r, err := NewRecorder(nil, 8192, start, "synthetic")
	if err != nil {
		t.Fatal(err)
	}
	c := corpus(t)
	for i := 0; i < 100; i++ {
		for _, name := range []string{"tcp4", "udp6", "icmp4", "fragment", "arp"} {
			r.Add(c[name], uint32(len(c[name])), start.Add(time.Duration(i)*time.Millisecond))
		}
	}
	out, counters, err := r.Close(start.Add(time.Second), 3)
	if err != nil || len(out) > 8192 || !r.Full() {
		t.Fatal(err, len(out), r.Full())
	}
	if counters.Seen != 500 || counters.Fragment != 100 || counters.Unsupported != 100 || counters.Retained+counters.OutputFull != 300 || counters.Retained == 0 {
		t.Fatalf("%+v", counters)
	}
	if bytes.Contains(out, []byte(marker)) {
		t.Fatal("payload marker in the capture")
	}
	n, err := CheckHeadersOnly(bytes.NewReader(out))
	if err != nil || uint64(n) != counters.Retained {
		t.Fatal(n, err)
	}
	// Original lengths survive truncation.
	rd, err := pcapgo.NewNgReader(bytes.NewReader(out), pcapgo.DefaultNgReaderOptions)
	if err != nil {
		t.Fatal(err)
	}
	_, ci, err := rd.ReadPacketData()
	if err != nil || ci.Length <= ci.CaptureLength {
		t.Fatal(ci, err)
	}
}

func TestCheckHeadersOnlyRejectsPayload(t *testing.T) {
	var buf bytes.Buffer
	w, err := pcapgo.NewNgWriterInterface(&buf, pcapgo.NgInterface{Name: "pod", LinkType: layers.LinkTypeEthernet, SnapLength: Snaplen}, pcapgo.DefaultNgWriterOptions)
	if err != nil {
		t.Fatal(err)
	}
	f := tcp4(t, false)
	if err := w.WritePacket(gopacket.CaptureInfo{Timestamp: time.Unix(1, 0), CaptureLength: len(f), Length: len(f)}, f); err != nil {
		t.Fatal(err)
	}
	_ = w.Flush()
	if _, err := CheckHeadersOnly(bytes.NewReader(buf.Bytes())); !errors.Is(err, ErrNotHeadersOnly) {
		t.Fatal("a frame with payload passed")
	}
	if _, err := CheckHeadersOnly(bytes.NewReader([]byte("not pcapng"))); !errors.Is(err, ErrNotHeadersOnly) {
		t.Fatal("garbage passed")
	}
}

func FuzzHeaderLength(f *testing.F) {
	f.Add([]byte{0, 1, 2, 3, 4, 5, 0, 1, 2, 3, 4, 6, 8, 0, 0x45})
	f.Fuzz(func(t *testing.T, b []byte) {
		d := newDecoder()
		n, drop := d.headerLength(b)
		if drop == DropNone && (n <= 0 || n > len(b) || n > Snaplen) {
			t.Fatal(n, len(b))
		}
		if drop == DropNone {
			if m, drop2 := d.headerLength(b[:n]); drop2 != DropNone || m != n {
				t.Fatalf("truncation not stable: %d %d %q", n, m, drop2)
			}
		}
	})
}
