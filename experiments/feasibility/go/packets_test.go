package feasibility

import (
	"bytes"
	"encoding/json"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"
	"github.com/gopacket/gopacket/pcapgo"
	gadget "github.com/inspektor-gadget/inspektor-gadget/pkg/libpcap-compiler"
	"golang.org/x/net/bpf"
	"net"
	"os"
	"testing"
	"time"
)

func packet(ipv6 bool, udp bool, port uint16) []byte {
	eth := &layers.Ethernet{SrcMAC: net.HardwareAddr{0, 1, 2, 3, 4, 5}, DstMAC: net.HardwareAddr{0, 1, 2, 3, 4, 6}, EthernetType: layers.EthernetTypeIPv4}
	ip := &layers.IPv4{Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolTCP, SrcIP: net.ParseIP("192.0.2.1"), DstIP: net.ParseIP("192.0.2.2")}
	ip6 := &layers.IPv6{Version: 6, HopLimit: 64, NextHeader: layers.IPProtocolTCP, SrcIP: net.ParseIP("2001:db8::1"), DstIP: net.ParseIP("2001:db8::2")}
	var network gopacket.NetworkLayer = ip
	var networkLayer gopacket.SerializableLayer = ip
	if ipv6 {
		eth.EthernetType = layers.EthernetTypeIPv6
		network = ip6
		networkLayer = ip6
	}
	var transport gopacket.SerializableLayer
	if udp {
		ip.Protocol = layers.IPProtocolUDP
		ip6.NextHeader = layers.IPProtocolUDP
		u := &layers.UDP{SrcPort: 12345, DstPort: layers.UDPPort(port)}
		if e := u.SetNetworkLayerForChecksum(network); e != nil {
			panic(e)
		}
		transport = u
	} else {
		tcp := &layers.TCP{SrcPort: 12345, DstPort: layers.TCPPort(port), SYN: true, Window: 100}
		if e := tcp.SetNetworkLayerForChecksum(network); e != nil {
			panic(e)
		}
		transport = tcp
	}
	b := gopacket.NewSerializeBuffer()
	if e := gopacket.SerializeLayers(b, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, eth, networkLayer, transport, gopacket.Payload("SYNTHETIC-ONLY")); e != nil {
		panic(e)
	}
	return b.Bytes()
}
func TestFilterCompilerComparison(t *testing.T) {
	corpus := []struct {
		expression string
		ipv6, udp  bool
		port       uint16
		want       bool
	}{
		{"tcp dst port 443", false, false, 443, true}, {"tcp dst port 443", true, false, 443, true}, {"udp port 53", false, true, 53, true}, {"udp port 53", true, true, 53, true},
		{"tcp and host 192.0.2.2", false, false, 443, true}, {"ip6 and dst host 2001:db8::2", true, false, 443, true}, {"tcp[tcpflags] & tcp-syn != 0", false, false, 443, true}, {"udp dst portrange 50-60", true, true, 53, true},
		{"tcp port 80 or udp port 53", false, true, 53, true}, {"not udp", false, false, 443, true}, {"tcp dst port 80", false, false, 443, false},
	}
	type result struct {
		Filter            string
		IPv6              bool
		Expected, Libpcap bool
		GadgetMatch       *bool
		GadgetError       string
	}
	var rows []result
	type kernelCase struct {
		Filter       string
		Packet       []byte
		Instructions []bpf.RawInstruction
		Want         bool
	}
	var kernelCases []kernelCase
	different := 0
	for _, tc := range corpus {
		p := packet(tc.ipv6, tc.udp, tc.port)
		ci := gopacket.CaptureInfo{CaptureLength: len(p), Length: len(p)}
		f, e := pcap.NewBPF(layers.LinkTypeEthernet, 65535, tc.expression)
		if e != nil {
			t.Fatal(e)
		}
		got := f.Matches(ci, p)
		compiled, e := pcap.CompileBPFFilter(layers.LinkTypeEthernet, 65535, tc.expression)
		if e != nil {
			t.Fatal(e)
		}
		classic := make([]bpf.RawInstruction, len(compiled))
		for i, v := range compiled {
			classic[i] = bpf.RawInstruction{Op: v.Code, Jt: v.Jt, Jf: v.Jf, K: v.K}
		}
		kernelCases = append(kernelCases, kernelCase{tc.expression, p, classic, tc.want})
		if got != tc.want {
			t.Fatal("reference corpus mismatch", tc.expression)
		}
		row := result{Filter: tc.expression, IPv6: tc.ipv6, Expected: tc.want, Libpcap: got}
		func() {
			defer func() {
				if r := recover(); r != nil {
					row.GadgetError = "compiler panic"
				}
			}()
			ins, e := gadget.CompileCbpf(tc.expression)
			if e != nil {
				row.GadgetError = e.Error()
				return
			}
			vm, e := bpf.NewVM(ins)
			if e != nil {
				row.GadgetError = e.Error()
				return
			}
			v, e := vm.Run(p)
			if e != nil {
				row.GadgetError = e.Error()
				return
			}
			match := v != 0
			row.GadgetMatch = &match
		}()
		if row.GadgetError != "" || row.GadgetMatch == nil || *row.GadgetMatch != got {
			different++
		}
		rows = append(rows, row)
	}
	if path := os.Getenv("ASSERVAT_PACKET_REPORT"); path != "" {
		b, _ := json.MarshalIndent(rows, "", "  ")
		if e := os.WriteFile(path, append(b, '\n'), 0600); e != nil {
			t.Fatal(e)
		}
	}
	if path := os.Getenv("ASSERVAT_FILTER_PROGRAMS"); path != "" {
		b, _ := json.MarshalIndent(kernelCases, "", "  ")
		if e := os.WriteFile(path, append(b, '\n'), 0600); e != nil {
			t.Fatal(e)
		}
	}
	t.Logf("%d corpus cases; libpcap matches reference expectations; %d Gadget compiler differences/errors (measurement, not a parity pass)", len(rows), different)
}
func TestNativePCAPNGFixture(t *testing.T) {
	var out bytes.Buffer
	w, e := pcapgo.NewNgWriter(&out, layers.LinkTypeEthernet)
	if e != nil {
		t.Fatal(e)
	}
	for i := 0; i < 4; i++ {
		p := packet(i%2 == 1, i >= 2, 443)
		if e = w.WritePacket(gopacket.CaptureInfo{Timestamp: time.Unix(1700000000+int64(i), 0), CaptureLength: len(p), Length: len(p)}, p); e != nil {
			t.Fatal(e)
		}
	}
	if e = w.Flush(); e != nil {
		t.Fatal(e)
	}
	if path := os.Getenv("ASSERVAT_PCAP_PATH"); path != "" {
		if e = os.WriteFile(path, out.Bytes(), 0600); e != nil {
			t.Fatal(e)
		}
	}
	r, e := pcapgo.NewNgReader(bytes.NewReader(out.Bytes()), pcapgo.DefaultNgReaderOptions)
	if e != nil {
		t.Fatal(e)
	}
	for i := 0; i < 4; i++ {
		got, _, e := r.ReadPacketData()
		if e != nil || !bytes.Equal(got, packet(i%2 == 1, i >= 2, 443)) {
			t.Fatal("native fixture mismatch", e)
		}
	}
}
