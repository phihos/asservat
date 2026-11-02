package httpheaders

import (
	"net"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

// All traffic is synthetic: documentation addresses and invented markers.
var (
	clientMAC = net.HardwareAddr{0, 1, 2, 3, 4, 5}
	serverMAC = net.HardwareAddr{0, 1, 2, 3, 4, 6}
	t0        = time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)
)

// conn writes the frames of one synthetic TCP connection.
type conn struct {
	v6         bool
	port       uint16
	cseq, sseq uint32
}

func newConn(port uint16) *conn { return &conn{port: port, cseq: 1000, sseq: 50000} }

type seg struct {
	client             bool
	seq                uint32
	syn, ack, fin, rst bool
	payload            []byte
}

func (c *conn) encode(s seg) []byte {
	src, dst := c.port, uint16(80)
	smac, dmac := clientMAC, serverMAC
	if !s.client {
		src, dst, smac, dmac = dst, src, dmac, smac
	}
	tcp := &layers.TCP{SrcPort: layers.TCPPort(src), DstPort: layers.TCPPort(dst), Seq: s.seq, SYN: s.syn, ACK: s.ack, FIN: s.fin, RST: s.rst, PSH: len(s.payload) > 0, Window: 65535}
	var ls []gopacket.SerializableLayer
	if c.v6 {
		a, b := net.ParseIP("2001:db8::1"), net.ParseIP("2001:db8::2")
		if !s.client {
			a, b = b, a
		}
		ip := &layers.IPv6{Version: 6, HopLimit: 64, NextHeader: layers.IPProtocolTCP, SrcIP: a, DstIP: b}
		_ = tcp.SetNetworkLayerForChecksum(ip)
		ls = []gopacket.SerializableLayer{&layers.Ethernet{SrcMAC: smac, DstMAC: dmac, EthernetType: layers.EthernetTypeIPv6}, ip, tcp}
	} else {
		a, b := net.IP{192, 0, 2, 1}, net.IP{192, 0, 2, 2}
		if !s.client {
			a, b = b, a
		}
		ip := &layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolTCP, SrcIP: a, DstIP: b}
		_ = tcp.SetNetworkLayerForChecksum(ip)
		ls = []gopacket.SerializableLayer{&layers.Ethernet{SrcMAC: smac, DstMAC: dmac, EthernetType: layers.EthernetTypeIPv4}, ip, tcp}
	}
	if len(s.payload) > 0 {
		ls = append(ls, gopacket.Payload(s.payload))
	}
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, ls...); err != nil {
		panic(err)
	}
	return append([]byte(nil), buf.Bytes()...)
}

// handshake returns SYN, SYN-ACK and ACK.
func (c *conn) handshake() [][]byte {
	out := [][]byte{
		c.encode(seg{client: true, seq: c.cseq, syn: true}),
		c.encode(seg{client: false, seq: c.sseq, syn: true, ack: true}),
	}
	c.cseq++
	c.sseq++
	return append(out, c.encode(seg{client: true, seq: c.cseq, ack: true}))
}

// data cuts b into segments of the given sizes, the last size repeating
// (1400 without sizes), and advances the direction's sequence number.
func (c *conn) data(client bool, b []byte, sizes ...int) [][]byte {
	seq := &c.sseq
	if client {
		seq = &c.cseq
	}
	var out [][]byte
	for len(b) > 0 {
		n := min(1400, len(b))
		if len(sizes) > 0 {
			n = min(sizes[0], len(b))
			if len(sizes) > 1 {
				sizes = sizes[1:]
			}
		}
		out = append(out, c.encode(seg{client: client, seq: *seq, ack: true, payload: b[:n]}))
		*seq += uint32(n)
		b = b[n:]
	}
	return out
}

func (c *conn) fin(client bool) []byte {
	seq := &c.sseq
	if client {
		seq = &c.cseq
	}
	f := c.encode(seg{client: client, seq: *seq, ack: true, fin: true})
	*seq++
	return f
}

// feeder adds frames 1 ms apart.
type feeder struct {
	p  *Projector
	at time.Time
}

func newFeeder(t testing.TB, l Limits) *feeder {
	t.Helper()
	p, err := NewProjector(l, t0)
	if err != nil {
		t.Fatal(err)
	}
	return &feeder{p: p, at: t0}
}

func (f *feeder) add(frames ...[]byte) {
	for _, fr := range frames {
		f.at = f.at.Add(time.Millisecond)
		f.p.Add(fr, uint32(len(fr)), f.at)
	}
}

func (f *feeder) addGroups(groups ...[][]byte) {
	for _, g := range groups {
		f.add(g...)
	}
}

func (f *feeder) close(t testing.TB) (Projection, Counters, []byte) {
	t.Helper()
	pr, c := f.p.Close(f.at.Add(time.Second), 0)
	b, err := pr.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if f.p.readers.used != 0 || f.p.active != 0 {
		t.Fatalf("state left after close: readers %d, flows %d", f.p.readers.used, f.p.active)
	}
	return pr, c, b
}
