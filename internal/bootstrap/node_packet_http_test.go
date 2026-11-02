package bootstrap

import (
	"bytes"
	"context"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/gadget"
	"asservat.local/asservat/internal/adapters/httpheaders"
	compiler "asservat.local/asservat/internal/application/planning"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/collector"
	"asservat.local/asservat/internal/domain/planning"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

// Synthetic only: documentation addresses and an invented marker that may
// appear only in fields the projection drops.
const httpSecret = "SYNTHETIC_SECRET_MARKER"

var testHTTPProjection = collector.HTTPProjection{MaxFlows: 16, MaxHeaderBytes: 8 << 10, MaxFlowBytes: 64 << 10, MaxTotalBytes: 1 << 20, IdleTimeout: 10 * time.Second}

// httpTestFlow encodes one synthetic IPv4 TCP connection to port 8080.
type httpTestFlow struct {
	cseq, sseq uint32
	port       layers.TCPPort
}

func (c *httpTestFlow) frame(client, syn, ack, fin bool, payload []byte) []byte {
	src, dst := net.IP{192, 0, 2, 1}, net.IP{192, 0, 2, 2}
	sport, dport := 40000+c.port, layers.TCPPort(8080)
	seq := &c.cseq
	if !client {
		src, dst, sport, dport, seq = dst, src, dport, sport, &c.sseq
	}
	ip := &layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolTCP, SrcIP: src, DstIP: dst}
	tcp := &layers.TCP{SrcPort: sport, DstPort: dport, Seq: *seq, SYN: syn, ACK: ack, FIN: fin, PSH: len(payload) > 0, Window: 65535}
	_ = tcp.SetNetworkLayerForChecksum(ip)
	ls := []gopacket.SerializableLayer{&layers.Ethernet{SrcMAC: net.HardwareAddr{0, 1, 2, 3, 4, 5}, DstMAC: net.HardwareAddr{0, 1, 2, 3, 4, 6}, EthernetType: layers.EthernetTypeIPv4}, ip, tcp}
	if len(payload) > 0 {
		ls = append(ls, gopacket.Payload(payload))
	}
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, ls...); err != nil {
		panic(err)
	}
	*seq += uint32(len(payload))
	if syn || fin {
		*seq++
	}
	return append([]byte(nil), buf.Bytes()...)
}

// frames returns a complete exchange whose request and response headers are
// split across several segments, plus one UDP frame the filter refuses.
func httpExchange() [][]byte {
	c := &httpTestFlow{cseq: 1000, sseq: 50000}
	request := "GET /orders/" + httpSecret + " HTTP/1.1\r\nHost: shop.example\r\nAuthorization: Bearer " + httpSecret + "\r\nCookie: s=" + httpSecret + "\r\n\r\n"
	body := `{"body":"` + httpSecret + `"}`
	response := "HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=utf-8; boundary=" + httpSecret + "\r\nSet-Cookie: s=" + httpSecret + "\r\nContent-Length: 34\r\n\r\n" + body
	if len(body) != 34 {
		panic("body length")
	}
	out := [][]byte{c.frame(true, true, false, false, nil), c.frame(false, true, true, false, nil), c.frame(true, false, true, false, nil)}
	for _, part := range []string{request[:9], request[9:40], request[40:]} {
		out = append(out, c.frame(true, false, true, false, []byte(part)))
	}
	for _, part := range []string{response[:20], response[20:70], response[70:]} {
		out = append(out, c.frame(false, false, true, false, []byte(part)))
	}
	out = append(out, c.frame(true, false, true, true, nil), c.frame(false, false, true, true, nil))
	udp := &layers.UDP{SrcPort: 5353, DstPort: 5353}
	ip := &layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolUDP, SrcIP: net.IP{192, 0, 2, 1}, DstIP: net.IP{192, 0, 2, 2}}
	_ = udp.SetNetworkLayerForChecksum(ip)
	buf := gopacket.NewSerializeBuffer()
	_ = gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, &layers.Ethernet{SrcMAC: net.HardwareAddr{0, 1, 2, 3, 4, 5}, DstMAC: net.HardwareAddr{0, 1, 2, 3, 4, 6}, EthernetType: layers.EthernetTypeIPv4}, ip, udp, gopacket.Payload(httpSecret))
	return append(out, buf.Bytes())
}

// httpWork is nodePermitWork as an httpHeaders recording with the program
// of "ip and tcp" (ldh [12]; jeq 0x800; ldb [23]; jeq 6).
func httpWork(now time.Time) (collector.Work, collector.Identity) {
	w, id := nodePermitWork(now)
	program := []planning.BPFInstruction{{Code: 0x28, K: 12}, {Code: 0x15, Jf: 3, K: 0x800}, {Code: 0x30, K: 23}, {Code: 0x15, Jf: 1, K: 6}, {Code: 6, K: 65535}, {Code: 6}}
	w.Packet.Program, w.Packet.ProgramDigest = program, [32]byte(compiler.FilterProgramDigest(program))
	w.Packet.Observation.Binding.ProgramDigest = w.Packet.ProgramDigest
	w.Packet.Raw = &collector.RawPrefix{Snaplen: artifact.MaxRawSnaplen}
	h := testHTTPProjection
	w.Packet.HTTP = &h
	return w, id
}

// ADR-282: the node runs the observed engine at the fixed snaplen, charges
// each frame to the meter, applies the hub-compiled filter and uploads only
// the JSON projection: approved headers kept, credentials, URL, Host,
// cookies and bodies absent.
func TestNodeProjectsHTTPHeaders(t *testing.T) {
	w, id := httpWork(time.Now())
	if !w.Packet.Valid() {
		t.Fatal("fixture invalid")
	}
	var mu sync.Mutex
	budget, _ := collector.NewBudget(collector.Ceilings{FrozenBytes: 16 << 20, UploadBytesPerSecond: 32 << 20, UploadBurstBytes: 64 << 20}, time.Now())
	type upload struct {
		r   collector.PacketResult
		out []byte
	}
	result := make(chan upload, 1)
	frames := httpExchange()
	var snaplen atomic.Int32
	n := &nodePackets{engine: func(context.Context, string, int, func(gadget.Frame)) (gadget.CaptureStats, error) {
		t.Error("unobserved fallback")
		return gadget.CaptureStats{}, nil
	}, identity: func() collector.Identity { return id }, available: true, now: time.Now, version: "fixture", budget: func() *collector.Budget { return budget }, budgetMu: &mu, log: func(string) {},
		upload: func(_ context.Context, _ string, r collector.PacketResult, out []byte) error {
			result <- upload{r, append([]byte(nil), out...)}
			return nil
		}}
	n.observedEngine = func(ctx context.Context, _ string, s int, deliver func(gadget.Frame), _ func(gadget.InputNotice)) (gadget.CaptureStats, error) {
		snaplen.Store(int32(s))
		for _, f := range frames {
			deliver(gadget.Frame{Data: f, Wire: uint32(len(f)), At: time.Now()})
		}
		<-ctx.Done()
		return gadget.CaptureStats{}, ctx.Err()
	}
	if r := n.start(t.Context(), id.Epoch, w); r.Outcome != collector.OutcomeAccepted {
		t.Fatal(r)
	}
	var got upload
	select {
	case got = <-result:
	case <-time.After(5 * time.Second):
		t.Fatal("no upload")
	}
	n.wg.Wait()
	r := got.r
	if r.Failure != "" || r.NativeType != artifact.HTTPHeadersArtifact || r.Snaplen != 1500 || snaplen.Load() != 1500 || !r.Valid() ||
		r.Seen != uint64(len(frames)) || r.Filtered != 1 || r.Retained != uint64(len(frames)-1) || r.LostSamples != 0 || r.CapturedBytes != int64(len(got.out)) {
		t.Fatalf("result %+v", r)
	}
	h := testHTTPProjection
	limits := httpheaders.Limits{MaxFlows: h.MaxFlows, MaxHeaderBytes: h.MaxHeaderBytes, MaxFlowBytes: h.MaxFlowBytes, MaxTotalBytes: h.MaxTotalBytes, IdleTimeout: h.IdleTimeout}
	if records, err := httpheaders.CheckProjection(bytes.NewReader(got.out), limits, w.Packet.MaxBytes); err != nil || records != 1 {
		t.Fatalf("projection %s: %d %v", got.out, records, err)
	}
	if !bytes.Contains(got.out, []byte(`"headers":[{"name":"content-type","value":"application/json; charset=utf-8"},{"name":"content-length","value":"34"}]`)) ||
		!bytes.Contains(got.out, []byte(`"engine_lost_frames":0`)) {
		t.Fatalf("projection %s", got.out)
	}
	for _, s := range []string{httpSecret, "Bearer", "orders", "shop.example", "Cookie", "body"} {
		if bytes.Contains(got.out, []byte(s)) {
			t.Fatalf("projection contains %q: %s", s, got.out)
		}
	}
}

// Work the node cannot run as approved is refused before any budget,
// observation or engine use: limits below the parser's floors, a missing
// observation permit or a snaplen other than the fixed engine setting.
func TestNodeRefusesInvalidHTTPProjectionWork(t *testing.T) {
	for _, mode := range []string{"floors", "no-observation", "snaplen"} {
		t.Run(mode, func(t *testing.T) {
			now := time.Now()
			w, id := httpWork(now)
			switch mode {
			case "floors":
				// Within the specified maxima, but the header block's read
				// buffers leave no reassembly page per direction.
				w.Packet.HTTP.MaxHeaderBytes, w.Packet.HTTP.MaxFlowBytes = 32<<10, 64<<10
				if !w.Packet.Valid() {
					t.Fatal("fixture must pass the domain check")
				}
			case "no-observation":
				w.Packet.Observation = nil
			case "snaplen":
				w.Packet.Raw.Snaplen = 1400
			}
			var mu sync.Mutex
			budget, _ := collector.NewBudget(collector.Ceilings{FrozenBytes: 16 << 20}, now)
			var calls atomic.Int32
			engine := func(context.Context, string, int, func(gadget.Frame)) (gadget.CaptureStats, error) {
				calls.Add(1)
				return gadget.CaptureStats{}, nil
			}
			n := &nodePackets{engine: engine, observedEngine: func(context.Context, string, int, func(gadget.Frame), func(gadget.InputNotice)) (gadget.CaptureStats, error) {
				calls.Add(1)
				return gadget.CaptureStats{}, nil
			}, identity: func() collector.Identity { return id }, available: true, now: func() time.Time { return now }, budget: func() *collector.Budget { return budget }, budgetMu: &mu, log: func(string) {}}
			receipt := n.start(context.Background(), id.Epoch, w)
			if receipt.Outcome == collector.OutcomeAccepted || receipt.Reason != collector.ReasonWorkUnknown || calls.Load() != 0 || budget.Usage(now).FrozenReserved != 0 || len(n.observations) != 0 {
				t.Fatal("invalid HTTP projection work was not refused before the engine", receipt, calls.Load())
			}
			n.wg.Wait()
		})
	}
}

// A projection that does not fit the recording's output cap drops its
// latest records and still passes the publisher's recheck.
func TestHTTPRecorderBoundsOutputByMaxBytes(t *testing.T) {
	w, _ := httpWork(time.Now())
	started := time.Now().UTC()
	rec, err := newHTTPRecorder(w.Packet.Program, 4096, started, testHTTPProjection)
	if err != nil {
		t.Fatal(err)
	}
	at := started
	for i := 0; i < 40; i++ {
		c := &httpTestFlow{cseq: 1000, sseq: 50000, port: layers.TCPPort(i)}
		for _, f := range [][]byte{c.frame(true, true, false, false, nil), c.frame(false, true, true, false, nil), c.frame(true, false, true, false, []byte("GET / HTTP/1.1\r\nHost: h\r\n\r\n")),
			c.frame(false, false, true, false, []byte("HTTP/1.1 204 No Content\r\nContent-Type: text/plain\r\n\r\n")), c.frame(true, false, true, true, nil), c.frame(false, false, true, true, nil)} {
			at = at.Add(time.Millisecond)
			rec.Add(f, uint32(len(f)), at)
		}
	}
	out, counters, err := rec.Close(at.Add(time.Second), 0)
	if err != nil || len(out) > 4096 || counters.Retained != 240 {
		t.Fatalf("%d bytes, %+v, %v", len(out), counters, err)
	}
	h := testHTTPProjection
	limits := httpheaders.Limits{MaxFlows: h.MaxFlows, MaxHeaderBytes: h.MaxHeaderBytes, MaxFlowBytes: h.MaxFlowBytes, MaxTotalBytes: h.MaxTotalBytes, IdleTimeout: h.IdleTimeout}
	records, err := httpheaders.CheckProjection(bytes.NewReader(out), limits, 4096)
	if err != nil || records == 0 || records >= 40 || !bytes.Contains(out, []byte(`"records_dropped":`)) || bytes.Contains(out, []byte(`"records_dropped":0`)) {
		t.Fatalf("bounded projection %d records: %v %s", records, err, out)
	}
}

// The publisher's HTTP check uses the expectation's accepted limits and
// output cap; any other recording yields a check that refuses everything.
func TestPublisherHTTPCheckUsesAcceptedRecording(t *testing.T) {
	w, _ := httpWork(time.Now())
	started := time.Now().UTC()
	rec, err := newHTTPRecorder(w.Packet.Program, w.Packet.MaxBytes, started, testHTTPProjection)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range httpExchange() {
		rec.Add(f, uint32(len(f)), time.Now())
	}
	out, _, err := rec.Close(time.Now(), 0)
	if err != nil {
		t.Fatal(err)
	}
	h := testHTTPProjection
	accepted := &artifact.Recording{Kind: "packetCapture", Profile: "httpHeaders", MaxBytes: w.Packet.MaxBytes, Snaplen: 1500,
		HTTP: &artifact.RecordingHTTP{MaxFlows: h.MaxFlows, MaxHeaderBytes: h.MaxHeaderBytes, MaxFlowBytes: h.MaxFlowBytes, MaxTotalBytes: h.MaxTotalBytes, IdleMillis: h.IdleTimeout.Milliseconds()}}
	check := func(r *artifact.Recording) error {
		limits, maxBytes := httpheaders.RecordingLimits(r)
		c := httpheaders.NewProjectionCheck(limits, maxBytes)
		if err := c.Write(out); err != nil {
			_ = c.Close()
			return err
		}
		return c.Close()
	}
	if err := check(accepted); err != nil {
		t.Fatal(err)
	}
	otherFlows, small, raw := *accepted, *accepted, *accepted
	otherHTTP := *accepted.HTTP
	otherHTTP.MaxFlows++
	otherFlows.HTTP = &otherHTTP
	small.MaxBytes = int64(len(out) - 1)
	raw.Profile = "rawPackets"
	for name, r := range map[string]*artifact.Recording{"nil": nil, "other limits": &otherFlows, "smaller cap": &small, "other profile": &raw} {
		if check(r) == nil {
			t.Fatal("accepted with", name)
		}
	}
}
