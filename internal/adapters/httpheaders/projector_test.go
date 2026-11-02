package httpheaders

import (
	"bytes"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
)

// secret appears only in fields the projection must drop.
const secret = "SECRET_MARKER"

var (
	secretRequest = "GET /orders/" + secret + "?token=" + secret + " HTTP/1.1\r\nHost: " + strings.ToLower(secret) + ".example\r\n" +
		"Authorization: Bearer " + secret + "\r\nProxy-Authorization: Basic " + secret + "\r\nCookie: session=" + secret + "\r\nX-Note: " + secret + "\r\n\r\n"
	secretBody     = "{\"body\":\"" + secret + "\"}"
	secretResponse = "HTTP/1.1 503 Service Unavailable\r\nContent-Type: application/json; charset=utf-8; boundary=" + secret + "\r\n" +
		"Set-Cookie: s=" + secret + "\r\nX-Debug: " + secret + "\r\nContent-Length: " + fmt.Sprint(len(secretBody)) + "\r\n\r\n" + secretBody
)

func noSecret(t *testing.T, b []byte) {
	t.Helper()
	for _, s := range []string{secret, strings.ToLower(secret), "orders", "token", "example", "Bearer"} {
		if bytes.Contains(b, []byte(s)) {
			t.Fatalf("projection contains %q: %s", s, b)
		}
	}
}

func summary(pr Projection) []string {
	var out []string
	for _, r := range pr.Records {
		out = append(out, fmt.Sprintf("%s %d %v %v", r.Method, r.Status, r.Headers, r.Partial))
	}
	return out
}

func want(t *testing.T, pr Projection, w ...string) {
	t.Helper()
	if got := summary(pr); !slices.Equal(got, w) {
		t.Fatalf("records\n got %q\nwant %q", got, w)
	}
}

func TestSplitHeadersBodyInLastPacketAndSecrets(t *testing.T) {
	for _, v6 := range []bool{false, true} {
		f := newFeeder(t, DefaultLimits())
		c := newConn(40000)
		c.v6 = v6
		f.addGroups(c.handshake(), c.data(true, []byte(secretRequest), 7, 30, 11), c.data(false, []byte(secretResponse), 20, 40))
		f.add(c.fin(true), c.fin(false))
		pr, n, b := f.close(t)
		want(t, pr, "GET 503 [{content-type application/json; charset=utf-8} {content-length 24}] false")
		noSecret(t, b)
		if n.Flows != 1 || n.Requests != 1 || n.Responses != 1 || n.Records != 1 || n.StoppedIncomplete != 0 {
			t.Fatalf("counters %+v", n)
		}
		var doc map[string]any
		if err := json.Unmarshal(b, &doc); err != nil || doc["format"] != artifact.HTTPHeadersFormat || doc["protocol"] != "http1" {
			t.Fatalf("document %s: %v", b, err)
		}
	}
}

func TestPipeliningHeadNoContentNotModified(t *testing.T) {
	f := newFeeder(t, DefaultLimits())
	c := newConn(40001)
	reqs := "GET /a HTTP/1.1\r\nHost: h\r\n\r\nHEAD /b HTTP/1.1\r\nHost: h\r\n\r\nDELETE /c HTTP/1.1\r\nHost: h\r\n\r\nGET /d HTTP/1.1\r\nHost: h\r\n\r\nBREW /e HTTP/1.1\r\nHost: h\r\nContent-Length: 4\r\n\r\nbody"
	resps := "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello" +
		"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 9000\r\n\r\n" + // HEAD: no body follows
		"HTTP/1.1 204 No Content\r\n\r\n" +
		"HTTP/1.1 304 Not Modified\r\nContent-Length: 77\r\n\r\n" +
		"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 201 Created\r\nContent-Length: 0\r\n\r\n"
	f.addGroups(c.handshake(), c.data(true, []byte(reqs)), c.data(false, []byte(resps), 100))
	f.add(c.fin(true), c.fin(false))
	pr, n, _ := f.close(t)
	want(t, pr,
		"GET 200 [{content-length 5}] false",
		"HEAD 200 [{content-type text/html} {content-length 9000}] false",
		"DELETE 204 [] false",
		"GET 304 [{content-length 77}] false",
		"OTHER 201 [{content-length 0}] false")
	if n.Requests != 5 || n.Responses != 6 {
		t.Fatalf("counters %+v", n)
	}
}

func TestChunkedBodyWithTrailers(t *testing.T) {
	f := newFeeder(t, DefaultLimits())
	c := newConn(40002)
	reqs := "POST /up HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n5\r\n" + secret[:5] + "\r\n0\r\nX-Sum: " + secret + "\r\n\r\nGET /x HTTP/1.1\r\nHost: h\r\n\r\n"
	resps := "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTrailer: X-Trailer\r\n\r\n" +
		"d;ext=1\r\n" + secret + "\r\n3\r\nabc\r\n0\r\nX-Trailer: " + secret + "\r\n\r\n" +
		"HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\nContent-Length: 3\r\n\r\nnope"[:len("HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\nContent-Length: 3\r\n\r\nnop")]
	f.addGroups(c.handshake(), c.data(true, []byte(reqs), 13), c.data(false, []byte(resps), 9, 9, 9))
	f.add(c.fin(true), c.fin(false))
	pr, _, b := f.close(t)
	want(t, pr, "POST 200 [] false", "GET 404 [{content-type text/plain} {content-length 3}] false")
	noSecret(t, b)
}

func TestRetransmissionOverlapAndOutOfOrder(t *testing.T) {
	f := newFeeder(t, DefaultLimits())
	c := newConn(40003)
	hs := c.handshake()
	start := c.cseq
	req := []byte(secretRequest)
	segs := c.data(true, req, 10, 10, 10, 10)
	// overlapping retransmission: bytes 5..25 again
	overlap := c.encode(seg{client: true, seq: start + 5, ack: true, payload: req[5:25]})
	ooo := slices.Clone(segs)
	slices.Reverse(ooo)
	f.addGroups(hs, ooo[:2], [][]byte{segs[0], segs[0], overlap}, ooo[2:])
	resp := c.data(false, []byte(secretResponse), 30)
	slices.Reverse(resp)
	f.add(resp...)
	f.add(resp[0]) // duplicate
	pr, n, b := f.close(t)
	want(t, pr, "GET 503 [{content-type application/json; charset=utf-8} {content-length 24}] false")
	noSecret(t, b)
	if n.StoppedGap != 0 || n.StoppedBufferLimit != 0 {
		t.Fatalf("counters %+v", n)
	}
}

func TestMidstreamStartIsNotParsed(t *testing.T) {
	f := newFeeder(t, DefaultLimits())
	c := newConn(40004)
	f.addGroups(c.data(true, []byte(secretRequest)), c.data(false, []byte(secretResponse)))
	pr, n, b := f.close(t)
	want(t, pr)
	noSecret(t, b)
	if n.MidstreamFrames != 2 || n.Flows != 0 {
		t.Fatalf("counters %+v", n)
	}
	// The SYN-ACK is seen but not the client's SYN.
	f = newFeeder(t, DefaultLimits())
	c = newConn(40005)
	hs := c.handshake()
	f.add(hs[1:]...)
	f.addGroups(c.data(true, []byte(secretRequest)))
	_, n, _ = f.close(t)
	if n.Flows != 0 || n.MidstreamFrames != 1 {
		t.Fatalf("counters %+v", n)
	}
}

func TestUnsupportedStreams(t *testing.T) {
	hello := []byte{0x16, 0x03, 0x01, 0x00, 0x2f, 0x01, 0x00, 0x00, 0x2b, 0x03, 0x03}
	cases := []struct {
		name     string
		req, rsp string
		records  []string
		check    func(Counters) bool
	}{
		{"tls", string(hello) + secret, string(hello) + secret, nil, func(n Counters) bool { return n.StoppedTLS == 2 }},
		{"http2 preface", "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" + secret, "", nil, func(n Counters) bool { return n.StoppedHTTP2 == 1 }},
		{"h2c upgrade", "GET / HTTP/1.1\r\nHost: h\r\nConnection: Upgrade, HTTP2-Settings\r\nUpgrade: h2c\r\nHTTP2-Settings: AAMAAABkAAQCAAAAAAIAAAAA\r\n\r\n" + secret,
			"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: h2c\r\n\r\n" + secret,
			[]string{"GET 101 [] false"}, func(n Counters) bool { return n.StoppedHTTP2 == 1 }},
		{"websocket upgrade", "GET /chat HTTP/1.1\r\nHost: h\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n" + secret,
			"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
			[]string{"GET 101 [] false"}, func(n Counters) bool { return n.StoppedUpgrade == 1 }},
		{"connect", "CONNECT db.example:5432 HTTP/1.1\r\nHost: db.example:5432\r\n\r\n" + secret,
			"HTTP/1.1 200 Connection established\r\n\r\n" + secret,
			[]string{"CONNECT 200 [] false"}, func(n Counters) bool { return n.StoppedConnect == 1 }},
		{"not http", secret + "\r\n\r\n", "", nil, func(n Counters) bool { return n.StoppedMalformed == 1 }},
		{"unpaired response", "", "HTTP/1.1 200 OK\r\n\r\n", nil, func(n Counters) bool { return n.StoppedUnpaired == 1 }},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFeeder(t, DefaultLimits())
			c := newConn(uint16(41000 + i))
			f.addGroups(c.handshake(), c.data(true, []byte(tc.req)), c.data(false, []byte(tc.rsp)))
			f.add(c.fin(true), c.fin(false))
			pr, n, b := f.close(t)
			want(t, pr, tc.records...)
			noSecret(t, b)
			if !tc.check(n) {
				t.Fatalf("counters %+v", n)
			}
		})
	}
}

func TestTruncatedFrameIsGap(t *testing.T) {
	f := newFeeder(t, DefaultLimits())
	c := newConn(40006)
	f.addGroups(c.handshake(), c.data(true, []byte("GET / HTTP/1.1\r\nHost: h\r\n\r\n")))
	body := strings.Repeat("x", 3000)
	rsp := []byte("HTTP/1.1 200 OK\r\nContent-Length: 3000\r\n\r\n" + body + "HTTP/1.1 200 OK\r\n\r\n")
	frames := c.data(false, rsp, 1400, 1600)
	f.add(frames[0])
	// The engine hands over 1500 bytes of a longer frame.
	f.at = f.at.Add(time.Millisecond)
	f.p.Add(frames[1][:Snaplen], uint32(len(frames[1])), f.at)
	f.add(frames[2:]...)
	f.add(c.fin(true))
	pr, n, _ := f.close(t)
	want(t, pr, "GET 200 [{content-length 3000}] false")
	if n.TruncatedFrames != 1 || n.StoppedGap != 1 {
		t.Fatalf("counters %+v", n)
	}
}

func TestFlowLimit(t *testing.T) {
	l := DefaultLimits()
	l.MaxFlows = 2
	f := newFeeder(t, l)
	for i := range 3 {
		c := newConn(uint16(42000 + i))
		f.addGroups(c.handshake(), c.data(true, []byte("GET / HTTP/1.1\r\nHost: h\r\n\r\n")), c.data(false, []byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")))
	}
	pr, n, _ := f.close(t)
	if len(pr.Records) != 2 || n.Flows != 2 || n.FlowLimitFrames != 5 || n.OpenAtCloseFlows != 2 {
		t.Fatalf("records %d counters %+v", len(pr.Records), n)
	}
}

func smallLimits() Limits {
	return Limits{MaxFlows: 8, MaxHeaderBytes: 1024, MaxFlowBytes: 30000, MaxTotalBytes: 30000, IdleTimeout: 30 * time.Second}
}

func TestHeaderBlockLimit(t *testing.T) {
	f := newFeeder(t, smallLimits())
	c := newConn(40007)
	pad := "X-Pad: " + strings.Repeat("p", 900) + "\r\n"
	okReq := "GET /1 HTTP/1.1\r\nHost: h\r\n" + pad + "\r\n"
	bigReq := "GET /2 HTTP/1.1\r\nHost: h\r\n" + pad + pad + "\r\n"
	f.addGroups(c.handshake(), c.data(true, []byte(okReq+bigReq), 500, 500, 500))
	f.addGroups(c.data(false, []byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")))
	pr, n, _ := f.close(t)
	want(t, pr, "GET 200 [{content-length 0}] false")
	if n.StoppedHeaderLimit != 1 || n.Requests != 1 {
		t.Fatalf("counters %+v", n)
	}
	// A huge header line without a line end is also stopped at the bound.
	f = newFeeder(t, smallLimits())
	c = newConn(40008)
	f.addGroups(c.handshake(), c.data(true, []byte("GET / HTTP/1.1\r\nX: "+strings.Repeat("y", 20000)), 1000))
	if f.p.readers.used > f.p.readers.limit {
		t.Fatal("budget exceeded")
	}
	_, n, _ = f.close(t)
	if n.StoppedHeaderLimit != 1 {
		t.Fatalf("counters %+v", n)
	}
}

func TestPerFlowOutOfOrderLimit(t *testing.T) {
	l := smallLimits()
	f := newFeeder(t, l)
	c := newConn(40009)
	f.addGroups(c.handshake())
	segs := c.data(true, []byte("GET / HTTP/1.1\r\nHost: h\r\nX: "+strings.Repeat("z", 9000)+"\r\n\r\n"), 1000)
	f.add(segs[1:]...) // the first segment never arrives
	_, n, _ := f.close(t)
	if n.StoppedBufferLimit != 1 || l.pagesPerHalf() != 2 {
		t.Fatalf("pages %d counters %+v", l.pagesPerHalf(), n)
	}
}

func TestTotalBudget(t *testing.T) {
	f := newFeeder(t, smallLimits())
	for i := range 6 {
		c := newConn(uint16(43000 + i))
		f.addGroups(c.handshake(), c.data(true, []byte("GET / HTTP/1.1\r\nHost: h\r\n")))
		if f.p.readers.used > f.p.readers.limit {
			t.Fatal("budget exceeded")
		}
	}
	_, n, _ := f.close(t)
	if n.StoppedBudget == 0 {
		t.Fatalf("counters %+v", n)
	}
}

func TestPipelineLimit(t *testing.T) {
	f := newFeeder(t, DefaultLimits())
	c := newConn(40010)
	f.addGroups(c.handshake(), c.data(true, []byte(strings.Repeat("GET / HTTP/1.1\r\nHost: h\r\n\r\n", maxPipeline+1)), 1000))
	pr, n, _ := f.close(t)
	if n.StoppedPipeline != 1 || len(pr.Records) != maxPipeline || n.PartialRecords != maxPipeline {
		t.Fatalf("records %d counters %+v", len(pr.Records), n)
	}
}

func TestIdleTimeoutAndOpenAtClose(t *testing.T) {
	f := newFeeder(t, DefaultLimits())
	c := newConn(40011)
	f.addGroups(c.handshake(), c.data(true, []byte("POST / HTTP/1.1\r\nHost: h\r\nContent-Length: 10\r\n\r\n")))
	f.at = f.at.Add(31 * time.Second)
	d := newConn(40012)
	f.addGroups(d.handshake(), d.data(true, []byte("GET / HTTP/1.1\r\nHost: h\r\n\r\n")))
	if f.p.active != 1 {
		t.Fatalf("idle flow still active: %d", f.p.active)
	}
	pr, n, _ := f.close(t)
	want(t, pr, "POST 0 [] true", "GET 0 [] true")
	if n.IdleClosedFlows != 1 || n.OpenAtCloseFlows != 1 || n.StoppedIncomplete != 1 {
		t.Fatalf("counters %+v", n)
	}
}

func TestValueChecks(t *testing.T) {
	f := newFeeder(t, DefaultLimits())
	c := newConn(40013)
	reqs := strings.Repeat("GET / HTTP/1.1\r\nHost: h\r\n\r\n", 3)
	resps := "HTTP/1.1 200 OK\r\nContent-Type: " + secret + "\r\nContent-Length: 0\r\n\r\n" +
		"HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=\"" + secret + "_\"\r\nContent-Length: 0\r\n\r\n" +
		"HTTP/1.1 999 Odd\r\nContent-Type: text/plain\r\nContent-Type: text/html\r\nContent-Length: 0\r\n\r\n"
	f.addGroups(c.handshake(), c.data(true, []byte(reqs)), c.data(false, []byte(resps)))
	pr, n, b := f.close(t)
	want(t, pr, "GET 200 [{content-length 0}] false", "GET 200 [{content-length 0}] false", "GET 0 [{content-length 0}] true")
	noSecret(t, b)
	if n.DroppedValues != 4 {
		t.Fatalf("counters %+v", n)
	}
}

func TestFramesThatAreNotTCP(t *testing.T) {
	f := newFeeder(t, DefaultLimits())
	f.add([]byte{1, 2, 3}, make([]byte, Snaplen+1))
	f.p.Add([]byte{1}, 1, t0.Add(-time.Second))
	_, n, _ := f.close(t)
	if n.Frames != 3 || n.NotTCPFrames != 1 || n.InvalidFrames != 2 {
		t.Fatalf("counters %+v", n)
	}
}

func TestLimitsValidate(t *testing.T) {
	if err := DefaultLimits().Validate(); err != nil {
		t.Fatal(err)
	}
	if err := smallLimits().Validate(); err != nil {
		t.Fatal(err)
	}
	for _, mut := range []func(*Limits){
		func(l *Limits) { l.MaxFlows = MaxFlows + 1 },
		func(l *Limits) { l.MaxHeaderBytes = MaxHeaderBytes + 1 },
		func(l *Limits) { l.MaxFlowBytes = MaxFlowBytes + 1 },
		func(l *Limits) { l.MaxTotalBytes = MaxTotalBytes + 1 },
		func(l *Limits) { l.IdleTimeout = MaxIdleTimeout + time.Second },
		func(l *Limits) { l.MaxFlowBytes = 20000 }, // no room for one page per direction
		func(l *Limits) { l.MaxFlows = 0 },
	} {
		l := DefaultLimits()
		mut(&l)
		if l.Validate() == nil {
			t.Fatalf("accepted %+v", l)
		}
	}
	if _, err := NewProjector(DefaultLimits(), time.Time{}); err == nil {
		t.Fatal("zero start accepted")
	}
}

func TestRecordBound(t *testing.T) {
	ct := strings.Repeat("a", 64) + "/" + strings.Repeat("b", 64) + "; charset=windows-1258"
	got, ok := projectContentType(ct)
	if !ok || got != ct {
		t.Fatalf("longest content type: %q %v", got, ok)
	}
	r := Record{Timestamp: time.Date(9999, 12, 31, 23, 59, 59, 999999999, time.UTC), Method: "OPTIONS", Status: 599,
		Headers: []Header{{"content-type", ct}, {"content-length", strings.Repeat("9", 19)}}, Partial: true}
	b, _ := json.Marshal(r)
	if len(b)+1 > maxRecordBytes || int64(maxRecords*maxRecordBytes+envelopeBytes) > artifact.HTTPHeadersNativeLimit {
		t.Fatalf("record %d bytes", len(b))
	}
}

// A stopped direction (TLS here) still closes on FIN: the flow frees its
// slot at once instead of holding it until the idle timeout.
func TestStoppedFlowReleasesSlotOnFIN(t *testing.T) {
	l := DefaultLimits()
	l.MaxFlows = 1
	f := newFeeder(t, l)
	tls := newConn(42100)
	f.addGroups(tls.handshake(), tls.data(true, []byte{0x16, 0x03, 0x01, 0x00, 0x05, 1, 2, 3, 4, 5}))
	f.add(tls.fin(true), tls.fin(false))
	plain := newConn(42101)
	f.addGroups(plain.handshake(), plain.data(true, []byte("GET / HTTP/1.1\r\nHost: h\r\n\r\n")), plain.data(false, []byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")))
	pr, n, _ := f.close(t)
	if len(pr.Records) != 1 || n.Flows != 2 || n.FlowLimitFrames != 0 {
		t.Fatalf("records %d counters %+v", len(pr.Records), n)
	}
}
