package httpheaders

import (
	"bufio"
	"errors"
	"io"
	"iter"
	"net/http"
	"net/http/httputil"
	"net/textproto"
	"strings"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/reassembly"
)

// stop says why a direction stopped parsing. The first reason wins and is
// counted once.
type stop uint8

const (
	stopNone        stop = iota
	stopEOF              // clean end at a message boundary; not counted
	stopTunnel           // response side after a counted CONNECT/Upgrade; not counted
	stopIncomplete       // stream ended inside a message
	stopGap              // missing or truncated bytes
	stopBufferLimit      // out-of-order pages exceeded the per-flow or total page bound
	stopMidstream        // direction without its SYN
	stopTLS
	stopHTTP2
	stopUpgrade
	stopConnect
	stopMalformed
	stopHeaderLimit
	stopBudget
	stopPipeline
	stopUnpaired
)

var errStopped = errors.New("direction stopped")

// pending is a request awaiting its response: the projected method only.
type pending struct {
	method string
	at     time.Time
	tunnel bool
}

// flow is one admitted TCP connection; halves[0] carries requests.
type flow struct {
	p      *Projector
	halves [2]*half
	fifo   []pending
}

func (f *flow) half(dir reassembly.TCPFlowDirection) *half {
	if dir == reassembly.TCPDirClientToServer {
		return f.halves[0]
	}
	return f.halves[1]
}

// Accept refuses bytes the direction will not parse, so no page is queued
// for them: a stopped direction, one that never saw its SYN, or a frame
// whose TCP payload was truncated (except their FIN/RST, see below).
func (f *flow) Accept(tcp *layers.TCP, _ gopacket.CaptureInfo, dir reassembly.TCPFlowDirection, nextSeq reassembly.Sequence, _ *bool, _ reassembly.AssemblerContext) bool {
	h := f.half(dir)
	// A stopped direction still passes FIN/RST so the assembler closes the
	// connection and frees its flow slot; ReassembledSG discards its bytes.
	switch {
	case h.done:
		return tcp.FIN || tcp.RST
	case nextSeq == invalidSequence && !tcp.SYN:
		h.close(stopMidstream)
		return tcp.FIN || tcp.RST
	case f.p.ctx.truncated:
		h.close(stopGap)
		return tcp.FIN || tcp.RST
	}
	return true
}

func (f *flow) ReassembledSG(sg reassembly.ScatterGather, _ reassembly.AssemblerContext) {
	dir, _, end, skip := sg.Info()
	h := f.half(dir)
	if h.done {
		return
	}
	if skip != 0 {
		if f.p.phase == phaseLive {
			h.close(stopBufferLimit) // the assembler flushed early to hold its page bound
		} else {
			h.close(stopGap)
		}
		return
	}
	if n, _ := sg.Lengths(); n > 0 {
		h.feed(sg.Fetch(n))
	}
	if end {
		h.close(stopNone)
	}
}

// ReassemblyComplete ends both directions and turns requests still awaiting
// a response into partial records.
func (f *flow) ReassemblyComplete(reassembly.AssemblerContext) bool {
	p := f.p
	f.halves[0].close(stopNone)
	f.halves[1].close(stopNone)
	for _, e := range f.fifo {
		p.addRecord(Record{Timestamp: e.at, Method: e.method, Partial: true})
	}
	f.fifo = nil
	switch p.phase {
	case phaseIdle:
		p.counters.IdleClosedFlows++
	case phaseFinal:
		p.counters.OpenAtCloseFlows++
	}
	p.active--
	return true
}

// half parses one direction in a coroutine (iter.Pull): feed hands it the
// bytes reassembled during one Add and resumes it until it needs more, so
// no reassembled byte is retained outside its bounded bufio buffer.
type half struct {
	p      *Projector
	f      *flow
	client bool

	next    func() (struct{}, bool)
	stopFn  func()
	yield   func(struct{}) bool
	started bool
	done    bool // no further bytes are parsed
	reason  stop
	closing bool

	fresh bool
	in    []byte
	cur   []byte
	br    *bufio.Reader

	// Header phase: bytes read from the stream are charged to the shared
	// budget and limited to the header block plus one buffer of look-ahead.
	header   bool
	hdrStart int
	hdrRead  int
	charged  int
	first    bool
}

func (h *half) setReason(r stop) {
	if h.reason == stopNone {
		h.reason = r
	}
}

// Read is the coroutine's byte source.
func (h *half) Read(b []byte) (int, error) {
	for len(h.cur) == 0 {
		h.cur = nil
		switch {
		case h.fresh:
			h.cur, h.in, h.fresh = h.in, nil, false
		case h.closing || !h.yield(struct{}{}):
			if h.reason > stopEOF {
				return 0, errStopped
			}
			return 0, io.EOF
		}
	}
	n := min(len(b), len(h.cur))
	if h.header {
		allow := h.p.limits.MaxHeaderBytes - h.hdrStart + readBuffer - h.hdrRead
		if allow <= 0 {
			h.setReason(stopHeaderLimit)
			return 0, errStopped
		}
		n = min(n, allow)
		if !h.p.readers.charge(n) {
			h.setReason(stopBudget)
			return 0, errStopped
		}
		h.charged += n
		h.hdrRead += n
	}
	copy(b, h.cur[:n])
	h.cur = h.cur[n:]
	return n, nil
}

func (h *half) beginHeader() {
	h.header, h.hdrStart, h.hdrRead = true, h.br.Buffered(), 0
}

// endHeader releases the header charge and checks the consumed block size.
func (h *half) endHeader() bool {
	h.header = false
	h.p.readers.release(h.charged)
	h.charged = 0
	if h.hdrStart+h.hdrRead-h.br.Buffered() > h.p.limits.MaxHeaderBytes {
		h.setReason(stopHeaderLimit)
		return false
	}
	return true
}

// fail classifies a read or parse error; a reason set by the source wins.
func (h *half) fail(err error, boundary bool) {
	switch {
	case h.reason != stopNone:
	case err == io.EOF && boundary:
		h.reason = stopEOF
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		h.reason = stopIncomplete
	default:
		h.reason = stopMalformed
	}
}

func (h *half) feed(b []byte) {
	if !h.started {
		h.started, h.first = true, true
		h.next, h.stopFn = iter.Pull(func(yield func(struct{}) bool) { h.yield = yield; h.run() })
	}
	h.in, h.fresh = b, true
	if _, ok := h.next(); !ok {
		h.in, h.cur = nil, nil
	}
}

// close ends the direction: with stopNone the parser sees a clean end of
// stream, otherwise a stopped stream. It is idempotent.
func (h *half) close(r stop) {
	if !h.done {
		h.setReason(r)
	}
	if !h.started {
		h.started = true
		h.settle()
		return
	}
	if h.stopFn == nil {
		return
	}
	if !h.done {
		h.closing = true
		h.next() // the parser drains its buffer, then sees the end
	}
	h.stopFn()
	h.stopFn = nil
	h.in, h.cur = nil, nil
}

// settle counts the stop reason once and marks the direction done.
func (h *half) settle() {
	if h.done {
		return
	}
	h.done = true
	h.p.counters.count(h.reason)
}

func (h *half) run() {
	defer h.settle()
	if !h.p.readers.charge(readBuffer) {
		h.setReason(stopBudget)
		return
	}
	defer h.p.readers.release(readBuffer)
	h.br = bufio.NewReaderSize(h, readBuffer)
	defer func() {
		if h.charged > 0 {
			h.p.readers.release(h.charged)
			h.charged = 0
		}
		h.br = nil
	}()
	for {
		h.beginHeader()
		b, err := h.br.Peek(1)
		if err != nil {
			h.fail(err, true)
			return
		}
		if h.first && b[0] == 0x16 { // TLS handshake record
			h.setReason(stopTLS)
			return
		}
		h.first = false
		var ok bool
		if h.client {
			ok = h.request()
		} else {
			ok = h.response()
		}
		if !ok {
			return
		}
	}
}

func (h *half) request() bool {
	req, err := http.ReadRequest(h.br)
	if err != nil {
		h.fail(err, false)
		return false
	}
	if !h.endHeader() {
		return false
	}
	if req.ProtoMajor != 1 || req.Method == "PRI" {
		h.setReason(stopHTTP2)
		return false
	}
	if len(h.f.fifo) >= maxPipeline {
		h.setReason(stopPipeline)
		return false
	}
	h.p.counters.Requests++
	e := pending{method: projectMethod(req.Method), at: h.p.now}
	upgrade := req.Header.Get("Upgrade")
	switch {
	case req.Method == http.MethodConnect:
		e.tunnel = true
		h.setReason(stopConnect)
	case upgrade != "":
		e.tunnel = true
		if strings.Contains(strings.ToLower(upgrade), "h2c") {
			h.setReason(stopHTTP2)
		} else {
			h.setReason(stopUpgrade)
		}
	}
	h.f.fifo = append(h.f.fifo, e)
	if e.tunnel {
		return false
	}
	return h.skipBody(req.Body, req.TransferEncoding, req.ContentLength)
}

func (h *half) response() bool {
	if len(h.f.fifo) == 0 {
		h.setReason(stopUnpaired)
		return false
	}
	e := h.f.fifo[0]
	resp, err := http.ReadResponse(h.br, &http.Request{Method: e.method})
	if err != nil {
		h.fail(err, false)
		return false
	}
	if !h.endHeader() {
		return false
	}
	if resp.ProtoMajor != 1 {
		h.setReason(stopHTTP2)
		return false
	}
	h.p.counters.Responses++
	if resp.StatusCode >= 100 && resp.StatusCode < 200 && resp.StatusCode != http.StatusSwitchingProtocols {
		return true // interim response; the final one follows
	}
	h.f.fifo = h.f.fifo[1:]
	h.p.addRecord(h.p.record(e, resp))
	switch {
	case e.tunnel: // counted by the request direction
		h.setReason(stopTunnel)
		return false
	case resp.StatusCode == http.StatusSwitchingProtocols:
		h.setReason(stopUpgrade)
		return false
	}
	return h.skipBody(resp.Body, resp.TransferEncoding, resp.ContentLength)
}

// skipBody reads past a message body without keeping it. The net/http body
// is not read because its trailer parsing is unbounded; chunked framing uses
// httputil's chunked reader and trailers are read under the header bound
// and discarded.
func (h *half) skipBody(body io.ReadCloser, te []string, length int64) bool {
	if body == http.NoBody || body == nil {
		return true
	}
	var err error
	switch {
	case len(te) > 0 && te[0] == "chunked":
		if _, err = io.Copy(io.Discard, httputil.NewChunkedReader(h.br)); err == nil {
			h.beginHeader()
			_, err = textproto.NewReader(h.br).ReadMIMEHeader()
			if err == nil && !h.endHeader() {
				return false
			}
		}
	case length >= 0:
		_, err = io.CopyN(io.Discard, h.br, length)
	default: // a response delimited by the end of the stream
		if _, err = io.Copy(io.Discard, h.br); err == nil {
			h.setReason(stopEOF)
			return false
		}
	}
	if err != nil {
		h.fail(err, false)
		return false
	}
	return true
}
