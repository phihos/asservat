// Package httpheaders turns captured Ethernet frames into the bounded
// `http-response-headers/v1` projection of an httpHeaders capture
// (REQ-NET-004, ADR-282). Frames are decoded with gopacket's layers, TCP is
// reassembled with gopacket/reassembly and HTTP/1 messages are read with
// net/http, net/http/httputil and net/textproto; this package parses no
// protocol itself. Bodies, trailers, URLs, Host and every header outside the
// projection pass through the bounded parser transiently and are never
// retained.
package httpheaders

import (
	"errors"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/reassembly"
)

// Snaplen is the longest frame the node's tcpdump gadget hands over for an
// httpHeaders capture. A frame whose TCP payload is cut short is a gap
// (ADR-282); the value is a measured-later engine setting, not a claim that
// headers fit in a frame.
const Snaplen = 1500

// Spec maxima (REQ-NET-004, packet-capture.schema.json httpHeaders).
const (
	MaxFlows        = 1024
	MaxHeaderBytes  = 32 << 10
	MaxFlowBytes    = 256 << 10
	MaxTotalBytes   = 16 << 20
	MaxIdleTimeout  = 30 * time.Second
	minIdleTimeout  = time.Second
	readBuffer      = 4 << 10 // bufio size per direction; also net/http's chunk-line maximum
	pageBytes       = 1900    // gopacket v1.7.4 reassembly page size
	maxPipeline     = 32      // queued requests awaiting a response per flow
	invalidSequence = -1      // gopacket's "no start seen" sequence
	flushInterval   = time.Second
	// stalledFlowAge: when every flow slot is held, a new connection's SYN
	// first closes flows that have seen no frame for this long (at most the
	// idle timeout). A flow whose FIN/RST was never captured (input lost,
	// another capture on the same pod) otherwise holds its slot for the whole
	// idle timeout, and on a busy pod every later connection hits the flow
	// limit (native run 42479876034). The flow cap itself is unchanged.
	stalledFlowAge = 2 * time.Second
	// stalledFlushInterval bounds how often a refused SYN may scan for them.
	stalledFlushInterval = 100 * time.Millisecond
	maxYear, minYear     = 9999, 1970
)

var ErrInvalid = errors.New("http header projector input invalid")

// Limits are the httpHeaders profile bounds. They are not tuning knobs: each
// is at most the specified maximum and the derived buffers must leave room
// for one reassembly page per direction.
type Limits struct {
	MaxFlows       int
	MaxHeaderBytes int
	MaxFlowBytes   int // maxReassemblyBytesPerFlow
	MaxTotalBytes  int // maxReassemblyBytes, shared by all flows
	IdleTimeout    time.Duration
}

// DefaultLimits are the specified defaults, equal to the maxima.
func DefaultLimits() Limits {
	return Limits{MaxFlows: MaxFlows, MaxHeaderBytes: MaxHeaderBytes, MaxFlowBytes: MaxFlowBytes, MaxTotalBytes: MaxTotalBytes, IdleTimeout: MaxIdleTimeout}
}

// readers is the most reader state one flow can hold: per direction the
// bufio buffer plus a header block read with one buffer of look-ahead.
func (l Limits) readers() int { return 2 * (l.MaxHeaderBytes + 2*readBuffer) }

// pagesPerHalf is gopacket's out-of-order page limit per direction. The
// assembler queues one packet before it enforces the limit, hence the -1.
func (l Limits) pagesPerHalf() int { return (l.MaxFlowBytes-l.readers())/(2*pageBytes) - 1 }

// pagesTotal gives out-of-order pages half of the shared budget; reader
// state gets the rest.
func (l Limits) pagesTotal() int { return (l.MaxTotalBytes/2)/pageBytes - 1 }

func (l Limits) readerBudget() int { return l.MaxTotalBytes - (l.pagesTotal()+1)*pageBytes }

// Validate checks the limits against the specified maxima and the floors the
// derived buffers need.
func (l Limits) Validate() error {
	switch {
	case l.MaxFlows < 1 || l.MaxFlows > MaxFlows,
		l.MaxHeaderBytes < 1 || l.MaxHeaderBytes > MaxHeaderBytes,
		l.MaxFlowBytes < 1 || l.MaxFlowBytes > MaxFlowBytes,
		l.MaxTotalBytes < l.MaxFlowBytes || l.MaxTotalBytes > MaxTotalBytes,
		l.IdleTimeout < minIdleTimeout || l.IdleTimeout > MaxIdleTimeout,
		l.pagesPerHalf() < 1, l.pagesTotal() < 1, l.readerBudget() < 2*readBuffer:
		return ErrInvalid
	}
	return nil
}

// budget is the shared reader-state counter under MaxTotalBytes.
type budget struct{ used, limit int }

func (b *budget) charge(n int) bool {
	if n > b.limit-b.used {
		return false
	}
	b.used += n
	return true
}

func (b *budget) release(n int) { b.used -= n }

// phase tells a completing flow why it completes.
type phase uint8

const (
	phaseLive  phase = iota // FIN/RST or a buffer-limit flush during Add
	phaseIdle               // FlushCloseOlderThan for the idle timeout
	phaseFinal              // Close
)

// frameContext passes the frame time and truncation to Stream.Accept. The
// assembler keeps the pointer on queued pages but this package reads it only
// in Accept, during the Add that supplied it.
type frameContext struct {
	ci        gopacket.CaptureInfo
	truncated bool
}

func (c *frameContext) GetCaptureInfo() gopacket.CaptureInfo { return c.ci }

// Projector builds one capture's projection. It is not safe for concurrent
// use and holds at most the limits' state.
type Projector struct {
	observer       func(ObservedRecord)
	retainObserved bool
	stamp          SourceStamp
	limits         Limits
	started        time.Time
	last           time.Time
	now            time.Time
	lastFlush      time.Time
	lastStalled    time.Time
	phase          phase
	closed         bool

	eth     layers.Ethernet
	ip4     layers.IPv4
	ip6     layers.IPv6
	tcp     layers.TCP
	parser  *gopacket.DecodingLayerParser
	decoded []gopacket.LayerType

	asm     *reassembly.Assembler
	ctx     frameContext
	active  int
	readers budget

	records  []Record
	counters Counters
}

// NewProjector prepares a projector for a capture that started at started.
// The caller applies the capture's packet filter before Add.
func NewProjector(limits Limits, started time.Time) (*Projector, error) {
	if limits.Validate() != nil || !validTime(started) {
		return nil, ErrInvalid
	}
	p := &Projector{limits: limits, started: started.UTC(), last: started.UTC(), lastFlush: started, decoded: make([]gopacket.LayerType, 0, 4)}
	p.parser = gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &p.eth, &p.ip4, &p.ip6, &p.tcp)
	p.parser.IgnoreUnsupported = true
	p.readers = budget{limit: limits.readerBudget()}
	p.asm = reassembly.NewAssembler(reassembly.NewStreamPool(factory{p}))
	p.asm.MaxBufferedPagesPerConnection = limits.pagesPerHalf()
	p.asm.MaxBufferedPagesTotal = limits.pagesTotal()
	return p, nil
}

func validTime(t time.Time) bool {
	y := t.UTC().Year()
	return !t.IsZero() && y >= minYear && y <= maxYear
}

// Add processes one engine frame: captured bytes (at most Snaplen) and the
// original wire length.
func (p *Projector) Add(frame []byte, wire uint32, at time.Time) {
	p.addObserved(frame, wire, at, SourceStamp{})
}

func (p *Projector) addObserved(frame []byte, wire uint32, at time.Time, stamp SourceStamp) {
	p.stamp = stamp
	if p.closed {
		return
	}
	p.counters.Frames++
	if len(frame) == 0 || len(frame) > Snaplen || !validTime(at) || at.Before(p.started) {
		p.counters.InvalidFrames++
		return
	}
	if int(wire) < len(frame) {
		wire = uint32(len(frame))
	}
	p.decoded = p.decoded[:0]
	if err := p.parser.DecodeLayers(frame, &p.decoded); err != nil && len(p.decoded) < 3 {
		p.counters.NotTCPFrames++
		return
	}
	if len(p.decoded) < 3 || p.decoded[0] != layers.LayerTypeEthernet || p.decoded[2] != layers.LayerTypeTCP {
		p.counters.NotTCPFrames++
		return
	}
	var netFlow gopacket.Flow
	expected := 0
	switch p.decoded[1] {
	case layers.LayerTypeIPv4:
		if p.ip4.Flags&layers.IPv4MoreFragments != 0 || p.ip4.FragOffset != 0 {
			p.counters.FragmentFrames++
			return
		}
		netFlow = p.ip4.NetworkFlow()
		expected = int(p.ip4.Length) - int(p.ip4.IHL)*4 - int(p.tcp.DataOffset)*4
	case layers.LayerTypeIPv6:
		netFlow = p.ip6.NetworkFlow()
		expected = int(p.ip6.Length) - int(p.tcp.DataOffset)*4
	default:
		p.counters.NotTCPFrames++
		return
	}
	if expected < 0 {
		p.counters.NotTCPFrames++
		return
	}
	// The IP length names the payload the wire carried; fewer captured
	// bytes are a gap, never guessed.
	truncated := len(p.tcp.Payload) < expected
	if truncated {
		p.counters.TruncatedFrames++
	}
	if at.After(p.last) {
		p.last = at.UTC()
	}
	p.now = at.UTC()
	if at.Sub(p.lastFlush) >= flushInterval {
		p.lastFlush = at
		p.phase = phaseIdle
		p.asm.FlushCloseOlderThan(at.Add(-p.limits.IdleTimeout))
		p.phase = phaseLive
	}
	if p.active >= p.limits.MaxFlows && p.tcp.SYN && !p.tcp.ACK && at.Sub(p.lastStalled) >= stalledFlushInterval {
		p.lastStalled = at
		p.phase = phaseIdle
		p.asm.FlushCloseOlderThan(at.Add(-min(stalledFlowAge, p.limits.IdleTimeout)))
		p.phase = phaseLive
	}
	p.ctx = frameContext{ci: gopacket.CaptureInfo{Timestamp: at, CaptureLength: len(frame), Length: int(wire)}, truncated: truncated}
	p.asm.AssembleWithContext(netFlow, &p.tcp, &p.ctx)
}

// Close completes every open flow and returns the projection. lost is the
// engine's count of frames it could not deliver.
func (p *Projector) Close(ended time.Time, lost uint64) (Projection, Counters) {
	if !p.closed {
		p.closed = true
		p.phase = phaseFinal
		p.asm.FlushAll()
		p.counters.EngineLostFrames = lost
	}
	end := ended.UTC()
	if !validTime(end) || end.Before(p.last) {
		end = p.last
	}
	return p.projection(end), p.counters
}

// factory admits a flow only from a client SYN and only below the flow cap;
// returning nil keeps no state for the frame.
type factory struct{ p *Projector }

func (f factory) New(_, _ gopacket.Flow, tcp *layers.TCP, _ reassembly.AssemblerContext) reassembly.Stream {
	p := f.p
	if p.active >= p.limits.MaxFlows {
		p.counters.FlowLimitFrames++ // whether it would have started cleanly is unknown
		return nil
	}
	if !tcp.SYN || tcp.ACK {
		if len(tcp.Payload) > 0 {
			p.counters.MidstreamFrames++
		}
		return nil
	}
	p.active++
	p.counters.Flows++
	fl := &flow{p: p}
	fl.halves[0] = &half{p: p, f: fl, client: true}
	fl.halves[1] = &half{p: p, f: fl}
	return fl
}
