package packets

import (
	"bytes"
	"errors"
	"io"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/planning"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

// Counters describe one capture: every frame the engine delivered is either
// retained or counted under exactly one drop reason; OutputFull counts frames
// that would have been retained after the output limit was reached.
type Counters struct {
	Seen        uint64
	Retained    uint64
	Filtered    uint64
	Unsupported uint64
	Fragment    uint64
	Extension   uint64
	Malformed   uint64
	OutputFull  uint64
	WireBytes   uint64 // original lengths of retained frames
}

// statsReserve is room kept for the closing interface statistics block.
const statsReserve = 128

var ErrInvalid = errors.New("packet recorder input invalid")

// limitedBuffer refuses a write that would exceed its limit, so the PCAPNG in
// it is always whole blocks.
type limitedBuffer struct {
	buf   bytes.Buffer
	limit int
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if b.buf.Len()+len(p) > b.limit {
		return 0, ErrInvalid
	}
	return b.buf.Write(p)
}

// Recorder turns engine frames into a bounded networkHeaders PCAPNG: the
// hub-compiled filter selects frames, each retained frame is cut at the end of
// its transport header, and the output never exceeds the capture's limit.
// It is not safe for concurrent use.
type Recorder struct {
	filter   *Filter
	decoder  *decoder
	out      *limitedBuffer
	w        *pcapgo.NgWriter
	counters Counters
	started  time.Time
	first    time.Time
	last     time.Time
	full     bool
	raw      *RawLimits
	snaplen  int
}

// RawLimits keep payload prefixes (ADR-279): Snaplen bytes of each retained
// frame, or a nonzero per-transport cap instead. Caps limit bytes; they do not
// redact.
type RawLimits struct{ Snaplen, TCP, UDP, ICMP int }

// Max is the longest prefix any frame keeps: the engine and interface
// snapshot length.
func (l RawLimits) Max() int { return max(l.Snaplen, l.TCP, l.UDP, l.ICMP) }

func (l RawLimits) valid() bool {
	return l.Snaplen >= 1 && min(l.TCP, l.UDP, l.ICMP) >= 0 && l.Max() <= artifact.MaxRawSnaplen
}

func (l RawLimits) cap(transport gopacket.LayerType) int {
	c := 0
	switch transport {
	case layers.LayerTypeTCP:
		c = l.TCP
	case layers.LayerTypeUDP:
		c = l.UDP
	case layers.LayerTypeICMPv4, layers.LayerTypeICMPv6:
		c = l.ICMP
	}
	if c == 0 {
		return l.Snaplen
	}
	return c
}

// NewRecorder prepares a recorder whose PCAPNG, including its closing
// statistics block, stays within maxBytes. description names the interface
// (fixed text, never workload data).
func NewRecorder(program []value.BPFInstruction, maxBytes int, started time.Time, description string) (*Recorder, error) {
	return newRecorder(program, maxBytes, started, description, nil)
}

// NewRawRecorder is NewRecorder for a rawPackets recording: retained frames
// keep their prefix up to limits instead of ending at the transport header.
func NewRawRecorder(program []value.BPFInstruction, maxBytes int, started time.Time, description string, limits RawLimits) (*Recorder, error) {
	if !limits.valid() || len(program) == 0 {
		return nil, ErrInvalid
	}
	return newRecorder(program, maxBytes, started, description, &limits)
}

func newRecorder(program []value.BPFInstruction, maxBytes int, started time.Time, description string, raw *RawLimits) (*Recorder, error) {
	f, err := NewFilter(program)
	if err != nil {
		return nil, err
	}
	if maxBytes < 4096 || len(description) > 256 {
		return nil, ErrInvalid
	}
	out := &limitedBuffer{limit: maxBytes}
	// The engine always hands over at least the header snaplen, so a frame
	// still decodes (and classifies its transport) under a shorter raw cap.
	snaplen, stored, application := Snaplen, Snaplen, "asservat networkHeaders"
	if raw != nil {
		snaplen, stored, application = max(raw.Max(), Snaplen), raw.Max(), "asservat rawPackets"
	}
	intf := pcapgo.NgInterface{Name: "pod", Description: description, LinkType: layers.LinkTypeEthernet, SnapLength: uint32(stored), TimestampResolution: 9}
	w, err := pcapgo.NewNgWriterInterface(out, intf, pcapgo.NgWriterOptions{SectionInfo: pcapgo.NgSectionInfo{Application: application}})
	if err != nil {
		return nil, err
	}
	if err := w.Flush(); err != nil {
		return nil, err
	}
	return &Recorder{filter: f, decoder: newDecoder(), out: out, w: w, started: started.UTC(), raw: raw, snaplen: snaplen}, nil
}

// Snaplen is the longest frame prefix the engine must hand over.
func (r *Recorder) Snaplen() int { return r.snaplen }

// Add processes one engine frame.
func (r *Recorder) Add(frame []byte, wire uint32, at time.Time) {
	r.counters.Seen++
	if int(wire) < len(frame) {
		wire = uint32(len(frame))
	}
	if !r.filter.Match(frame, int(wire)) {
		r.counters.Filtered++
		return
	}
	n, drop := r.decoder.headerLength(frame)
	switch drop {
	case DropUnsupported:
		r.counters.Unsupported++
		return
	case DropFragment:
		r.counters.Fragment++
		return
	case DropExtension:
		r.counters.Extension++
		return
	case DropMalformed:
		r.counters.Malformed++
		return
	}
	if r.raw != nil {
		n = min(len(frame), r.raw.cap(r.decoder.decoded[2]))
	}
	// An enhanced packet block is 32 bytes plus the data padded to 4.
	block := 32 + (n+3)&^3
	if r.full || r.out.buf.Len()+block+statsReserve > r.out.limit {
		r.full = true
		r.counters.OutputFull++
		return
	}
	ci := gopacket.CaptureInfo{Timestamp: at, CaptureLength: n, Length: int(wire)}
	if err := r.w.WritePacket(ci, frame[:n]); err != nil {
		r.counters.Malformed++
		return
	}
	if err := r.w.Flush(); err != nil {
		r.full = true
		r.counters.OutputFull++
		return
	}
	if r.counters.Retained == 0 {
		r.first = at
	}
	r.last = at
	r.counters.Retained++
	r.counters.WireBytes += uint64(wire)
}

// Close appends the interface statistics block (frames delivered by the
// engine and frames not retained) and returns the PCAPNG and the counters.
func (r *Recorder) Close(ended time.Time, lost uint64) ([]byte, Counters, error) {
	stats := pcapgo.NgInterfaceStatistics{LastUpdate: ended.UTC(), StartTime: r.started, EndTime: ended.UTC(), PacketsReceived: r.counters.Seen, PacketsDropped: r.counters.Seen - r.counters.Retained + lost}
	if err := r.w.WriteInterfaceStats(0, stats); err != nil {
		return nil, r.counters, err
	}
	if err := r.w.Flush(); err != nil {
		return nil, r.counters, err
	}
	return r.out.buf.Bytes(), r.counters, nil
}

// Full reports whether the output limit was reached.
func (r *Recorder) Full() bool { return r.full }

// First and Last are the timestamps of the first and last retained frames.
func (r *Recorder) First() time.Time { return r.first }
func (r *Recorder) Last() time.Time  { return r.last }

// ErrNotHeadersOnly is a PCAPNG that holds anything but whole Ethernet, IP
// and transport headers of supported frames.
var ErrNotHeadersOnly = errors.New("packet capture holds more than network headers")

// CheckHeadersOnly is the verifier's recheck of a networkHeaders PCAPNG
// (ADR-248). Independently of the node's counters it decodes every packet with
// the same gopacket rule and requires: Ethernet link type on every interface
// with a snapshot length of at most Snaplen; every packet decodes as Ethernet
// II carrying unfragmented IPv4 or extension-free IPv6 with TCP, UDP, ICMP or
// ICMPv6; its captured bytes end exactly at the end of the transport header
// (no byte of payload, padding or trailer); captured length at most Snaplen
// and at most the original length. It returns the packet count.
func CheckHeadersOnly(src io.Reader) (int, error) {
	r, err := pcapgo.NewNgReader(src, pcapgo.NgReaderOptions{ErrorOnMismatchingLinkType: true})
	if err != nil {
		return 0, ErrNotHeadersOnly
	}
	d := newDecoder()
	count := 0
	for {
		data, ci, err := r.ReadPacketData()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return count, ErrNotHeadersOnly
		}
		if r.LinkType() != layers.LinkTypeEthernet || len(data) != ci.CaptureLength || len(data) > Snaplen || ci.CaptureLength > ci.Length {
			return count, ErrNotHeadersOnly
		}
		for i := 0; i < r.NInterfaces(); i++ {
			intf, err := r.Interface(i)
			if err != nil || intf.LinkType != layers.LinkTypeEthernet || intf.SnapLength == 0 || intf.SnapLength > Snaplen {
				return count, ErrNotHeadersOnly
			}
		}
		n, drop := d.headerLength(data)
		if drop != DropNone || n != len(data) {
			return count, ErrNotHeadersOnly
		}
		count++
	}
	return count, nil
}

// HeadersCheck is the streaming form of CheckHeadersOnly for a verifier that
// sees the authenticated native stream in chunks (ADR-248).
type HeadersCheck struct {
	w    *io.PipeWriter
	done chan error
	n    int
}

// NewHeadersCheck starts a check; Close returns its verdict.
func NewHeadersCheck() *HeadersCheck { return newStreamCheck(CheckHeadersOnly) }

func newStreamCheck(check func(io.Reader) (int, error)) *HeadersCheck {
	r, w := io.Pipe()
	c := &HeadersCheck{w: w, done: make(chan error, 1)}
	go func() {
		n, err := check(r)
		c.n = n
		_, _ = io.Copy(io.Discard, r)
		c.done <- err
	}()
	return c
}

func (c *HeadersCheck) Write(p []byte) error {
	_, err := c.w.Write(p)
	return err
}

// Close ends the stream and returns the verdict.
func (c *HeadersCheck) Close() error {
	_ = c.w.Close()
	return <-c.done
}

// Packets is the number of packets checked; valid after Close.
func (c *HeadersCheck) Packets() int { return c.n }

// ErrRawOverCap is a raw PCAPNG frame longer than its approved cap.
var ErrRawOverCap = errors.New("raw packet capture exceeds its approved prefix caps")

// CheckRaw is the verifier's recheck of a rawPackets PCAPNG (ADR-279),
// independently of the node: Ethernet interfaces with a snapshot length of at
// most limits.Max(); every packet at most its original length and at most the
// cap of its decoded transport (a prefix cut inside its headers, at most
// limits.Max()). It returns the packet count.
func CheckRaw(src io.Reader, limits RawLimits) (int, error) {
	if !limits.valid() {
		return 0, ErrRawOverCap
	}
	r, err := pcapgo.NewNgReader(src, pcapgo.NgReaderOptions{ErrorOnMismatchingLinkType: true})
	if err != nil {
		return 0, ErrRawOverCap
	}
	count := 0
	for {
		data, ci, err := r.ReadPacketData()
		if errors.Is(err, io.EOF) {
			return count, nil
		}
		if err != nil || r.LinkType() != layers.LinkTypeEthernet || len(data) != ci.CaptureLength || len(data) > limits.Max() || ci.CaptureLength > ci.Length {
			return count, ErrRawOverCap
		}
		for i := 0; i < r.NInterfaces(); i++ {
			intf, err := r.Interface(i)
			if err != nil || intf.LinkType != layers.LinkTypeEthernet || intf.SnapLength == 0 || intf.SnapLength > uint32(limits.Max()) {
				return count, ErrRawOverCap
			}
		}
		if c, ok := rawFrameCap(data, limits); !ok || len(data) > c {
			return count, ErrRawOverCap
		}
		count++
	}
}

// rawFrameCap classifies a stored raw frame from its own Ethernet and IP
// header bytes, as the recorder retained it: the cap of its transport as soon
// as the IP header names it; a frame too short to name it fits the smallest
// effective cap (caps are byte budgets, header bytes included). A frame the
// recorder never retains (another ethertype, a fragment, IPv6 extension
// headers or another transport) is refused.
func rawFrameCap(b []byte, l RawLimits) (int, bool) {
	smallest := min(l.cap(layers.LayerTypeTCP), l.cap(layers.LayerTypeUDP), l.cap(layers.LayerTypeICMPv4))
	if len(b) < 14 {
		return smallest, true
	}
	var proto byte
	switch uint16(b[12])<<8 | uint16(b[13]) {
	case 0x0800:
		if len(b) < 24 {
			return smallest, true
		}
		if (uint16(b[20])<<8|uint16(b[21]))&0x3fff != 0 {
			return 0, false // more-fragments flag or a fragment offset
		}
		if proto = b[23]; proto == 58 {
			return 0, false
		}
	case 0x86dd:
		if len(b) < 21 {
			return smallest, true
		}
		if proto = b[20]; proto == 1 {
			return 0, false
		}
	default:
		return 0, false
	}
	switch proto {
	case 6:
		return l.cap(layers.LayerTypeTCP), true
	case 17:
		return l.cap(layers.LayerTypeUDP), true
	case 1, 58:
		return l.cap(layers.LayerTypeICMPv4), true
	}
	return 0, false
}

// NewRawCheck is the streaming form of CheckRaw (see NewHeadersCheck).
func NewRawCheck(limits RawLimits) *HeadersCheck {
	return newStreamCheck(func(r io.Reader) (int, error) { return CheckRaw(r, limits) })
}
