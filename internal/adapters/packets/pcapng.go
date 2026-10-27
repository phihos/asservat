package packets

import (
	"bytes"
	"errors"
	"io"
	"time"

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
}

// NewRecorder prepares a recorder whose PCAPNG, including its closing
// statistics block, stays within maxBytes. description names the interface
// (fixed text, never workload data).
func NewRecorder(program []value.BPFInstruction, maxBytes int, started time.Time, description string) (*Recorder, error) {
	f, err := NewFilter(program)
	if err != nil {
		return nil, err
	}
	if maxBytes < 4096 || len(description) > 256 {
		return nil, ErrInvalid
	}
	out := &limitedBuffer{limit: maxBytes}
	intf := pcapgo.NgInterface{Name: "pod", Description: description, LinkType: layers.LinkTypeEthernet, SnapLength: Snaplen, TimestampResolution: 9}
	w, err := pcapgo.NewNgWriterInterface(out, intf, pcapgo.NgWriterOptions{SectionInfo: pcapgo.NgSectionInfo{Application: "asservat networkHeaders"}})
	if err != nil {
		return nil, err
	}
	if err := w.Flush(); err != nil {
		return nil, err
	}
	return &Recorder{filter: f, decoder: newDecoder(), out: out, w: w, started: started.UTC()}, nil
}

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
func NewHeadersCheck() *HeadersCheck {
	r, w := io.Pipe()
	c := &HeadersCheck{w: w, done: make(chan error, 1)}
	go func() {
		n, err := CheckHeadersOnly(r)
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
