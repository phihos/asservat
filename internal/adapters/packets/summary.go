package packets

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net/netip"
	"sort"
	"time"

	query "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
	"github.com/gopacket/gopacket/layers"
)

const summaryBlockLimit = 256 << 10 // same canonical native block ceiling

type summaryInterface struct {
	snap                          uint32
	resolution                    uint8
	packets                       int64
	drops, received               *int64
	maximumDrops, maximumReceived int64
}
type summaryScan struct {
	sections       int
	ctx            context.Context
	order          binary.ByteOrder
	interfaces     []summaryInterface
	rows           map[[3]string]int64
	packets, drops int64
	unclassified   int64
	unknown        bool
}

// SummarizePCAPNG interprets fixed numeric metadata from saved metadata or raw
// PCAPNG. Raw byte caps may cut inside a header: every record still counts,
// while only completely decoded endpoint tuples enter conversations.
// It never exports options, payload or names.
// Authenticity belongs to the enclosing source reader and canonical checker.
func SummarizePCAPNG(ctx context.Context, source io.Reader, e artifact.ContextExpectation, from, until time.Time) (query.PacketSummary, error) {
	var zero query.PacketSummary
	if ctx == nil || ctx.Err() != nil || source == nil || (e.NativeType != artifact.PCAPNGArtifact || e.DataClass != "metadata") && (e.NativeType != artifact.RawPCAPNGArtifact || e.DataClass != "raw") || e.Registration.NativeLimit < 1 || e.Registration.NativeLimit > artifact.RecordingNativeLimit || from.IsZero() || until.Before(from) {
		return zero, query.ErrUnavailable
	}
	raw := e.NativeType == artifact.RawPCAPNGArtifact
	limit := Snaplen
	var rawLimits RawLimits
	if raw {
		if e.Recording == nil || e.Recording.Profile != "rawPackets" {
			return zero, query.ErrUnavailable
		}
		rawLimits.Snaplen = e.Recording.Snaplen
		if caps := e.Recording.ProtocolSnaplen; caps != nil {
			rawLimits.TCP, rawLimits.UDP, rawLimits.ICMP = caps.TCP, caps.UDP, caps.ICMP
		}
		if !rawLimits.valid() {
			return zero, query.ErrUnavailable
		}
		limit = rawLimits.Max()
	}
	s := summaryScan{ctx: ctx, rows: make(map[[3]string]int64)}
	limited := &io.LimitedReader{R: summaryContextReader{ctx, source}, N: e.Registration.NativeLimit + 1}
	buffer := make([]byte, summaryBlockLimit)
	defer clear(buffer)
	decoder := newDecoder()
	for {
		n, err := io.ReadFull(limited, buffer[:12])
		if errors.Is(err, io.EOF) && n == 0 {
			break
		}
		if err != nil || ctx.Err() != nil {
			return zero, query.ErrUnavailable
		}
		kind := binary.LittleEndian.Uint32(buffer)
		if kind == 0x0a0d0d0a {
			switch binary.LittleEndian.Uint32(buffer[8:12]) {
			case 0x1a2b3c4d:
				s.order = binary.LittleEndian
			case 0x4d3c2b1a:
				s.order = binary.BigEndian
			default:
				return zero, query.ErrUnavailable
			}
		} else if s.order == nil {
			return zero, query.ErrUnavailable
		} else {
			kind = s.order.Uint32(buffer)
		}
		size := s.order.Uint32(buffer[4:8])
		if size < 12 || size%4 != 0 || size > summaryBlockLimit || int64(size-12) > limited.N || limited.N <= 0 {
			return zero, query.ErrUnavailable
		}
		if _, err = io.ReadFull(limited, buffer[12:size]); err != nil || limited.N < 1 || s.order.Uint32(buffer[size-4:size]) != size {
			return zero, query.ErrUnavailable
		}
		body := buffer[8 : size-4]
		switch kind {
		case 0x0a0d0d0a:
			if len(body) < 16 || s.order.Uint16(body[4:]) != 1 || s.sections > 0 && len(s.interfaces) == 0 || s.finishSection() != nil || !summaryOptions(body[16:], s.order, nil) {
				return zero, query.ErrUnavailable
			}
			s.sections++
			s.interfaces = nil
		case 1:
			if len(body) < 8 || s.order.Uint16(body) != 1 || s.order.Uint32(body[4:]) < 1 || s.order.Uint32(body[4:]) > uint32(limit) || len(s.interfaces) >= 4096 {
				return zero, query.ErrUnavailable
			}
			inf := summaryInterface{snap: s.order.Uint32(body[4:]), resolution: 6}
			if !summaryOptions(body[8:], s.order, func(code uint16, v []byte) bool {
				if code == 9 {
					if len(v) != 1 || v[0] > 9 {
						return false
					}
					inf.resolution = v[0]
				}
				return code != 14 // no clock offset transform or provenance inference
			}) {
				return zero, query.ErrUnavailable
			}
			s.interfaces = append(s.interfaces, inf)
		case 6:
			if len(body) < 20 {
				return zero, query.ErrUnavailable
			}
			index, captured, wire := s.order.Uint32(body), s.order.Uint32(body[12:]), s.order.Uint32(body[16:])
			if index >= uint32(len(s.interfaces)) || captured > wire || captured > s.interfaces[index].snap || captured > uint32(limit) || int((captured+3)&^3) > len(body)-20 {
				return zero, query.ErrUnavailable
			}
			inf := &s.interfaces[index]
			if !summaryOptions(body[20+int((captured+3)&^3):], s.order, nil) {
				return zero, query.ErrUnavailable
			}
			stamp := uint64(s.order.Uint32(body[4:]))<<32 | uint64(s.order.Uint32(body[8:]))
			scale := uint64(1)
			for range inf.resolution {
				scale *= 10
			}
			if stamp/scale > uint64(1<<63-1) {
				return zero, query.ErrUnavailable
			}
			at := time.Unix(int64(stamp/scale), int64(stamp%scale)*(1e9/int64(scale)))
			if e.Snapshot != nil && (at.Before(from) || at.After(until)) {
				return zero, query.ErrUnavailable
			}
			frame := body[20 : 20+captured]
			if s.packets >= query.PacketSummaryMaxCount {
				return zero, query.ErrUnavailable
			}
			s.packets++
			inf.packets++
			if raw {
				cap, ok := rawFrameCap(frame, rawLimits)
				if !ok || len(frame) > cap {
					return zero, query.ErrUnavailable
				}
			}
			count, drop := decoder.headerLength(frame)
			if raw && drop != DropNone {
				s.unclassified++
				continue
			}
			if drop != DropNone || !raw && count != len(frame) {
				return zero, query.ErrUnavailable
			}
			row, ok := summaryConversation(decoder)
			if !ok {
				return zero, query.ErrUnavailable
			}
			key := [3]string{row.Protocol, row.Source, row.Destination}
			if _, ok := s.rows[key]; !ok && len(s.rows) >= query.PacketSummaryMaxAggregates {
				return zero, query.ErrUnavailable
			}
			s.rows[key]++
		case 5:
			if len(body) < 12 || s.order.Uint32(body) >= uint32(len(s.interfaces)) {
				return zero, query.ErrUnavailable
			}
			inf := &s.interfaces[s.order.Uint32(body)]
			var drops, received *int64
			if !summaryOptions(body[12:], s.order, func(code uint16, v []byte) bool {
				if code >= 2 && code <= 8 {
					if len(v) != 8 {
						return false
					}
				}
				if code == 4 || code == 5 {
					n := s.order.Uint64(v)
					if n > uint64(query.PacketSummaryMaxCount) {
						return false
					}
					value := int64(n)
					if code == 4 {
						received = &value
					} else {
						drops = &value
					}
				}
				return true
			}) {
				return zero, query.ErrUnavailable
			}
			if drops != nil && *drops < inf.maximumDrops || received != nil && (*received < inf.maximumReceived || *received < inf.packets) {
				return zero, query.ErrUnavailable
			}
			// Missing latest counters cannot erase previous cumulative lower bounds.
			if drops != nil {
				inf.maximumDrops = *drops
			}
			if received != nil {
				inf.maximumReceived = *received
			}
			// Each statistics block is a cumulative snapshot, not an increment.
			inf.drops, inf.received = drops, received
		default:
			return zero, query.ErrUnavailable
		}
	}
	if ctx.Err() != nil || s.order == nil || len(s.interfaces) == 0 || s.finishSection() != nil {
		return zero, query.ErrUnavailable
	}
	out := query.PacketSummary{CaptureMode: "networkHeaders", Packets: s.packets, DropReporting: "unavailable", Conversations: make([]query.PacketConversation, 0, min(len(s.rows), query.PacketSummaryMaxConversations)), ConversationsTotal: len(s.rows)}
	if raw {
		out.CaptureMode = "rawPackets"
		out.UnclassifiedPackets = &s.unclassified
	}
	if !s.unknown {
		out.Drops = &s.drops
		out.DropReporting = "captureExclusions"
		if e.Snapshot != nil {
			out.DropReporting = "snapshotOutputLimit"
		}
	}
	// Work is capped before the aggregate map grows; only the bounded prefix is
	// published, ranked from the complete scan rather than an input prefix.
	all := make([]query.PacketConversation, 0, len(s.rows))
	for key, count := range s.rows {
		all = append(all, query.PacketConversation{Protocol: key[0], Source: key[1], Destination: key[2], Packets: count})
	}
	sort.Slice(all, func(i, j int) bool { return query.PacketConversationBefore(all[i], all[j]) })
	out.Conversations = append(out.Conversations, all[:min(len(all), query.PacketSummaryMaxConversations)]...)
	clear(all)
	out.ConversationsTruncated = len(s.rows) > len(out.Conversations)
	if !out.Valid() {
		return zero, query.ErrUnavailable
	}
	return out, nil
}
func (s *summaryScan) finishSection() error {
	for _, inf := range s.interfaces {
		if inf.drops == nil {
			s.unknown = true
			continue
		}
		if *inf.drops > query.PacketSummaryMaxCount-s.drops {
			return query.ErrUnavailable
		}
		s.drops += *inf.drops
	}
	return nil
}

// Options are framed before inspection; malformed or duplicate semantic options
// cannot be interpreted differently by another PCAPNG reader. Comments are ignored.
func summaryOptions(b []byte, order binary.ByteOrder, accept func(uint16, []byte) bool) bool {
	seen := map[uint16]bool{}
	for len(b) > 0 {
		if len(b) < 4 {
			return false
		}
		code, n := order.Uint16(b), int(order.Uint16(b[2:]))
		b = b[4:]
		if code == 0 {
			if n != 0 {
				return false
			}
			for _, v := range b {
				if v != 0 {
					return false
				}
			}
			return true
		}
		padded := (n + 3) &^ 3
		if padded > len(b) {
			return false
		}
		if code != 1 {
			if seen[code] {
				return false
			}
			seen[code] = true
		}
		if accept != nil && !accept(code, b[:n]) {
			return false
		}
		b = b[padded:]
	}
	return true
}
func summaryConversation(d *decoder) (query.PacketConversation, bool) {
	var src, dst netip.Addr
	var ok bool
	if d.decoded[1] == layers.LayerTypeIPv4 {
		src, ok = netip.AddrFromSlice(d.ip4.SrcIP)
		if !ok {
			return query.PacketConversation{}, false
		}
		dst, ok = netip.AddrFromSlice(d.ip4.DstIP)
	} else {
		src, ok = netip.AddrFromSlice(d.ip6.SrcIP)
		if !ok {
			return query.PacketConversation{}, false
		}
		dst, ok = netip.AddrFromSlice(d.ip6.DstIP)
	}
	if !ok {
		return query.PacketConversation{}, false
	}
	src, dst = src.Unmap(), dst.Unmap()
	out := query.PacketConversation{Source: src.String(), Destination: dst.String()}
	var sp, dp uint16
	switch d.decoded[2] {
	case layers.LayerTypeTCP:
		out.Protocol = "TCP"
		sp, dp = uint16(d.tcp.SrcPort), uint16(d.tcp.DstPort)
	case layers.LayerTypeUDP:
		out.Protocol = "UDP"
		sp, dp = uint16(d.udp.SrcPort), uint16(d.udp.DstPort)
	case layers.LayerTypeICMPv4:
		out.Protocol = "ICMPv4"
	case layers.LayerTypeICMPv6:
		out.Protocol = "ICMPv6"
	default:
		return query.PacketConversation{}, false
	}
	if out.Protocol == "TCP" || out.Protocol == "UDP" {
		out.Source = netip.AddrPortFrom(src, sp).String()
		out.Destination = netip.AddrPortFrom(dst, dp).String()
	}
	return out, true
}

type summaryContextReader struct {
	ctx    context.Context
	source io.Reader
}

func (r summaryContextReader) Read(b []byte) (int, error) {
	if r.ctx.Err() != nil {
		return 0, r.ctx.Err()
	}
	n, e := r.source.Read(b)
	if r.ctx.Err() != nil {
		return 0, r.ctx.Err()
	}
	return n, e
}
