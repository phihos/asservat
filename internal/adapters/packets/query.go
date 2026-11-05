package packets

import (
	query "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
	planning "asservat.local/asservat/internal/domain/planning"
	"context"
	"encoding/hex"
	"github.com/gopacket/gopacket/layers"
	"io"
	"time"
)

// QueryPCAPNG interprets only a closed compiled selection. The source wrapper
// independently authenticates the complete canonical stream and final metadata.
func QueryPCAPNG(ctx context.Context, source io.Reader, e artifact.ContextExpectation, from, until time.Time, s query.PacketQuerySelection) (query.PacketQueryResult, error) {
	var zero query.PacketQueryResult
	if ctx == nil || ctx.Err() != nil || !s.ValidFor(e.NativeType) {
		return zero, query.ErrUnavailable
	}
	program := make([]planning.BPFInstruction, len(s.Program.Instructions))
	for i, v := range s.Program.Instructions {
		program[i] = planning.BPFInstruction{Code: v.Code, Jt: v.Jt, Jf: v.Jf, K: v.K}
	}
	filter, err := NewFilter(program)
	if err != nil {
		return zero, query.ErrUnavailable
	}
	out := query.PacketQueryResult{CaptureMode: "networkHeaders", Fields: append([]query.PacketQueryField{}, s.Fields...), Rows: make([][]query.PacketQueryCell, 0, min(s.MaxPackets, 100))}
	if e.NativeType == artifact.RawPCAPNGArtifact {
		out.CaptureMode = "rawPackets"
	}
	stop := false
	_, err = scanSavedPCAPNG(ctx, source, e, from, until, func(p savedPacket) error {
		if stop {
			return nil
		}
		if out.ScannedBytes+int64(len(p.frame)) > s.MaxScanBytes {
			out.ScanLimitReached = true
			stop = true
			return nil
		}
		out.ScannedBytes += int64(len(p.frame))
		out.ScannedPackets++
		if s.StartTime != nil && p.at.Before(*s.StartTime) || s.EndTime != nil && !p.at.Before(*s.EndTime) {
			return nil
		}
		if s.TCPFlags != nil && (!p.headerOK || len(p.decoder.decoded) != 3 || p.decoder.decoded[2] != layers.LayerTypeTCP || packetTCPFlags(p.decoder)&s.TCPFlags.Mask != s.TCPFlags.Value) {
			return nil
		}
		if !filter.Match(p.frame, int(p.wire)) {
			return nil
		}
		row := make([]query.PacketQueryCell, len(s.Fields))
		for i, f := range s.Fields {
			row[i] = packetQueryCell(f, p, s)
		}
		out.Rows = append(out.Rows, row)
		if out.EncodedSize() > query.PacketQueryPageBytes {
			clear(row)
			out.Rows = out.Rows[:len(out.Rows)-1]
			out.OutputLimitReached = true
			stop = true
			return nil
		}
		if len(out.Rows) == s.MaxPackets {
			out.RowLimitReached = true
			stop = true
		}
		return nil
	})
	if err != nil || ctx.Err() != nil || !out.Valid(s, e.NativeType) {
		out.Clear()
		return zero, query.ErrUnavailable
	}
	return out, nil
}
func queryNumber(n uint32) query.PacketQueryCell { return query.PacketQueryCell{Number: &n} }
func queryText(s string) query.PacketQueryCell   { return query.PacketQueryCell{Text: &s} }
func packetTCPFlags(d *decoder) uint16 {
	var n uint16
	for i, v := range []bool{d.tcp.FIN, d.tcp.SYN, d.tcp.RST, d.tcp.PSH, d.tcp.ACK, d.tcp.URG, d.tcp.ECE, d.tcp.CWR, d.tcp.NS} {
		if v {
			n |= 1 << i
		}
	}
	return n
}
func packetQueryCell(f query.PacketQueryField, p savedPacket, s query.PacketQuerySelection) query.PacketQueryCell {
	switch f {
	case query.PacketIndex:
		return queryNumber(p.ordinal)
	case query.PacketTime:
		if p.at.Year() < 0 || p.at.Year() > 9999 {
			return query.PacketQueryCell{}
		}
		return queryText(p.at.UTC().Format(time.RFC3339Nano))
	case query.PacketCapturedLength:
		return queryNumber(uint32(len(p.frame)))
	case query.PacketWireLength:
		return queryNumber(p.wire)
	case query.PacketFramePrefixHex:
		if int(s.FramePrefix.Offset) >= len(p.frame) {
			return query.PacketQueryCell{}
		}
		end := min(len(p.frame), int(s.FramePrefix.Offset)+int(s.FramePrefix.Length))
		return queryText(hex.EncodeToString(p.frame[int(s.FramePrefix.Offset):end]))
	}
	if !p.headerOK {
		return query.PacketQueryCell{}
	}
	d := p.decoder
	protocol := d.decoded[2]
	switch f {
	case query.PacketSourceAddress:
		if d.decoded[1] == layers.LayerTypeIPv4 {
			return queryText(d.ip4.SrcIP.String())
		}
		return queryText(d.ip6.SrcIP.String())
	case query.PacketDestinationAddress:
		if d.decoded[1] == layers.LayerTypeIPv4 {
			return queryText(d.ip4.DstIP.String())
		}
		return queryText(d.ip6.DstIP.String())
	case query.PacketProtocol:
		switch protocol {
		case layers.LayerTypeTCP:
			return queryText("TCP")
		case layers.LayerTypeUDP:
			return queryText("UDP")
		case layers.LayerTypeICMPv4:
			return queryText("ICMPv4")
		case layers.LayerTypeICMPv6:
			return queryText("ICMPv6")
		}
	case query.PacketSourcePort:
		if protocol == layers.LayerTypeTCP {
			return queryNumber(uint32(d.tcp.SrcPort))
		}
		if protocol == layers.LayerTypeUDP {
			return queryNumber(uint32(d.udp.SrcPort))
		}
	case query.PacketDestinationPort:
		if protocol == layers.LayerTypeTCP {
			return queryNumber(uint32(d.tcp.DstPort))
		}
		if protocol == layers.LayerTypeUDP {
			return queryNumber(uint32(d.udp.DstPort))
		}
	case query.PacketTCPFlags:
		if protocol == layers.LayerTypeTCP {
			return queryNumber(uint32(packetTCPFlags(d)))
		}
	case query.PacketTCPSeq:
		if protocol == layers.LayerTypeTCP {
			return queryNumber(d.tcp.Seq)
		}
	case query.PacketTCPAck:
		if protocol == layers.LayerTypeTCP {
			return queryNumber(d.tcp.Ack)
		}
	case query.PacketTCPWindow:
		if protocol == layers.LayerTypeTCP {
			return queryNumber(uint32(d.tcp.Window))
		}
	case query.PacketICMPType:
		if protocol == layers.LayerTypeICMPv4 {
			return queryNumber(uint32(d.icmp4.TypeCode.Type()))
		}
		if protocol == layers.LayerTypeICMPv6 {
			return queryNumber(uint32(d.icmp6.TypeCode.Type()))
		}
	case query.PacketICMPCode:
		if protocol == layers.LayerTypeICMPv4 {
			return queryNumber(uint32(d.icmp4.TypeCode.Code()))
		}
		if protocol == layers.LayerTypeICMPv6 {
			return queryNumber(uint32(d.icmp6.TypeCode.Code()))
		}
	}
	return query.PacketQueryCell{}
}
