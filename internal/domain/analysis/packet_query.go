package analysis

import (
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"crypto/sha256"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

const (
	PacketQueryDisplayVersion        = "approved-pcap-query/v1"
	PacketQueryMaxFields             = 32
	PacketQueryMaxPackets            = 100
	PacketQueryMaxScanBytes    int64 = 1 << 30
	PacketQueryMaxInstructions       = 256
	PacketQueryMaxPrefixBytes        = 64
	PacketQueryPageBytes             = ContextResultBytes - 4096
	PacketQueryReadBatches           = 2
	PacketQueryQueryUnits            = 4
	PacketQueryWorkerBytes           = 256 << 20
)

type PacketQueryField string

const (
	PacketIndex              PacketQueryField = "packet_index"
	PacketTime               PacketQueryField = "packet_time"
	PacketCapturedLength     PacketQueryField = "captured_length"
	PacketWireLength         PacketQueryField = "wire_length"
	PacketSourceAddress      PacketQueryField = "source_address"
	PacketDestinationAddress PacketQueryField = "destination_address"
	PacketSourcePort         PacketQueryField = "source_port"
	PacketDestinationPort    PacketQueryField = "destination_port"
	PacketProtocol           PacketQueryField = "protocol"
	PacketTCPFlags           PacketQueryField = "tcp_flags"
	PacketTCPSeq             PacketQueryField = "tcp_seq"
	PacketTCPAck             PacketQueryField = "tcp_ack"
	PacketTCPWindow          PacketQueryField = "tcp_window"
	PacketICMPType           PacketQueryField = "icmp_type"
	PacketICMPCode           PacketQueryField = "icmp_code"
	PacketFramePrefixHex     PacketQueryField = "frame_prefix_hex"
)

func (f PacketQueryField) Valid() bool {
	switch f {
	case PacketIndex, PacketTime, PacketCapturedLength, PacketWireLength, PacketSourceAddress, PacketDestinationAddress, PacketSourcePort, PacketDestinationPort, PacketProtocol, PacketTCPFlags, PacketTCPSeq, PacketTCPAck, PacketTCPWindow, PacketICMPType, PacketICMPCode, PacketFramePrefixHex:
		return true
	}
	return false
}

type PacketQueryTCPFlags struct{ Mask, Value uint16 }
type PacketQueryFramePrefix struct{ Offset, Length uint16 }
type PacketQueryProgram struct {
	CompilerDigest, ProgramDigest artifact.Digest
	Instructions                  []artifact.FilterInstruction
}

func PacketQueryCompilerDigest() artifact.Digest {
	return artifact.Digest{0x92, 0x37, 0xf5, 0xba, 0xe9, 0xdc, 0xf3, 0xa9, 0x18, 0x23, 0xd9, 0x96, 0x3e, 0xc4, 0x3b, 0x7c, 0x0e, 0x2e, 0x33, 0x74, 0xef, 0x2a, 0xd5, 0x7d, 0x92, 0xc8, 0xcd, 0x39, 0x53, 0x0f, 0x47, 0x23}
}
func PacketQueryProgramDigest(program []artifact.FilterInstruction) artifact.Digest {
	b := make([]byte, 0, len(program)*8)
	for _, v := range program {
		b = append(b, byte(v.Code), byte(v.Code>>8), v.Jt, v.Jf, byte(v.K), byte(v.K>>8), byte(v.K>>16), byte(v.K>>24))
	}
	return artifact.Digest(sha256.Sum256(b))
}
func (p PacketQueryProgram) Valid() bool {
	if len(p.Instructions) == 0 {
		return p.CompilerDigest == (artifact.Digest{}) && p.ProgramDigest == (artifact.Digest{})
	}
	return len(p.Instructions) <= PacketQueryMaxInstructions && p.CompilerDigest == PacketQueryCompilerDigest() && p.ProgramDigest == PacketQueryProgramDigest(p.Instructions)
}

type PacketQuerySelection struct {
	Fields             []PacketQueryField
	Program            PacketQueryProgram
	StartTime, EndTime *time.Time
	TCPFlags           *PacketQueryTCPFlags
	FramePrefix        *PacketQueryFramePrefix
	MaxPackets         int
	MaxScanBytes       int64
}

func (s PacketQuerySelection) Valid() bool {
	if len(s.Fields) < 1 || len(s.Fields) > PacketQueryMaxFields || !s.Program.Valid() || s.MaxPackets < 1 || s.MaxPackets > 100 || s.MaxScanBytes < 1 || s.MaxScanBytes > PacketQueryMaxScanBytes {
		return false
	}
	seen := map[PacketQueryField]bool{}
	for _, f := range s.Fields {
		if !f.Valid() || seen[f] {
			return false
		}
		seen[f] = true
	}
	if s.StartTime != nil && s.StartTime.IsZero() || s.EndTime != nil && s.EndTime.IsZero() || s.StartTime != nil && s.EndTime != nil && !s.EndTime.After(*s.StartTime) {
		return false
	}
	if s.TCPFlags != nil && (s.TCPFlags.Mask < 1 || s.TCPFlags.Mask > 511 || s.TCPFlags.Value & ^s.TCPFlags.Mask != 0) {
		return false
	}
	if seen[PacketFramePrefixHex] != (s.FramePrefix != nil) {
		return false
	}
	if p := s.FramePrefix; p != nil && (p.Length < 1 || p.Length > 64 || uint32(p.Offset)+uint32(p.Length) > artifact.MaxRawSnaplen) {
		return false
	}
	return true
}
func (s PacketQuerySelection) ValidFor(nativeType string) bool {
	if !s.Valid() {
		return false
	}
	return nativeType == artifact.RawPCAPNGArtifact || nativeType == artifact.PCAPNGArtifact && s.FramePrefix == nil
}

type PacketQueryWindow struct {
	Fields                                        [32]PacketQueryField
	FieldCount                                    int
	Instructions                                  [256]artifact.FilterInstruction
	ProgramCount                                  int
	CompilerDigest, ProgramDigest                 artifact.Digest
	StartTime, EndTime                            time.Time
	HasStart, HasEnd                              bool
	TCPMask, TCPValue, PrefixOffset, PrefixLength uint16
	MaxPackets                                    int
	MaxScanBytes                                  int64
}

func (s PacketQuerySelection) Window() (PacketQueryWindow, error) {
	if !s.Valid() {
		return PacketQueryWindow{}, ErrInvalid
	}
	w := PacketQueryWindow{FieldCount: len(s.Fields), ProgramCount: len(s.Program.Instructions), CompilerDigest: s.Program.CompilerDigest, ProgramDigest: s.Program.ProgramDigest, MaxPackets: s.MaxPackets, MaxScanBytes: s.MaxScanBytes}
	copy(w.Fields[:], s.Fields)
	copy(w.Instructions[:], s.Program.Instructions)
	if s.StartTime != nil {
		w.StartTime = s.StartTime.UTC()
		w.HasStart = true
	}
	if s.EndTime != nil {
		w.EndTime = s.EndTime.UTC()
		w.HasEnd = true
	}
	if s.TCPFlags != nil {
		w.TCPMask, w.TCPValue = s.TCPFlags.Mask, s.TCPFlags.Value
	}
	if s.FramePrefix != nil {
		w.PrefixOffset, w.PrefixLength = s.FramePrefix.Offset, s.FramePrefix.Length
	}
	return w, nil
}
func (w PacketQueryWindow) Selection() PacketQuerySelection {
	if w.FieldCount < 1 || w.FieldCount > 32 || w.ProgramCount < 0 || w.ProgramCount > 256 {
		return PacketQuerySelection{}
	}
	s := PacketQuerySelection{Fields: append([]PacketQueryField(nil), w.Fields[:w.FieldCount]...), Program: PacketQueryProgram{CompilerDigest: w.CompilerDigest, ProgramDigest: w.ProgramDigest, Instructions: append([]artifact.FilterInstruction(nil), w.Instructions[:w.ProgramCount]...)}, MaxPackets: w.MaxPackets, MaxScanBytes: w.MaxScanBytes}
	if w.HasStart {
		v := w.StartTime
		s.StartTime = &v
	}
	if w.HasEnd {
		v := w.EndTime
		s.EndTime = &v
	}
	if w.TCPMask != 0 {
		s.TCPFlags = &PacketQueryTCPFlags{w.TCPMask, w.TCPValue}
	}
	if w.PrefixLength != 0 {
		s.FramePrefix = &PacketQueryFramePrefix{w.PrefixOffset, w.PrefixLength}
	}
	return s
}
func (w PacketQueryWindow) Valid() bool {
	s := w.Selection()
	back, err := s.Window()
	return err == nil && back == w
}

type PacketQueryCell struct {
	Text   *string
	Number *uint32
}
type PacketQueryResult struct {
	CaptureMode                                           string
	Fields                                                []PacketQueryField
	Rows                                                  [][]PacketQueryCell
	ScannedBytes                                          int64
	ScannedPackets                                        uint32
	RowLimitReached, ScanLimitReached, OutputLimitReached bool
}

func (r PacketQueryResult) Valid(s PacketQuerySelection, nativeType string) bool {
	if !s.ValidFor(nativeType) || r.CaptureMode != "networkHeaders" && r.CaptureMode != "rawPackets" || (nativeType == artifact.RawPCAPNGArtifact) != (r.CaptureMode == "rawPackets") || r.Fields == nil || r.Rows == nil || len(r.Fields) != len(s.Fields) || len(r.Rows) > s.MaxPackets || r.ScannedBytes < 0 || r.ScannedBytes > s.MaxScanBytes {
		return false
	}
	flags := 0
	for _, v := range []bool{r.RowLimitReached, r.ScanLimitReached, r.OutputLimitReached} {
		if v {
			flags++
		}
	}
	if flags > 1 || r.RowLimitReached && len(r.Rows) != s.MaxPackets {
		return false
	}
	for i, f := range r.Fields {
		if f != s.Fields[i] {
			return false
		}
	}
	var last uint32
	for _, row := range r.Rows {
		if len(row) != len(r.Fields) {
			return false
		}
		var captured, wire *uint32
		var protocol *string
		var prefix *string
		for j, c := range row {
			f := r.Fields[j]
			switch f {
			case PacketCapturedLength:
				captured = c.Number
			case PacketWireLength:
				wire = c.Number
			case PacketProtocol:
				protocol = c.Text
			case PacketFramePrefixHex:
				prefix = c.Text
			}
			if !packetCellValid(f, c, s) {
				return false
			}
			if f == PacketIndex {
				if *c.Number <= last || *c.Number > r.ScannedPackets {
					return false
				}
				last = *c.Number
			}
		}
		if captured != nil && wire != nil && *captured > *wire {
			return false
		}
		if captured != nil && prefix != nil && s.FramePrefix != nil {
			available := int64(*captured) - int64(s.FramePrefix.Offset)
			if available <= 0 || int64(len(*prefix)/2) != min(int64(s.FramePrefix.Length), available) {
				return false
			}
		}
		if protocol != nil {
			for j, c := range row {
				if c.Text == nil && c.Number == nil {
					continue
				}
				switch r.Fields[j] {
				case PacketTCPFlags, PacketTCPSeq, PacketTCPAck, PacketTCPWindow:
					if *protocol != "TCP" {
						return false
					}
				case PacketSourcePort, PacketDestinationPort:
					if *protocol != "TCP" && *protocol != "UDP" {
						return false
					}
				case PacketICMPType, PacketICMPCode:
					if *protocol != "ICMPv4" && *protocol != "ICMPv6" {
						return false
					}
				}
			}
		}
	}
	return r.EncodedSize() <= PacketQueryPageBytes
}
func packetCellValid(f PacketQueryField, c PacketQueryCell, s PacketQuerySelection) bool {
	if c.Text != nil && c.Number != nil {
		return false
	}
	if c.Text == nil && c.Number == nil {
		return f != PacketIndex && f != PacketCapturedLength && f != PacketWireLength
	}
	switch f {
	case PacketTime:
		if c.Text == nil {
			return false
		}
		v, err := time.Parse(time.RFC3339Nano, *c.Text)
		return err == nil && v.Format(time.RFC3339Nano) == *c.Text && strings.HasSuffix(*c.Text, "Z") && (s.StartTime == nil || !v.Before(*s.StartTime)) && (s.EndTime == nil || v.Before(*s.EndTime))
	case PacketSourceAddress, PacketDestinationAddress:
		if c.Text == nil {
			return false
		}
		v, e := netip.ParseAddr(*c.Text)
		return e == nil && v.Zone() == "" && v.Unmap().String() == *c.Text
	case PacketProtocol:
		return c.Text != nil && (*c.Text == "TCP" || *c.Text == "UDP" || *c.Text == "ICMPv4" || *c.Text == "ICMPv6")
	case PacketFramePrefixHex:
		if c.Text == nil || s.FramePrefix == nil || len(*c.Text) < 2 || len(*c.Text)%2 != 0 || len(*c.Text) > int(s.FramePrefix.Length)*2 {
			return false
		}
		return strings.Trim(*c.Text, "0123456789abcdef") == ""
	}
	if c.Number == nil {
		return false
	}
	switch f {
	case PacketIndex:
		return *c.Number > 0
	case PacketCapturedLength:
		return *c.Number <= 1500
	case PacketSourcePort, PacketDestinationPort, PacketTCPWindow:
		return *c.Number <= 65535
	case PacketTCPFlags:
		return *c.Number <= 511
	case PacketICMPType, PacketICMPCode:
		return *c.Number <= 255
	case PacketWireLength, PacketTCPSeq, PacketTCPAck:
		return true
	}
	return false
}
func ClonePacketQueryResult(r PacketQueryResult) PacketQueryResult {
	r.Fields = append([]PacketQueryField{}, r.Fields...)
	rows := make([][]PacketQueryCell, len(r.Rows))
	for i, row := range r.Rows {
		rows[i] = append([]PacketQueryCell{}, row...)
		for j, c := range rows[i] {
			if c.Text != nil {
				v := *c.Text
				rows[i][j].Text = &v
			}
			if c.Number != nil {
				v := *c.Number
				rows[i][j].Number = &v
			}
		}
	}
	r.Rows = rows
	return r
}
func (r *PacketQueryResult) Clear() {
	if r == nil {
		return
	}
	for _, row := range r.Rows {
		clear(row)
	}
	clear(r.Rows)
	*r = PacketQueryResult{}
}

// EncodedSize is the exact primitive page JSON size; its closed text values
// contain no escaping characters. Shared wire codecs independently enforce24KiB.
func (r PacketQueryResult) EncodedSize() int {
	n := len(`{"capture_mode":"","fields":[],"rows":[],"scanned_bytes":,"scanned_packets":,"row_limit_reached":,"scan_limit_reached":,"output_limit_reached":}`) + len(r.CaptureMode) + len(strconv.FormatInt(r.ScannedBytes, 10)) + len(strconv.FormatUint(uint64(r.ScannedPackets), 10))
	for i, f := range r.Fields {
		n += len(f) + 2
		if i > 0 {
			n++
		}
	}
	for i, row := range r.Rows {
		if i > 0 {
			n++
		}
		n += 2
		for j, c := range row {
			if j > 0 {
				n++
			}
			if c.Text != nil {
				n += len(*c.Text) + 2
			} else if c.Number != nil {
				n += len(strconv.FormatUint(uint64(*c.Number), 10))
			} else {
				n += 4
			}
		}
	}
	for _, b := range []bool{r.RowLimitReached, r.ScanLimitReached, r.OutputLimitReached} {
		if b {
			n += 4
		} else {
			n += 5
		}
	}
	return n
}

// New bindings are omitted on all legacy scopes and queries.
type ContextQueryGrant struct{ ParentID, ChildID string }

func (g ContextQueryGrant) Valid() bool {
	return authorization.UUID(g.ParentID) && authorization.UUID(g.ChildID)
}

type ContextQueryInvocationKey struct {
	Key           string
	RequestDigest artifact.Digest
}

func (k ContextQueryInvocationKey) Valid() bool {
	return len(k.Key) >= 1 && len(k.Key) <= 128 && k.RequestDigest != (artifact.Digest{})
}

// PacketQueryRequest is ephemeral authored input, never retained query state.
type PacketQueryRequest struct {
	CaseID, ArtifactID, GrantID, IdempotencyKey, PacketFilter string
	Fields                                                    []PacketQueryField
	StartTime, EndTime                                        *time.Time
	TCPFlags                                                  *PacketQueryTCPFlags
	FramePrefix                                               *PacketQueryFramePrefix
	MaxPackets                                                int
	MaxScanBytes                                              int64
}

func (r PacketQueryRequest) Selection(p PacketQueryProgram) PacketQuerySelection {
	return PacketQuerySelection{Fields: r.Fields, Program: p, StartTime: r.StartTime, EndTime: r.EndTime, TCPFlags: r.TCPFlags, FramePrefix: r.FramePrefix, MaxPackets: r.MaxPackets, MaxScanBytes: r.MaxScanBytes}
}
func (r PacketQueryRequest) Valid() bool {
	if !authorization.UUID(r.CaseID) || !authorization.UUID(r.ArtifactID) || r.GrantID != "" && !authorization.UUID(r.GrantID) || len(r.IdempotencyKey) < 1 || len(r.IdempotencyKey) > 128 || len(r.PacketFilter) > 512 || !r.Selection(PacketQueryProgram{}).Valid() {
		return false
	}
	for _, c := range r.PacketFilter {
		if c == '\t' || c == '\r' || c == '\n' {
			continue
		}
		if c < 32 || c > 126 {
			return false
		}
	}
	return true
}
