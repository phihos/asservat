package packets

import (
	q "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
	"testing"
	"time"
)

func querySelection() q.PacketQuerySelection {
	return q.PacketQuerySelection{Fields: []q.PacketQueryField{q.PacketIndex, q.PacketCapturedLength, q.PacketWireLength, q.PacketSourceAddress, q.PacketDestinationPort, q.PacketTCPAck}, MaxPackets: 100, MaxScanBytes: 1 << 20}
}
func TestPacketQueryRawPrefixNullsAndByteOffsets(t *testing.T) {
	full := tcp4(t, false)
	frames := [][]byte{full, full[:1], full[:40]}
	b, e, at := summaryFixtureWithSnaplen(t, frames, 1500, 0)
	e = rawSummaryExpectation(e, RawLimits{Snaplen: 1500})
	s := querySelection()
	s.Fields = append(s.Fields, q.PacketFramePrefixHex)
	s.FramePrefix = &q.PacketQueryFramePrefix{Offset: 0, Length: 64}
	out, err := QueryPCAPNG(t.Context(), bytes.NewReader(b), e, at, at.Add(time.Second), s)
	if err != nil || len(out.Rows) != 3 || out.ScannedPackets != 3 || out.CaptureMode != "rawPackets" {
		t.Fatal(out, err)
	}
	for i := range out.Rows {
		if *out.Rows[i][0].Number != uint32(i+1) || *out.Rows[i][1].Number != uint32(len(frames[i])) || *out.Rows[i][6].Text != hex.EncodeToString(frames[i][:min(len(frames[i]), 64)]) {
			t.Fatal("actual frame selection", i, out.Rows[i])
		}
	}
	if out.Rows[0][3].Text == nil || out.Rows[1][3].Text != nil || out.Rows[1][4].Number != nil || out.Rows[2][5].Number != nil {
		t.Fatal("stale or invented decoded values", out.Rows)
	}
	s.FramePrefix = &q.PacketQueryFramePrefix{Offset: 1, Length: 64}
	out, err = QueryPCAPNG(t.Context(), bytes.NewReader(b), e, at, at.Add(time.Second), s)
	if err != nil || out.Rows[1][6] != (q.PacketQueryCell{}) {
		t.Fatal("offset pastsavedbytes must be null", err)
	}
}
func TestPacketQueryStopsLogicalScanButValidatesWholeTail(t *testing.T) {
	b, e, at := summaryFixtureWithSnaplen(t, [][]byte{tcp4(t, false), tcp4(t, false)}, 1500, 0)
	e = rawSummaryExpectation(e, RawLimits{Snaplen: 1500})
	s := querySelection()
	s.MaxPackets = 1
	for _, scan := range []int64{1, 1 << 20} {
		s.MaxScanBytes = scan
		out, err := QueryPCAPNG(t.Context(), bytes.NewReader(b), e, at, at.Add(time.Second), s)
		if err != nil {
			t.Fatal(err)
		}
		if scan == 1 {
			if !out.ScanLimitReached || out.ScannedPackets != 0 || len(out.Rows) != 0 {
				t.Fatal(out)
			}
		} else if !out.RowLimitReached || len(out.Rows) != 1 || out.ScannedPackets != 1 {
			t.Fatal(out)
		}
		bad := append([]byte{}, b...)
		bad[len(bad)-1] ^= 1
		if _, err = QueryPCAPNG(t.Context(), bytes.NewReader(bad), e, at, at.Add(time.Second), s); err == nil {
			t.Fatal("logical stop swallowed malformed tail")
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := QueryPCAPNG(ctx, bytes.NewReader(b), e, at, at.Add(time.Second), s); !errors.Is(err, q.ErrUnavailable) {
		t.Fatal("cancel", err)
	}
}
func TestPacketQueryWireLengthAndTimeFlagFilters(t *testing.T) {
	b, e, at := summaryFixtureWithSnaplen(t, [][]byte{tcp4(t, false)}, 1500, 0)
	e = rawSummaryExpectation(e, RawLimits{Snaplen: 1500})
	s := querySelection()
	s.Program = q.PacketQueryProgram{CompilerDigest: q.PacketQueryCompilerDigest(), Instructions: []artifact.FilterInstruction{{Code: 0x80}, {Code: 0x35, Jf: 1, K: uint32(len(tcp4(t, false)) + 50)}, {Code: 0x06, K: 65535}, {Code: 0x06}}}
	s.Program.ProgramDigest = q.PacketQueryProgramDigest(s.Program.Instructions)
	end := at
	s.EndTime = &end
	out, err := QueryPCAPNG(t.Context(), bytes.NewReader(b), e, at, at.Add(time.Second), s)
	if err != nil || len(out.Rows) != 0 || out.ScannedPackets != 1 {
		t.Fatal("half-open excludes end", out, err)
	}
	s.EndTime = nil
	out, err = QueryPCAPNG(t.Context(), bytes.NewReader(b), e, at, at.Add(time.Second), s)
	if err != nil || len(out.Rows) != 1 {
		t.Fatal(out, err)
	}
	s.TCPFlags = &q.PacketQueryTCPFlags{Mask: 18, Value: 16}
	out, err = QueryPCAPNG(t.Context(), bytes.NewReader(b), e, at, at.Add(time.Second), s)
	if err != nil || len(out.Rows) != 1 {
		t.Fatal("ACK/noSYN flags", err)
	}
	s.TCPFlags.Value = 2
	out, err = QueryPCAPNG(t.Context(), bytes.NewReader(b), e, at, at.Add(time.Second), s)
	if err != nil || len(out.Rows) != 0 {
		t.Fatal("typed flags did not restrict", err)
	}
}

func TestPacketQueryOutputStopAndTimestampOutsideRFC3339(t *testing.T) {
	ip := ip4(layers.IPProtocolTCP)
	tc := &layers.TCP{SrcPort: 65535, DstPort: 65535, Seq: ^uint32(0), Ack: ^uint32(0), Window: 65535, ACK: true}
	_ = tc.SetNetworkLayerForChecksum(ip)
	full := frame(t, eth(layers.EthernetTypeIPv4), ip, tc, gopacket.Payload(bytes.Repeat([]byte{7}, 100)))
	frames := make([][]byte, 100)
	for i := range frames {
		frames[i] = full
	}
	b, e, at := summaryFixtureWithSnaplen(t, frames, 1500, 0)
	e = rawSummaryExpectation(e, RawLimits{Snaplen: 1500})
	s := querySelection()
	s.Fields = []q.PacketQueryField{q.PacketIndex, q.PacketTime, q.PacketCapturedLength, q.PacketWireLength, q.PacketSourceAddress, q.PacketDestinationAddress, q.PacketSourcePort, q.PacketDestinationPort, q.PacketProtocol, q.PacketTCPFlags, q.PacketTCPSeq, q.PacketTCPAck, q.PacketTCPWindow, q.PacketICMPType, q.PacketICMPCode, q.PacketFramePrefixHex}
	s.FramePrefix = &q.PacketQueryFramePrefix{Offset: 0, Length: 64}
	out, err := QueryPCAPNG(t.Context(), bytes.NewReader(b), e, at, at.Add(time.Second), s)
	if err != nil || !out.OutputLimitReached || len(out.Rows) < 1 || len(out.Rows) >= 100 || out.EncodedSize() > q.PacketQueryPageBytes {
		t.Fatal("output boundary", len(out.Rows), out.EncodedSize(), err)
	}
	// Ordinary recording timestamps are not forced into manifest acquisition time.
	// Use second precision so an otherwise valid stored timestamp can exceed9999.
	one, e, at := summaryFixtureWithSnaplen(t, [][]byte{full}, 1500)
	e = rawSummaryExpectation(e, RawLimits{Snaplen: 1500})
	for pos := 0; pos < len(one); {
		kind, n := binary.LittleEndian.Uint32(one[pos:]), int(binary.LittleEndian.Uint32(one[pos+4:]))
		if kind == 1 {
			body := one[pos+8 : pos+n-4]
			for off := 8; off < len(body); {
				code, l := binary.LittleEndian.Uint16(body[off:]), int(binary.LittleEndian.Uint16(body[off+2:]))
				if code == 9 {
					body[off+4] = 0
				}
				off += 4 + (l+3)&^3
			}
		}
		if kind == 6 {
			stamp := uint64(253402300800)
			binary.LittleEndian.PutUint32(one[pos+12:], uint32(stamp>>32))
			binary.LittleEndian.PutUint32(one[pos+16:], uint32(stamp))
		}
		pos += n
	}
	s = querySelection()
	s.Fields = []q.PacketQueryField{q.PacketTime}
	out, err = QueryPCAPNG(t.Context(), bytes.NewReader(one), e, at, at.Add(time.Second), s)
	if err != nil || len(out.Rows) != 1 || out.Rows[0][0] != (q.PacketQueryCell{}) {
		t.Fatal("unrepresentable timestamp fabricated/refused", err)
	}
}
func TestPacketQueryMaximumProgramAndWireLengthCacheSaturation(t *testing.T) {
	var raw bytes.Buffer
	w, err := pcapgo.NewNgWriterInterface(&raw, pcapgo.NgInterface{LinkType: layers.LinkTypeEthernet, SnapLength: 1}, pcapgo.NgWriterOptions{})
	if err != nil {
		t.Fatal(err)
	}
	at := time.Unix(1800000000, 0)
	for n := 1; n <= 5000; n++ {
		if err = w.WritePacket(gopacket.CaptureInfo{Timestamp: at, CaptureLength: 1, Length: n}, []byte{0}); err != nil {
			t.Fatal(err)
		}
	}
	if err = w.Flush(); err != nil {
		t.Fatal(err)
	}
	e := artifact.ContextExpectation{NativeType: artifact.RawPCAPNGArtifact, DataClass: "raw", Registration: artifact.Registration{NativeLimit: artifact.RecordingNativeLimit}, Recording: &artifact.Recording{Profile: "rawPackets", Snaplen: 1}}
	s := querySelection()
	program := make([]artifact.FilterInstruction, 256)
	program[0].Code = 0x80
	for i := 1; i < 255; i++ {
		program[i].Code = 0x04
	}
	program[255].Code = 0x06
	s.Program = q.PacketQueryProgram{CompilerDigest: q.PacketQueryCompilerDigest(), ProgramDigest: q.PacketQueryProgramDigest(program), Instructions: program}
	out, err := QueryPCAPNG(t.Context(), bytes.NewReader(raw.Bytes()), e, at, at.Add(time.Second), s)
	if err != nil || out.ScannedPackets != 5000 || out.ScannedBytes != 5000 || len(out.Rows) != 0 {
		t.Fatal("max bounded VM/cache work", out.ScannedPackets, err)
	}
}

func TestPacketQueryClosedProtocolFields(t *testing.T) {
	cases := corpus(t)
	for _, name := range []string{"tcp4opts", "udp6", "icmp4", "icmp6"} {
		t.Run(name, func(t *testing.T) {
			native, e, at := summaryFixture(t, [][]byte{summaryHeader(t, cases[name])})
			s := querySelection()
			s.Fields = []q.PacketQueryField{q.PacketProtocol, q.PacketSourceAddress, q.PacketSourcePort, q.PacketTCPFlags, q.PacketTCPSeq, q.PacketICMPType, q.PacketICMPCode}
			r, err := QueryPCAPNG(t.Context(), bytes.NewReader(native), e, at, at.Add(time.Second), s)
			if err != nil || len(r.Rows) != 1 || r.Rows[0][0].Text == nil || r.Rows[0][1].Text == nil {
				t.Fatal(err, r)
			}
			row := r.Rows[0]
			if name == "tcp4opts" {
				if row[3].Number == nil || *row[3].Number != 24 || row[5].Number != nil {
					t.Fatal("TCPfields", row)
				}
			} else if name == "udp6" {
				if *row[2].Number != 5353 || row[3].Number != nil || row[5].Number != nil {
					t.Fatal("UDPfields", row)
				}
			} else if row[2].Number != nil || row[4].Number != nil || row[5].Number == nil || row[6].Number == nil || *row[6].Number != 0 {
				t.Fatal("ICMPnull/zero", row)
			}
		})
	}
}
