package packets

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"testing"
	"time"

	query "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

func summaryFixture(t *testing.T, frames [][]byte, stats ...uint64) ([]byte, artifact.ContextExpectation, time.Time) {
	t.Helper()
	at := time.Unix(1800000000, 0).UTC()
	var out bytes.Buffer
	w, err := pcapgo.NewNgWriterInterface(&out, pcapgo.NgInterface{LinkType: layers.LinkTypeEthernet, SnapLength: Snaplen, TimestampResolution: 9, Name: "private-interface-comment"}, pcapgo.NgWriterOptions{SectionInfo: pcapgo.NgSectionInfo{Application: "synthetic-private-application-comment"}})
	if err != nil {
		t.Fatal(err)
	}
	for _, data := range frames {
		if err = w.WritePacket(gopacket.CaptureInfo{Timestamp: at, CaptureLength: len(data), Length: len(data) + 100}, data); err != nil {
			t.Fatal(err)
		}
	}
	for _, drops := range stats {
		if err = w.WriteInterfaceStats(0, pcapgo.NgInterfaceStatistics{StartTime: at, EndTime: at.Add(time.Second), LastUpdate: at.Add(time.Second), PacketsReceived: uint64(len(frames)), PacketsDropped: drops, Comment: "private-statistics-comment"}); err != nil {
			t.Fatal(err)
		}
	}
	if err = w.Flush(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes(), artifact.ContextExpectation{NativeType: artifact.PCAPNGArtifact, DataClass: "metadata", Registration: artifact.Registration{NativeLimit: artifact.RecordingNativeLimit}}, at
}
func summaryHeader(t *testing.T, data []byte) []byte {
	t.Helper()
	n, drop := newDecoder().headerLength(data)
	if drop != DropNone {
		t.Fatal(drop)
	}
	return bytes.Clone(data[:n])
}
func summarizeFixture(t *testing.T, b []byte, e artifact.ContextExpectation, at time.Time) query.PacketSummary {
	t.Helper()
	s, err := SummarizePCAPNG(t.Context(), bytes.NewReader(b), e, at, at.Add(time.Second))
	if err != nil || !s.Valid() {
		t.Fatal(s, err)
	}
	return s
}

func TestPacketSummaryCountsDirectionsProtocolsAndCumulativeExclusions(t *testing.T) {
	c := corpus(t)
	frames := [][]byte{summaryHeader(t, c["tcp4"]), summaryHeader(t, c["tcp4"]), summaryHeader(t, c["udp6"]), summaryHeader(t, c["icmp4"]), summaryHeader(t, c["icmp6"])}
	reverse := bytes.Clone(frames[0])
	copy(reverse[26:30], frames[0][30:34])
	copy(reverse[30:34], frames[0][26:30])
	copy(reverse[34:36], frames[0][36:38])
	copy(reverse[36:38], frames[0][34:36])
	frames = append(frames, reverse)
	b, e, at := summaryFixture(t, frames, 2, 7)
	s := summarizeFixture(t, b, e, at)
	if s.Packets != 6 || s.Drops == nil || *s.Drops != 7 || s.DropReporting != "captureExclusions" || s.ConversationsTotal != 5 || s.Conversations[0].Packets != 2 || s.Conversations[0].Source != "192.0.2.1:40000" || s.Conversations[0].Destination != "192.0.2.2:80" {
		t.Fatalf("wrong saved aggregates: %+v", s)
	}
	raw, _ := json.Marshal(s)
	for _, v := range []string{marker, "private-interface", "private-application", "private-statistics"} {
		if bytes.Contains(raw, []byte(v)) {
			t.Fatal("private nonnumeric field escaped")
		}
	}
	e.Snapshot = &artifact.SourceSnapshotRequest{}
	if summarizeFixture(t, b, e, at).DropReporting != "snapshotOutputLimit" {
		t.Fatal("snapshot exclusion meaning changed")
	}
	b, e, at = summaryFixture(t, nil)
	s = summarizeFixture(t, b, e, at)
	if s.Drops != nil || s.DropReporting != "unavailable" || s.Packets != 0 {
		t.Fatal("missing statistics invented zero")
	}
}
func TestPacketSummaryRejectsSectionWithoutInterface(t *testing.T) {
	b, e, at := summaryFixture(t, nil)
	first := int(binary.LittleEndian.Uint32(b[4:]))
	if _, err := SummarizePCAPNG(t.Context(), bytes.NewReader(b[:first]), e, at, at.Add(time.Second)); err == nil {
		t.Fatal("section without interface invented zero drops")
	}
}
func TestPacketSummaryRefusesMalformedTailAndUnapprovedFrames(t *testing.T) {
	data := summaryHeader(t, tcp4(t, false))
	b, e, at := summaryFixture(t, [][]byte{data}, 3)
	for _, mode := range []string{"short-tail", "unknown-block", "bad-trailer", "oversized-block", "bad-option", "out-of-window", "raw-class", "wrong-type", "over-native-limit", "payload", "decreasing-stats"} {
		t.Run(mode, func(t *testing.T) {
			raw := bytes.Clone(b)
			expect := e
			from := at
			switch mode {
			case "short-tail":
				raw = append(raw, 1, 2, 3)
			case "unknown-block":
				raw = append(raw, summaryTestBlock(binary.LittleEndian, 4, nil)...)
			case "bad-trailer":
				raw[len(raw)-1] ^= 1
			case "oversized-block":
				raw = append(raw, []byte{6, 0, 0, 0, 4, 0, 4, 0, 0, 0, 0, 0}...)
			case "bad-option":
				body := make([]byte, 16)
				binary.LittleEndian.PutUint16(body[12:], 5)
				binary.LittleEndian.PutUint16(body[14:], 8)
				raw = append(raw, summaryTestBlock(binary.LittleEndian, 5, body)...)
			case "out-of-window":
				from = at.Add(time.Second)
				expect.Snapshot = &artifact.SourceSnapshotRequest{}
			case "raw-class":
				expect.DataClass = "raw"
			case "wrong-type":
				expect.NativeType = artifact.RawPCAPNGArtifact
			case "over-native-limit":
				expect.Registration.NativeLimit = int64(len(raw) - 1)
			case "payload":
				raw, expect, _ = summaryFixture(t, [][]byte{tcp4(t, false)}, 3)
			case "decreasing-stats":
				raw, expect, _ = summaryFixture(t, [][]byte{data}, 7, 3)
			}
			if result, err := SummarizePCAPNG(t.Context(), bytes.NewReader(raw), expect, from, at.Add(time.Second)); err == nil || result.CaptureMode != "" {
				t.Fatal("malformed/unapproved input returned summary", err)
			}
		})
	}
}
func summaryTestBlock(order binary.ByteOrder, kind uint32, body []byte) []byte {
	out := make([]byte, len(body)+12)
	order.PutUint32(out, kind)
	order.PutUint32(out[4:], uint32(len(out)))
	copy(out[8:], body)
	order.PutUint32(out[len(out)-4:], uint32(len(out)))
	return out
}
func TestPacketSummaryTopPrefixUsesFullBoundedAggregateSet(t *testing.T) {
	base := summaryHeader(t, tcp4(t, false))
	frames := make([][]byte, query.PacketSummaryMaxAggregates)
	for i := range frames {
		frames[i] = bytes.Clone(base)
		binary.BigEndian.PutUint16(frames[i][34:], uint16(i))
	}
	// Last distinct key becomes the top-ranked conversation, beyond any input prefix.
	frames = append(frames, frames[len(frames)-1], frames[len(frames)-1])
	b, e, at := summaryFixture(t, frames, 0)
	s := summarizeFixture(t, b, e, at)
	if s.ConversationsTotal != query.PacketSummaryMaxAggregates || !s.ConversationsTruncated || len(s.Conversations) != 100 || s.Conversations[0].Source != "192.0.2.1:16383" || s.Conversations[0].Packets != 3 || s.Packets != int64(len(frames)) {
		t.Fatal("truncated before complete aggregation", s.ConversationsTotal, s.Packets)
	}
	extra := bytes.Clone(base)
	binary.BigEndian.PutUint16(extra[34:], uint16(query.PacketSummaryMaxAggregates))
	b, e, at = summaryFixture(t, append(frames, extra), 0)
	if _, err := SummarizePCAPNG(t.Context(), bytes.NewReader(b), e, at, at.Add(time.Second)); err == nil {
		t.Fatal("aggregate cap widened")
	}
}

type summaryCancelReader struct {
	r      io.Reader
	cancel context.CancelFunc
}

func (r summaryCancelReader) Read(p []byte) (int, error) {
	n, e := r.r.Read(p)
	r.cancel()
	return n, e
}
func TestPacketSummaryCancellationAndMaximumNativeRead(t *testing.T) {
	data := summaryHeader(t, tcp4(t, false))
	b, e, at := summaryFixture(t, [][]byte{data}, 0)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	if _, err := SummarizePCAPNG(ctx, summaryCancelReader{bytes.NewReader(b), cancel}, e, at, at.Add(time.Second)); err == nil {
		t.Fatal("canceled read returned result")
	}

	// Exactly8MiB using bounded statistics comment options, which are ignored.
	var out bytes.Buffer
	out.Write(b)
	for out.Len() < int(artifact.RecordingNativeLimit) {
		size := min(summaryBlockLimit, int(artifact.RecordingNativeLimit)-out.Len())
		body := make([]byte, 12)
		drop := make([]byte, 12)
		binary.LittleEndian.PutUint16(drop, 5)
		binary.LittleEndian.PutUint16(drop[2:], 8)
		body = append(body, drop...)
		remaining := size - 40 // block12 + statistics12 + drop12 + end4
		for remaining > 0 {
			n := min(65532, remaining-4)
			option := make([]byte, 4+n)
			binary.LittleEndian.PutUint16(option, 1)
			binary.LittleEndian.PutUint16(option[2:], uint16(n))
			body = append(body, option...)
			remaining -= 4 + n
		}
		body = append(body, 0, 0, 0, 0)
		out.Write(summaryTestBlock(binary.LittleEndian, 5, body))
	}
	if out.Len() != int(artifact.RecordingNativeLimit) {
		t.Fatal("maximum fixture shape", out.Len())
	}
	if s, err := SummarizePCAPNG(t.Context(), bytes.NewReader(out.Bytes()), e, at, at.Add(time.Second)); err != nil || s.Packets != 1 {
		t.Fatal("exact maximum refused", err)
	}
	out.WriteByte(0)
	if _, err := SummarizePCAPNG(t.Context(), bytes.NewReader(out.Bytes()), e, at, at.Add(time.Second)); err == nil {
		t.Fatal("oversized input accepted")
	}
}

func TestPacketSummaryEndianSectionsAndIndependentInterfaces(t *testing.T) {
	data := summaryHeader(t, tcp4(t, false))
	at := time.Unix(1800000000, 0).UTC()
	section := func(order binary.ByteOrder, missingStats bool) []byte {
		var out bytes.Buffer
		body := make([]byte, 16)
		order.PutUint32(body, 0x1a2b3c4d)
		order.PutUint16(body[4:], 1)
		order.PutUint64(body[8:], ^uint64(0))
		out.Write(summaryTestBlock(order, 0x0a0d0d0a, body))
		for range 2 {
			body = make([]byte, 20)
			order.PutUint16(body, 1)
			order.PutUint32(body[4:], Snaplen)
			order.PutUint16(body[8:], 9)
			order.PutUint16(body[10:], 1)
			body[12] = 9
			out.Write(summaryTestBlock(order, 1, body))
		}
		stamp := uint64(at.UnixNano())
		for _, iface := range []uint32{0, 1, 1} {
			body = make([]byte, 20+(len(data)+3)&^3)
			order.PutUint32(body, iface)
			order.PutUint32(body[4:], uint32(stamp>>32))
			order.PutUint32(body[8:], uint32(stamp))
			order.PutUint32(body[12:], uint32(len(data)))
			order.PutUint32(body[16:], 1500)
			copy(body[20:], data)
			out.Write(summaryTestBlock(order, 6, body))
		}
		for _, stat := range []struct {
			iface           uint32
			received, drops uint64
		}{{0, 1, 2}, {0, 1, 7}, {1, 2, 3}} {
			if missingStats && stat.iface == 1 {
				continue
			}
			body = make([]byte, 40)
			order.PutUint32(body, stat.iface)
			order.PutUint32(body[4:], uint32(stamp>>32))
			order.PutUint32(body[8:], uint32(stamp))
			order.PutUint16(body[12:], 4)
			order.PutUint16(body[14:], 8)
			order.PutUint64(body[16:], stat.received)
			order.PutUint16(body[24:], 5)
			order.PutUint16(body[26:], 8)
			order.PutUint64(body[28:], stat.drops)
			out.Write(summaryTestBlock(order, 5, body))
		}
		return out.Bytes()
	}
	_, e, _ := summaryFixture(t, nil)
	for _, order := range []binary.ByteOrder{binary.LittleEndian, binary.BigEndian} {
		s := summarizeFixture(t, section(order, false), e, at)
		if s.Packets != 3 || s.Drops == nil || *s.Drops != 10 || len(s.Conversations) != 1 {
			t.Fatal("section/interface statistics changed", s)
		}
		s = summarizeFixture(t, section(order, true), e, at)
		if s.Drops != nil || s.DropReporting != "unavailable" {
			t.Fatal("missing interface statistics claimed coverage")
		}
	}
	both := append(section(binary.LittleEndian, false), section(binary.BigEndian, false)...)
	s := summarizeFixture(t, both, e, at)
	if s.Packets != 6 || s.Drops == nil || *s.Drops != 20 || s.Conversations[0].Packets != 6 {
		t.Fatal("section-local interface IDs mixed", s)
	}
}

func TestPacketSummaryFiniteMicrosecondManifestDoesNotInventClockCoverage(t *testing.T) {
	b, e, at := summaryFixture(t, [][]byte{summaryHeader(t, tcp4(t, false))})
	// Finite publication truncates its manifest end to microseconds while saved
	// packet stamps retain nanoseconds. This projection reports no interval.
	for off := 0; off < len(b); {
		size := int(binary.LittleEndian.Uint32(b[off+4:]))
		if binary.LittleEndian.Uint32(b[off:]) == 6 {
			stamp := uint64(at.Add(500 * time.Nanosecond).UnixNano())
			binary.LittleEndian.PutUint32(b[off+12:], uint32(stamp>>32))
			binary.LittleEndian.PutUint32(b[off+16:], uint32(stamp))
			break
		}
		off += size
	}
	if s, err := SummarizePCAPNG(t.Context(), bytes.NewReader(b), e, at, at); err != nil || s.Packets != 1 {
		t.Fatal("finite precision difference rejected saved metadata", err)
	}
	e.Snapshot = &artifact.SourceSnapshotRequest{}
	if _, err := SummarizePCAPNG(t.Context(), bytes.NewReader(b), e, at, at); err == nil {
		t.Fatal("snapshot retained out-of-window timestamp")
	}
}

func TestPacketSummaryMissingStatisticsCannotEraseMonotonicHistory(t *testing.T) {
	for _, counter := range []uint16{4, 5} {
		b, e, at := summaryFixture(t, [][]byte{summaryHeader(t, tcp4(t, false))}, 7, 2)
		var out bytes.Buffer
		seen := 0
		for off := 0; off < len(b); {
			size := int(binary.LittleEndian.Uint32(b[off+4:]))
			block := bytes.Clone(b[off : off+size])
			if binary.LittleEndian.Uint32(block) == 5 {
				seen++
				if counter == 4 {
					// Existing fixture has received1 in both ISBs; change it to7 then2.
					value := uint64(7)
					if seen == 2 {
						value = 2
					}
					for option := 20; option < len(block)-4; {
						code := binary.LittleEndian.Uint16(block[option:])
						n := int(binary.LittleEndian.Uint16(block[option+2:]))
						if code == 0 {
							break
						}
						if code == 4 {
							binary.LittleEndian.PutUint64(block[option+4:], value)
						}
						option += 4 + (n+3)&^3
					}
					// Keep drops equal so this case fails solely on received history.
					for option := 20; option < len(block)-4; {
						code := binary.LittleEndian.Uint16(block[option:])
						n := int(binary.LittleEndian.Uint16(block[option+2:]))
						if code == 0 {
							break
						}
						if code == 5 {
							binary.LittleEndian.PutUint64(block[option+4:], 7)
						}
						option += 4 + (n+3)&^3
					}
				}
				if seen == 2 {
					out.Write(summaryTestBlock(binary.LittleEndian, 5, make([]byte, 12)))
				}
			}
			out.Write(block)
			off += size
		}
		if _, err := SummarizePCAPNG(t.Context(), bytes.NewReader(out.Bytes()), e, at, at.Add(time.Second)); err == nil {
			t.Fatalf("missing statistics reset cumulative counter%d", counter)
		}
	}
}

func TestPacketSummaryStatisticsDescribeTheirOwnObservationPoint(t *testing.T) {
	b, e, at := summaryFixture(t, [][]byte{summaryHeader(t, tcp4(t, false))}, 2)
	var packet []byte
	for off := 0; off < len(b); {
		n := int(binary.LittleEndian.Uint32(b[off+4:]))
		if binary.LittleEndian.Uint32(b[off:]) == 6 {
			packet = bytes.Clone(b[off : off+n])
			break
		}
		off += n
	}
	// Later saved records do not retroactively turn an earlier received1 statistic
	// into a complete-capture assertion. Its reported exclusions remain2.
	b = append(b, packet...)
	s, err := SummarizePCAPNG(t.Context(), bytes.NewReader(b), e, at, at.Add(time.Second))
	if err != nil || s.Packets != 2 || s.Drops == nil || *s.Drops != 2 {
		t.Fatal("earlier statistics were treated as final coverage", err)
	}
}
