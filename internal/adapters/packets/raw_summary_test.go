package packets

import (
	query "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"testing"
	"time"
)

func TestRawPacketSummaryRetainsPayloadAndTinyPrefixCounts(t *testing.T) {
	frame := tcp4(t, false)
	raw, expect, at := summaryFixtureWithSnaplen(t, [][]byte{frame, frame[:1], frame[:37]}, 1500, 2)
	expect.NativeType, expect.DataClass = artifact.RawPCAPNGArtifact, "raw"
	expect.Recording = &artifact.Recording{Kind: "packetCapture", Profile: "rawPackets", Snaplen: 1500}
	summary, err := SummarizePCAPNG(t.Context(), bytes.NewReader(raw), expect, at, at.Add(time.Second))
	if err != nil {
		t.Fatalf("valid raw payload/tiny prefixes refused: %v", err)
	}
	encoded, _ := json.Marshal(summary)
	var result struct {
		Packets      int64  `json:"packets"`
		Unclassified *int64 `json:"unclassified_packets"`
	}
	if json.Unmarshal(encoded, &result) != nil || result.Packets != 3 || result.Unclassified == nil || *result.Unclassified != 2 || summary.ConversationsTotal != 1 || summary.Conversations[0].Packets != 1 {
		t.Fatalf("saved raw records lost or invented: %s", encoded)
	}
	if bytes.Contains(encoded, []byte(marker)) {
		t.Fatal("payload entered closed summary")
	}
}

func rawSummaryExpectation(e artifact.ContextExpectation, limits RawLimits) artifact.ContextExpectation {
	e.NativeType, e.DataClass = artifact.RawPCAPNGArtifact, "raw"
	e.Recording = &artifact.Recording{Kind: "packetCapture", Profile: "rawPackets", Snaplen: limits.Snaplen}
	if limits.TCP != 0 || limits.UDP != 0 || limits.ICMP != 0 {
		e.Recording.ProtocolSnaplen = &artifact.RecordingProtocolSnaplen{TCP: limits.TCP, UDP: limits.UDP, ICMP: limits.ICMP}
	}
	return e
}
func TestRawPacketSummaryCanonicalPrefixesAndProtocolCaps(t *testing.T) {
	frame := tcp4(t, false)
	for _, cap := range []int{1, 13, 20, 23, 24, 33, 37, 53, 54, 1500} {
		t.Run(fmt.Sprint(cap), func(t *testing.T) {
			limits := RawLimits{Snaplen: cap}
			data := frame[:min(cap, len(frame))]
			b, e, at := summaryFixtureWithSnaplen(t, [][]byte{data}, limits.Max(), 0)
			e = rawSummaryExpectation(e, limits)
			if n, err := CheckRaw(bytes.NewReader(b), limits); err != nil || n != 1 {
				t.Fatalf("fixture must pass actual canonical raw check: %d %v", n, err)
			}
			result := summarizeFixture(t, b, e, at)
			unknown := int64(0)
			if cap < 54 {
				unknown = 1
			}
			if result.Packets != 1 || result.UnclassifiedPackets == nil || *result.UnclassifiedPackets != unknown {
				t.Fatal("raw prefix accounting", cap, result)
			}
		})
	}
	// Protocol overrides permit a full TCP prefix without widening UDP/ICMP.
	limits := RawLimits{Snaplen: 1, TCP: 1500}
	b, e, at := summaryFixtureWithSnaplen(t, [][]byte{frame, frame[:1]}, limits.Max())
	e = rawSummaryExpectation(e, limits)
	if n, err := CheckRaw(bytes.NewReader(b), limits); err != nil || n != 2 {
		t.Fatal("override canonical fixture", err)
	}
	result := summarizeFixture(t, b, e, at)
	if result.Packets != 2 || *result.UnclassifiedPackets != 1 {
		t.Fatal("protocol override lost prefix")
	}
	e.Recording.ProtocolSnaplen.TCP = 32
	if _, err := SummarizePCAPNG(t.Context(), bytes.NewReader(b), e, at, at.Add(time.Second)); err == nil {
		t.Fatal("raw TCP cap widened")
	}
}
func TestRawPacketSummaryFullTailUnknownAndCancellation(t *testing.T) {
	frame := tcp4(t, false)
	b, e, at := summaryFixtureWithSnaplen(t, [][]byte{frame, frame[:1]}, 1500)
	e = rawSummaryExpectation(e, RawLimits{Snaplen: 1500})
	result := summarizeFixture(t, b, e, at)
	if result.Drops != nil || result.DropReporting != "unavailable" {
		t.Fatal("missing raw statistics invented zero")
	}
	for _, mode := range []string{"tail", "trailer", "cap", "unsupported", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			data := bytes.Clone(b)
			expect := e
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			switch mode {
			case "tail":
				data = append(data, 1, 2, 3)
			case "trailer":
				data[len(data)-1] ^= 1
			case "cap":
				expect.Registration.NativeLimit = int64(len(data) - 1)
			case "unsupported":
				data, expect, _ = summaryFixtureWithSnaplen(t, [][]byte{corpus(t)["fragment"]}, 1500)
				expect = rawSummaryExpectation(expect, RawLimits{Snaplen: 1500})
			case "cancel":
				cancel()
			}
			if out, err := SummarizePCAPNG(ctx, bytes.NewReader(data), expect, at, at.Add(time.Second)); err == nil || out.Conversations != nil {
				t.Fatal("invalid raw source returned result", mode, err)
			}
		})
	}
}
func TestRawPacketSummaryBoundedAggregatesAndLateRanking(t *testing.T) {
	base := tcp4(t, false)
	frames := make([][]byte, query.PacketSummaryMaxAggregates)
	for i := range frames {
		frames[i] = bytes.Clone(base)
		binary.BigEndian.PutUint16(frames[i][34:], uint16(i))
	}
	frames = append(frames, base[:1], frames[len(frames)-1], frames[len(frames)-1])
	b, e, at := summaryFixtureWithSnaplen(t, frames, 1500, 0)
	e = rawSummaryExpectation(e, RawLimits{Snaplen: 1500})
	result := summarizeFixture(t, b, e, at)
	if result.Packets != int64(len(frames)) || *result.UnclassifiedPackets != 1 || result.ConversationsTotal != query.PacketSummaryMaxAggregates || !result.ConversationsTruncated || result.Conversations[0].Packets != 3 || result.Conversations[0].Source != "192.0.2.1:16383" {
		t.Fatal("raw full-scan ranking/counts", result.Packets, result.ConversationsTotal)
	}
	extra := bytes.Clone(base)
	binary.BigEndian.PutUint16(extra[34:], uint16(query.PacketSummaryMaxAggregates))
	b, e, at = summaryFixtureWithSnaplen(t, append(frames, extra), 1500, 0)
	e = rawSummaryExpectation(e, RawLimits{Snaplen: 1500})
	if _, err := SummarizePCAPNG(t.Context(), bytes.NewReader(b), e, at, at.Add(time.Second)); err == nil {
		t.Fatal("raw aggregate budget widened")
	}
}

func TestRawPacketSummaryMaximumNativePayloadRead(t *testing.T) {
	frame := make([]byte, 1500)
	copy(frame, tcp4(t, false))
	binary.BigEndian.PutUint16(frame[16:], 1500-14)
	// Fill most of8MiB with maximum retained payload records, then bounded
	// comment/statistics blocks reach the exact native ceiling.
	frames := make([][]byte, 5400)
	for i := range frames {
		frames[i] = frame
	}
	b, e, at := summaryFixtureWithSnaplen(t, frames, 1500, 0)
	e = rawSummaryExpectation(e, RawLimits{Snaplen: 1500})
	raw := summaryMaximumNative(t, b)
	if n, err := CheckRaw(bytes.NewReader(raw.Bytes()), RawLimits{Snaplen: 1500}); err != nil || n != len(frames) {
		t.Fatal("canonical raw maximum fixture", n, err)
	}
	result := summarizeFixture(t, raw.Bytes(), e, at)
	if result.Packets != int64(len(frames)) || *result.UnclassifiedPackets != 0 || result.Conversations[0].Packets != int64(len(frames)) {
		t.Fatal("maximum native raw counts")
	}
	encoded, _ := json.Marshal(result)
	if bytes.Contains(encoded, []byte(marker)) {
		t.Fatal("maximum payload leaked")
	}
	raw.WriteByte(0)
	if _, err := SummarizePCAPNG(t.Context(), bytes.NewReader(raw.Bytes()), e, at, at.Add(time.Second)); err == nil {
		t.Fatal("raw native limit widened")
	}
}
