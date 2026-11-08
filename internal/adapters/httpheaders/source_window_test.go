package httpheaders

import (
	"bytes"
	"encoding/json"
	"io"
	"reflect"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/packets"
	"asservat.local/asservat/internal/domain/artifact"
)

type sourceWindowEntries []packets.RingPacket

func (s *sourceWindowEntries) Next(p *packets.RingPacket) error {
	if len(*s) == 0 {
		return io.EOF
	}
	*p = (*s)[0]
	*s = (*s)[1:]
	return nil
}
func entryPacket(t *testing.T, at time.Time, b []byte, err error) packets.RingPacket {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
	var p packets.RingPacket
	p.At = at
	p.Length = copy(p.Header[:], b)
	return p
}
func TestHTTPSourceWindowActualCountersUnknownCutoffAndFiniteCompatibility(t *testing.T) {
	finite, old := validProjection(t)
	type legacy struct {
		Format    string       `json:"format"`
		Protocol  string       `json:"protocol"`
		StartedAt time.Time    `json:"started_at"`
		EndedAt   time.Time    `json:"ended_at"`
		Limits    LimitsRecord `json:"limits"`
		Records   []Record     `json:"records"`
		Counters  Counters     `json:"counters"`
	}
	expected, _ := json.Marshal(legacy{finite.Format, finite.Protocol, finite.StartedAt, finite.EndedAt, finite.Limits, finite.Records, finite.Counters})
	if !bytes.Equal(old, expected) {
		t.Fatal("finite native bytes changed")
	}
	from, until := finite.StartedAt, finite.EndedAt
	stamp := SourceStamp{RawTimestamp: 1, Clock: "monotonic"}
	var entries sourceWindowEntries
	b, err := EncodeSourceRecord(ObservedRecord{Record: finite.Records[0], Stamp: stamp})
	entries = append(entries, entryPacket(t, until, b, err))
	outside := finite.Records[0]
	outside.Timestamp = from.Add(-time.Nanosecond)
	b, err = EncodeSourceRecord(ObservedRecord{Record: outside, Stamp: stamp})
	entries = append(entries, entryPacket(t, until, b, err))
	d := SourceAccounting{FramesSeen: 8, FramesFiltered: 2, WireBytes: 9000, MatchedWireBytes: 8000, Projection: Counters{Frames: 6, Requests: 2, Responses: 2, Records: 2, StoppedTLS: 1}}
	b, err = EncodeSourceAccounting(d, stamp)
	entries = append(entries, entryPacket(t, until, b, err))
	native, frames, complete, err := EncodeSourceWindow(t.Context(), &entries, DefaultLimits(), 65536, from, until, false)
	if err != nil || complete || frames.Seen != 8 || frames.Filtered != 2 || frames.Retained != 6 || frames.WireBytes != 8000 {
		t.Fatal("incorrect saved-window accounting", frames, complete, err)
	}
	var pr Projection
	if json.Unmarshal(native, &pr) != nil || pr.SourceWindow == nil || pr.SourceWindow.WindowClippedRecords != 1 || pr.Counters.Records != 1 || !bytes.Contains(native, []byte(`"open_at_close_flows":null`)) {
		t.Fatal("unknown state became a measurement", string(native))
	}
	if n, err := CheckProjection(bytes.NewReader(native), DefaultLimits(), 65536); err != nil || n != 1 {
		t.Fatal(n, err)
	}
	page, err := ReadPage(native, DefaultLimits(), 65536, selection(t, "", 10))
	if err != nil || !strings.Contains(strings.Join(page.CoverageGaps, " "), "unknown") || !strings.Contains(strings.Join(page.CoverageGaps, " "), "outside") {
		t.Fatal("public projection concealed source gaps", page, err)
	}
	for _, bad := range [][]byte{bytes.Replace(native, []byte(`"open_at_close_flows":null`), []byte(`"open_at_close_flows":0`), 1), bytes.Replace(native, []byte(`"counter_scope":"event-window"`), []byte(`"counter_scope":"whole-source"`), 1), bytes.Replace(native, []byte(`"open_flows_known":false`), []byte(`"open_flows_known":true`), 1)} {
		if _, err := CheckProjection(bytes.NewReader(bad), DefaultLimits(), 65536); err == nil {
			t.Fatal("invented window coverage accepted")
		}
	}
	l := DefaultLimits()
	e := artifact.ContextExpectation{NativeType: artifact.HTTPHeadersArtifact, Snapshot: &artifact.SourceSnapshotRequest{HTTP: artifact.RecordingHTTP{MaxFlows: l.MaxFlows, MaxHeaderBytes: l.MaxHeaderBytes, MaxFlowBytes: l.MaxFlowBytes, MaxTotalBytes: l.MaxTotalBytes, IdleMillis: l.IdleTimeout.Milliseconds()}, MaxBytes: 65536, SourceStartedAt: from, T0: until, Before: until.Sub(from), SourceHardUntil: until.Add(time.Hour)}}
	check := NewExpectationCheck(e)
	if check.Write(native) != nil || check.Close() != nil || check.PacketCount() != 6 {
		t.Fatal("typed snapshot checker failed")
	}
	if got, cap := ExpectationLimits(e); !reflect.DeepEqual(got, l) || cap != 65536 {
		t.Fatal("source limits lost")
	}
	check = NewExpectationCheck(e)
	_ = check.Write(old)
	if check.Close() == nil {
		t.Fatal("finite native replaced ongoing window")
	}
}
