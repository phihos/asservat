package httpheaders

import (
	"bytes"
	"encoding/json"
	"math"
	"reflect"
	"testing"
	"unsafe"
)

func TestHTTPSourceEntriesAreOnlyApprovedMetadataAndActualDeltas(t *testing.T) {
	delta := SourceAccounting{Projection: Counters{Frames: 2, Requests: 1, Responses: 1, Records: 1}, FramesSeen: 3, FramesFiltered: 1, WireBytes: 4500}
	stamp := SourceStamp{RawTimestamp: 123, Clock: "monotonic"}
	encoded, err := EncodeSourceAccounting(delta, stamp)
	if err != nil {
		t.Fatal(err)
	}
	entry, err := DecodeSourceEntry(encoded)
	if err != nil || entry.Accounting == nil || !reflect.DeepEqual(*entry.Accounting, delta) || entry.Stamp != stamp || len(encoded) != SourceCounterEntryBytes {
		t.Fatal("counter metadata changed", err)
	}
	total, err := AddSourceAccounting(delta, delta)
	if err != nil || total.WireBytes != 9000 {
		t.Fatal(err)
	}
	change, err := SourceAccountingDelta(delta, total)
	if err != nil || change != delta {
		t.Fatal("not actual interval delta", err)
	}
	if _, err := SourceAccountingDelta(total, delta); err == nil {
		t.Fatal("negative counter change invented")
	}
	if _, err := AddSourceAccounting(SourceAccounting{WireBytes: math.MaxUint64}, delta); err == nil {
		t.Fatal("counter overflow accepted")
	}
	record := ObservedRecord{Record: Record{Timestamp: t0, Method: "GET", Status: 200, Headers: []Header{{Name: "content-type", Value: "text/plain"}, {Name: "content-length", Value: "0"}}}, Stamp: stamp}
	row, err := EncodeSourceRecord(record)
	if err != nil {
		t.Fatal(err)
	}
	back, err := DecodeSourceEntry(row)
	if err != nil || back.Record == nil || !reflect.DeepEqual(*back.Record, record.Record) || back.Stamp != stamp {
		t.Fatal("record metadata changed", err)
	}
	for _, bad := range [][]byte{append(bytes.Clone(encoded), 0), append(bytes.Clone(row), []byte("{}")...), {9, 0, 0, 0, 0, 0, 0, 0, 0, 0}} {
		if _, err := DecodeSourceEntry(bad); err == nil {
			t.Fatal("unclosed source record accepted")
		}
	}
	record.Record.Headers = append(record.Record.Headers, Header{Name: "authorization", Value: secret})
	if _, err := EncodeSourceRecord(record); err == nil {
		t.Fatal("unapproved header entered source ring")
	}
	b, _ := json.Marshal(entry.Accounting)
	noSecret(t, b)
	t.Logf("counter-entry encoded=%dB; representative approved row=%dB; accounting value=%dB; raw payload retained=0", len(encoded), len(row), unsafe.Sizeof(delta))
}
func BenchmarkHTTPSourceCounterEntry(b *testing.B) {
	d := SourceAccounting{Projection: Counters{Frames: 1}, FramesSeen: 1, WireBytes: 1500}
	stamp := SourceStamp{RawTimestamp: 1, Clock: "monotonic"}
	b.ReportAllocs()
	for range b.N {
		raw, err := EncodeSourceAccounting(d, stamp)
		if err != nil {
			b.Fatal(err)
		}
		if _, err := DecodeSourceEntry(raw); err != nil {
			b.Fatal(err)
		}
	}
}
