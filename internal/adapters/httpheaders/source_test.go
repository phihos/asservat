package httpheaders

import (
	"encoding/json"
	"testing"
	"time"
)

func TestSourceProjectorCarriesOriginalRequestClockAndKeepsNoHistory(t *testing.T) {
	var observed []ObservedRecord
	p, err := NewSourceProjector(DefaultLimits(), t0, func(r ObservedRecord) { observed = append(observed, r) })
	if err != nil {
		t.Fatal(err)
	}
	at := t0
	raw := uint64(1000)
	add := func(frames [][]byte) {
		for _, frame := range frames {
			at = at.Add(time.Millisecond)
			raw++
			p.AddObserved(frame, uint32(len(frame)), at, SourceStamp{RawTimestamp: raw, Clock: "monotonic"})
		}
	}
	c := newConn(40000)
	add(c.handshake())
	add(c.data(true, []byte(secretRequest), 7, 30, 11))
	requestStamp := raw
	add(c.data(false, []byte(secretResponse), 20, 40))
	add([][]byte{c.fin(true), c.fin(false)})
	counters := p.CloseSource(at.Add(time.Second), 0)
	if len(observed) != 1 || observed[0].Stamp.RawTimestamp != requestStamp || observed[0].Stamp.Clock != "monotonic" || !observed[0].Stamp.Valid() || observed[0].Record.Status != 503 || len(p.records) != 0 || p.active != 0 || p.readers.used != 0 || counters.Records != 1 {
		t.Fatal("source lost original clock, record or joined reassembly", observed, counters)
	}
	b, _ := json.Marshal(observed)
	noSecret(t, b)
}
func TestSourceProjectorDoesNotExpireAfterFiniteRecordCap(t *testing.T) {
	count := 0
	p, err := NewSourceProjector(DefaultLimits(), t0, func(ObservedRecord) { count++ })
	if err != nil {
		t.Fatal(err)
	}
	at := t0
	add := func(frames [][]byte) {
		for _, f := range frames {
			at = at.Add(time.Microsecond)
			p.AddObserved(f, uint32(len(f)), at, SourceStamp{RawTimestamp: uint64(at.Sub(t0)) + 1, Clock: "boottime"})
		}
	}
	c := newConn(40000)
	add(c.handshake())
	for range maxRecords + 1 {
		add(c.data(true, []byte("GET / HTTP/1.1\r\nHost: private\r\n\r\n")))
		add(c.data(false, []byte("HTTP/1.1 204 No Content\r\nContent-Type: text/plain\r\n\r\n")))
	}
	counters := p.CloseSource(at, 0)
	if count != maxRecords+1 || counters.Records != uint64(count) || counters.RecordsDropped != 0 || len(p.records) != 0 || p.readers.used != 0 || p.active != 0 {
		t.Fatal("source silently stopped at finite capture output cap", count, counters)
	}
}
