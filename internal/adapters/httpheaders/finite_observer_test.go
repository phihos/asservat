package httpheaders

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"
)

func TestObservedFiniteHTTPPreservesNativeRecordsAndOriginalClock(t *testing.T) {
	legacy, e := NewProjector(DefaultLimits(), t0)
	if e != nil {
		t.Fatal(e)
	}
	var observed []ObservedRecord
	finite, e := NewObservedProjector(DefaultLimits(), t0, func(r ObservedRecord) { observed = append(observed, r) })
	if e != nil {
		t.Fatal(e)
	}
	sourceCount := 0
	source, e := NewSourceProjector(DefaultLimits(), t0, func(ObservedRecord) { sourceCount++ })
	if e != nil {
		t.Fatal(e)
	}
	at := t0
	raw := uint64(1000)
	c := newConn(40000)
	for _, frames := range [][][]byte{c.handshake(), c.data(true, []byte(secretRequest), 7, 30, 11), c.data(false, []byte(secretResponse), 20, 40), {c.fin(true), c.fin(false)}} {
		for _, frame := range frames {
			at = at.Add(time.Millisecond)
			raw++
			legacy.Add(frame, uint32(len(frame)), at)
			stamp := SourceStamp{RawTimestamp: raw, Clock: "monotonic"}
			finite.AddObserved(frame, uint32(len(frame)), at, stamp)
			source.AddObserved(frame, uint32(len(frame)), at, stamp)
		}
	}
	ended := at.Add(time.Second)
	original, _ := legacy.Close(ended, 2)
	got, _ := finite.Close(ended, 2)
	empty, _ := source.Close(ended, 2)
	a, e := original.EncodeWithin(1 << 20)
	if e != nil {
		t.Fatal(e)
	}
	b, e := got.EncodeWithin(1 << 20)
	if e != nil {
		t.Fatal(e)
	}
	if len(got.Records) != 1 || len(observed) != 1 || !bytes.Equal(a, b) {
		t.Fatal("observing finite capture lost/changed native records", len(got.Records), len(observed))
	}
	if len(empty.Records) != 0 || sourceCount != 1 {
		t.Fatal("ongoing source retained native history")
	}
	if !observed[0].Stamp.Valid() || observed[0].Stamp.Clock != "monotonic" {
		t.Fatal("original source clock missing")
	}
	rawObserved, _ := json.Marshal(observed)
	noSecret(t, rawObserved)
}
