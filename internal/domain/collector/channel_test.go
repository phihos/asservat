package collector

import (
	"testing"
	"time"
)

func TestStatusCadence(t *testing.T) {
	var c StatusCadence
	if c.Wait(t0) != 0 {
		t.Fatal("the first report is immediate")
	}
	c.Sent(t0)
	if w := c.Wait(t0); w != StatusInterval {
		t.Fatalf("next report after the interval: %v", w)
	}
	if w := c.Wait(t0.Add(14 * time.Second)); w != time.Second {
		t.Fatalf("one second left: %v", w)
	}
	if c.Wait(t0.Add(15*time.Second)) != 0 || c.Wait(t0.Add(time.Minute)) != 0 {
		t.Fatal("due at and after the interval")
	}
	c.Urgent()
	if w := c.Wait(t0.Add(200 * time.Millisecond)); w != 800*time.Millisecond {
		t.Fatalf("urgent reports keep the minimum spacing: %v", w)
	}
	if c.Wait(t0.Add(time.Second)) != 0 {
		t.Fatal("urgent report due after the spacing")
	}
	c.Sent(t0.Add(time.Second))
	if w := c.Wait(t0.Add(time.Second)); w != StatusInterval {
		t.Fatalf("urgency cleared by a report: %v", w)
	}
}

func TestDecideRefusesEveryKindInThisBuild(t *testing.T) {
	for _, k := range []WorkKind{WorkArmSource, WorkStopSource, WorkSnapshot, WorkPeerGeneration} {
		r := Decide(Work{ID: "w", Sequence: 3, Kind: k, NotAfter: t0.Add(time.Second)}, t0)
		if r.Outcome != OutcomeRefused || r.Reason != ReasonRecorderNotImplemented || r.Sequence != 3 || r.WorkID != "w" {
			t.Fatalf("%s: %+v", k, r)
		}
	}
	if r := Decide(Work{Kind: WorkSnapshot, NotAfter: t0}, t0); r.Reason != ReasonWorkExpired {
		t.Fatalf("expired: %+v", r)
	}
	if r := Decide(Work{Kind: "exec", NotAfter: t0.Add(time.Hour)}, t0); r.Reason != ReasonWorkUnknown || WorkKind("exec").Valid() {
		t.Fatalf("unknown kind: %+v", r)
	}
	for _, r := range []Reason{ReasonWorkExpired, ReasonRecorderNotImplemented, ReasonNoTrafficHook} {
		if !r.Valid() {
			t.Fatal(r)
		}
	}
	if Reason("Other").Valid() {
		t.Fatal("open reason")
	}
}
