package live

import (
	v "asservat.local/asservat/internal/domain/live"
	"context"
	"testing"
	"time"
)

func TestLiveBufferBoundedCopiesOverflowAndOriginalActivation(t *testing.T) {
	_, f, _, _ := setup(t)
	b, e := NewBuffer(f.source, v.Packet, f.now)
	if e != nil {
		t.Fatal(e)
	}
	if e = b.Activate(f.source, f.now.Add(5*time.Second), f.now); e != nil {
		t.Fatal(e)
	}
	for n := 0; n < 700; n++ {
		f.add()
		row := f.rows[len(f.rows)-1]
		if !b.Append(row, int64(time.Hour)+int64(n), "monotonic", f.now) {
			t.Fatal("append", n)
		}
	}
	if len(b.rows) != 500 || b.Pending() != 500 || b.bytes > v.MaxBufferBytes || b.Lost() != 200 {
		t.Fatal(len(b.rows), b.Pending(), b.bytes, b.Lost())
	}
	call, cancel := context.WithTimeout(t.Context(), time.Millisecond)
	defer cancel()
	rows, pos, lost, e := b.Read(call, 0, 100, func() time.Time { return f.now })
	if e != nil || len(rows) != 100 || rows[0].Row.Sequence != 201 || pos != 300 || lost != 200 || b.Pending() != 500 {
		t.Fatal(len(rows), pos, lost, b.Pending(), e)
	}
	rows[0].Row.Packet.RemoteIP = "203.0.113.1"
	if b.rows[0].Row.Packet.RemoteIP == rows[0].Row.Packet.RemoteIP {
		t.Fatal("borrowed buffer")
	}
	f.now = f.now.Add(5 * time.Second)
	if b.Append(f.rows[0], 1, "monotonic", f.now) || len(b.rows) != 0 {
		t.Fatal("activation expiry retained payload")
	}
	b.Close()
	if e = b.Activate(f.source, f.now.Add(time.Second), f.now); e == nil {
		t.Fatal("closed epoch revived")
	}
}
func TestLiveBufferNeverBackpressuresAndCancellationReturns(t *testing.T) {
	_, f, _, _ := setup(t)
	b, _ := NewBuffer(f.source, v.Packet, f.now)
	_ = b.Activate(f.source, f.now.Add(time.Second), f.now)
	f.add()
	b.mu.Lock()
	if b.Append(f.rows[0], 1, "monotonic", f.now) {
		t.Fatal("locked collector was blocked")
	}
	b.mu.Unlock()
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, _, _, e := b.Read(ctx, 0, 1, func() time.Time { return f.now }); e != context.Canceled {
		t.Fatal(e)
	}
	b.Close()
}

func TestLiveSourceCountersSurviveCohortEraseWithoutRetainingRows(t *testing.T) {
	_, f, _, _ := setup(t)
	counters := &BufferCounters{}
	b, _ := NewBufferWithCounters(f.source, v.Packet, f.now, counters)
	_ = b.Activate(f.source, f.now.Add(time.Second), f.now)
	f.add()
	if !b.Append(f.rows[0], 1, "monotonic", f.now) {
		t.Fatal("first append")
	}
	b.Lose(2)
	b.Close()
	if len(b.rows) != 0 || b.source.ID() != "" {
		t.Fatal("closed cohort retained fields")
	}
	next, _ := NewBufferWithCounters(f.source, v.Packet, f.now, counters)
	defer next.Close()
	_ = next.Activate(f.source, f.now.Add(time.Second), f.now)
	if next.Head() != 1 || next.Lost() != 2 {
		t.Fatal("source sequence/loss restarted")
	}
	if !next.Append(f.rows[0], 2, "monotonic", f.now) || next.Head() != 2 {
		t.Fatal("row identity reused after reactivation")
	}
}
