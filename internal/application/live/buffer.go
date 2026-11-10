package live

import (
	"context"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	v "asservat.local/asservat/internal/domain/live"
)

// PendingRow contains only approved fields and an original kernel stamp. Its
// row cannot be disclosed until a bounded authenticated clock proof places it.
type PendingRow = v.StampedRow

// Buffer is one shared exact-source/projection cohort. It owns no ring/history
// reference; overflow drops the viewer data without waiting for collection.
// The accepted source budget must reserve this buffer before construction.
// BufferCounters contains no rows and belongs to the original source epoch.
// Keeping it across inactive cohort disposal prevents sequence/loss reuse.
type BufferCounters struct {
	Sequence    atomic.Uint64
	Lost        atomic.Uint64
	ClockLost   atomic.Uint64
	Unsupported atomic.Uint64
	SensorLost  atomic.Uint64
}

type Buffer struct {
	mu         sync.Mutex
	source     v.Source
	projection string
	until      time.Time
	rows       []PendingRow
	bytes      int
	counters   *BufferCounters
	closed     bool
	wake       chan struct{}
}

func NewBuffer(source v.Source, projection string, now time.Time) (*Buffer, error) {
	return NewBufferWithCounters(source, projection, now, &BufferCounters{})
}
func NewBufferWithCounters(source v.Source, projection string, now time.Time, counters *BufferCounters) (*Buffer, error) {
	if !source.Valid(now) || !v.Projection(projection) || !slices.Contains(source.Projections, projection) || counters == nil {
		return nil, v.ErrInvalid
	}
	return &Buffer{source: source.Clone(), projection: projection, counters: counters, wake: make(chan struct{})}, nil
}

// Activate receives an independently authorized original short reader interval.
// It can retain approved metadata only until that interval, never renew source.
func (b *Buffer) Activate(source v.Source, until, now time.Time) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed || !b.source.Same(source) || !source.Valid(now) || !now.Before(until) || until.After(now.Add(5*time.Second)) || until.After(source.LeaseUntil) || until.After(source.HardUntil) {
		return v.ErrDenied
	}
	b.source = source.Clone()
	b.until = until
	return nil
}
func (b *Buffer) Append(row v.Row, stamp int64, clock string, now time.Time) bool {
	if !b.mu.TryLock() {
		b.counters.Lost.Add(1)
		return false
	}
	defer b.mu.Unlock()
	if b.closed || !now.Before(b.until) {
		b.eraseLocked()
		return false
	}
	if stamp <= 0 || clock != "monotonic" && clock != "boottime" || row.SourceID != b.source.ID() || row.PodUID != b.source.Target.PodUID || row.Projection != b.projection || !row.Valid(now) {
		b.counters.Lost.Add(1)
		return false
	}
	b.trimLocked(now)
	sequence := b.counters.Sequence.Add(1)
	if sequence > 1<<53-1 {
		b.counters.Lost.Add(1)
		return false
	}
	row.Sequence = sequence
	row.ID = b.source.ID() + ":" + uintString(sequence)
	row = row.Clone()
	size := row.Bytes() + 64
	if size > v.MaxBufferBytes {
		b.counters.Lost.Add(1)
		return false
	}
	for len(b.rows) >= v.MaxBufferRows || b.bytes+size > v.MaxBufferBytes {
		b.bytes -= b.rows[0].Row.Bytes() + 64
		clear(b.rows[:1])
		b.rows = b.rows[1:]
		b.counters.Lost.Add(1)
	}
	b.rows = append(b.rows, PendingRow{Row: row, Nanos: stamp, Clock: clock})
	b.bytes += size
	close(b.wake)
	b.wake = make(chan struct{})
	return true
}
func uintString(n uint64) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
func (b *Buffer) trimLocked(now time.Time) {
	for len(b.rows) > 0 && !now.Before(b.rows[0].Row.ExpiresAt) {
		b.bytes -= b.rows[0].Row.Bytes() + 64
		clear(b.rows[:1])
		b.rows = b.rows[1:]
	}
}
func (b *Buffer) eraseLocked()  { clear(b.rows); b.rows = nil; b.bytes = 0 }
func (b *Buffer) Lost() uint64  { return b.counters.Lost.Load() }
func (b *Buffer) Lose(n uint64) { b.counters.Lost.Add(n) }
func (b *Buffer) Head() uint64  { b.mu.Lock(); defer b.mu.Unlock(); return b.counters.Sequence.Load() }

// Read waits only inside the original authorized short activation. One read
// returns at most100 approved rows; no scan of the source ring is possible.
func (b *Buffer) Read(ctx context.Context, after uint64, limit int, now func() time.Time, wait ...bool) ([]PendingRow, uint64, uint64, error) {
	if ctx == nil || limit < 1 || limit > 100 || now == nil {
		return nil, 0, 0, v.ErrInvalid
	}
	for {
		if ctx.Err() != nil {
			return nil, 0, 0, ctx.Err()
		}
		b.mu.Lock()
		at := now()
		if b.closed || !at.Before(b.until) || !at.Before(b.source.LeaseUntil) {
			b.eraseLocked()
			b.mu.Unlock()
			return nil, 0, 0, v.ErrUnavailable
		}
		b.trimLocked(at)
		result := make([]PendingRow, 0, min(limit, len(b.rows)))
		position := after
		for _, p := range b.rows {
			if p.Row.Sequence > after {
				p.Row = p.Row.Clone()
				result = append(result, p)
				position = p.Row.Sequence
				if len(result) == limit {
					break
				}
			}
		}
		lost := b.counters.Lost.Load()
		wake := b.wake
		b.mu.Unlock()
		if len(result) > 0 || len(wait) == 1 && !wait[0] {
			return result, position, lost, nil
		}
		select {
		case <-ctx.Done():
			if ctx.Err() == context.DeadlineExceeded {
				return []PendingRow{}, after, lost, nil
			}
			return nil, 0, 0, ctx.Err()
		case <-wake:
		}
	}
}
func (b *Buffer) Pending() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.rows)
}

func (b *Buffer) Close() {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.closed {
		b.closed = true
		b.eraseLocked()
		b.source = v.Source{}
		close(b.wake)
	}
}

// Specialized loss counters are updated under the owning cohort/source lock.
// Lose remains the total, so old generic gap accounting is conservative.
func (b *Buffer) LoseClock(n uint64)    { b.counters.ClockLost.Add(n) }
func (b *Buffer) LoseProtocol(n uint64) { b.counters.Unsupported.Add(n) }
func (b *Buffer) LoseSensor(n uint64)   { b.counters.SensorLost.Add(n) }
func (b *Buffer) LossPosition() v.Position {
	return v.Position{Lost: b.counters.Lost.Load(), ClockLost: b.counters.ClockLost.Load(), Unsupported: b.counters.Unsupported.Load(), SensorLost: b.counters.SensorLost.Load()}
}
