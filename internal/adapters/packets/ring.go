package packets

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"sync"
	"time"

	planning "asservat.local/asservat/internal/domain/planning"
)

var ErrRingClosed = errors.New("packet ring closed")
var ErrRingCapacity = errors.New("packet ring capacity unavailable")

// All limits are resolved caller/admin inputs, not defaults or authority.
// Historical storage includes the segment headers and record framing. Filter,
// parser, Go control/allocator and later encoder/upload memory are separate.
type RingLimits struct {
	MaxAge                                 time.Duration
	MaxBytes, SegmentBytes, MaxFrozenBytes int64
	MaxSegments, MaxConcurrentSnapshots    int
}
type RingBounds struct{ StartedAt, Until time.Time }
type RingWindow struct{ From, Until time.Time }
type RingCoverage struct {
	Requested                                     RingWindow
	AvailableFrom, ObservedUntil, SourceStoppedAt time.Time
	Complete, HistoryEvicted, InputUnknown        bool
}
type RingState struct {
	LiveBytes, FrozenBytes    int64
	Snapshots                 int
	Packets                   Counters
	HistoryEvicted, Oversized uint64
	Stopped, Closed           bool
}

// Ring is an unwired sanitized-record container, not source/processing authority.
// Its owner must drive Advance while quiet and Close on cancellation/expiry;
// no timer or goroutine here provides that lifecycle guarantee.
type Ring struct {
	mu                                                      sync.Mutex
	ctx                                                     context.Context
	bounds                                                  RingBounds
	limits                                                  RingLimits
	filter                                                  *Filter
	decoder                                                 *decoder
	scratch                                                 [Snaplen]byte // Bounded parser working state, outside historical storage.
	arena                                                   []byte
	write                                                   int
	now, through, floor, cleanSince, stopped, evictedBefore time.Time
	nextExpiry                                              time.Time
	state                                                   RingState
	evictedRetainedThrough                                  uint64
}

const ringSegmentHeader = 32
const ringRecordHeader = 16

var ringEndian = binary.LittleEndian

func NewRing(ctx context.Context, bounds RingBounds, limits RingLimits, program []planning.BPFInstruction) (*Ring, error) {
	if ctx == nil || ctx.Err() != nil || bounds.StartedAt.IsZero() || !bounds.Until.After(bounds.StartedAt) {
		return nil, ErrInvalid
	}
	deadline, ok := ctx.Deadline()
	if !ok {
		return nil, ErrInvalid
	}
	if deadline.Before(bounds.Until) {
		bounds.Until = deadline
	}
	if !bounds.Until.After(bounds.StartedAt) || limits.MaxAge <= 0 || limits.MaxAge > time.Hour || limits.MaxSegments < 2 || limits.MaxSegments > 64 || limits.MaxBytes < 1 || limits.MaxBytes > 256<<20 || limits.SegmentBytes <= ringSegmentHeader || limits.SegmentBytes > 64<<20 || int64(limits.MaxSegments) > limits.MaxBytes/limits.SegmentBytes || limits.MaxConcurrentSnapshots < 1 || limits.MaxConcurrentSnapshots > 4 || limits.MaxFrozenBytes < 1 || limits.MaxFrozenBytes > 256<<20 {
		return nil, ErrInvalid
	}
	filter, err := NewFilter(program)
	if err != nil {
		return nil, err
	}
	arena := make([]byte, int64(limits.MaxSegments)*limits.SegmentBytes)
	if ctx.Err() != nil {
		return nil, ErrRingClosed
	}
	return &Ring{ctx: ctx, bounds: bounds, limits: limits, filter: filter, decoder: newDecoder(), arena: arena, now: bounds.StartedAt, floor: bounds.StartedAt, cleanSince: bounds.StartedAt, state: RingState{LiveBytes: int64(len(arena))}}, nil
}
func (r *Ring) segment(i int) []byte { n := int(r.limits.SegmentBytes); return r.arena[i*n : (i+1)*n] }
func later(a, b time.Time) time.Time {
	if b.After(a) {
		return b
	}
	return a
}
func (r *Ring) evict(i int) {
	s := r.segment(i)
	n := uint64(ringEndian.Uint32(s[4:]))
	if n > 0 {
		r.state.HistoryEvicted += n
		r.evictedRetainedThrough = max(r.evictedRetainedThrough, ringEndian.Uint64(s[24:])+n-1)
		r.evictedBefore = later(r.evictedBefore, time.Unix(0, int64(ringEndian.Uint64(s[16:]))).Add(time.Nanosecond))
		r.floor = later(r.floor, r.evictedBefore)
	}
	clear(s)
}
func (r *Ring) closeLive() {
	clear(r.arena)
	r.arena = nil
	r.filter = nil
	r.decoder = nil
	r.state.LiveBytes = 0
	r.state.Closed = true
	r.nextExpiry = time.Time{}
}
func (r *Ring) advance(now time.Time) error {
	if r.state.Closed {
		return ErrRingClosed
	}
	if r.ctx.Err() != nil || !now.Before(r.bounds.Until) {
		r.closeLive()
		return ErrRingClosed
	}
	if now.IsZero() || now.Before(r.now) {
		return ErrInvalid
	}
	r.now = now
	cutoff := now.Add(-r.limits.MaxAge)
	r.floor = later(r.floor, cutoff)
	r.nextExpiry = time.Time{}
	for i := 0; i < r.limits.MaxSegments; i++ {
		s := r.segment(i)
		if ringEndian.Uint32(s[4:]) > 0 && time.Unix(0, int64(ringEndian.Uint64(s[8:]))).Before(cutoff) {
			r.evict(i)
		}
		if ringEndian.Uint32(s[4:]) > 0 {
			r.includeExpiry(time.Unix(0, int64(ringEndian.Uint64(s[8:]))))
		}
	}
	return nil
}
func (r *Ring) Advance(now time.Time) error { r.mu.Lock(); defer r.mu.Unlock(); return r.advance(now) }

// NextExpiry lets the existing source owner use its one deadline timer for
// quiet erasure as well as leaf expiry. It creates no timer or coverage proof.
// advance's existing strict-before cutoff expires at the following nanosecond.
func (r *Ring) NextExpiry() time.Time {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.nextExpiry
}

func (r *Ring) includeExpiry(at time.Time) {
	until := at.Add(r.limits.MaxAge).Add(time.Nanosecond)
	if r.nextExpiry.IsZero() || until.Before(r.nextExpiry) {
		r.nextExpiry = until
	}
}

// ObservedThrough records owner-supplied continuous source operation through at,
// under declared clock/cut/loss semantics, not every future callback's timestamp.
// Late buffered records may arrive. The owner must not infer continuity from
// wall time or an empty queue; actual engine health/clock qualification is pending.
// The first assertion starts coverage and cannot backfill earlier quiet history.
func (r *Ring) ObservedThrough(at time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.advance(at); err != nil {
		return err
	}
	if !r.stopped.IsZero() && at.After(r.stopped) {
		return ErrRingClosed
	}
	if r.through.IsZero() {
		r.cleanSince = later(r.cleanSince, at)
	}
	r.through = later(r.through, at)
	return nil
}

// Gap makes earlier coverage conservative without an unbounded gap journal or
// inventing a count of lost samples. A subsequent clean interval can warm again.
func (r *Ring) Gap(at time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.advance(at); err != nil {
		return err
	}
	r.cleanSince = later(r.cleanSince, at.Add(time.Nanosecond))
	return nil
}
func (r *Ring) Stop(at time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.stopped.IsZero() {
		if at.Equal(r.stopped) {
			return nil
		}
		return ErrInvalid
	}
	if err := r.advance(at); err != nil {
		return err
	}
	r.stopped = at
	r.state.Stopped = true
	return nil
}

// Add evaluates the existing filter and sanitizer before copying any bytes.
// Original timestamps/wire lengths survive; invalid lengths are not normalized.
func (r *Ring) Add(frame []byte, wire uint32, at, observedAt time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.advance(observedAt); err != nil {
		if errors.Is(err, ErrInvalid) {
			r.state.Packets.Seen++
			r.state.Packets.Malformed++
			r.cleanSince = later(r.cleanSince, r.now.Add(time.Nanosecond))
		}
		return err
	}
	if r.state.Stopped {
		return ErrRingClosed
	}
	r.state.Packets.Seen++
	if at.IsZero() || at.Before(r.bounds.StartedAt) || at.After(observedAt) || at.Before(observedAt.Add(-r.limits.MaxAge)) || at.UnixNano() <= 0 || !time.Unix(0, at.UnixNano()).Equal(at) || len(frame) > Snaplen || wire == 0 || uint64(wire) < uint64(len(frame)) {
		r.state.Packets.Malformed++
		r.cleanSince = later(r.cleanSince, observedAt.Add(time.Nanosecond))
		return ErrInvalid
	}
	prefix := r.scratch[:len(frame)]
	copy(prefix, frame)
	defer clear(r.scratch[:])
	if !r.filter.Match(prefix, int(wire)) {
		r.state.Packets.Filtered++
		return nil
	}
	n, drop := r.decoder.headerLength(prefix)
	switch drop {
	case DropUnsupported:
		r.state.Packets.Unsupported++
	case DropFragment:
		r.state.Packets.Fragment++
	case DropExtension:
		r.state.Packets.Extension++
	case DropMalformed:
		r.state.Packets.Malformed++
	}
	if drop != DropNone {
		return nil
	}
	if r.state.Packets.Retained == ^uint64(0) {
		r.cleanSince = later(r.cleanSince, observedAt.Add(time.Nanosecond))
		return ErrRingCapacity
	}
	size := ringRecordHeader + (n+3)&^3
	if size > int(r.limits.SegmentBytes)-ringSegmentHeader {
		r.state.Oversized++
		r.cleanSince = later(r.cleanSince, observedAt.Add(time.Nanosecond))
		return ErrRingCapacity
	}
	s := r.segment(r.write)
	used := int(ringEndian.Uint32(s))
	if used+size > len(s)-ringSegmentHeader {
		r.write = (r.write + 1) % r.limits.MaxSegments
		r.evict(r.write)
		s = r.segment(r.write)
		used = 0
	}
	record := s[ringSegmentHeader+used : ringSegmentHeader+used+size]
	ringEndian.PutUint64(record, uint64(at.UnixNano()))
	ringEndian.PutUint32(record[8:], wire)
	ringEndian.PutUint16(record[12:], uint16(n))
	copy(record[ringRecordHeader:], prefix[:n])
	ringEndian.PutUint32(s, uint32(used+size))
	count := ringEndian.Uint32(s[4:])
	ringEndian.PutUint32(s[4:], count+1)
	stamp := uint64(at.UnixNano())
	if count == 0 {
		ringEndian.PutUint64(s[24:], r.state.Packets.Retained+1)
	}
	if count == 0 || stamp < ringEndian.Uint64(s[8:]) {
		ringEndian.PutUint64(s[8:], stamp)
	}
	if count == 0 || stamp > ringEndian.Uint64(s[16:]) {
		ringEndian.PutUint64(s[16:], stamp)
	}
	r.state.Packets.Retained++
	r.state.Packets.WireBytes += uint64(wire)
	r.includeExpiry(at)
	return nil
}
func (r *Ring) State() RingState { r.mu.Lock(); defer r.mu.Unlock(); return r.state }
func (r *Ring) Close() error     { r.mu.Lock(); defer r.mu.Unlock(); r.closeLive(); return nil }

// RingPacket is a caller-owned copy; callers cannot borrow snapshot storage across
// Close or mutate the ring. Length selects the valid header prefix.
type RingPacket struct {
	At     time.Time
	Wire   uint32
	Length int
	Header [Snaplen]byte
}
type RingSnapshot struct {
	mu       sync.Mutex
	ring     *Ring
	data     []byte
	cursor   int
	closed   bool
	coverage RingCoverage
}

func (r *Ring) walk(window RingWindow, visit func([]byte)) {
	r.walkRetained(window, func(b []byte, _ uint64) { visit(b) })
}
func (r *Ring) walkRetained(window RingWindow, visit func([]byte, uint64)) {
	for step := 1; step <= r.limits.MaxSegments; step++ {
		s := r.segment((r.write + step) % r.limits.MaxSegments)
		end := ringSegmentHeader + int(ringEndian.Uint32(s))
		sequence := ringEndian.Uint64(s[24:])
		for at := ringSegmentHeader; at < end; {
			n := int(ringEndian.Uint16(s[at+12:]))
			size := ringRecordHeader + (n+3)&^3
			t := time.Unix(0, int64(ringEndian.Uint64(s[at:])))
			if !t.Before(window.From) && !t.After(window.Until) {
				visit(s[at:at+size], sequence)
			}
			sequence++
			at += size
		}
	}
}

// Snapshot copies records, not a native artifact. Future encoding/publication
// has its separate output/framing/processing budget. No partial-as-complete copy.
func (r *Ring) Snapshot(window RingWindow, now time.Time, maxCopyBytes int64) (*RingSnapshot, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.advance(now); err != nil {
		return nil, err
	}
	if window.From.IsZero() || window.Until.Before(window.From) || maxCopyBytes < 1 || maxCopyBytes > r.limits.MaxFrozenBytes {
		return nil, ErrInvalid
	}
	var n int64
	r.walk(window, func(record []byte) { n += int64(len(record)) })
	if r.state.Snapshots >= r.limits.MaxConcurrentSnapshots || n > maxCopyBytes || n > r.limits.MaxFrozenBytes-r.state.FrozenBytes {
		return nil, ErrRingCapacity
	}
	data := make([]byte, int(n))
	at := 0
	r.walk(window, func(record []byte) { at += copy(data[at:], record) })
	if r.ctx.Err() != nil {
		clear(data)
		r.closeLive()
		return nil, ErrRingClosed
	}
	c := r.coverage(window)
	r.state.FrozenBytes += int64(cap(data))
	r.state.Snapshots++
	return &RingSnapshot{ring: r, data: data, coverage: c}, nil
}
func (r *Ring) coverage(window RingWindow) RingCoverage {
	observed := r.through
	if !r.stopped.IsZero() && observed.After(r.stopped) {
		observed = r.stopped
	}
	c := RingCoverage{Requested: window, AvailableFrom: later(r.floor, r.cleanSince), ObservedUntil: observed, SourceStoppedAt: r.stopped, HistoryEvicted: !r.evictedBefore.IsZero() && window.From.Before(r.evictedBefore), InputUnknown: window.From.Before(r.cleanSince)}
	c.Complete = !window.From.Before(c.AvailableFrom) && !observed.IsZero() && !window.Until.After(observed)
	return c
}
func (s *RingSnapshot) Coverage() RingCoverage { return s.coverage }

// Next and Close serialize on the snapshot mutex. No callback or borrowed
// slice can keep a clearing goroutine racing a reader. Reuse the destination
// only after its consumer joins; Close never erases that independent copy.
func (s *RingSnapshot) Next(p *RingPacket) error {
	if p == nil {
		return ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.nextLocked(p)
}
func (s *RingSnapshot) nextLocked(p *RingPacket) error {
	*p = RingPacket{}
	if s.closed {
		return ErrRingClosed
	}
	if s.cursor == len(s.data) {
		return io.EOF
	}
	b := s.data[s.cursor:]
	p.At = time.Unix(0, int64(ringEndian.Uint64(b))).UTC()
	p.Wire = ringEndian.Uint32(b[8:])
	p.Length = int(ringEndian.Uint16(b[12:]))
	copy(p.Header[:], b[ringRecordHeader:ringRecordHeader+p.Length])
	s.cursor += ringRecordHeader + (p.Length+3)&^3
	return nil
}

// Close releases only local copied RAM, never SQL/capture/input spend. Future
// callers must separately join their upload/processing owner before releasing
// its aggregate reservation. Existing admitted copies outlive Ring.Close.
func (s *RingSnapshot) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	n := int64(cap(s.data))
	clear(s.data[:cap(s.data)])
	s.data = nil
	s.ring.mu.Lock()
	defer s.ring.mu.Unlock()
	s.ring.state.FrozenBytes -= n
	s.ring.state.Snapshots--
	return nil
}

// WindowSnapshot reserves one fixed arena for an immutable pre/post window.
// It is not authority: the owner supplies the original processing context.
// Its pending iterator is inaccessible until Complete seals it exactly once.
type WindowSnapshot struct {
	snapshot   *RingSnapshot
	processing context.Context
	t0         time.Time
	pre        RingCoverage
	final      RingCoverage
	finished   bool
	failure    error
	cut        uint64
}

func (r *Ring) BeginWindowSnapshot(processing context.Context, window RingWindow, t0, now time.Time, maxCopyBytes int64) (*WindowSnapshot, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	deadline, ok := time.Time{}, false
	if processing != nil {
		deadline, ok = processing.Deadline()
	}
	if !ok || processing.Err() != nil || !now.Before(deadline) || window.From.IsZero() || t0.Before(window.From) || t0.After(window.Until) || t0.After(now) || maxCopyBytes < 1 || maxCopyBytes > r.limits.MaxFrozenBytes {
		return nil, ErrInvalid
	}
	if err := r.advance(now); err != nil {
		return nil, err
	}
	if r.state.Snapshots >= r.limits.MaxConcurrentSnapshots || maxCopyBytes > r.limits.MaxFrozenBytes-r.state.FrozenBytes {
		return nil, ErrRingCapacity
	}
	preWindow := RingWindow{window.From, t0}
	var used int
	r.walk(preWindow, func(b []byte) { used += len(b) })
	if int64(used) > maxCopyBytes {
		return nil, ErrRingCapacity
	}
	data := make([]byte, int(maxCopyBytes))
	used = 0
	r.walk(preWindow, func(b []byte) { used += copy(data[used:], b) })
	if processing.Err() != nil || r.ctx.Err() != nil {
		clear(data)
		return nil, ErrRingClosed
	}
	pre := r.coverage(preWindow)
	final := pre
	final.Requested = window
	final.Complete = false
	snapshot := &RingSnapshot{ring: r, data: data[:used]}
	r.state.FrozenBytes += maxCopyBytes
	r.state.Snapshots++
	return &WindowSnapshot{snapshot: snapshot, processing: processing, t0: t0, pre: pre, final: final, cut: r.state.Packets.Retained}, nil
}

// Complete copies posthistory once, never growing the admission arena. Source
// memory expiry can preserve only the independent pre-copy, not renew its data.
func (w *WindowSnapshot) Complete(now time.Time) error {
	s := w.snapshot
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || w.finished || w.processing.Err() != nil {
		return ErrRingClosed
	}
	if now.Before(w.t0) {
		return ErrInvalid
	}
	deadline, _ := w.processing.Deadline()
	if !now.Before(deadline) {
		return context.DeadlineExceeded
	}
	r := s.ring
	r.mu.Lock()
	defer r.mu.Unlock()
	if now.Before(r.now) {
		return ErrInvalid
	}
	if now.Before(w.final.Requested.Until) && !r.state.Stopped && !r.state.Closed && now.Before(r.bounds.Until) && r.ctx.Err() == nil {
		return ErrInvalid
	}
	w.finished = true
	w.final.SourceStoppedAt = r.stopped
	// A frozen pre-copy survives eviction, not newly known unknown input.
	w.final.InputUnknown = w.pre.InputUnknown || r.coverage(w.final.Requested).InputUnknown
	if err := r.advance(now); err != nil {
		if w.t0.Equal(w.final.Requested.Until) && r.state.Packets.Retained == w.cut && !w.final.InputUnknown {
			w.final = w.pre
		}
		w.final.SourceStoppedAt = r.stopped
		return nil
	}
	window := w.final.Requested
	var used int
	r.walkRetained(window, func(b []byte, sequence uint64) {
		if time.Unix(0, int64(ringEndian.Uint64(b))).After(w.t0) || sequence > w.cut {
			used += len(b)
		}
	})
	if used > cap(s.data)-len(s.data) {
		w.failure = ErrRingCapacity
		return w.failure
	}
	if w.processing.Err() != nil {
		w.failure = ErrRingClosed
		return w.failure
	}
	if r.ctx.Err() != nil {
		r.closeLive()
		return nil
	}
	at := len(s.data)
	s.data = s.data[:at+used]
	r.walkRetained(window, func(b []byte, sequence uint64) {
		if time.Unix(0, int64(ringEndian.Uint64(b))).After(w.t0) || sequence > w.cut {
			at += copy(s.data[at:], b)
		}
	})
	if w.processing.Err() != nil {
		w.failure = ErrRingClosed
		return w.failure
	}
	if r.ctx.Err() != nil {
		clear(s.data[at-used:])
		s.data = s.data[:at-used]
		r.closeLive()
		return nil
	}
	// Records have nanosecond timestamps; postcoverage excludes the copied t0.
	post := w.pre
	if !w.t0.Equal(window.Until) {
		post = r.coverage(RingWindow{w.t0.Add(time.Nanosecond), window.Until})
	}
	uncopiedEvicted := r.evictedRetainedThrough > w.cut
	unknown := w.final.InputUnknown || post.InputUnknown || uncopiedEvicted
	w.final.Complete = w.pre.Complete && (w.t0.Equal(window.Until) || post.Complete) && !unknown
	w.final.ObservedUntil = post.ObservedUntil
	w.final.SourceStoppedAt = r.stopped
	w.final.HistoryEvicted = w.pre.HistoryEvicted || post.HistoryEvicted
	w.final.InputUnknown = unknown
	return nil
}
func (w *WindowSnapshot) Coverage() RingCoverage {
	w.snapshot.mu.Lock()
	defer w.snapshot.mu.Unlock()
	return w.final
}
func (w *WindowSnapshot) Next(p *RingPacket) error {
	if p == nil {
		return ErrInvalid
	}
	w.snapshot.mu.Lock()
	defer w.snapshot.mu.Unlock()
	if !w.finished || w.failure != nil || w.processing.Err() != nil {
		return ErrRingClosed
	}
	return w.snapshot.nextLocked(p)
}
func (w *WindowSnapshot) Close() error { return w.snapshot.Close() }
