package syscalls

import (
	"cmp"
	"slices"
)

// Status says how much of a call was observed.
type Status uint8

const (
	Returned   Status = iota + 1 // ENTER and EXIT paired; Ret is valid
	NoReturn                     // exit, exit_group, rt_sigreturn: traceloop emits no EXIT
	Unfinished                   // ENTER without EXIT when flushed
	Unmatched                    // EXIT without ENTER; EnteredBoot is unknown (0)
)

// Call is one syscall's metadata. Times are CLOCK_BOOTTIME nanoseconds.
// ExitedBoot and Ret are zero unless the EXIT was observed.
type Call struct {
	Number      uint16
	Status      Status
	PID         uint32
	EnteredBoot uint64
	ExitedBoot  uint64
	Ret         int64
}

// x86_64 numbers whose sys_exit traceloop skips (skip_exit_probe).
func noReturn(nr uint16) bool { return nr == 60 || nr == 231 || nr == 15 }

// Stats are cumulative event counts. Counts are events, not calls: an ENTER
// evicted on overflow may later also count its EXIT as unmatched.
type Stats struct {
	Calls      uint64 // Returned and NoReturn calls emitted by Add
	Unfinished uint64 // pending ENTER at Flush, or replaced by a key collision
	Unmatched  uint64 // EXIT whose ENTER never arrived
	Overflow   uint64 // pending halves evicted because MaxTracked was reached
	Invalid    uint64 // CONT or unknown event type: invariant violation, dropped
}

type pairKey struct {
	mono uint64
	pid  uint32
}

type half struct {
	exit bool
	nr   uint16
	boot uint64
	ret  int64
}

// Pairer matches ENTER and EXIT by (monotonic_timestamp, pid). Per-CPU perf
// rings are read without cross-CPU order, so a thread that migrates during a
// call can deliver its EXIT first; either half waits for the other. At most
// MaxTracked halves wait; beyond that the oldest is evicted as a gap. Not
// safe for concurrent use.
type Pairer struct {
	max     int
	pending map[pairKey]half
	// order holds pending keys oldest first; removed keys are skipped lazily.
	order []pairKey
	stats Stats
	gaps  uint64
}

// NewPairer bounds pending halves to maxTracked (at least 1).
func NewPairer(maxTracked int) *Pairer {
	return &Pairer{max: max(maxTracked, 1), pending: make(map[pairKey]half)}
}

// Add consumes one event and returns a completed call when it finishes one.
func (p *Pairer) Add(e RawEvent) (Call, bool) {
	k := pairKey{e.Monotonic, e.PID}
	switch e.Type {
	case EventEnter:
		if noReturn(e.Number) {
			p.stats.Calls++
			return Call{Number: e.Number, Status: NoReturn, PID: e.PID, EnteredBoot: e.Boot}, true
		}
		if h, ok := p.pending[k]; ok {
			if h.exit {
				delete(p.pending, k)
				return p.complete(e.Number, e.PID, e.Boot, h.boot, h.ret), true
			}
			p.stats.Unfinished++ // two ENTERs on one key: keep the newer
		}
		p.put(k, half{nr: e.Number, boot: e.Boot})
	case EventExit:
		if h, ok := p.pending[k]; ok {
			if !h.exit {
				delete(p.pending, k)
				return p.complete(h.nr, e.PID, h.boot, e.Boot, e.Ret), true
			}
			p.stats.Unmatched++
			p.gaps++
		}
		p.put(k, half{exit: true, nr: e.Number, boot: e.Boot, ret: e.Ret})
	default:
		p.stats.Invalid++
		p.gaps++
	}
	return Call{}, false
}

func (p *Pairer) complete(nr uint16, pid uint32, entered, exited uint64, ret int64) Call {
	p.stats.Calls++
	return Call{Number: nr, Status: Returned, PID: pid, EnteredBoot: entered, ExitedBoot: exited, Ret: ret}
}

func (p *Pairer) put(k pairKey, h half) {
	if _, ok := p.pending[k]; !ok {
		for len(p.pending) >= p.max && len(p.order) > 0 {
			oldest := p.order[0]
			p.order = p.order[1:]
			if _, live := p.pending[oldest]; live {
				delete(p.pending, oldest)
				p.stats.Overflow++
				p.gaps++
			}
		}
		p.order = append(p.order, k)
		// Paired keys leave stale queue entries; compact them (amortized O(1)).
		if len(p.order) > 2*p.max {
			live := p.order[:0]
			for _, o := range p.order {
				if _, ok := p.pending[o]; ok {
					live = append(live, o)
				}
			}
			p.order = append([]pairKey(nil), live...)
		}
	}
	p.pending[k] = h
}

// Flush ends a recording: pending ENTERs become Unfinished calls and pending
// EXITs Unmatched calls (also counted as gaps), ordered by observed time.
func (p *Pairer) Flush() []Call {
	out := make([]Call, 0, len(p.pending))
	for k, h := range p.pending {
		if h.exit {
			p.stats.Unmatched++
			p.gaps++
			out = append(out, Call{Number: h.nr, Status: Unmatched, PID: k.pid, ExitedBoot: h.boot, Ret: h.ret})
		} else {
			p.stats.Unfinished++
			out = append(out, Call{Number: h.nr, Status: Unfinished, PID: k.pid, EnteredBoot: h.boot})
		}
	}
	clear(p.pending)
	p.order = p.order[:0]
	slices.SortFunc(out, func(a, b Call) int {
		return cmp.Or(cmp.Compare(a.Time(), b.Time()), cmp.Compare(a.PID, b.PID), cmp.Compare(a.Number, b.Number))
	})
	return out
}

// Pending is the number of halves waiting for their partner.
func (p *Pairer) Pending() int { return len(p.pending) }

// Stats returns the cumulative counters.
func (p *Pairer) Stats() Stats { return p.stats }

// TakeGaps returns the events lost since the last call (overflow, unmatched
// EXIT, invalid events) and resets the count, for recording a ring gap.
func (p *Pairer) TakeGaps() uint64 {
	n := p.gaps
	p.gaps = 0
	return n
}

// Time is the call's observed time: its completion (exit) when observed, so a
// long-blocking call is not stale when it returns; otherwise its entry.
func (c Call) Time() uint64 {
	if c.Status == Returned || c.Status == Unmatched {
		return c.ExitedBoot
	}
	return c.EnteredBoot
}
