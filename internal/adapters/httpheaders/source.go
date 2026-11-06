package httpheaders

import "time"

// SourceStamp is the original kernel event clock, never reconstructed from the
// record's wall timestamp. Missing/unsupported clocks cannot qualify live rows.
type SourceStamp struct {
	RawTimestamp uint64
	Clock        string
}

func (s SourceStamp) Valid() bool {
	return s.RawTimestamp > 0 && (s.Clock == "monotonic" || s.Clock == "boottime")
}

type ObservedRecord struct {
	Record Record
	Stamp  SourceStamp
}

// NewSourceProjector reuses the finite sanitizer/reassembly. Completed approved
// records are synchronously handed to an owner that already reserved its ring;
// this projector does not retain a second unbounded source history. The callback
// must be nonblocking and must not reenter this projector. No goroutine is added.
func NewSourceProjector(limits Limits, started time.Time, onRecord func(ObservedRecord)) (*Projector, error) {
	if onRecord == nil {
		return nil, ErrInvalid
	}
	p, err := NewProjector(limits, started)
	if err != nil {
		return nil, err
	}
	p.observer = onRecord
	return p, nil
}
func (p *Projector) AddObserved(frame []byte, wire uint32, at time.Time, stamp SourceStamp) {
	p.addObserved(frame, wire, at, stamp)
}

// SourceCounters is an owned cumulative snapshot. The source stores bounded
// content-free deltas in the existing ring for actual saved-window accounting.
func (p *Projector) SourceCounters() Counters { return p.counters }

// CloseSource joins the existing synchronous parser and flushes partial records.
// Its cumulative counters are not a saved-window measurement.
func (p *Projector) CloseSource(ended time.Time, lost uint64) Counters {
	_, c := p.Close(ended, lost)
	return c
}

// NewObservedProjector is the finite capture's existing sanitizer with an
// additional nonblocking approved-record observer. Unlike the ongoing source
// constructor, it retains exactly the normal finite native record history and
// its original maxRecords bound. No second parser or history is allocated.
func NewObservedProjector(limits Limits, started time.Time, onRecord func(ObservedRecord)) (*Projector, error) {
	p, err := NewSourceProjector(limits, started, onRecord)
	if err != nil {
		return nil, err
	}
	p.retainObserved = true
	return p, nil
}
