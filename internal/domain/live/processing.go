package live

import "time"

// ProcessingLimits are protected, operator-qualified incremental viewer limits.
// Zero disables the mechanism. They neither grant collection nor change rings.
// Time is elapsed processing time: a conservative upper bound on CPU spent in
// the synchronous metadata callback; wall blocking consumes rather than refills it.
type ProcessingLimits struct {
	Subscriptions                   int
	MemoryBytes                     int64
	EventsPerSecond, BytesPerSecond int64
	TimePerSecond                   time.Duration
}

func (p ProcessingLimits) Valid() bool {
	return p.Subscriptions >= 1 && p.Subscriptions <= 16 && p.MemoryBytes >= MaxBufferBytes && p.MemoryBytes <= 16*MaxBufferBytes && p.EventsPerSecond >= 1 && p.EventsPerSecond <= 100000 && p.BytesPerSecond >= 1 && p.BytesPerSecond <= 256<<20 && p.TimePerSecond > 0 && p.TimePerSecond <= 100*time.Millisecond
}
