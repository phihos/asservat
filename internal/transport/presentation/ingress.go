package presentation

import "sync/atomic"

// IngressCounters are fixed-size, saturating, process-local security counters.
// No caller-controlled labels, identifiers or raw input are retained. These are
// not durable operation records; retained exhaustion evidence remains unwired.
type IngressCounters struct {
	values [4]atomic.Uint64
}
type IngressCounter uint8

const (
	IngressPreAdmission IngressCounter = iota
	IngressOversized
	IngressOverloaded
	IngressAuditUnavailable
)

type IngressSecuritySnapshot struct {
	PreAdmission, Oversized, Overloaded, AuditUnavailable uint64
}

func (c *IngressCounters) Add(kind IngressCounter) {
	if c == nil || int(kind) >= len(c.values) {
		return
	}
	v := &c.values[kind]
	for old := v.Load(); old != ^uint64(0); old = v.Load() {
		if v.CompareAndSwap(old, old+1) {
			return
		}
	}
}
func (c *IngressCounters) Snapshot() IngressSecuritySnapshot {
	return IngressSecuritySnapshot{c.values[0].Load(), c.values[1].Load(), c.values[2].Load(), c.values[3].Load()}
}
