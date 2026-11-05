package analysis

import value "asservat.local/asservat/internal/domain/analysis"

// ContextProjectionRefusal is a ready, content-free result of a charged read.
// It keeps the original delivery/authority/audit owner; it is not closure or
// permission to release spend before the exact outcome has been acknowledged.
type ContextProjectionRefusal uint8

const (
	ContextProjectionNoRefusal ContextProjectionRefusal = iota
	ContextProjectionInvalidCursor
	ContextProjectionRecordTooLarge
	ContextProjectionIncompatibleProfiles
)

func (d *ContextProjectionDelivery) Refusal() ContextProjectionRefusal {
	if d == nil || d.owner == nil {
		return ContextProjectionNoRefusal
	}
	d.owner.mu.Lock()
	defer d.owner.mu.Unlock()
	return d.refusal
}

// RefuseOversizedResult is a restrictive transition before C-20 binds a body:
// discard result content while retaining the same charged read and cleanup
// owner for its acknowledged size refusal. It cannot revive a closed delivery.
func (d *ContextProjectionDelivery) RefuseOversizedResult() bool {
	if d == nil || d.owner == nil || d.pending {
		return false
	}
	d.owner.mu.Lock()
	defer d.owner.mu.Unlock()
	if d.owner.closed || d.batch == nil || d.read == nil || d.effect != ContextQueryReadCharged || d.refusal != ContextProjectionNoRefusal {
		return false
	}
	d.clearProjectionLocked()
	d.refusal = ContextProjectionRecordTooLarge
	return true
}

func (d *ContextProjectionDelivery) clearProjectionLocked() {
	if d.comparison != nil {
		d.comparison.Clear()
		d.comparison = nil
	}
	clear(d.excerpt.Lines)
	d.excerpt = value.ContextExcerpt{}
	clear(d.page.Records)
	clear(d.page.CoverageGaps)
	d.page = value.HTTPHeaderPage{}
	if d.syscallSummary != nil {
		clear(d.syscallSummary.Rows)
		*d.syscallSummary = value.SyscallSummaryPage{}
		d.syscallSummary = nil
	}
	if d.syscallEvents != nil {
		clear(d.syscallEvents.Events)
		*d.syscallEvents = value.SyscallEventPage{}
		d.syscallEvents = nil
	}
	if d.syscallQuery != nil {
		d.syscallQuery.Clear()
		d.syscallQuery = nil
	}
	if d.packetQuery != nil {
		d.packetQuery.Clear()
		d.packetQuery = nil
	}
	if d.packetSummary != nil {
		clear(d.packetSummary.Conversations)
		*d.packetSummary = value.PacketSummary{}
		d.packetSummary = nil
	}
	if d.summary != nil {
		clear(d.summary.Top)
		*d.summary = value.ProfileSummary{}
		d.summary = nil
	}
}
