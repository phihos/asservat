package live

import "asservat.local/asservat/internal/domain/collector"

// StampedRow is private approved metadata with the original native clock stamp.
// Public delivery replaces placement using the authenticated exchange bracket.
type StampedRow struct {
	Row   Row
	Nanos int64
	Clock string
}
type NodeReply struct {
	ObservedManual                         *collector.ManualLiveObservation
	Manual                                 *collector.ManualLiveSource
	WorkID, SourceID, Fence, BootID, Clock string
	Sample                                 int64
	Rows                                   []StampedRow
	Position                               Position
	Dropped                                int
	Examined                               int
	Bytes                                  int64
}
