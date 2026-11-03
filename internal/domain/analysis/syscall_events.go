package analysis

import (
	"asservat.local/asservat/internal/domain/artifact"
	"time"
)

// SyscallEventPage contains a prefix of the selected native-order metadata.
// Counts concern the entire recorded file, including rows hidden by filters;
// they contain no assertion about events missing from that file.
type SyscallEventPage struct {
	Version       artifact.Digest
	Start         int
	TotalMatching int
	Events        []artifact.SyscallMetadataEvent
	SyscallRecordCounts
}

func (c SyscallRecordCounts) Valid() bool {
	return c.RecordCount <= SyscallMaxRecords && c.UnmatchedEvents <= c.RecordCount && c.UnfinishedEvents <= c.RecordCount && c.UnknownEvents <= c.RecordCount && c.UnmatchedEvents+c.UnfinishedEvents+c.UnknownEvents <= c.RecordCount
}

func (p SyscallEventPage) Valid(s SyscallSelection, version artifact.Digest, pod string, from, until time.Time) bool {
	if p.Version != version || !s.Matches(version) || s.View != SyscallEventsView || !p.SyscallRecordCounts.Valid() || p.Start != s.Start || p.TotalMatching < 0 || uint64(p.TotalMatching) > p.RecordCount || p.Start > p.TotalMatching || len(p.Events) > s.Limit || len(p.Events) > p.TotalMatching-p.Start {
		return false
	}
	if len(p.Events) == 0 && (p.TotalMatching != 0 || p.Start != 0) {
		return false
	}
	for _, e := range p.Events {
		if !e.Valid(pod, from, until) || !s.Includes(e.Syscall, e.Outcome) {
			return false
		}
	}
	return true
}

func (p SyscallEventPage) Next(s SyscallSelection, version artifact.Digest) string {
	next := p.Start + len(p.Events)
	if p.Version != version || !s.Matches(version) || next >= p.TotalMatching || len(p.Events) == 0 || p.Start != s.Start {
		return ""
	}
	return s.Cursor(next, version)
}

// Includes is a display filter only; it cannot reduce the work charged for
// reading and verifying the source, nor authorize raw observations.
func (s SyscallSelection) Includes(name, outcome string) bool {
	if s.ErrorsOnly && outcome != "error" {
		return false
	}
	if len(s.Names) == 0 {
		return true
	}
	for _, n := range s.Names {
		if n == name {
			return true
		}
	}
	return false
}
