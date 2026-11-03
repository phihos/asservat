package analysis

import (
	"asservat.local/asservat/internal/domain/artifact"
	"slices"
	"unicode/utf8"
)

// SyscallSummaryPage is the bounded sorted prefix selected from a complete scan.
type SyscallSummaryPage struct {
	Version      artifact.Digest
	Start, Total int
	Rows         []SyscallCount
	SyscallRecordCounts
}

func (p SyscallSummaryPage) Valid(s SyscallSelection, version artifact.Digest) bool {
	if !s.Matches(version) || s.View != SyscallSummaryView || p.Version != version || p.Start != s.Start || !p.SyscallRecordCounts.Valid() || p.Total < 0 || uint64(p.Total) > p.RecordCount || p.Start > p.Total || len(p.Rows) > s.Limit || len(p.Rows) > p.Total-p.Start {
		return false
	}
	if len(p.Rows) == 0 && (p.Total != 0 || p.Start != 0) {
		return false
	}
	var count uint64
	for i, r := range p.Rows {
		if !utf8.ValidString(r.Syscall) || utf8.RuneCountInString(r.Syscall) < 1 || utf8.RuneCountInString(r.Syscall) > 64 || i > 0 && p.Rows[i-1].Syscall >= r.Syscall || r.Count == 0 || r.Count > p.RecordCount || r.Errors > r.Count || r.PairedCount > r.Count || r.TotalDurationNS > artifact.MaxSyscallDurationNS || r.PairedCount == 0 && r.TotalDurationNS != 0 {
			return false
		}
		count += r.Count
	}
	return count <= p.RecordCount && (p.Start != 0 || len(p.Rows) != p.Total || count == p.RecordCount)
}
func (p SyscallSummaryPage) Next(s SyscallSelection, version artifact.Digest) string {
	next := p.Start + len(p.Rows)
	if !p.Valid(s, version) || len(p.Rows) == 0 || next >= p.Total {
		return ""
	}
	return s.Cursor(next, version)
}
func CloneSyscallEventPage(p SyscallEventPage) SyscallEventPage {
	p.Events = slices.Clone(p.Events)
	for i := range p.Events {
		if p.Events[i].DurationNS != nil {
			v := *p.Events[i].DurationNS
			p.Events[i].DurationNS = &v
		}
	}
	return p
}
func CloneSyscallSummaryPage(p SyscallSummaryPage) SyscallSummaryPage {
	p.Rows = slices.Clone(p.Rows)
	return p
}
