package analysis

// SyscallCount is an aggregate of recorded metadata only. Count includes
// unpaired events; PairedCount and TotalDurationNS include observed pairs.
type SyscallCount struct {
	Syscall         string `json:"syscall"`
	Count           uint64 `json:"count"`
	Errors          uint64 `json:"errors"`
	PairedCount     uint64 `json:"paired_count"`
	TotalDurationNS uint64 `json:"total_duration_ns"`
}

// SyscallAggregation is internal parser output, before bounded page selection.
// Native metadata JSONL carries no loss counters, so it cannot establish zero
// loss or complete source coverage. This value confers no disclosure authority.
type SyscallAggregation struct {
	Rows             []SyscallCount
	UnmatchedEvents  uint64
	UnfinishedEvents uint64
	UnknownEvents    uint64
}
