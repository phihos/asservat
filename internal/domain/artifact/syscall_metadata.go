package artifact

import (
	"time"
	"unicode/utf8"
)

const MaxSyscallDurationNS = 1<<53 - 1

// SyscallMetadataIdentity preserves source process/thread provenance.
type SyscallMetadataIdentity struct {
	ProcessRef string `json:"process_ref"`
	ThreadRef  string `json:"thread_ref"`
	PodUID     string `json:"pod_uid"`
}

// SyscallMetadataEvent is the closed native metadata event; it contains no
// arguments, buffers, paths, return values or pointers.
type SyscallMetadataEvent struct {
	Identity   SyscallMetadataIdentity `json:"identity"`
	Syscall    string                  `json:"syscall"`
	ABI        string                  `json:"abi"`
	Timestamp  string                  `json:"timestamp"`
	DurationNS *uint64                 `json:"duration_ns,omitempty"`
	Outcome    string                  `json:"outcome"`
	Errno      string                  `json:"errno,omitempty"`
}

// Valid checks native event values against independently supplied source facts.
// It establishes neither artifact authenticity nor read permission.
func (e SyscallMetadataEvent) Valid(pod string, from, until time.Time) bool {
	if from.IsZero() || until.Before(from) {
		return false
	}
	bounded := func(s string, n int) bool {
		return utf8.ValidString(s) && utf8.RuneCountInString(s) > 0 && utf8.RuneCountInString(s) <= n
	}
	if e.Identity.PodUID != pod || !bounded(e.Identity.PodUID, 64) || !bounded(e.Identity.ProcessRef, 128) || !bounded(e.Identity.ThreadRef, 128) || !bounded(e.Syscall, 64) || !bounded(e.ABI, 32) {
		return false
	}
	at, err := time.Parse(time.RFC3339Nano, e.Timestamp)
	if err != nil || at.Before(from) || at.After(until) || e.DurationNS != nil && *e.DurationNS > MaxSyscallDurationNS {
		return false
	}
	switch e.Outcome {
	case "success":
		return e.Errno == "" || bounded(e.Errno, 32)
	case "error":
		return bounded(e.Errno, 32)
	case "unfinished", "unmatched", "unknown":
		return e.DurationNS == nil && e.Errno == ""
	}
	return false
}
