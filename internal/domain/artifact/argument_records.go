package artifact

import (
	"encoding/base64"
	"strconv"
	"strings"
	"time"
)

// Closed native values; these records grant no authority.
type ArgumentIdentity struct {
	ProcessRef string `json:"process_ref"`
	ThreadRef  string `json:"thread_ref"`
	PodUID     string `json:"pod_uid"`
}
type ArgumentValue struct {
	Name      string `json:"name"`
	Value     string `json:"value"`
	Truncated bool   `json:"truncated"`
}
type RawArgumentEvent struct {
	Identity   ArgumentIdentity `json:"identity"`
	Syscall    string           `json:"syscall"`
	ABI        string           `json:"abi"`
	Timestamp  string           `json:"timestamp"`
	DurationNS *uint64          `json:"duration_ns,omitempty"`
	Outcome    string           `json:"outcome"`
	Errno      string           `json:"errno,omitempty"`
	Arguments  []ArgumentValue  `json:"arguments"`
}

type ArgumentHeader struct {
	NodeUID          string    `json:"node_uid"`
	CollectorPodUID  string    `json:"collector_pod_uid"`
	SessionID        string    `json:"session_id"`
	Fence            string    `json:"fence"`
	Record           string    `json:"record"`
	Format           string    `json:"format"`
	PodUID           string    `json:"pod_uid"`
	BootID           string    `json:"boot_id"`
	SourceEpoch      string    `json:"source_epoch"`
	EngineDigest     string    `json:"engine_digest"`
	DefinitionDigest string    `json:"definition_digest"`
	AccountingRule   string    `json:"accounting_rule"`
	Decoder          string    `json:"decoder"`
	ABI              string    `json:"abi"`
	StartedAt        time.Time `json:"started_at"`
}
type ArgumentEventLine struct {
	Record string           `json:"record"`
	Event  RawArgumentEvent `json:"event"`
}
type ArgumentFooter struct {
	OutputFull      uint64    `json:"output_full"`
	Record          string    `json:"record"`
	EndedAt         time.Time `json:"ended_at"`
	Outcome         string    `json:"outcome"`
	Retained        uint64    `json:"retained"`
	Filtered        uint64    `json:"filtered"`
	PairGaps        uint64    `json:"pair_gaps"`
	Malformed       uint64    `json:"malformed"`
	Faults          uint64    `json:"faults"`
	Truncated       uint64    `json:"truncated"`
	LostSamples     uint64    `json:"lost_samples"`
	CoverageUnknown bool      `json:"coverage_unknown"`
	ObservedEvents  *uint64   `json:"observed_events"`
	ObservedBytes   *uint64   `json:"observed_bytes"`
}

// WellFormed checks the existing qualified recorded value without converting it
// to a number, text buffer or another encoding. Native definition checks remain
// independently responsible for each syscall's allowed argument positions.
func (a ArgumentValue) WellFormed() bool {
	switch a.Name {
	case "fd", "dirfd", "offset":
		if a.Truncated || !strings.HasPrefix(a.Value, "decimal:") {
			return false
		}
		text := strings.TrimPrefix(a.Value, "decimal:")
		n, err := strconv.ParseInt(text, 10, 64)
		return err == nil && strconv.FormatInt(n, 10) == text && (a.Name == "offset" || n == int64(int32(n)))
	case "count", "flags", "mode":
		if a.Truncated || !strings.HasPrefix(a.Value, "decimal:") {
			return false
		}
		text := strings.TrimPrefix(a.Value, "decimal:")
		n, err := strconv.ParseUint(text, 10, 64)
		return err == nil && strconv.FormatUint(n, 10) == text && (a.Name == "count" || n == uint64(uint32(n)))
	case "path", "buffer":
		if a.Value == "unavailable:fault" {
			return !a.Truncated
		}
		if !strings.HasPrefix(a.Value, "base64:") || len(a.Value) > 179 {
			return false
		}
		encoded := strings.TrimPrefix(a.Value, "base64:")
		decoded, err := base64.StdEncoding.Strict().DecodeString(encoded)
		defer clear(decoded)
		return err == nil && len(decoded) <= 128 && base64.StdEncoding.EncodeToString(decoded) == encoded
	}
	return false
}

// WellFormed is a structural output check, not source authentication or read
// authority. It preserves the qualified native argument ABI and exact values.
func (e RawArgumentEvent) WellFormed() bool {
	metadata := SyscallMetadataEvent{Identity: SyscallMetadataIdentity{ProcessRef: e.Identity.ProcessRef, ThreadRef: e.Identity.ThreadRef, PodUID: e.Identity.PodUID}, Syscall: e.Syscall, ABI: e.ABI, Timestamp: e.Timestamp, DurationNS: e.DurationNS, Outcome: e.Outcome, Errno: e.Errno}
	if !metadata.WellFormed() || e.ABI != "x86_64" || e.Arguments == nil || len(e.Arguments) > 6 {
		return false
	}
	switch e.Outcome {
	case "success", "error":
		if e.DurationNS == nil || *e.DurationNS > uint64(time.Minute) || (e.Outcome == "error") != (e.Errno != "") {
			return false
		}
	case "unfinished", "unmatched":
	default:
		return false
	}
	names := map[string]bool{}
	for _, a := range e.Arguments {
		if names[a.Name] || !a.WellFormed() {
			return false
		}
		names[a.Name] = true
	}
	return true
}

func (e RawArgumentEvent) Valid(pod string, from, until time.Time) bool {
	if !e.WellFormed() || e.Identity.PodUID != pod || from.IsZero() || until.Before(from) {
		return false
	}
	at, _ := time.Parse(time.RFC3339Nano, e.Timestamp)
	return !at.Before(from) && !at.After(until) && (e.DurationNS == nil || !at.Add(time.Duration(*e.DurationNS)).After(until))
}
