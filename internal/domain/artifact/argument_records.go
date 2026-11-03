package artifact

import "time"

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
