package contracts

import "time"

type NodeArgumentObservationBinding struct {
	Scope             string `json:"scope"`
	ProgramDigest     string `json:"programDigest"`
	DefinitionDigest  string `json:"definitionDigest"`
	ExpectationDigest string `json:"expectationDigest"`
	AccountingRule    string `json:"accountingRule"`
	SessionID         string `json:"sessionID"`
	Fence             string `json:"fence"`
	CaptureID         string `json:"captureID"`
	ActionID          string `json:"actionID"`
	PodUID            string `json:"podUID"`
	NodeUID           string `json:"nodeUID"`
	BootID            string `json:"bootID"`
	CollectorPodUID   string `json:"collectorPodUID"`
	CollectorEpoch    string `json:"collectorEpoch"`
}
type NodeArgumentObservationPermit struct {
	Binding           NodeArgumentObservationBinding `json:"binding"`
	StartedAt         time.Time                      `json:"startedAt"`
	SessionUntil      time.Time                      `json:"sessionUntil"`
	LeaseUntil        time.Time                      `json:"leaseUntil"`
	StartBy           time.Time                      `json:"startBy"`
	DurationMillis    int64                          `json:"durationMillis"`
	Sequence          uint64                         `json:"sequence"`
	EventCredit       int64                          `json:"eventCredit"`
	ByteCredit        int64                          `json:"byteCredit"`
	EventsPerSecond   int64                          `json:"eventsPerSecond"`
	BytesPerSecond    int64                          `json:"bytesPerSecond"`
	MaxProbeBytes     int64                          `json:"maxProbeBytes"`
	MaxBytesPerEvent  int64                          `json:"maxBytesPerEvent"`
	MaxTrackedThreads int64                          `json:"maxTrackedThreads"`
	CaptureBuffers    bool                           `json:"captureBuffers"`
}
