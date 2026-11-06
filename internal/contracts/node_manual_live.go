package contracts

import "time"

// Optional private finite-holder provenance. No parent authority, action or
// observation identity can be selected by a public live reader.
type NodeManualLiveSource struct {
	ExecutorPodUID       string    `json:"executorPodUID"`
	ExecutorEpoch        string    `json:"executorEpoch"`
	RootID               string    `json:"rootID"`
	CaptureID            string    `json:"captureID"`
	AttemptID            string    `json:"attemptID"`
	ActionID             string    `json:"actionID"`
	WorkID               string    `json:"workID"`
	PodUID               string    `json:"podUID"`
	NodeUID              string    `json:"nodeUID"`
	BootID               string    `json:"bootID"`
	CollectorPodUID      string    `json:"collectorPodUID"`
	CollectorEpoch       string    `json:"collectorEpoch"`
	Scope                string    `json:"scope"`
	ExpectationDigest    string    `json:"expectationDigest"`
	StartedAt            time.Time `json:"startedAt"`
	HardUntil            time.Time `json:"hardUntil"`
	ObservationKind      string    `json:"observationKind,omitempty"`
	ObservationSessionID string    `json:"observationSessionID,omitempty"`
	ObservationFence     string    `json:"observationFence,omitempty"`
}

// Only observed runtime facts cross the result wire. Full accepted provenance
// remains in the request and is rebound by its current original owner.
type NodeManualLiveObservation struct {
	CaptureID            string    `json:"captureID"`
	WorkID               string    `json:"workID"`
	PodUID               string    `json:"podUID"`
	NodeUID              string    `json:"nodeUID"`
	BootID               string    `json:"bootID"`
	CollectorPodUID      string    `json:"collectorPodUID"`
	CollectorEpoch       string    `json:"collectorEpoch"`
	StartedAt            time.Time `json:"startedAt"`
	HardUntil            time.Time `json:"hardUntil"`
	ObservationKind      string    `json:"observationKind,omitempty"`
	ObservationSessionID string    `json:"observationSessionID,omitempty"`
	ObservationFence     string    `json:"observationFence,omitempty"`
}
