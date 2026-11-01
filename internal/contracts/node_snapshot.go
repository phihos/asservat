package contracts

import "time"

type NodeSnapshotRequest struct {
	RequireApproval     bool      `json:"requireApproval,omitempty"`
	SourceBindingDigest string    `json:"sourceBindingDigest"`
	SourceID            string    `json:"sourceID"`
	Fence               string    `json:"fence"`
	SnapshotID          string    `json:"snapshotID"`
	SourceStartedAt     time.Time `json:"sourceStartedAt"`
	SourceHardUntil     time.Time `json:"sourceHardUntil"`
	T0                  time.Time `json:"t0"`
	IssuedAt            time.Time `json:"issuedAt"`
	StartBy             time.Time `json:"startBy"`
	ProcessingUntil     time.Time `json:"processingUntil"`
	BeforeNanos         int64     `json:"beforeNanos"`
	AfterNanos          int64     `json:"afterNanos"`
	MaxBytes            int64     `json:"maxBytes"`
}
type NodeSourceSnapshot struct {
	AttemptID         string              `json:"attemptID"`
	WriterPodUID      string              `json:"writerPodUID,omitempty"`
	WriterEpoch       string              `json:"writerEpoch,omitempty"`
	Binding           NodeSourceBinding   `json:"binding"`
	CaptureID         string              `json:"captureID"`
	ExpectationDigest string              `json:"expectationDigest"`
	Request           NodeSnapshotRequest `json:"request"`
}
type NodeSnapshotOutcome struct {
	Request                   NodeSnapshotRequest `json:"request"`
	AcceptedExpectationDigest string              `json:"acceptedExpectationDigest"`
	NativeSHA256              string              `json:"nativeSHA256"`
	NativeBytes               int64               `json:"nativeBytes"`
	Retained                  uint64              `json:"retained"`
	OutputFull                uint64              `json:"outputFull"`
	AvailableFrom             time.Time           `json:"availableFrom"`
	ObservedUntil             time.Time           `json:"observedUntil"`
	SourceClosedAt            time.Time           `json:"sourceClosedAt,omitzero"`
	SourceStoppedAt           time.Time           `json:"sourceStoppedAt"`
	CompletedAt               time.Time           `json:"completedAt"`
	HistoryComplete           bool                `json:"historyComplete"`
	WindowComplete            bool                `json:"windowComplete"`
	HistoryEvicted            bool                `json:"historyEvicted"`
	InputUnknown              bool                `json:"inputUnknown"`
}
