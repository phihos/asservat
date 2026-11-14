package contracts

import "time"

// NativeNoCommand is a positively checked transport response, not a generic
// availability error. It permits only another bounded idle lookup, never replay
// of an accepted or uncertain command. NativeClient constructs it only after an
// exact nonce/worker response over the actually verified h2/TLS connection.
type NativeNoCommand struct {
	Reference NativeReference
	Nonce     string
	Until     time.Time
}

func (*NativeNoCommand) Error() string { return "no native command admitted" }

// NativeFinished is the positively checked answer that the worker's download
// parent ended. NativeClient constructs it only after an exact nonce/worker
// response over the verified h2/TLS connection; the worker then stops cleanly.
// It never authorizes, replays or retries any operation.
type NativeFinished struct {
	Reference NativeReference
	Nonce     string
}

func (*NativeFinished) Error() string { return "native download parent finished" }

const NativeIdleRetry = time.Second
const NativeMaximumConversations = 32768

type NativeConversationState string

const (
	NativeJoined    NativeConversationState = "Joined"
	NativeUncertain NativeConversationState = "Uncertain"
)

// NativeConversationResult stays inside the worker process; it is not a wire
// command, receipt, or SQL proof. Only the local authenticated conversation may
// mark a single-batch projection exhausted after its exact joined ACK.
type NativeConversationResult struct {
	ExhaustedProjection bool `json:"-"`
	State               NativeConversationState
	Reference           NativeReference
}
