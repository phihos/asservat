package contracts

import (
	"net/netip"
	"time"
)

// NativeOwnerRoute directs an unclaimed worker Hello to the current operation
// owner's Pod. Only the TCP destination changes. The worker keeps the installed
// authority, port, TLS roots, client identity and original opening deadline.
type NativeOwnerRoute struct {
	Addresses []string
}

func (*NativeOwnerRoute) Error() string { return "native operation on another hub replica" }

func (r *NativeOwnerRoute) Valid() bool {
	// A Pod has one address per IP family.
	if r == nil || len(r.Addresses) < 1 || len(r.Addresses) > 2 {
		return false
	}
	for i, s := range r.Addresses {
		a, err := netip.ParseAddr(s)
		if err != nil || a.String() != s || a.Zone() != "" || a.Is4In6() || !a.IsGlobalUnicast() || i > 0 && r.Addresses[i-1] >= s {
			return false
		}
	}
	return true
}

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
