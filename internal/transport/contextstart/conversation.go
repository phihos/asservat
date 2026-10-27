package contextstart

import (
	"context"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/fleet"
)

// Stream is one actual, retained HTTP/2 conversation. Implementations bound
// bytes, frames, current peers and socket operations; Close cancels and joins.
// There is no reconnect, multiplexing or alternate destination within a stream.
type Stream interface {
	Context() context.Context
	AwaitWork(context.Context) (contracts.APIContextFrame, fleet.APIContextReceiver, error)
	Send(context.Context, contracts.APIContextFrame) error
	Receive(context.Context) (contracts.APIContextFrame, error)
	Close() error
}

func knownResult(state string) bool {
	switch state {
	case "StoredPendingVerification", "AlreadyStarted", "PreparationUncertain", "Unavailable", "Recording", "Failed":
		return true
	}
	return false
}
