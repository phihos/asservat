package fleet

import (
	"context"

	value "asservat.local/asservat/internal/domain/fleet"
)

// ConnectorLifecycleRequest belongs to one Enroll, client signing or server
// signing call, under that call's original five-second and parent bounds.
// The concrete reader must clone both CSR buffers before retaining the request.
type ConnectorLifecycleRequest struct {
	Binding value.ConnectorLifecycleBinding
	Request value.ConnectorProcessRequest
}

// ConnectorLifecycleOperation performs actual native I/O at each phase. It
// implements no general source/proof reader. Failed or repeated phases close it
// permanently; Close cancels and joins admitted reads before returning.
type ConnectorLifecycleOperation interface {
	Read(context.Context, value.ConnectorLifecyclePhase) (value.ConnectorLifecycleObservation, error)
	Close()
}

// ConnectorLifecycleOperationReader is selected only by explicit private
// enrollment/signing composition. A returned observation cannot construct or
// replace an operation. Begin binds cancellation and the original finite end;
// the Initial read still performs the first complete native observation.
type ConnectorLifecycleOperationReader interface {
	BeginConnectorLifecycle(context.Context, ConnectorLifecycleRequest) (ConnectorLifecycleOperation, error)
}
