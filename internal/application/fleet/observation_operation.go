package fleet

import (
	"context"
	"time"

	value "asservat.local/asservat/internal/domain/fleet"
)

// The installed bootstrap supplies only the concrete local native readers.
// Their handles own admitted work and joined Close. Returned public values do
// not implement these ports and cannot instantiate another private operation.
type OwnerNativeObservationOperation interface {
	Original(context.Context) (value.OwnerObservationNativeFacts, error)
	Final(context.Context) (value.OwnerObservationNativeFacts, error)
	Close()
}
type OwnerNativeObservationOperations interface {
	OpenOwnerObservationOperation(context.Context, value.OwnerObservationRequest, []value.OwnerBinding) (OwnerNativeObservationOperation, error)
}
type ConnectorNativeObservationOperation interface {
	Read(context.Context, int) (value.ConnectorObservationNativeValue, error)
	Close()
}
type ConnectorNativeObservationOperations interface {
	OpenConnectorObservationOperation(context.Context, value.OwnerObservationRequest, value.ConnectorProcessIdentity) (ConnectorNativeObservationOperation, error)
}

// V2 alone: every call reads the next real source value on the same channel.
// Only ordinals 1 and 4 establish the two native brackets. This deliberately
// does not implement ConnectorIdentitySourceReader's full-proof semantics.
type ConnectorObservationOperationSource interface {
	ReadConnectorObservationValue(context.Context, int) (value.ConnectorObservationOperationValue, error)
}

// Last retains the exact post-SQL source phase. The consumer must require the
// second pair (ordinal 4, Final) before releasing a metadata result, then the
// existing terminal Receipt/EOF. A first-pair registry result is not completion.
type ConnectorObservationOperationRegistration struct {
	Registration ConnectorLeafRegistration
	Last         value.ConnectorObservationOperationValue
}

// FinalMatches is a required result-boundary predicate, not a substitute for
// current TLS/key checks or the final Receipt/EOF. The first registry pair can
// never satisfy it, even if its SQL row is still current.
func (r ConnectorObservationOperationRegistration) FinalMatches(pin value.ConnectorObservationPin, request value.OwnerObservationRequest, now time.Time) bool {
	return r.Registration.Valid(now) && r.Last.Matches(pin, request, value.ConnectorObservationMaximumChecks, now) && r.Last.Native.Final &&
		r.Registration.Certificate == r.Last.Certificate && r.Registration.Process == r.Last.Native.Workload.Process && r.Registration.Revision == r.Last.Native.Source.Observation.Profile.Revision && !r.Registration.FreshUntil.After(r.Last.Until())
}

type ConnectorObservationOperationRegistry interface {
	ReadConnectorObservationOperation(context.Context, value.OwnerObservationRequest, ConnectorObservationOperationSource, value.ConnectorCredentialCertificate, int) (ConnectorObservationOperationRegistration, error)
}
