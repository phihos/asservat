package kubernetes

import (
	"context"

	app "asservat.local/asservat/internal/application/fleet"
	value "asservat.local/asservat/internal/domain/fleet"
)

var _ app.OwnerNativeObservationOperations = (*OwnerObservationOperationReader)(nil)
var _ app.OwnerNativeObservationOperation = (*OwnerObservationOperation)(nil)

// These closed ports call the unchanged concrete Begin methods; they neither
// accept returned facts nor reopen, cache or renew an existing operation.
func (r *OwnerObservationOperationReader) OpenOwnerObservationOperation(ctx context.Context, request value.OwnerObservationRequest, peers []value.OwnerBinding) (app.OwnerNativeObservationOperation, error) {
	o, err := r.Begin(ctx, request, peers)
	if err != nil {
		return nil, err
	}
	return o, nil
}
