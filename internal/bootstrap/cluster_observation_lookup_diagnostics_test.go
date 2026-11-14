package bootstrap

import (
	"context"

	app "asservat.local/asservat/internal/application/fleet"
	value "asservat.local/asservat/internal/domain/fleet"
)

type lookupDiagnosticNative struct {
	fail func(context.Context) error
}

func (n lookupDiagnosticNative) OpenOwnerObservationOperation(ctx context.Context, _ value.OwnerObservationRequest, _ []value.OwnerBinding) (app.OwnerNativeObservationOperation, error) {
	return nil, n.fail(ctx)
}

type lookupDiagnosticRegistry struct {
	app.OwnerCertificateRegistry
	fail func(context.Context) error
}

func (r lookupDiagnosticRegistry) ReadOwnerRegistration(ctx context.Context, _ value.OwnerCertificate) (value.OwnerRegistrationObservation, error) {
	return value.OwnerRegistrationObservation{}, r.fail(ctx)
}
