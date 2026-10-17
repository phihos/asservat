package fleet

import (
	"context"
	"time"

	identityport "asservat.local/asservat/internal/application/identity"
	value "asservat.local/asservat/internal/domain/fleet"
)

type AdministrationReader interface {
	FleetAdministration(context.Context) (value.Administration, error)
}
type EnrollmentAuthorizer struct {
	Identities identityport.Resolver
	Settings   AdministrationReader
	Now        func() time.Time
}

func (a EnrollmentAuthorizer) AuthorizeEnrollment(ctx context.Context, token, deliveryProfile string) (value.EnrollmentAuthority, error) {
	var out value.EnrollmentAuthority
	if a.Identities == nil || a.Settings == nil || a.Now == nil {
		return out, value.ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	i, err := a.Identities.Resolve(ctx, token)
	if err != nil {
		return out, err
	}
	settings, err := a.Settings.FleetAdministration(ctx)
	if err != nil {
		return out, err
	}
	if ctx.Err() != nil {
		return out, value.ErrUnavailable
	}
	return value.AuthorizeEnrollment(i, settings, deliveryProfile, a.Now())
}
