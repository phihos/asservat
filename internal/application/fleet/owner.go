package fleet

import (
	"context"
	"time"

	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
)

// OwnerEndpointReader resolves only a pinned hub pool and exact Pod UID. Its
// result is routing observation, never process attestation or effect authority.
type OwnerEndpointReader interface {
	OwnerEndpoint(context.Context, value.OwnerBinding) (value.OwnerEndpoint, error)
}

type OwnerConfigurationReader interface {
	ReadOwnerConfiguration(context.Context) (value.OwnerConfigurationObservation, error)
}
type OwnerRouteReader interface {
	CurrentOwnerRoute(context.Context, value.OwnerBinding) (value.OwnerRoute, error)
}
type OwnerRoutes struct {
	Configurations OwnerConfigurationReader
	Endpoints      OwnerEndpointReader
	Now            func() time.Time
}

func (s *OwnerRoutes) CurrentOwnerRoute(ctx context.Context, b value.OwnerBinding) (value.OwnerRoute, error) {
	var out value.OwnerRoute
	if s == nil || ctx == nil || s.Configurations == nil || s.Endpoints == nil || s.Now == nil || !b.Valid() {
		return out, value.ErrInvalid
	}
	start := s.Now()
	ctx, end := context.WithDeadline(ctx, start.Add(5*time.Second))
	defer end()
	first, err := s.Configurations.ReadOwnerConfiguration(ctx)
	if err != nil {
		ownerRouteReadRefusal(ctx, "route-read/config-first/read", err)
		return out, value.ErrUnavailable
	}
	if !first.Valid(s.Now()) || first.Configuration.Suspended {
		refusalStep(ctx, "route-read/config-first/current")
		return out, value.ErrUnavailable
	}
	first.Configuration = first.Configuration.Clone()
	p := first.Configuration.Pool
	if b.InstallationID != p.InstallationID || b.ClusterID != p.ClusterID || b.IssuerEpoch != p.IssuerEpoch {
		refusalStep(ctx, "route-read/config-first/scope")
		return out, value.ErrDenied
	}
	endpoint, err := s.Endpoints.OwnerEndpoint(ctx, b)
	if err != nil {
		ownerRouteReadRefusal(ctx, "route-read/endpoints/read", err)
		return out, value.ErrUnavailable
	}
	if endpoint.Binding != b || endpoint.Pool != p || !endpoint.Valid(s.Now()) {
		refusalStep(ctx, "route-read/endpoints/current")
		return out, value.ErrUnavailable
	}
	endpoint.Addresses = append([]string(nil), endpoint.Addresses...)
	last, err := s.Configurations.ReadOwnerConfiguration(ctx)
	if err != nil {
		ownerRouteReadRefusal(ctx, "route-read/config-final/read", err)
		return out, value.ErrUnavailable
	}
	if !last.Valid(s.Now()) || !last.Configuration.Equal(first.Configuration) {
		refusalStep(ctx, "route-read/config-final/current")
		return out, value.ErrUnavailable
	}
	if err := ctx.Err(); err != nil {
		ownerRouteReadRefusal(ctx, "route-read/context", err)
		return out, value.ErrUnavailable
	}
	out = value.OwnerRoute{Configuration: first, Endpoint: endpoint, ObservedAt: start, FreshUntil: identity.Earlier(start.Add(5*time.Second), identity.Earlier(first.FreshUntil, identity.Earlier(last.FreshUntil, endpoint.FreshUntil)))}
	if !out.Valid(s.Now()) {
		refusalStep(ctx, "route-read/current")
		return value.OwnerRoute{}, value.ErrUnavailable
	}
	return out, nil
}
