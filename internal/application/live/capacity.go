package live

import (
	"context"
	"errors"
	"slices"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/collector"
	"asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	v "asservat.local/asservat/internal/domain/live"
)

type CapacityAdministration interface {
	FleetAdministration(context.Context) (fleet.Administration, error)
}

type CapacityRecovery interface {
	RecoveryState(context.Context) (artifact.RecoveryProof, error)
}

type CapacityTargets interface {
	ReadLiveRuntime(context.Context, collector.LiveRuntimeRequest) (collector.LiveRuntimeSnapshot, error)
}

var ErrClusterUnknown = errors.New("unknown live capacity cluster")

// CapacityReader returns one selected cluster's content-free live runtime. It
// authorizes before the regional read and rechecks the caller before replying.
type CapacityReader struct {
	InstallationID string
	Administration CapacityAdministration
	Recovery       CapacityRecovery
	Targets        CapacityTargets
	Clusters       []string
	Now            func() time.Time
}

func (s CapacityReader) Read(ctx context.Context, current CurrentIdentity, cluster string) (collector.LiveRuntimeSnapshot, time.Time, error) {
	var zero collector.LiveRuntimeSnapshot
	if ctx == nil || current == nil || s.Administration == nil || s.Recovery == nil || s.Targets == nil || s.Now == nil || !authorization.UUID(s.InstallationID) {
		return zero, time.Time{}, identity.ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	caller, err := current.ResolveIdentity(ctx)
	if err != nil || !caller.Valid(s.Now()) {
		return zero, time.Time{}, identity.ErrDenied
	}
	admin, err := s.Administration.FleetAdministration(ctx)
	if err != nil || !admin.Valid(s.Now()) || admin.InstallationID != s.InstallationID {
		return zero, time.Time{}, identity.ErrUnavailable
	}
	if !admin.Operator(caller) {
		return zero, time.Time{}, identity.ErrDenied
	}
	until := identity.Earlier(caller.ValidUntil, admin.FreshUntil)
	request := collector.LiveRuntimeRequest{ClusterID: cluster}
	if !request.Valid() {
		return zero, time.Time{}, v.ErrInvalid
	}
	if !slices.Contains(s.Clusters, cluster) {
		return zero, time.Time{}, ErrClusterUnknown
	}
	recovery, err := s.Recovery.RecoveryState(ctx)
	if err != nil || recovery.InstallationID != s.InstallationID || !recovery.Valid(s.Now()) {
		return zero, time.Time{}, identity.ErrUnavailable
	}
	until = identity.Earlier(until, recovery.FreshUntil)
	out, err := s.Targets.ReadLiveRuntime(ctx, request)
	if err != nil || out.ClusterID != cluster || !out.Valid(s.Now()) {
		return zero, time.Time{}, identity.ErrUnavailable
	}
	until = identity.Earlier(until, out.FreshUntil)
	fresh, err := current.ResolveIdentity(ctx)
	if err != nil || fresh.Principal != caller.Principal || fresh.Policy != caller.Policy || !fresh.Valid(s.Now()) || !admin.Operator(fresh) {
		return zero, time.Time{}, identity.ErrDenied
	}
	until = identity.Earlier(until, fresh.ValidUntil)
	if ctx.Err() != nil || !s.Now().Before(until) {
		return zero, time.Time{}, identity.ErrUnavailable
	}
	return out, until, nil
}
