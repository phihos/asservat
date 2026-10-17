package kubernetes

import (
	"context"
	"time"

	app "asservat.local/asservat/internal/application/fleet"
	cfg "asservat.local/asservat/internal/domain/configuration"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
)

// OwnerObservationWorkload reads only this process's installed owner workload.
// The serving adapter supplies the independently activated actual owner key and
// Ready route; this reader cannot manufacture either from a caller's Pod hint.
type OwnerObservationWorkload struct {
	local *ClusterObservationCallerAdmission
	pin   value.OwnerObservationPin
}

var _ app.OwnerObservationWorkloadReader = (*OwnerObservationWorkload)(nil)

func NewOwnerObservationWorkload(c *PermissionClient, g *OwnerWorkloadProtection, p value.OwnerObservationPin) (*OwnerObservationWorkload, error) {
	pool := p.Pool
	control := cfg.NamespaceRef{Name: pool.Namespace, UID: pool.NamespaceUID}
	if c == nil || g == nil || g.observer != c || !p.Valid() || c.clusterID != pool.ClusterID || c.control != control || g.plan.ControlNamespace != control || g.plan.Deployment != pool.Deployment || g.plan.DeploymentUID != pool.DeploymentUID || g.digest != p.ProtectionDigest {
		return nil, cfg.ErrInvalid
	}
	// Reuse the exact API-defaulted template/Pod comparison, not the HWORK
	// TokenReview entry point or its distinct-account constructor.
	workload := value.ClusterObservationCallerPin{RootID: p.RootID, InstallationID: pool.InstallationID, ClusterID: pool.ClusterID, Namespace: control, Account: pool.ServiceAccount, AccountUID: pool.AccountUID, Deployment: pool.Deployment, DeploymentUID: pool.DeploymentUID, TemplateDigest: p.TemplateDigest, ImageDigest: p.ImageDigest, ProtectionDigest: p.ProtectionDigest}
	return &OwnerObservationWorkload{local: &ClusterObservationCallerAdmission{client: c, protection: g, pin: workload}, pin: p}, nil
}

func (s *OwnerObservationWorkload) ObserveOwnerWorkload(ctx context.Context, b value.OwnerBinding, pod string) (value.OwnerObservationWorkload, error) {
	var zero value.OwnerObservationWorkload
	if s == nil || s.local == nil || ctx == nil || ctx.Err() != nil || !b.Valid() || !identity.Text(pod, 253) || b.InstallationID != s.pin.Pool.InstallationID || b.ClusterID != s.pin.Pool.ClusterID || b.IssuerEpoch != s.pin.Pool.IssuerEpoch {
		return zero, value.ErrInvalid
	}
	start := s.local.client.now()
	until := start.Add(5 * time.Second)
	if d, ok := ctx.Deadline(); ok {
		until = identity.Earlier(until, d)
	}
	call, cancel := context.WithDeadline(ctx, until)
	defer cancel()
	guard, guardEnd, e := s.local.protection.Current(call)
	if e != nil || guard != s.pin.ProtectionDigest {
		return zero, value.ErrUnavailable
	}
	until = identity.Earlier(until, guardEnd)
	bounded, stop := context.WithDeadline(call, until)
	defer stop()
	first, e := s.local.live(bounded, pod, b.PodUID)
	if e != nil {
		return zero, e
	}
	last, e := s.local.live(bounded, pod, b.PodUID)
	if e != nil || last != first {
		return zero, cfg.ErrChanged
	}
	final, finalEnd, e := s.local.protection.Current(bounded)
	if e != nil || final != guard {
		return zero, value.ErrUnavailable
	}
	until = identity.Earlier(until, finalEnd)
	out := value.OwnerObservationWorkload{Pin: s.pin, Binding: b, Pod: pod, ReplicaSetUID: first.ReplicaSetUID, WorkloadDigest: first.Digest, ObservedAt: start, FreshUntil: until}
	if bounded.Err() != nil || !out.Valid(s.local.client.now()) {
		return zero, value.ErrUnavailable
	}
	return out, nil
}
