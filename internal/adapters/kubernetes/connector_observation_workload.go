package kubernetes

import (
	"context"
	"time"

	app "asservat.local/asservat/internal/application/fleet"
	cfg "asservat.local/asservat/internal/domain/configuration"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
)

// ConnectorObservationWorkload adds the original installed template/image
// comparison to the separate online Pod-token/process enrollment attestation.
// It neither calls the API-context executor nor borrows its execution identity.
type ConnectorObservationWorkload struct {
	local *ClusterObservationCallerAdmission
	pin   value.ConnectorObservationPin
}

var _ app.ConnectorObservationWorkloadReader = (*ConnectorObservationWorkload)(nil)

func NewConnectorObservationWorkload(c *PermissionClient, g *OwnerWorkloadProtection, pin value.ConnectorObservationPin) (*ConnectorObservationWorkload, error) {
	p := pin.Profile
	d := p.Deployment
	control := cfg.NamespaceRef{Name: d.Namespace, UID: d.NamespaceUID}
	if c == nil || g == nil || g.observer != c || !pin.Valid() || c.clusterID != p.Binding.ClusterID || c.control != control || g.plan.ControlNamespace != control || g.plan.Deployment != d.Deployment || g.plan.DeploymentUID != d.DeploymentUID || g.digest != pin.ProtectionDigest {
		return nil, cfg.ErrInvalid
	}
	workload := value.ClusterObservationCallerPin{RootID: p.RootID, InstallationID: p.Binding.InstallationID, ClusterID: p.Binding.ClusterID, Namespace: control, Account: d.ServiceAccount, AccountUID: d.AccountUID, Deployment: d.Deployment, DeploymentUID: d.DeploymentUID, TemplateDigest: pin.TemplateDigest, ImageDigest: pin.ImageDigest, ProtectionDigest: pin.ProtectionDigest}
	// Only the actual exact native workload reader is shared. Its HWORK token
	// admission method and audience are not part of this regional constructor.
	return &ConnectorObservationWorkload{local: &ClusterObservationCallerAdmission{client: c, protection: g, pin: workload}, pin: pin.Clone()}, nil
}

func (s *ConnectorObservationWorkload) ObserveConnectorWorkload(ctx context.Context, process value.ConnectorProcessIdentity, pod string) (value.ConnectorObservationWorkload, error) {
	var zero value.ConnectorObservationWorkload
	if s == nil || s.local == nil || ctx == nil || ctx.Err() != nil || !process.Valid() || process.Binding != s.pin.Profile.Binding || !identity.Text(pod, 253) {
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
	first, e := s.local.live(bounded, pod, process.PodUID)
	if e != nil {
		return zero, e
	}
	last, e := s.local.live(bounded, pod, process.PodUID)
	if e != nil || first != last {
		return zero, cfg.ErrChanged
	}
	final, finalEnd, e := s.local.protection.Current(bounded)
	if e != nil || final != guard {
		return zero, value.ErrUnavailable
	}
	until = identity.Earlier(until, finalEnd)
	out := value.ConnectorObservationWorkload{Process: process, Pod: pod, ReplicaSetUID: first.ReplicaSetUID, TemplateDigest: s.pin.TemplateDigest, ImageDigest: s.pin.ImageDigest, ProtectionDigest: guard, WorkloadDigest: first.Digest, ObservedAt: start, FreshUntil: until}
	if bounded.Err() != nil || !out.Matches(s.pin, s.local.client.now()) {
		return zero, value.ErrUnavailable
	}
	return out, nil
}
