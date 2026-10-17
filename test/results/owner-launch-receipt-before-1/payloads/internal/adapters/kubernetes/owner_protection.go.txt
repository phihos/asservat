package kubernetes

import (
	app "asservat.local/asservat/internal/application/fleet"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	"context"
	"time"
)

var _ app.OwnerProtectionReader = (*OwnerWorkloadProtection)(nil)

func (g *OwnerWorkloadProtection) ReadOwnerProtection(ctx context.Context, p value.OwnerPool) (value.OwnerProtection, error) {
	var zero value.OwnerProtection
	if g == nil || g.observer == nil || ctx == nil || !p.Valid() || g.observer.clusterID != p.ClusterID || g.plan.ControlNamespace.Name != p.Namespace || g.plan.ControlNamespace.UID != p.NamespaceUID || g.plan.Deployment != p.Deployment || g.plan.DeploymentUID != p.DeploymentUID {
		return zero, value.ErrInvalid
	}
	start := g.observer.now()
	digest, until, err := g.Current(ctx)
	if err != nil {
		return zero, err
	}
	out := value.OwnerProtection{Pool: p, Digest: digest, ObservedAt: start, FreshUntil: identity.Earlier(start.Add(5*time.Second), until)}
	if !out.Valid(g.observer.now()) || ctx.Err() != nil {
		return zero, value.ErrUnavailable
	}
	return out, nil
}
