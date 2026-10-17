package bootstrap

import (
	"context"
	"time"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/adapters/mounts"
	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/transport/clusterobservation"
)

// ownerLocalCapacity returns the factory for the hub cluster's capacity
// observation this owner serves to the installed hub-worker (ADR-190
// decision 7). The probe account's tokens are minted in memory by this Pod's
// own account and bound to this Pod; the caller admission accepts only the
// original hub-worker caller pin.
func ownerLocalCapacity(in *ownerInputs, observer *kube.PermissionClient, guard *kube.OwnerWorkloadProtection, c contracts.OwnerDeployment, podUID string, maximum int, closers *[]func()) func(context.Context, string) (*clusterobservation.LocalHandler, error) {
	l := c.Observation.LocalCapacity
	if l == nil {
		return nil
	}
	return func(ctx context.Context, host string) (*clusterobservation.LocalHandler, error) {
		probeNS := cfg.NamespaceRef{Name: l.ProbeNamespace.Name, UID: l.ProbeNamespace.UID}
		read, err := kube.NewPermissionClientFrom(observer, probeNS)
		if err != nil {
			return nil, mounts.ErrUnavailable
		}
		tokens, err := kube.NewCapacityTokens(ctx, read, l.ProbeAccount.Name, l.ProbeAudience, podUID)
		if err != nil {
			return nil, mounts.ErrUnavailable
		}
		*closers = append(*closers, tokens.Close)
		probe, err := kube.NewPermissionClient(in.kubernetesToken(tokens.Token), c.ClusterID, probeNS, time.Now)
		if err != nil {
			return nil, mounts.ErrUnavailable
		}
		admins := make([]cfg.KubernetesActor, 0, len(l.Guard.Administrators))
		for _, a := range l.Guard.Administrators {
			admins = append(admins, cfg.KubernetesActor{Kind: a.Kind, Name: a.Name})
		}
		g := l.Guard
		selector, err := kube.NewCapacityNamespaceGuard(read, probe, cfg.CapacityNamespaceAdministration{Name: g.Name, Administrators: admins, Keys: l.Keys, ProbeNamespace: probeNS, ProbeAccount: cfg.NamespaceRef{Name: l.ProbeAccount.Name, UID: l.ProbeAccount.UID}},
			kube.GuardPin{PolicyUID: g.PolicyUID, PolicyGeneration: g.PolicyGeneration, BindingUID: g.BindingUID, BindingResourceVersion: g.BindingResourceVersion})
		if err != nil {
			return nil, mounts.ErrUnavailable
		}
		metadata, err := kube.NewClusterObservationMetadata(read, selector, c.PermissionRootID)
		if err != nil {
			return nil, mounts.ErrUnavailable
		}
		pin := ownerCapacityCaller(c)
		callers, err := kube.NewClusterObservationCallerAdmission(observer, guard, pin)
		if err != nil {
			return nil, mounts.ErrUnavailable
		}
		return clusterobservation.NewLocalHandler(ctx, host, pin, callers, metadata, maximum, time.Now)
	}
}

// ownerCapacityCaller is the one hub-worker caller the owner admits for
// capacity observation, v1 local and v2 alike.
func ownerCapacityCaller(c contracts.OwnerDeployment) fleet.ClusterObservationCallerPin {
	k := c.Observation.LocalCapacity.Caller
	return fleet.ClusterObservationCallerPin{RootID: c.PermissionRootID, InstallationID: c.InstallationID, ClusterID: c.ClusterID,
		Namespace: cfg.NamespaceRef{Name: c.Namespace.Name, UID: c.Namespace.UID}, Account: k.Account, AccountUID: k.AccountUID, Deployment: k.Deployment, DeploymentUID: k.DeploymentUID,
		TemplateDigest: ownerObservationDigest(k.TemplateDigest), ImageDigest: ownerObservationDigest(k.ImageDigest), ProtectionDigest: ownerObservationDigest(k.ProtectionDigest)}
}
