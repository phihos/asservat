package bootstrap

import (
	"encoding/hex"
	"slices"
	"time"

	"asservat.local/asservat/internal/adapters/mounts"
	"asservat.local/asservat/internal/adapters/mtls"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/fleet"
)

func ownerObservationDigest(s string) artifact.Digest {
	var out artifact.Digest
	b, e := hex.DecodeString(s)
	if e != nil || len(b) != len(out) || hex.EncodeToString(b) != s {
		return out
	}
	copy(out[:], b)
	return out
}

// projected requires the activation the owner projection attaches.
func validateOwnerObservationInputs(c *contracts.OwnerObservationBootstrap, projected bool) error {
	if c == nil {
		return nil
	}
	if projected && c.Activation == nil || c.Format != contracts.OwnerObservationFormat || ownerObservationDigest(c.TemplateDigest) == (artifact.Digest{}) || ownerObservationDigest(c.ImageDigest) == (artifact.Digest{}) || ownerObservationDigest(c.ProtectionDigest) == (artifact.Digest{}) || len(c.Peers) < 1 || len(c.Peers) > 16 {
		return mounts.ErrUnavailable
	}
	seen := make(map[value.PeerBinding]bool, len(c.Peers))
	for _, p := range c.Peers {
		b := value.PeerBinding{InstallationID: p.InstallationID, ClusterID: p.ClusterID, IssuerEpoch: p.IssuerEpoch, PeerID: p.PeerID, Role: value.ConnectorPeer}
		if !b.Valid() || seen[b] {
			return mounts.ErrUnavailable
		}
		if _, _, e := mtls.OwnerTrustRoots(p.Roots, time.Now()); e != nil {
			return mounts.ErrUnavailable
		}
		seen[b] = true
	}
	if l := c.LocalCapacity; l != nil {
		g := l.Guard
		if !authorization.UUID(g.PolicyUID) || !authorization.UUID(g.BindingUID) || g.PolicyGeneration < 1 || g.BindingResourceVersion == "" || len(g.Administrators) == 0 ||
			len(l.Keys) == 0 || len(l.Keys) > 256 || !slices.IsSorted(l.Keys) || len(slices.Compact(slices.Clone(l.Keys))) != len(l.Keys) ||
			!authorization.UUID(l.ProbeNamespace.UID) || l.ProbeNamespace.Name == "" || !authorization.UUID(l.ProbeAccount.UID) || l.ProbeAccount.Name == "" || l.ProbeAudience == "" ||
			!authorization.UUID(l.Caller.AccountUID) || !authorization.UUID(l.Caller.DeploymentUID) || l.Caller.Account == "" || l.Caller.Deployment == "" ||
			ownerObservationDigest(l.Caller.TemplateDigest) == (artifact.Digest{}) || ownerObservationDigest(l.Caller.ImageDigest) == (artifact.Digest{}) || ownerObservationDigest(l.Caller.ProtectionDigest) == (artifact.Digest{}) {
			return mounts.ErrUnavailable
		}
	}
	return nil
}

func ownerObservationConfig(c contracts.OwnerDeployment, p value.OwnerPool) (value.OwnerObservationPin, []mtls.OwnerObservationPeer, error) {
	var zero value.OwnerObservationPin
	o := c.Observation
	// ADR-190 decision 4: a promoted installed owner also serves observation.
	if o == nil || c.Native != nil && (c.ProviderAuthentication == nil || c.Public == nil) || validateOwnerObservationInputs(o, true) != nil || p.NativeBootstrap != value.OwnerBootstrapProfile || p.InstallationID != c.InstallationID || p.ClusterID != c.ClusterID || p.NamespaceUID != c.Namespace.UID || p.Namespace != c.Namespace.Name {
		return zero, nil, mounts.ErrUnavailable
	}
	pin := value.OwnerObservationPin{RootID: c.PermissionRootID, SourceUID: c.ConfigurationUID, Pool: p, TemplateDigest: ownerObservationDigest(o.TemplateDigest), ImageDigest: ownerObservationDigest(o.ImageDigest), ProtectionDigest: ownerObservationDigest(o.ProtectionDigest)}
	if !pin.Valid() {
		return zero, nil, mounts.ErrUnavailable
	}
	peers := make([]mtls.OwnerObservationPeer, len(o.Peers))
	for i, w := range o.Peers {
		if w.InstallationID != p.InstallationID || w.IssuerEpoch != p.IssuerEpoch {
			return zero, nil, mounts.ErrUnavailable
		}
		roots := make([][]byte, len(w.Roots))
		for j, r := range w.Roots {
			roots[j] = append([]byte(nil), r...)
		}
		peers[i] = mtls.OwnerObservationPeer{Binding: value.PeerBinding{InstallationID: w.InstallationID, ClusterID: w.ClusterID, IssuerEpoch: w.IssuerEpoch, PeerID: w.PeerID, Role: value.ConnectorPeer}, Roots: roots}
	}
	return pin, peers, nil
}
