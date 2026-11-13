package kubernetes

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/json/jsontext"
	"time"

	"asservat.local/asservat/internal/adapters/mtls"
	app "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
)

// ConnectorIdentitySource serves the connector's identity document. Helm
// renders the connector's names; the document is derived from the hub's
// public regional offer, the browser-issued cluster binding and those names
// (ConnectorIdentityDocument), so the hub derives the identical bytes for its
// catalog pin. Nothing is read from an installer-written source or guard.
type ConnectorIdentitySource struct {
	client          *PermissionClient
	document        []byte
	name, uid, root string
	installation    string
	binding         value.PeerBinding
	protection      artifact.Digest
}

var _ app.ConnectorIdentitySourceReader = (*ConnectorIdentitySource)(nil)
var _ app.ConnectorIdentityConfigurationReader = (*ConnectorIdentitySource)(nil)

// RegionalSource is the fixed source name of the connector identity document;
// it is part of the deterministic protection digest.
const RegionalSource = "connector-identity"

// ConnectorSourceDigest is the deterministic source protection digest of the
// Helm-native installation (field map, persisted couplings 1): it names the
// cluster, namespace and source, not an admission policy.
func ConnectorSourceDigest(clusterID, namespace, name string) artifact.Digest {
	return sha256.Sum256([]byte("asservat-configmap-source/v2\x00" + clusterID + "\x00" + namespace + "\x00" + name))
}

// ConnectorWorkloadDigest is the deterministic workload protection digest of
// one Helm-rendered Deployment (field map, persisted couplings 2).
func ConnectorWorkloadDigest(clusterID, namespace, deployment string) artifact.Digest {
	return sha256.Sum256([]byte("asservat-workload-source/v2\x00" + clusterID + "\x00" + namespace + "\x00" + deployment))
}

// ConnectorIdentityDocument is the canonical identity document of one
// regional connector. The connector serves it and the hub pins the same bytes
// (ConnectorCatalogPeer); both derive it from the same public inputs.
func ConnectorIdentityDocument(offer contracts.RegionalOffer, clusterID, peerID string, d contracts.ConnectorDeployment) ([]byte, error) {
	if offer.Format != contracts.RegionalOfferFormat || !authorization.UUID(clusterID) || !authorization.UUID(peerID) {
		return nil, value.ErrInvalid
	}
	return json.Marshal(contracts.ConnectorIdentityConfiguration{Format: contracts.ConnectorIdentityFormat, RootID: offer.PermissionRootID, InstallationID: offer.InstallationID, ClusterID: clusterID, IssuerEpoch: offer.IssuerEpoch, PeerID: peerID, Revision: 1,
		ServerName: clusterID + "." + offer.ConnectorServerSuffix, ClientIssuerRoots: offer.ConnectorIssuerRoots, ServerIssuerRoots: offer.ConnectorIssuerRoots, Roles: offer.Roles, Deployment: d, Backing: offer.ConnectorBacking})
}

// ConnectorCatalogPeer is the hub's catalog pin of one regional connector:
// the same document, the peer ID as its stable source UID and the
// deterministic source digest.
func ConnectorCatalogPeer(offer contracts.RegionalOffer, clusterID, peerID string, d contracts.ConnectorDeployment) (contracts.FederationPeer, error) {
	doc, err := ConnectorIdentityDocument(offer, clusterID, peerID, d)
	if err != nil {
		return contracts.FederationPeer{}, err
	}
	digest := ConnectorSourceDigest(clusterID, d.Namespace, RegionalSource)
	return contracts.FederationPeer{SourceUID: peerID, ProtectionDigest: hex.EncodeToString(digest[:]), Source: doc}, nil
}

// NewConnectorIdentitySource serves document under the peer ID as source UID.
// c is the connector's own namespace client; it supplies the clock and the
// cluster/namespace the digest names.
func NewConnectorIdentitySource(c *PermissionClient, document []byte, root string, binding value.PeerBinding) (*ConnectorIdentitySource, error) {
	if c == nil || !authorization.UUID(root) || !binding.Valid() || binding.Role != value.ConnectorPeer || binding.ClusterID != c.clusterID {
		return nil, value.ErrInvalid
	}
	s := &ConnectorIdentitySource{client: c, document: bytes.Clone(document), name: RegionalSource, uid: binding.PeerID, root: root, installation: binding.InstallationID, binding: binding, protection: ConnectorSourceDigest(c.clusterID, c.control.Name, RegionalSource)}
	if _, _, err := s.decode(); err != nil {
		return nil, err
	}
	return s, nil
}

// Protection is the deterministic source digest the hub pins.
func (s *ConnectorIdentitySource) Protection() artifact.Digest { return s.protection }

func (s *ConnectorIdentitySource) decode() (app.ConnectorIdentityConfiguration, time.Time, error) {
	return DecodeConnectorIdentityConfiguration(s.document, s.uid, s.root, s.binding, s.client.now())
}

// DecodeConnectorIdentityConfiguration validates exact source document bytes
// for the original ConfigMap UID, root and binding. The regional source reader
// and the hub's federation peer pins (ADR-170) share it, so both derive the
// identical profile and revision digest. It establishes no protection proof.
func DecodeConnectorIdentityConfiguration(b []byte, uid, root string, binding value.PeerBinding, now time.Time) (app.ConnectorIdentityConfiguration, time.Time, error) {
	var out app.ConnectorIdentityConfiguration
	if len(b) < 1 || len(b) > 128<<10 || !authorization.UUID(uid) {
		return out, time.Time{}, value.ErrInvalid
	}
	var wire contracts.ConnectorIdentityConfiguration
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(&wire) != nil {
		return out, time.Time{}, value.ErrInvalid
	}
	encoded, err := json.Marshal(wire)
	a, z := jsontext.Value(b), jsontext.Value(encoded)
	if err != nil || a.Canonicalize() != nil || z.Canonicalize() != nil || !bytes.Equal(a, z) || wire.Format != contracts.ConnectorIdentityFormat || wire.InstallationID != binding.InstallationID || wire.Revision < 1 || wire.Revision > 2147483647 {
		return out, time.Time{}, value.ErrInvalid
	}
	// Only the separately versioned backing is excluded from behavioral scope.
	// Every role, root, workload, suspension and issuer field remains bound.
	behavior := wire
	behavior.Backing = nil
	behaviorBytes, err := json.Marshal(behavior)
	canonicalBehavior := jsontext.Value(behaviorBytes)
	if err != nil || canonicalBehavior.Canonicalize() != nil {
		return out, time.Time{}, value.ErrInvalid
	}
	profile := value.ConnectorCredentialProfile{RootID: wire.RootID, Binding: value.PeerBinding{InstallationID: wire.InstallationID, ClusterID: wire.ClusterID, IssuerEpoch: wire.IssuerEpoch, PeerID: wire.PeerID, Role: value.ConnectorPeer}, Revision: identity.Revision{UID: uid, Generation: wire.Revision, Digest: sha256.Sum256(canonicalBehavior)}, ServerName: wire.ServerName, Deployment: value.ConnectorDeployment{Namespace: wire.Deployment.Namespace, ServiceAccount: wire.Deployment.ServiceAccount, Deployment: wire.Deployment.Deployment, ServingSlots: wire.Deployment.ServingSlots, RetainedProcesses: wire.Deployment.RetainedProcesses}, ClientIssuerRoots: wire.ClientIssuerRoots, ServerIssuerRoots: wire.ServerIssuerRoots, Suspended: wire.Suspended, Retiring: wire.Retiring}
	// Syntax is checked separately; no protection proof is synthesized here.

	roles := value.ConnectorIdentityRoles{Source: wire.Roles.Source, Journal: wire.Roles.Journal, Acknowledgement: wire.Roles.Acknowledgement, Cleanup: wire.Roles.Cleanup, Verifier: wire.Roles.Verifier, Finalizer: wire.Roles.Finalizer}
	if !profile.WellFormed() || profile.RootID != root || profile.Binding != binding || !roles.Valid() {
		return out, time.Time{}, value.ErrInvalid
	}
	_, clientUntil, err := mtls.OwnerTrustRoots(profile.ClientIssuerRoots, now)
	if err != nil {
		return out, time.Time{}, err
	}
	_, serverUntil, err := mtls.OwnerTrustRoots(profile.ServerIssuerRoots, now)
	if err != nil {
		return out, time.Time{}, err
	}

	var backing app.ConnectorIdentityBacking
	bd := json.NewDecoder(bytes.NewReader(wire.Backing))
	bd.DisallowUnknownFields()
	if bd.Decode(&backing) != nil || !backing.Valid() || backing.Policy.RootID != profile.RootID || backing.Policy.InstallationID != profile.Binding.InstallationID {
		return out, time.Time{}, value.ErrInvalid
	}
	bb, e := json.Marshal(backing)
	left, right := jsontext.Value(wire.Backing), jsontext.Value(bb)
	if e != nil || left.Canonicalize() != nil || right.Canonicalize() != nil || !bytes.Equal(left, right) {
		return out, time.Time{}, value.ErrInvalid
	}
	out = app.ConnectorIdentityConfiguration{Source: value.ConnectorIdentitySource{Observation: value.ConnectorCredentialObservation{Profile: profile, Backing: value.ConnectorBackingObservation{Revision: backing.Policy.BackingRevision, Digest: sha256.Sum256(left), SourceDigest: sha256.Sum256(a)}}, Roles: roles}, Backing: backing.Clone()}
	return out, identity.Earlier(clientUntil, serverUntil), nil
}
func (s *ConnectorIdentitySource) ReadConnectorIdentitySource(ctx context.Context) (value.ConnectorIdentitySource, error) {
	c, e := s.ReadConnectorIdentityConfiguration(ctx)
	return c.Source, e
}

// ReadConnectorIdentityConfiguration returns one five-second observation of
// the fixed document; its roots bound it further.
func (s *ConnectorIdentitySource) ReadConnectorIdentityConfiguration(ctx context.Context) (app.ConnectorIdentityConfiguration, error) {
	if s == nil || ctx == nil || ctx.Err() != nil {
		return app.ConnectorIdentityConfiguration{}, value.ErrInvalid
	}
	start := s.client.now()
	out, rootsUntil, err := s.decode()
	if err != nil {
		return app.ConnectorIdentityConfiguration{}, connectorAPIStage("source-decode", err)
	}
	out.Source.Observation.Profile.ProtectionDigest = s.protection
	out.Source.Observation.ObservedAt = start
	out.Source.Observation.FreshUntil = identity.Earlier(start.Add(5*time.Second), rootsUntil)
	if !out.Valid(s.client.now()) {
		return app.ConnectorIdentityConfiguration{}, value.ErrUnavailable
	}
	return out, nil
}

func connectorBackingEqual(a, b app.ConnectorIdentityBacking) bool {
	x, e := json.Marshal(a)
	y, f := json.Marshal(b)
	return e == nil && f == nil && bytes.Equal(x, y)
}
