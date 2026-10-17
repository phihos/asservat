package fleet

import (
	"errors"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
)

// ClusterBootstrapPurpose prefixes the exporter-bound bootstrap signature.
const ClusterBootstrapPurpose = "asservat-cluster-bootstrap/v1"

// ErrClusterBootstrapPending marks a generation-0 Secret: the connector holds
// only its bootstrap envelope and cannot admit, renew or rotate yet.
var ErrClusterBootstrapPending = errors.New("cluster enrollment bootstrap pending")

// BootstrapEnvelope is the one-use bootstrap a fleet operator issued for a new
// connector (ADR-193). It lives only in the connector's generation-0 Secret
// until generation 1 is active. It is possession material for one claim,
// never a credential.
type BootstrapEnvelope struct {
	BootstrapID         string
	Binding             PeerBinding
	DeliveryProfile     string
	RequestDigest       artifact.Digest
	NotBefore, NotAfter time.Time
	Secret              string
}

func (e BootstrapEnvelope) Valid() bool {
	return authorization.UUID(e.BootstrapID) && e.Binding.Valid() && e.Binding.Role == ConnectorPeer && identity.Text(e.DeliveryProfile, 64) &&
		e.RequestDigest != (artifact.Digest{}) && e.NotBefore.Year() >= 2020 && e.NotAfter.Year() <= 9999 && e.NotAfter.After(e.NotBefore) &&
		!e.NotAfter.After(e.NotBefore.Add(5*time.Minute)) && identity.Text(e.Secret, 512)
}

// ClusterBootstrapRequest is what the connector signs, over the TLS exporter,
// with its pending generation-1 key. KeyDigest is the SHA-256 of that key's
// SubjectPublicKeyInfo; SecretDigest binds the bootstrap secret.
type ClusterBootstrapRequest struct {
	InstallationID, BootstrapID, RootID string
	ClusterID, PeerID, IssuerEpoch      string
	KeyDigest, SecretDigest             artifact.Digest
	RequestedAt                         time.Time
}

func (r ClusterBootstrapRequest) Valid() bool {
	for _, id := range []string{r.InstallationID, r.BootstrapID, r.RootID, r.ClusterID, r.PeerID, r.IssuerEpoch} {
		if !authorization.UUID(id) {
			return false
		}
	}
	return r.KeyDigest != (artifact.Digest{}) && r.SecretDigest != (artifact.Digest{}) && r.RequestedAt.Year() >= 2020 && r.RequestedAt.Equal(r.RequestedAt.UTC().Truncate(time.Microsecond))
}

// Matches binds the request to the envelope the connector holds.
func (r ClusterBootstrapRequest) Matches(e BootstrapEnvelope) bool {
	b := e.Binding
	return r.BootstrapID == e.BootstrapID && r.InstallationID == b.InstallationID && r.ClusterID == b.ClusterID && r.PeerID == b.PeerID && r.IssuerEpoch == b.IssuerEpoch
}

// ClusterBootstrapResult is the hub's reply after the activated generation 1.
// Replay marks a repeated, already-activated result that grants nothing new.
type ClusterBootstrapResult struct {
	LineageID            string
	Generation           int64
	KeyDigest            artifact.Digest
	IssuedAt, ValidUntil time.Time
	Replay               bool
}

func (r ClusterBootstrapResult) Valid() bool {
	return authorization.UUID(r.LineageID) && r.Generation == 1 && r.KeyDigest != (artifact.Digest{}) && r.IssuedAt.Year() >= 2020 && r.ValidUntil.After(r.IssuedAt)
}

// ClusterBootstrapSource is the staged connector source a generation-1
// reservation binds.
type ClusterBootstrapSource struct {
	UID              string
	Generation       int64
	ProtectionDigest artifact.Digest
}

func (s ClusterBootstrapSource) Valid() bool {
	return authorization.UUID(s.UID) && s.Generation >= 1 && s.Generation <= 2147483647 && s.ProtectionDigest != (artifact.Digest{})
}
