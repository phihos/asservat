package fleet

import (
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
)

type PeerRole string

const (
	ConnectorPeer PeerRole = "connector"
	NodePeer      PeerRole = "node"
)

// PeerBinding has installation-issued IDs, never request-selected node names.
// Node enrollment independently verifies the admitted pod/node/boot binding.
type PeerBinding struct {
	InstallationID, ClusterID, IssuerEpoch, PeerID string
	Role                                           PeerRole
	NodeUID, NodeBootID, CollectorEpoch            string
}

func (p PeerBinding) Valid() bool {
	for _, id := range []string{p.InstallationID, p.ClusterID, p.IssuerEpoch, p.PeerID} {
		if !authorization.UUID(id) {
			return false
		}
	}
	switch p.Role {
	case ConnectorPeer:
		return p.NodeUID == "" && p.NodeBootID == "" && p.CollectorEpoch == ""
	case NodePeer:
		return authorization.UUID(p.NodeUID) && authorization.UUID(p.NodeBootID) && authorization.UUID(p.CollectorEpoch)
	default:
		return false
	}
}

type PeerCertificate struct {
	Binding             PeerBinding
	Digest              artifact.Digest
	NotBefore, NotAfter time.Time
}

func (c PeerCertificate) Valid(now time.Time) bool {
	return c.Binding.Valid() && c.Digest != (artifact.Digest{}) && !c.NotBefore.IsZero() && !now.Before(c.NotBefore) && now.Before(c.NotAfter) && c.NotAfter.After(c.NotBefore) && !c.NotAfter.After(c.NotBefore.Add(time.Hour))
}

type PeerRegistration struct {
	Binding                PeerBinding
	Revision               identity.Revision
	Enabled                bool
	ObservedAt, FreshUntil time.Time
	Certificates           []PeerCertificate // At most two during bounded rotation overlap.
}

type AuthenticatedPeer struct {
	Certificate            PeerCertificate
	RegistrationRevision   identity.Revision
	VerifiedAt, ValidUntil time.Time
}
