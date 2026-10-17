package fleet

import (
	"bytes"
	"errors"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
)

// ADR-168: one rotating Ed25519 enrollment key per connector profile, held in a
// protected workload-cluster Secret. Possession only admits that profile's
// ADR-126/153 process enrollment or renewal; it is never evidence, workload,
// key-service, fleet or administrator authority.
const (
	ClusterCredentialPurpose  = "asservat-cluster-enrollment/v1"
	ClusterCredentialExporter = "EXPORTER-Asservat-Cluster-Enrollment-v1"

	DefaultClusterCredentialValidity = 7 * 24 * time.Hour
	DefaultClusterCredentialRotation = 24 * time.Hour
	MinClusterCredentialValidity     = time.Hour
	MaxClusterCredentialValidity     = 30 * 24 * time.Hour
	ClusterPublicKeyBytes            = 32 // Ed25519
	ClusterCredentialRequestSkew     = 30 * time.Second
)

const (
	ClusterAdmission = "admission"
	ClusterRenewal   = "renewal"
	ClusterRotation  = "rotation"
)

var (
	ErrClusterCredentialDenied = errors.New("cluster enrollment credential denied")
	ErrClusterCredentialFenced = errors.New("cluster enrollment credential fenced; administrator reenrollment required")
)

// ClusterCredentialProfile is the exact connector profile a key may serve.
type ClusterCredentialProfile struct {
	RootID, PeerID, InstallationID, ClusterID string
}

func (p ClusterCredentialProfile) Valid() bool {
	return authorization.UUID(p.RootID) && authorization.UUID(p.PeerID) && authorization.UUID(p.InstallationID) && authorization.UUID(p.ClusterID)
}

// ClusterCredentialPolicy: validity bounds unattended outage recovery; the
// rotation interval bounds passive theft and leaves two missed rotations.
type ClusterCredentialPolicy struct {
	Validity, Rotation time.Duration
}

func DefaultClusterCredentialPolicy() ClusterCredentialPolicy {
	return ClusterCredentialPolicy{Validity: DefaultClusterCredentialValidity, Rotation: DefaultClusterCredentialRotation}
}

func (p ClusterCredentialPolicy) Valid() bool {
	return p.Validity >= MinClusterCredentialValidity && p.Validity <= MaxClusterCredentialValidity && p.Rotation >= time.Minute && 3*p.Rotation <= p.Validity
}

// ClusterCredentialRequest is the signed request; its canonical encoding and
// Ed25519 signature live in the application layer. Admission/renewal
// bind the process and both CSR key digests; rotation binds the next key.
type ClusterCredentialRequest struct {
	Operation            string
	Profile              ClusterCredentialProfile
	Generation           int64
	PodUID, ProcessEpoch string          `json:",omitempty"`
	ClientKey, ServerKey artifact.Digest `json:",omitempty"`
	NextKey              []byte          `json:",omitempty"`
	RequestedAt          time.Time
}

func (r ClusterCredentialRequest) Valid() bool {
	if !r.Profile.Valid() || r.Generation < 1 || r.RequestedAt.IsZero() || !r.RequestedAt.Equal(r.RequestedAt.UTC().Truncate(time.Microsecond)) {
		return false
	}
	switch r.Operation {
	case ClusterAdmission, ClusterRenewal:
		return authorization.UUID(r.PodUID) && authorization.UUID(r.ProcessEpoch) && r.ClientKey != (artifact.Digest{}) && r.ServerKey != (artifact.Digest{}) && r.ClientKey != r.ServerKey && r.NextKey == nil
	case ClusterRotation:
		return r.PodUID == "" && r.ProcessEpoch == "" && r.ClientKey == (artifact.Digest{}) && r.ServerKey == (artifact.Digest{}) && len(r.NextKey) == ClusterPublicKeyBytes
	}
	return false
}

// ClusterCredential is one stored generation. The hub keeps public keys only.
type ClusterCredential struct {
	Generation                                    int64
	PublicKey                                     []byte
	IssuedAt, ValidUntil, SupersededAt, FirstUsed time.Time
	Successor                                     artifact.Digest
}

func (c ClusterCredential) WellFormed() bool {
	if c.Generation < 1 || len(c.PublicKey) != ClusterPublicKeyBytes || c.IssuedAt.IsZero() || !c.IssuedAt.Before(c.ValidUntil) || c.ValidUntil.Sub(c.IssuedAt) > MaxClusterCredentialValidity {
		return false
	}
	// A superseded generation names exactly its successor key.
	return c.SupersededAt.IsZero() == (c.Successor == artifact.Digest{})
}

// ClusterCredentialLineage is one (re)enrollment's history for a profile.
// Fenced is permanent: "fork" (two lineages from one key) or "revoked".
type ClusterCredentialLineage struct {
	Profile ClusterCredentialProfile
	ID      string
	Policy  ClusterCredentialPolicy
	Current int64
	Fenced  string
}

func (l ClusterCredentialLineage) Valid() bool {
	return l.Profile.Valid() && authorization.UUID(l.ID) && l.Policy.Valid() && l.Current >= 1 && (l.Fenced == "" || l.Fenced == "fork" || l.Fenced == "revoked")
}

type ClusterDecisionKind string

const (
	ClusterAccept ClusterDecisionKind = "accept" // admission/renewal under the current key
	ClusterRotate ClusterDecisionKind = "rotate" // new current generation
	ClusterReplay ClusterDecisionKind = "replay" // exact repeat of an acknowledged rotation
	ClusterFork   ClusterDecisionKind = "fork"   // valid old-key misuse; persist the fence
)

// ClusterDecision is what the transactional adapter must persist. Next is the
// new generation for Rotate; Supersede is the updated signer for Rotate; First
// is set when an Accept is the current generation's first use.
type ClusterDecision struct {
	Kind      ClusterDecisionKind
	Next      *ClusterCredential
	Supersede *ClusterCredential
	FirstUse  bool
}

// DecideClusterCredential classifies one request. signed reports whether the
// request's exporter-bound signature verified under signer's public key;
// successor is the digest of r.NextKey for rotations. signer is the stored credential for
// r.Generation; current is the lineage's current generation. Pure: the caller
// supplies now from the database clock after taking the lineage row lock, and
// the adapter persists the decision atomically.
func DecideClusterCredential(l ClusterCredentialLineage, signer, current *ClusterCredential, r ClusterCredentialRequest, signed bool, successor artifact.Digest, now time.Time) (ClusterDecision, error) {
	if !l.Valid() || signer == nil || current == nil || !signer.WellFormed() || !current.WellFormed() || current.Generation != l.Current || !current.SupersededAt.IsZero() || !r.Valid() || r.Profile != l.Profile || r.Generation != signer.Generation {
		return ClusterDecision{}, ErrClusterCredentialDenied
	}
	if l.Fenced != "" {
		return ClusterDecision{}, ErrClusterCredentialFenced
	}
	// Unsigned or wrongly signed traffic never changes state: anyone can send it.
	if !signed {
		return ClusterDecision{}, ErrClusterCredentialDenied
	}
	if r.RequestedAt.Before(now.Add(-ClusterCredentialRequestSkew)) || r.RequestedAt.After(now.Add(ClusterCredentialRequestSkew)) {
		return ClusterDecision{}, ErrClusterCredentialDenied
	}
	if signer.Generation == current.Generation {
		if !now.Before(current.ValidUntil) {
			return ClusterDecision{}, ErrClusterCredentialDenied // expired: administrator reenrollment
		}
		if r.Operation != ClusterRotation {
			return ClusterDecision{Kind: ClusterAccept, FirstUse: current.FirstUsed.IsZero()}, nil
		}
		if bytes.Equal(r.NextKey, current.PublicKey) {
			return ClusterDecision{}, ErrClusterCredentialDenied
		}
		next := ClusterCredential{Generation: current.Generation + 1, PublicKey: bytes.Clone(r.NextKey), IssuedAt: now, ValidUntil: now.Add(l.Policy.Validity)}
		old := *current
		old.PublicKey = bytes.Clone(current.PublicKey)
		if successor == (artifact.Digest{}) {
			return ClusterDecision{}, ErrClusterCredentialDenied
		}
		old.SupersededAt, old.Successor = now, successor
		return ClusterDecision{Kind: ClusterRotate, Next: &next, Supersede: &old}, nil
	}
	if signer.Generation > current.Generation || signer.SupersededAt.IsZero() {
		return ClusterDecision{}, ErrClusterCredentialDenied // stored history is inconsistent
	}
	// A validly signed request under a superseded key is either the exact
	// replay of the immediately preceding rotation, before its successor's first
	// use and expiry, or evidence that the key was copied. No shorter time bound
	// applies: a connector that crashed after an unacknowledged rotation must be
	// able to finish it, and only a holder of the pending key can replay exactly.
	if r.Operation == ClusterRotation && signer.Generation == current.Generation-1 && successor == signer.Successor && bytes.Equal(r.NextKey, current.PublicKey) && current.FirstUsed.IsZero() && now.Before(current.ValidUntil) {
		return ClusterDecision{Kind: ClusterReplay}, nil
	}
	return ClusterDecision{Kind: ClusterFork}, nil
}

// ClusterCredentialPresentation is a short observation after an accepted
// possession proof: an input to ADR-126/153 admission, never a permit by itself.
type ClusterCredentialPresentation struct {
	Profile               ClusterCredentialProfile
	LineageID, Operation  string
	Generation            int64
	CheckedAt, ValidUntil time.Time
}

func (p ClusterCredentialPresentation) Valid(now time.Time) bool {
	return p.Profile.Valid() && authorization.UUID(p.LineageID) && (p.Operation == ClusterAdmission || p.Operation == ClusterRenewal || p.Operation == ClusterRotation) && p.Generation >= 1 && identity.Fresh(p.CheckedAt, p.ValidUntil, now, 5*time.Second)
}
