// Package fleet defines bounded peer-control values. A valid signature is not
// authority to execute, spend capacity, disclose or extend an evidence deadline.
package fleet

import (
	"errors"
	"slices"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
)

var (
	ErrInvalid     = errors.New("invalid signed control work")
	ErrUnavailable = errors.New("current signing trust unavailable")
	ErrDenied      = errors.New("signed control work rejected")
	ErrUnsupported = errors.New("control purpose or capability unsupported")
	ErrPending     = errors.New("enrollment is pending")
	ErrCapacity    = errors.New("fleet enrollment limit reached")
	ErrConflict    = errors.New("enrollment request conflicts with its original identity")
)

type Reference struct {
	ID, Region string
	Digest     artifact.Digest
	ExpiresAt  time.Time
}

func (r Reference) Valid(region string, until time.Time) bool {
	return authorization.UUID(r.ID) && r.Digest != (artifact.Digest{}) && r.Region == region && !r.ExpiresAt.Before(until)
}

type RunAction struct {
	WorkID, OperationID, ClusterID, IssuerEpoch string
	DeliveryFence                               int64
	IssuedAt, NotAfter                          time.Time
	ScopeDigest                                 artifact.Digest
	Scope, Authority, Budget, Audit             Reference
	RequiredCapabilities                        []string
	PodUID, NodeUID, NodeBootID                 string
	CaptureID, ActionID, AttemptID              string
}

// Receiver is supplied by current verified peer enrollment and local node/boot
// identity. Public callers and the signed payload cannot select this context.
// The signature facet still requires an independently authenticated TLS channel.
type Receiver struct {
	PeerID, ClusterID, IssuerEpoch, NodeUID, NodeBootID, CollectorEpoch, Region string
	Capabilities                                                                []string
	VerifiedAt, ValidUntil                                                      time.Time
}

func (r Receiver) Valid(now time.Time) bool {
	for _, id := range []string{r.PeerID, r.ClusterID, r.IssuerEpoch, r.NodeUID, r.NodeBootID, r.CollectorEpoch} {
		if !authorization.UUID(id) {
			return false
		}
	}
	return identity.Text(r.Region, 63) && len(r.Capabilities) > 0 && identity.Strings(r.Capabilities, 32, 96) && identity.Fresh(r.VerifiedAt, r.ValidUntil, now, 30*time.Second)
}
func (w RunAction) Validate(r Receiver, now time.Time) error {
	if !r.Valid(now) {
		return ErrUnavailable
	}
	for _, id := range []string{w.WorkID, w.OperationID, w.ClusterID, w.IssuerEpoch, w.PodUID, w.NodeUID, w.NodeBootID, w.CaptureID, w.AttemptID} {
		if !authorization.UUID(id) {
			return ErrInvalid
		}
	}
	if !identity.Text(w.ActionID, 63) || w.DeliveryFence < 1 || w.DeliveryFence > 9007199254740991 || w.ScopeDigest == (artifact.Digest{}) || !identity.Strings(w.RequiredCapabilities, 32, 96) || !slices.IsSorted(w.RequiredCapabilities) {
		return ErrInvalid
	}
	if w.ClusterID != r.ClusterID || w.IssuerEpoch != r.IssuerEpoch || w.NodeUID != r.NodeUID || w.NodeBootID != r.NodeBootID || !identity.Fresh(w.IssuedAt, w.NotAfter, now, 60*time.Second) {
		return ErrDenied
	}
	if w.Scope.Digest != w.ScopeDigest {
		return ErrDenied
	}
	for _, ref := range []Reference{w.Scope, w.Authority, w.Budget, w.Audit} {
		if !ref.Valid(r.Region, w.NotAfter) {
			return ErrDenied
		}
	}
	for _, cap := range w.RequiredCapabilities {
		if !slices.Contains(r.Capabilities, cap) {
			return ErrUnsupported
		}
	}
	return nil
}

// Keys are public Ed25519 bytes from the protected current trust reader. There
// is no JWK/URL supplied by the incoming message and no dynamic algorithm choice.
type WorkKey struct {
	ID, ClusterID, IssuerEpoch string
	PublicKey                  []byte
	NotBefore, NotAfter        time.Time
}
type WorkTrust struct {
	Revision               identity.Revision
	ObservedAt, FreshUntil time.Time
	Keys                   []WorkKey
}

func (s WorkTrust) Valid(now time.Time) bool {
	if !s.Revision.Valid() || !identity.Fresh(s.ObservedAt, s.FreshUntil, now, 30*time.Second) || len(s.Keys) < 1 || len(s.Keys) > 8 {
		return false
	}
	seen := map[string]bool{}
	for _, k := range s.Keys {
		if !identity.Text(k.ID, 128) || seen[k.ID] || !authorization.UUID(k.ClusterID) || !authorization.UUID(k.IssuerEpoch) || len(k.PublicKey) != 32 || k.NotBefore.IsZero() || !k.NotBefore.Before(k.NotAfter) {
			return false
		}
		seen[k.ID] = true
	}
	return true
}

type AuthenticatedAction struct {
	Work                   RunAction
	KeyID                  string
	TrustRevision          identity.Revision
	VerifiedAt, ValidUntil time.Time
}
