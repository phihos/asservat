package capture

import (
	"slices"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
)

type SubmissionKey struct {
	ID                  string
	PublicKey           []byte
	NotBefore, NotAfter time.Time
}
type SubmissionTrust struct {
	RootID, InstallationID, IssuerEpoch string
	Revision                            identity.Revision
	ObservedAt, FreshUntil              time.Time
	Keys                                []SubmissionKey
}

func (s SubmissionTrust) Valid(now time.Time) bool {
	if !authorization.UUID(s.RootID) || !authorization.UUID(s.InstallationID) || !authorization.UUID(s.IssuerEpoch) || !s.Revision.Valid() || !identity.Fresh(s.ObservedAt, s.FreshUntil, now, 5*time.Second) || len(s.Keys) < 1 || len(s.Keys) > 32 {
		return false
	}
	ids := make([]string, 0, len(s.Keys))
	for _, k := range s.Keys {
		if !identity.Text(k.ID, 128) || len(k.PublicKey) != 32 || k.NotBefore.IsZero() || !k.NotAfter.After(k.NotBefore) || slices.Contains(ids, k.ID) {
			return false
		}
		ids = append(ids, k.ID)
	}
	return true
}

// PolicySubmissionIntent is private, post-persistence input from authenticated
// ingress and the resolved-scope compiler. It is not a caller-authored DTO.
type PolicySubmissionIntent struct {
	RootID, InstallationID, IssuerEpoch string
	ReplacesID, Nonce                   string
	Actor                               identity.Principal
	Source                              identity.Revision
	ClusterID, NamespaceUID, Name       string
	ScopeDigest                         artifact.Digest
	IssuedAt, ExpiresAt                 time.Time
}

func (s PolicySubmissionIntent) Valid(now time.Time) bool {
	return authorization.UUID(s.RootID) && authorization.UUID(s.InstallationID) && authorization.UUID(s.IssuerEpoch) && (s.ReplacesID == "" || authorization.UUID(s.ReplacesID)) && authorization.UUID(s.Nonce) && s.Actor.Valid() && s.Actor.Kind == identity.Human && s.Source.Valid() && s.Source.Generation <= 2147483647 && authorization.UUID(s.ClusterID) && identity.Text(s.NamespaceUID, 64) && identity.Text(s.Name, 253) && s.ScopeDigest != (artifact.Digest{}) && identity.Fresh(s.IssuedAt, s.ExpiresAt, now, 60*time.Second) && s.IssuedAt.Nanosecond()%1000 == 0 && s.ExpiresAt.Nanosecond()%1000 == 0
}

// SubmissionCheck is short-lived verification provenance, never collection or
// approval authority. Consumers recheck it after blocking work.
type SubmissionCheck struct {
	Submission                                 VerifiedPolicySubmission
	RootID, InstallationID, IssuerEpoch, KeyID string
	TrustRevision                              identity.Revision
	VerifiedAt, ValidUntil                     time.Time
}

func (s SubmissionCheck) Valid(now time.Time) bool {
	return s.Submission.Valid(now) && authorization.UUID(s.RootID) && authorization.UUID(s.InstallationID) && authorization.UUID(s.IssuerEpoch) && identity.Text(s.KeyID, 128) && s.TrustRevision.Valid() && identity.Fresh(s.VerifiedAt, s.ValidUntil, now, 5*time.Second) && !s.ValidUntil.After(s.Submission.ExpiresAt)
}
