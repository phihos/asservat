package capture

import (
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
)

// PolicySourceInterval bounds one policy source observation (ADR-228).
const PolicySourceInterval = authorization.PolicySourceInterval

// PolicySource is a protected, complete Kubernetes observation. Source writers
// cannot accept execution. A tombstoned UID cannot be reused or revived.
type PolicySource struct {
	InstallationID, ClusterID, NamespaceUID, Name string
	Revision                                      identity.Revision
	ResourceVersion                               string
	ObservedAt, FreshUntil                        time.Time
	CollectionDigest                              artifact.Digest
	Suspended                                     bool
	Deleted                                       bool
}

func (s PolicySource) Valid(now time.Time) bool {
	return s.CollectionDigest != (artifact.Digest{}) && authorization.UUID(s.InstallationID) && authorization.UUID(s.ClusterID) && identity.Text(s.NamespaceUID, 64) && identity.Text(s.Name, 253) && s.Revision.Valid() && s.Revision.Generation <= 2147483647 && identity.Text(s.ResourceVersion, 128) && identity.Fresh(s.ObservedAt, s.FreshUntil, now, PolicySourceInterval)
}

// VerifiedPolicySubmission comes only from independently verified ingress and
// resolved scope, not a public DTO. The signature verifier must bind the final
// persisted post-admission resource and exact reviewed scope to this human.
// No token, signature bytes or personal group list is retained in SQL/audit.
type VerifiedPolicySubmission struct {
	ReplacesID                    string // Explicit authenticated replacement; empty only for first acceptance.
	Nonce                         string
	Actor                         identity.Principal
	Source                        identity.Revision
	ClusterID, NamespaceUID, Name string
	ScopeDigest, EnvelopeDigest   artifact.Digest
	IssuedAt, ExpiresAt           time.Time
}

func (s VerifiedPolicySubmission) Valid(now time.Time) bool {
	return (s.ReplacesID == "" || authorization.UUID(s.ReplacesID)) && authorization.UUID(s.Nonce) && s.Actor.Valid() && s.Actor.Kind == identity.Human && s.Source.Valid() && authorization.UUID(s.ClusterID) && identity.Text(s.NamespaceUID, 64) && identity.Text(s.Name, 253) && s.ScopeDigest != (artifact.Digest{}) && s.EnvelopeDigest != (artifact.Digest{}) && identity.Fresh(s.IssuedAt, s.ExpiresAt, now, 60*time.Second)
}

// PolicyAdmission binds the submission to the policy object's own location
// (source cluster/namespace) and the authority to its target workload. ADR-228
// hub-held policies live in the hub control namespace, so the two locations
// differ; the target is bound by the accepted authority and Target only.
type PolicyAdmission struct {
	RootID       string
	Submission   VerifiedPolicySubmission
	Verification SubmissionCheck
	Author       identity.Identity
	Authority    authorization.AcceptedPolicyAuthority
	Target       authorization.Target
	Recovery     artifact.RecoveryProof
	// Sharing is the activation's recurring sharing decision (ADR-239).
	Sharing *PolicyShareInstruction
}

func (a PolicyAdmission) Valid(now time.Time) bool {
	s, p := a.Submission, a.Authority
	return authorization.UUID(a.RootID) && s.Valid(now) && a.Verification.Valid(now) && a.Verification.Submission == s && a.Verification.RootID == a.RootID && a.Verification.InstallationID == p.InstallationID && a.Verification.IssuerEpoch == a.Recovery.IssuerEpoch && a.Author.Valid(now) && a.Author.Principal == s.Actor && p.Valid(now) && a.Target.Valid() && a.Target.ClusterID == p.ClusterID && a.Target.NamespaceUID == p.NamespaceUID && a.Target.WorkloadUID == p.WorkloadUID && s.Source.UID == p.PolicyUID && s.ScopeDigest == p.ScopeDigest && a.Recovery.Valid(now) && a.Recovery.InstallationID == p.InstallationID && (a.Sharing == nil || a.Sharing.Valid() && a.Sharing.Creator == a.Author.Principal && a.Sharing.NotAfter.After(now))
}

// PolicyAcceptance is immutable provenance, not a permit or current eligibility.
// Authority.Creator stays the first creator; Submitter is this generation's
// authenticated human and remains the requester for independent review.
type PolicyAcceptance struct {
	ID, RootID                           string
	Source                               PolicySource
	Submission                           VerifiedPolicySubmission
	Authority                            authorization.AcceptedPolicyAuthority
	Submitter                            identity.Principal
	IdentityRevision, PermissionRevision identity.Revision
	Recovery                             artifact.RecoveryProof
	IntentVersion                        int64
	AcceptedAt                           time.Time
	// Sharing is the immutable recurring sharing instruction (ADR-239); its
	// counter and revocation live beside the record, never in it.
	Sharing *PolicyShareInstruction `json:",omitempty"`
}

func (r PolicyAcceptance) Valid() bool {
	a, s := r.Authority, r.Submission
	return authorization.UUID(r.ID) && authorization.UUID(r.RootID) && r.Source.Valid(r.AcceptedAt) && !r.Source.Deleted && !r.Source.Suspended && r.IntentVersion > 0 && s.Valid(r.AcceptedAt) && a.Valid(r.AcceptedAt) && r.Submitter == s.Actor && r.IdentityRevision.Valid() && r.PermissionRevision.Valid() && r.Recovery.Valid(r.AcceptedAt) && r.Source.InstallationID == a.InstallationID && r.Recovery.InstallationID == a.InstallationID && r.Source.Revision == s.Source && s.Source.UID == a.PolicyUID && r.Source.ClusterID == s.ClusterID && r.Source.NamespaceUID == s.NamespaceUID && r.Source.Name == s.Name && a.ScopeDigest == s.ScopeDigest && (r.Sharing == nil || r.Sharing.Valid() && r.Sharing.Creator == r.Submitter)
}

type AcceptedPolicy struct {
	Record PolicyAcceptance
	Replay bool
}
