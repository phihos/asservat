package audit

import (
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
)

type CaptureGroupBinding struct {
	ParentCaptureID        string
	SelectionDigest        artifact.Digest
	ChildIndex, ChildCount int
}

// CaptureIntent is the minimized accepted-capture provenance read back from
// the context_capture row. The expectation digest binds the complete
// audience/retention facts. It is not acquisition authority.
type CaptureIntent struct {
	Group                                                          *CaptureGroupBinding `json:",omitempty"`
	Initiator                                                      *identity.Principal  `json:",omitempty"`
	RootID, CaptureID, CaseID, OccurrenceID, ArtifactID, AttemptID string
	Actor                                                          identity.Principal
	Target                                                         authorization.Target
	ScopeDigest, SubmissionDigest, ExpectationDigest               artifact.Digest
	PermissionEpoch                                                string
	PermissionSequence                                             int64
	IdentityRevision                                               identity.Revision
	CreatedAt, Deadline, ExpiresAt, DeleteBy                       time.Time
	ReservedBytes                                                  int64
}

func (r CaptureIntent) Valid() bool {
	if g := r.Group; g != nil {
		// A recording save child runs as its policy for a named initiator; an
		// ADR-276 composition child runs as the requesting human itself.
		_, _, policy := authorization.PolicyExecutor(r.Actor)
		if (r.Initiator == nil) == policy || !authorization.UUID(g.ParentCaptureID) || g.ParentCaptureID == r.CaptureID || g.SelectionDigest != r.ScopeDigest || g.ChildCount < 2 || g.ChildCount > 16 || g.ChildIndex < 0 || g.ChildIndex >= g.ChildCount {
			return false
		}
	}
	if r.Initiator != nil {
		if !r.Initiator.Valid() {
			return false
		}
		if _, _, policy := authorization.PolicyExecutor(r.Actor); !policy {
			return false
		}
	}
	for _, id := range []string{r.RootID, r.CaptureID, r.CaseID, r.OccurrenceID, r.ArtifactID, r.AttemptID} {
		if !authorization.UUID(id) {
			return false
		}
	}
	return r.Actor.Valid() && r.Target.Valid() && authorization.UUID(r.PermissionEpoch) && r.PermissionSequence > 0 && r.IdentityRevision.Valid() && r.ScopeDigest != (artifact.Digest{}) && r.SubmissionDigest != (artifact.Digest{}) && r.ExpectationDigest != (artifact.Digest{}) && !r.CreatedAt.IsZero() && r.CreatedAt.Before(r.Deadline) && r.CreatedAt.Before(r.ExpiresAt) && r.ExpiresAt.Before(r.DeleteBy) && r.ReservedBytes > 0 && r.ReservedBytes <= (artifact.Registration{NativeLimit: artifact.MaxGoTraceBytes}).ReservedBytes()
}

func (r CaptureIntent) Requester() identity.Principal {
	if r.Initiator != nil {
		return *r.Initiator
	}
	return r.Actor
}
