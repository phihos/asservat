package audit

import (
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
)

// CaptureIntent is minimized accepted-control provenance. The expectation
// digest binds the complete audience/retention facts without copying evidence,
// reason text, policy bodies, bearer tokens or source Kubernetes objects here.
type CaptureIntent struct {
	Initiator                                                      *identity.Principal `json:",omitempty"`
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
	return r.Actor.Valid() && r.Target.Valid() && authorization.UUID(r.PermissionEpoch) && r.PermissionSequence > 0 && r.IdentityRevision.Valid() && r.ScopeDigest != (artifact.Digest{}) && r.SubmissionDigest != (artifact.Digest{}) && r.ExpectationDigest != (artifact.Digest{}) && !r.CreatedAt.IsZero() && r.CreatedAt.Before(r.Deadline) && r.CreatedAt.Before(r.ExpiresAt) && r.ExpiresAt.Before(r.DeleteBy) && r.ReservedBytes > 0 && r.ReservedBytes < 16<<20
}

func (r CaptureIntent) Requester() identity.Principal {
	if r.Initiator != nil {
		return *r.Initiator
	}
	return r.Actor
}
func CaptureIntentKey(root, capture string) string {
	return "capture-intent/v1/" + root + "/" + capture + "/record"
}
func (r Receipt) ValidCaptureIntent(root, capture string) bool {
	return authorization.UUID(root) && authorization.UUID(capture) && r.Key == CaptureIntentKey(root, capture) && (r.Version != "null" && identity.Text(r.Version, 1024)) && identity.Text(r.ETag, 256) && r.Bytes > 0 && r.Bytes <= 128<<10 && r.SHA256 != (artifact.Digest{})
}
