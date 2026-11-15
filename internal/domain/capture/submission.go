package capture

import (
	"time"

	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
)

// SubmissionCheck is short-lived verification provenance, never collection or
// approval authority. Consumers recheck it after blocking work.
type SubmissionCheck struct {
	Submission                    VerifiedPolicySubmission
	RootID, InstallationID, KeyID string
	TrustRevision                 identity.Revision
	VerifiedAt, ValidUntil        time.Time
}

func (s SubmissionCheck) Valid(now time.Time) bool {
	return s.Submission.Valid(now) && authorization.UUID(s.RootID) && authorization.UUID(s.InstallationID) && identity.Text(s.KeyID, 128) && s.TrustRevision.Valid() && identity.Fresh(s.VerifiedAt, s.ValidUntil, now, 5*time.Second) && !s.ValidUntil.After(s.Submission.ExpiresAt)
}
