package artifact

import (
	"time"
)

// PublicationAuthority is supplied by a current trusted result gate.
// The five-second lease cannot renew the original write or evidence deadline.
// A public caller, upload manifest or successful decrypt cannot construct it.
type PublicationAuthority struct {
	RootID, CaptureID, PermissionEpoch                   string
	PermissionSequence                                   int64
	ProjectionDigest, ExpectationDigest, AuthorityDigest Digest
	CheckedAt, ValidUntil                                time.Time
}

func (a PublicationAuthority) Valid(e ContextExpectation, expectationDigest Digest, now time.Time) bool {
	return uuid(a.RootID) && a.CaptureID == e.CaptureUID && uuid(a.PermissionEpoch) && a.PermissionSequence > 0 && a.ProjectionDigest != (Digest{}) && a.AuthorityDigest != (Digest{}) && expectationDigest != (Digest{}) && a.ExpectationDigest == expectationDigest && !a.CheckedAt.IsZero() && !a.CheckedAt.After(now) && a.ValidUntil.After(a.CheckedAt) && !a.ValidUntil.After(a.CheckedAt.Add(5*time.Second)) && now.Before(a.ValidUntil) && now.Before(e.Registration.WriteUntil) && now.Before(e.Registration.ExpiresAt)
}

type PublishedContext struct {
	RootID, CaptureID       string
	Expectation             ContextExpectation
	Copies                  Copies
	VerifiedAt, PublishedAt time.Time
}
