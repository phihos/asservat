package capture

import (
	"fmt"
	"slices"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
)

// ErrSharingDenied refuses a reviewed request whose requester does not hold
// evidence-owner and evidence:share for the target (ADR-235). It is a denial,
// raised before any capture is admitted.
var ErrSharingDenied = fmt.Errorf("capture sharing not permitted: %w", ErrDenied)

// ContextSharing is a capture-time sharing instruction (ADR-235, S-06
// increment 5): the reviewed recipients of the capture's one published
// artifact and an optional absolute end. It is outside the execution digest
// and grants nothing by itself; admission pins the requester's management and
// publication materializes exactly one concrete share.
type ContextSharing struct {
	Recipients []authorization.ShareRecipient
	NotAfter   time.Time `json:",omitzero"`
}

// Valid checks the shape only: 1..8 distinct recipients of one issuer. That
// issuer is the requester's, checked where the requester is known.
func (s ContextSharing) Valid() bool {
	if len(s.Recipients) < 1 || len(s.Recipients) > authorization.ShareMaxRecipients || !s.NotAfter.IsZero() && !previewTime(s.NotAfter) {
		return false
	}
	seen := map[string]bool{}
	for _, r := range s.Recipients {
		if !r.Valid() || r.Issuer != s.Recipients[0].Issuer || seen[r.Key()] {
			return false
		}
		seen[r.Key()] = true
	}
	return true
}

func (s *ContextSharing) clone() *ContextSharing {
	if s == nil {
		return nil
	}
	c := *s
	c.Recipients = slices.Clone(s.Recipients)
	return &c
}

// CaptureShareInstruction is the accepted instruction stored with the accepted
// capture. Publication materializes exactly one evidence share with ShareID
// from it; it is never re-evaluated against the requester's full current
// rights at publication (readers re-check the pinned management every time).
type CaptureShareInstruction struct {
	ShareID    string
	Creator    identity.Principal
	Management []artifact.AudienceAssignment
	Recipients []authorization.ShareRecipient
	NotAfter   time.Time
}

// Sharing states that get_capture reports separately from capture progress.
const (
	SharingPending     = "Pending"
	SharingShared      = "Shared"
	SharingUnavailable = "SharingUnavailable"
)

// ContextSharingStatus is the sharing projection of one capture.
type ContextSharingStatus struct {
	State   string
	ShareID string
}
