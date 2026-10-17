package capture

import "time"

type ContextRequestState string

const (
	RequestAccepted ContextRequestState = "accepted"
	RequestClosed   ContextRequestState = "closed"
)

// ContextRequestDisposition is an acknowledged transaction outcome for exactly
// one actor/client/preview. Closed never claims that no other captures exist.
// Errors, missing reads and expired delivery authority are not dispositions.
type ContextRequestDisposition struct {
	State      ContextRequestState
	Accepted   *Accepted
	ValidUntil time.Time `json:"-"`
}

func (d ContextRequestDisposition) Valid(now time.Time) bool {
	if d.ValidUntil.IsZero() || !now.Before(d.ValidUntil) {
		return false
	}
	switch d.State {
	case RequestClosed:
		return d.Accepted == nil
	case RequestAccepted:
		return d.Accepted != nil && !d.Accepted.MetadataValidUntil.IsZero() && !d.ValidUntil.After(d.Accepted.MetadataValidUntil)
	default:
		return false
	}
}
