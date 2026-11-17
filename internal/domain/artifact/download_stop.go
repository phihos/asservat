package artifact

import (
	"time"

	"asservat.local/asservat/internal/domain/identity"
)

// DownloadStopReceipt reveals no artifact, native metadata, finer prior
// terminal state or evidence-retention dates. Current original actor/client
// authentication suffices; evidence-read scope is not needed to reduce access.
type DownloadStopReceipt struct {
	DownloadID, RequestID, State string
	ObservedAt, ValidUntil       time.Time
}

func (r DownloadStopReceipt) Valid(now time.Time) bool {
	return uuid(r.DownloadID) && uuid(r.RequestID) && validStopState(r.State) && identity.Fresh(r.ObservedAt, r.ValidUntil, now, DownloadLease)
}

// DownloadStop is the stored stop of one download (ADR-330 D6/D7). It is
// written with its audit row in one transaction; a retry with the same key
// returns it unchanged.
type DownloadStop struct {
	RootID, DownloadID, RequestID string
	Actor                         identity.Principal
	KeyDigest                     Digest
	State                         string
}

func (d DownloadStop) Valid() bool {
	return uuid(d.RootID) && uuid(d.DownloadID) && uuid(d.RequestID) && d.Actor.Valid() && d.KeyDigest != (Digest{}) && validStopState(d.State)
}

func validStopState(s string) bool { return s == "Cancelled" || s == "AlreadyTerminal" }
