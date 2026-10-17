package identity

import (
	"context"
	"time"

	value "asservat.local/asservat/internal/domain/identity"
)

// RefreshOwnerJournal requires the concrete SQL43 adapter. It creates no identity: the
// exact current original browser session and accepted download are independently
// checked before admission. Consumer capacity comes from accepted downloads;
// owner capacity is the union with existing globally capped browser sessions.
type RefreshOwnerJournal interface {
	AdmitBrowserRefresh(context.Context, CurrentIdentity, value.RefreshSessionPin, value.RefreshOwnerRef, string) (value.RefreshOwnerObservation, error)
	// Only after the exact POST admission call has joined without starting work.
	AbandonBrowserRefreshAdmission(context.Context, value.RefreshOwnerRef) error
	ObserveBrowserRefresh(context.Context, value.RefreshOwnerRef) (value.RefreshDemand, error)
	ClaimBrowserOwnedRefresh(context.Context, CurrentIdentity, value.RefreshDemand, int64, [32]byte) error
	JoinBrowserRefreshClaim(context.Context, value.RefreshOwnerRef, int64, [32]byte) error
	CloseBrowserRefreshOwner(context.Context, value.RefreshOwnerRef) error
}

// BrowserRefreshPauseReader is consumed only by the existing content response
// controller. The requested tuple is server-owned connection identity, never
// caller-supplied credentials. It gives no permission to restart a response or
// repeat a prepaid window/chunk after an uncertain reply.
type BrowserRefreshPauseReader interface {
	BrowserRefreshPause(context.Context, [32]byte, value.Principal, value.RefreshResponseBinding) (value.RefreshPause, error)
}

// refreshSessionSchedule is transient C02 scheduling data. No provider token or
// raw cookie crosses into a worker, database owner row or public result.
type refreshSessionSchedule struct {
	Pin       value.RefreshSessionPin
	Version   int64
	RefreshAt time.Time
	Window    CredentialWindow
}

// Ordinary interactive refresh retains the existing store API. Only C02's
// POST-owned continuation requires a fresh evidence-bound claim check.
type currentRefreshClaimStore interface {
	ClaimCurrentRefresh(context.Context, [32]byte, int64, [32]byte, value.Identity) error
}
