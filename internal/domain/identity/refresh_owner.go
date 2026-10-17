package identity

import "time"

const (
	RefreshAttachmentGrace = 30 * time.Second
	RefreshOwnerLease      = 15 * time.Second
	RefreshClaimWindow     = 10 * time.Second
	MaxRefreshConsumers    = 16
)

// RefreshOwnerRef is private server identity, never a cookie or credential.
// Process identity is independently established by protected bootstrap. A
// process epoch by itself proves neither uniqueness nor termination.
type RefreshOwnerRef struct {
	RootID, Epoch, OwnerID, InstallationID, ClusterID, PodUID, ProcessEpoch string
	SessionID                                                               [32]byte
	Generation                                                              int64
}

func (r RefreshOwnerRef) Valid() bool {
	return browserUUID(r.RootID) && browserUUID(r.Epoch) && browserUUID(r.OwnerID) && browserUUID(r.InstallationID) && browserUUID(r.ClusterID) && browserUUID(r.PodUID) && browserUUID(r.ProcessEpoch) && r.SessionID != ([32]byte{}) && r.Generation > 0
}

// Original session dates and actor include client. Current settings may only
// reduce ExpiresAt. No group set or provider token is retained in this pin.
type RefreshSessionPin struct {
	ID                                    [32]byte
	Principal                             Principal
	ProviderSession                       string
	CreatedAt, AuthenticatedAt, ExpiresAt time.Time
}

func (p RefreshSessionPin) Matches(s BrowserSession, now time.Time) bool {
	return s.Current(now) && p.ID == s.ID && p.Principal == s.Principal && p.ProviderSession == s.ProviderSession && p.CreatedAt.Equal(s.CreatedAt) && p.AuthenticatedAt.Equal(s.AuthenticatedAt) && !s.ExpiresAt.After(p.ExpiresAt)
}

type RefreshOwnerObservation struct {
	Owner                                          RefreshOwnerRef
	SessionEnd, LeaseUntil, ObservedAt, ValidUntil time.Time
}

func (o RefreshOwnerObservation) Valid(now time.Time) bool {
	return o.Owner.Valid() && Fresh(o.ObservedAt, o.ValidUntil, now, 5*time.Second) && now.Before(o.LeaseUntil) && !o.LeaseUntil.After(o.ObservedAt.Add(RefreshOwnerLease)) && !o.LeaseUntil.After(o.SessionEnd) && !o.ValidUntil.After(o.LeaseUntil)
}

// RefreshDemand carries scheduling demand only. It is never preparation
// liveness, evidence permission or renewed byte authority.
type RefreshDemand struct {
	Owner                       RefreshOwnerObservation
	DownloadID                  string
	HardUntil, GraceUntil       time.Time
	ResponseID, ResponseOwnerID string
	ResponseGeneration          int64
	ResponseLeaseUntil          time.Time
}

func (d RefreshDemand) Valid(now time.Time) bool {
	if !d.Owner.Valid(now) || !browserUUID(d.DownloadID) || !now.Before(d.HardUntil) || d.HardUntil.After(d.Owner.SessionEnd) || d.GraceUntil.After(d.HardUntil) {
		return false
	}
	responsePresent := d.ResponseID != "" || d.ResponseOwnerID != "" || d.ResponseGeneration != 0 || !d.ResponseLeaseUntil.IsZero()
	responseCurrent := browserUUID(d.ResponseID) && browserUUID(d.ResponseOwnerID) && d.ResponseGeneration > 0 && now.Before(d.ResponseLeaseUntil) && !d.ResponseLeaseUntil.After(d.Owner.ObservedAt.Add(5*time.Second))
	if responsePresent && !responseCurrent {
		return false
	}
	return now.Before(d.GraceUntil) || responseCurrent
}

// A reader may pause only for this exact admitted refresh/response association.
// Busy by itself is not a pause permit. It emits no bytes or SQL delivery lease.
type RefreshPause struct {
	// Settled is wakeup-only: the exact joined claim committed a newer session
	// version. It permits one fresh identity attempt, never bytes or a new budget.
	Settled                                 bool
	Owner                                   RefreshOwnerRef
	DownloadID, ResponseID, ResponseOwnerID string
	ResponseGeneration, CredentialVersion   int64
	ClaimUntil, ObservedAt, ValidUntil      time.Time
}

func (p RefreshPause) Valid(now time.Time) bool {
	return p.Owner.Valid() && browserUUID(p.DownloadID) && browserUUID(p.ResponseID) && browserUUID(p.ResponseOwnerID) && p.ResponseGeneration > 0 && p.CredentialVersion > 0 && Fresh(p.ObservedAt, p.ValidUntil, now, 5*time.Second) && now.Before(p.ClaimUntil) && !p.ClaimUntil.After(p.ObservedAt.Add(RefreshClaimWindow)) && !p.ValidUntil.After(p.ClaimUntil)
}

// RefreshProcessBinding is supplied only by protected hub composition. It is
// not a request field and is checked against accepted owner identity by SQL.
type RefreshProcessBinding struct {
	RootID, Epoch, InstallationID, ClusterID, PodUID, ProcessEpoch string
}

func (b RefreshProcessBinding) Valid() bool {
	return browserUUID(b.RootID) && browserUUID(b.Epoch) && browserUUID(b.InstallationID) && browserUUID(b.ClusterID) && browserUUID(b.PodUID) && browserUUID(b.ProcessEpoch)
}
func (b RefreshProcessBinding) Owns(r RefreshOwnerRef) bool {
	return b.Valid() && r.Valid() && b.RootID == r.RootID && b.Epoch == r.Epoch && b.InstallationID == r.InstallationID && b.ClusterID == r.ClusterID && b.PodUID == r.PodUID && b.ProcessEpoch == r.ProcessEpoch
}

// RefreshResponseBinding is the exact server-owned response returned by SQL42.
// It contains no cookie, provider token, evidence metadata or byte authority.
type RefreshResponseBinding struct {
	DownloadID, ResponseID, ResponseOwnerID string
	ResponseGeneration                      int64
}

func (b RefreshResponseBinding) Valid() bool {
	return browserUUID(b.DownloadID) && browserUUID(b.ResponseID) && browserUUID(b.ResponseOwnerID) && b.ResponseGeneration > 0
}
func (p RefreshPause) Matches(b RefreshResponseBinding) bool {
	return b.Valid() && p.DownloadID == b.DownloadID && p.ResponseID == b.ResponseID && p.ResponseOwnerID == b.ResponseOwnerID && p.ResponseGeneration == b.ResponseGeneration
}
