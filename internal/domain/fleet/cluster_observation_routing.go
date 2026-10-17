package fleet

import (
	"time"

	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
)

// ClusterObservationLocatorQuery is only a routing selection. It omits the
// metadata selection and cannot authenticate an owner or authorize a read.
type ClusterObservationLocatorQuery struct {
	RequestID, Challenge, RootID, ClusterID string
	RequestedAt, NotAfter                   time.Time
}

func (q ClusterObservationLocatorQuery) Valid(now time.Time) bool {
	return authorization.UUID(q.RequestID) && authorization.UUID(q.Challenge) && authorization.UUID(q.RootID) && authorization.UUID(q.ClusterID) && identity.Fresh(q.RequestedAt, q.NotAfter, now, 5*time.Second)
}

// LocatorQuery copies the original request interval, including any earlier
// caller cutoff. A new lookup must never manufacture a later interval.
func (r ClusterObservationRequest) LocatorQuery() ClusterObservationLocatorQuery {
	return ClusterObservationLocatorQuery{r.ID, r.Challenge, r.RootID, r.ClusterID, r.RequestedAt, r.NotAfter}
}

// ClusterObservationLocator names one process-local registration, not a
// persistent route or permission. Sequence prevents an old handle from
// claiming a later registration even if an exchange UUID is repeated.
type ClusterObservationLocator struct {
	RequestID, Challenge, RootID, ClusterID string
	Holder                                  OwnerBinding
	ExchangeID                              string
	Sequence                                uint64
	Interval                                ClusterObservationInterval
}

// Matches requires the independently authenticated holder. Equal wire fields
// alone cannot supply that peer proof. The trusted caller must bind that holder
// to the installed permission root; RootID is not the installation UUID. The
// interval must already intersect the
// original request, current peer proof and original standby socket deadline.
func (v ClusterObservationLocator) Matches(q ClusterObservationLocatorQuery, holder OwnerBinding, now time.Time) bool {
	return q.Valid(now) && holder.Valid() && v.Holder == holder && v.RequestID == q.RequestID && v.Challenge == q.Challenge && v.RootID == q.RootID && v.ClusterID == q.ClusterID && authorization.UUID(v.ExchangeID) && v.Sequence != 0 && v.Interval.Valid(now) && !v.Interval.ObservedAt.Before(q.RequestedAt) && !v.Interval.FreshUntil.After(q.NotAfter)
}

// ClusterObservationClaim is the one selected non-replayable attempt. Value
// validation does not claim the local holder, reserve a slot or make unknown
// delivery retryable. Those remain receiving-transport responsibilities.
type ClusterObservationClaim struct {
	Request ClusterObservationRequest
	Locator ClusterObservationLocator
}

func (c ClusterObservationClaim) Matches(holder OwnerBinding, now time.Time) bool {
	return c.Request.Valid(now) && c.Locator.Matches(c.Request.LocatorQuery(), holder, now)
}

func (c ClusterObservationClaim) Clone() ClusterObservationClaim {
	c.Request = c.Request.Clone()
	return c
}
