package clusterobservation

import (
	"time"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/fleet"
)

func parseLocatorQuery(q contracts.ClusterObservationLocatorQuery, now time.Time) (fleet.ClusterObservationLocatorQuery, error) {
	out := fleet.ClusterObservationLocatorQuery{RequestID: q.RequestID, Challenge: q.Challenge, RootID: q.RootID, ClusterID: q.ClusterID, RequestedAt: readTime(q.RequestedAt), NotAfter: readTime(q.NotAfter)}
	if q.Format != contracts.ClusterObservationLocatorFormat || !out.Valid(now) {
		return fleet.ClusterObservationLocatorQuery{}, fleet.ErrInvalid
	}
	return out, nil
}

func locatorWire(v fleet.ClusterObservationLocator) contracts.ClusterObservationLocator {
	h := v.Holder
	return contracts.ClusterObservationLocator{Format: contracts.ClusterObservationLocatorFormat, RootID: v.RootID, ClusterID: v.ClusterID, RequestID: v.RequestID, Challenge: v.Challenge, Holder: contracts.ClusterObservationHolder{InstallationID: h.InstallationID, ClusterID: h.ClusterID, IssuerEpoch: h.IssuerEpoch, PodUID: h.PodUID, ProcessEpoch: h.ProcessEpoch}, ExchangeID: v.ExchangeID, Sequence: v.Sequence, ObservedAt: writeTime(v.Interval.ObservedAt), FreshUntil: writeTime(v.Interval.FreshUntil)}
}

func parseLocator(v contracts.ClusterObservationLocator) fleet.ClusterObservationLocator {
	h := v.Holder
	return fleet.ClusterObservationLocator{RootID: v.RootID, ClusterID: v.ClusterID, RequestID: v.RequestID, Challenge: v.Challenge, Holder: fleet.OwnerBinding{InstallationID: h.InstallationID, ClusterID: h.ClusterID, IssuerEpoch: h.IssuerEpoch, PodUID: h.PodUID, ProcessEpoch: h.ProcessEpoch}, ExchangeID: v.ExchangeID, Sequence: v.Sequence, Interval: fleet.ClusterObservationInterval{ObservedAt: readTime(v.ObservedAt), FreshUntil: readTime(v.FreshUntil)}}
}

func localLocator(v fleet.ClusterObservationLocator) HubObservationLocator {
	return HubObservationLocator{RootID: v.RootID, ClusterID: v.ClusterID, ExchangeID: v.ExchangeID, Sequence: v.Sequence, ObservedAt: v.Interval.ObservedAt, FreshUntil: v.Interval.FreshUntil}
}

// LocatorQueryWire preserves the existing closed query shape and dates.
func LocatorQueryWire(v fleet.ClusterObservationLocatorQuery) contracts.ClusterObservationLocatorQuery {
	return contracts.ClusterObservationLocatorQuery{Format: contracts.ClusterObservationLocatorFormat, RequestID: v.RequestID, Challenge: v.Challenge, RootID: v.RootID, ClusterID: v.ClusterID, RequestedAt: writeTime(v.RequestedAt), NotAfter: writeTime(v.NotAfter)}
}

// LocatorWire exposes the same existing conversion for the typed bootstrap
// forwarder. The value and codec remain routing observations, not authority.
func LocatorWire(v fleet.ClusterObservationLocator) contracts.ClusterObservationLocator {
	return locatorWire(v)
}

// ParseLocator also requires the original query and independently authenticated
// holder; wire equality cannot supply that authentication.
func ParseLocator(v contracts.ClusterObservationLocator, q fleet.ClusterObservationLocatorQuery, holder fleet.OwnerBinding, now time.Time) (fleet.ClusterObservationLocator, error) {
	out := parseLocator(v)
	if v.Format != contracts.ClusterObservationLocatorFormat || !out.Matches(q, holder, now) {
		return fleet.ClusterObservationLocator{}, fleet.ErrUnavailable
	}
	return out, nil
}
