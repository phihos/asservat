package contracts

import "net/url"

// Local v2 has separate paths and types from owner-to-owner mTLS routing.
// Token bytes occur only in the fixed Authorization header, never these values.
const (
	ClusterObservationLocalLocatorPath   = "/internal/cluster-observation/local/locator/v2"
	ClusterObservationLocalClaimPath     = "/internal/cluster-observation/local/claim/v2"
	ClusterObservationLocalLocatorFormat = "local-cluster-observation-locator/v2"
	ClusterObservationLocalClaimFormat   = "local-cluster-observation-claim/v2"
	ClusterObservationLocalLocatorMedia  = "application/vnd.asservat.local-cluster-observation-locator.v2+json"
	ClusterObservationLocalClaimMedia    = "application/vnd.asservat.local-cluster-observation-claim.v2+json"
)

type ClusterObservationLocalLocatorQuery struct {
	PodUID string
	Query  ClusterObservationOperationLocatorQuery
}

// Nil Locator means a positively authenticated absence in this exact holder's
// local map. It never represents an unavailable/unknown lookup or global absence.
// Query and PodUID correlate only; the receiving native proof supplies identity.
type ClusterObservationLocalLocator struct {
	Format  string                                  `json:"format"`
	PodUID  string                                  `json:"podUID"`
	Query   ClusterObservationOperationLocatorQuery `json:"query"`
	Locator *ClusterObservationOperationLocator     `json:"locator,omitempty"`
}

type ClusterObservationLocalClaim struct {
	Format  string                             `json:"format"`
	PodUID  string                             `json:"podUID"`
	Request ClusterObservationRequest          `json:"request"`
	Locator ClusterObservationOperationLocator `json:"locator"`
}

func EncodeClusterObservationLocalLocatorTarget(v ClusterObservationLocalLocatorQuery) (string, error) {
	q := v.Query
	if !routingUUID(v.PodUID) || !q.shape() {
		return "", ErrClusterObservationProtocol
	}
	values := url.Values{"format": {ClusterObservationLocalLocatorFormat}, "podUID": {v.PodUID}, "rootID": {q.RootID}, "clusterID": {q.ClusterID}, "requestID": {q.RequestID}, "challenge": {q.Challenge}, "requestedAt": {q.RequestedAt}, "notAfter": {q.NotAfter}}
	target := ClusterObservationLocalLocatorPath + "?" + values.Encode()
	if len(target) > ClusterObservationLocatorTargetBytes {
		return "", ErrClusterObservationProtocol
	}
	return target, nil
}

func DecodeClusterObservationLocalLocatorTarget(target string) (ClusterObservationLocalLocatorQuery, error) {
	var zero ClusterObservationLocalLocatorQuery
	if len(target) == 0 || len(target) > ClusterObservationLocatorTargetBytes {
		return zero, ErrClusterObservationProtocol
	}
	u, err := url.ParseRequestURI(target)
	if err != nil || u.Scheme != "" || u.Host != "" || u.User != nil || u.Path != ClusterObservationLocalLocatorPath || u.RawPath != "" || u.Fragment != "" || u.Opaque != "" {
		return zero, ErrClusterObservationProtocol
	}
	values, err := url.ParseQuery(u.RawQuery)
	if err != nil || len(values) != 8 {
		return zero, ErrClusterObservationProtocol
	}
	for _, key := range []string{"format", "podUID", "rootID", "clusterID", "requestID", "challenge", "requestedAt", "notAfter"} {
		if len(values[key]) != 1 {
			return zero, ErrClusterObservationProtocol
		}
	}
	if values.Get("format") != ClusterObservationLocalLocatorFormat {
		return zero, ErrClusterObservationProtocol
	}
	v := ClusterObservationLocalLocatorQuery{PodUID: values.Get("podUID"), Query: ClusterObservationOperationLocatorQuery{Format: ClusterObservationOperationLocatorFormat, RootID: values.Get("rootID"), ClusterID: values.Get("clusterID"), RequestID: values.Get("requestID"), Challenge: values.Get("challenge"), RequestedAt: values.Get("requestedAt"), NotAfter: values.Get("notAfter")}}
	canonical, err := EncodeClusterObservationLocalLocatorTarget(v)
	if err != nil || canonical != target {
		return zero, ErrClusterObservationProtocol
	}
	return v, nil
}

func (v ClusterObservationLocalLocator) shape() bool {
	if v.Format != ClusterObservationLocalLocatorFormat || !routingUUID(v.PodUID) || !v.Query.shape() {
		return false
	}
	if v.Locator == nil {
		return true
	}
	l, q := v.Locator, v.Query
	if !l.shape() || l.RootID != q.RootID || l.ClusterID != q.ClusterID || l.RequestID != q.RequestID || l.Challenge != q.Challenge {
		return false
	}
	start, end, good := routingInterval(q.RequestedAt, q.NotAfter)
	at, until, bounded := routingInterval(l.ObservedAt, l.FreshUntil)
	// The standby may predate the query. Its original start is retained; only
	// the end must remain within this original request. No receipt-time renewal.
	return good && bounded && !until.After(end) && until.After(start) && !at.After(end)
}

func EncodeClusterObservationLocalLocator(v ClusterObservationLocalLocator) ([]byte, error) {
	if !v.shape() {
		return nil, ErrClusterObservationProtocol
	}
	return encodeObservationRouting(v, ClusterObservationLocatorBytes)
}
func DecodeClusterObservationLocalLocator(b []byte) (ClusterObservationLocalLocator, error) {
	v, err := decodeObservationRouting[ClusterObservationLocalLocator](b, ClusterObservationLocatorBytes)
	if err != nil || !v.shape() {
		return ClusterObservationLocalLocator{}, ErrClusterObservationProtocol
	}
	return v, nil
}
func (v ClusterObservationLocalClaim) shape() bool {
	return v.Format == ClusterObservationLocalClaimFormat && routingUUID(v.PodUID) && (ClusterObservationOperationClaim{Format: ClusterObservationOperationClaimFormat, Request: v.Request, Locator: v.Locator}).shape()
}
func EncodeClusterObservationLocalClaim(v ClusterObservationLocalClaim) ([]byte, error) {
	if !v.shape() {
		return nil, ErrClusterObservationProtocol
	}
	return encodeObservationRouting(v, ClusterObservationClaimBytes)
}
func DecodeClusterObservationLocalClaim(b []byte) (ClusterObservationLocalClaim, error) {
	v, err := decodeObservationRouting[ClusterObservationLocalClaim](b, ClusterObservationClaimBytes)
	if err != nil || !v.shape() {
		return ClusterObservationLocalClaim{}, ErrClusterObservationProtocol
	}
	return v, nil
}
