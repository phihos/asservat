package contracts

import "net/url"

// V2 is explicitly selected by the installed operation-owned proof profile.
// There is no negotiation or v1 fallback. The nested metadata request/digest
// stays unchanged; these envelopes carry routing observations, not authority.
const (
	ClusterObservationOperationLocatorPath      = "/internal/cluster-observation/locator/v2"
	ClusterObservationOperationClaimPath        = "/internal/cluster-observation/claim/v2"
	ClusterObservationOperationLocatorFormat    = "cluster-observation-locator/v2"
	ClusterObservationOperationClaimFormat      = "cluster-observation-claim/v2"
	ClusterObservationOperationLocatorMediaType = "application/vnd.asservat.cluster-observation-locator.v2+json"
	ClusterObservationOperationClaimMediaType   = "application/vnd.asservat.cluster-observation-claim.v2+json"
)

type ClusterObservationOperationLocatorQuery ClusterObservationLocatorQuery
type ClusterObservationOperationLocator ClusterObservationLocator
type ClusterObservationOperationClaim struct {
	Format  string                             `json:"format"`
	Request ClusterObservationRequest          `json:"request"`
	Locator ClusterObservationOperationLocator `json:"locator"`
}

func (q ClusterObservationOperationLocatorQuery) shape() bool {
	if q.Format != ClusterObservationOperationLocatorFormat {
		return false
	}
	legacy := ClusterObservationLocatorQuery(q)
	legacy.Format = ClusterObservationLocatorFormat
	return legacy.shape()
}
func EncodeClusterObservationOperationLocatorTarget(q ClusterObservationOperationLocatorQuery) (string, error) {
	if !q.shape() {
		return "", ErrClusterObservationProtocol
	}
	v := url.Values{"format": {q.Format}, "rootID": {q.RootID}, "clusterID": {q.ClusterID}, "requestID": {q.RequestID}, "challenge": {q.Challenge}, "requestedAt": {q.RequestedAt}, "notAfter": {q.NotAfter}}
	target := ClusterObservationOperationLocatorPath + "?" + v.Encode()
	if len(target) > ClusterObservationLocatorTargetBytes {
		return "", ErrClusterObservationProtocol
	}
	return target, nil
}
func DecodeClusterObservationOperationLocatorTarget(target string) (ClusterObservationOperationLocatorQuery, error) {
	var zero ClusterObservationOperationLocatorQuery
	if len(target) == 0 || len(target) > ClusterObservationLocatorTargetBytes {
		return zero, ErrClusterObservationProtocol
	}
	u, err := url.ParseRequestURI(target)
	if err != nil || u.Scheme != "" || u.Host != "" || u.User != nil || u.Path != ClusterObservationOperationLocatorPath || u.RawPath != "" || u.Fragment != "" || u.Opaque != "" {
		return zero, ErrClusterObservationProtocol
	}
	v, err := url.ParseQuery(u.RawQuery)
	if err != nil || len(v) != 7 {
		return zero, ErrClusterObservationProtocol
	}
	for _, k := range []string{"format", "rootID", "clusterID", "requestID", "challenge", "requestedAt", "notAfter"} {
		if len(v[k]) != 1 {
			return zero, ErrClusterObservationProtocol
		}
	}
	q := ClusterObservationOperationLocatorQuery{v.Get("format"), v.Get("rootID"), v.Get("clusterID"), v.Get("requestID"), v.Get("challenge"), v.Get("requestedAt"), v.Get("notAfter")}
	canonical, err := EncodeClusterObservationOperationLocatorTarget(q)
	if err != nil || canonical != target {
		return zero, ErrClusterObservationProtocol
	}
	return q, nil
}
func (v ClusterObservationOperationLocator) shape() bool {
	if v.Format != ClusterObservationOperationLocatorFormat {
		return false
	}
	legacy := ClusterObservationLocator(v)
	legacy.Format = ClusterObservationLocatorFormat
	return legacy.shape()
}
func (v ClusterObservationOperationClaim) shape() bool {
	if v.Format != ClusterObservationOperationClaimFormat || !v.Locator.shape() {
		return false
	}
	legacy := ClusterObservationLocator(v.Locator)
	legacy.Format = ClusterObservationLocatorFormat
	return (ClusterObservationClaim{Format: ClusterObservationClaimFormat, Request: v.Request, Locator: legacy}).shape()
}
func EncodeClusterObservationOperationLocator(v ClusterObservationOperationLocator) ([]byte, error) {
	if !v.shape() {
		return nil, ErrClusterObservationProtocol
	}
	return encodeObservationRouting(v, ClusterObservationLocatorBytes)
}
func DecodeClusterObservationOperationLocator(b []byte) (ClusterObservationOperationLocator, error) {
	v, err := decodeObservationRouting[ClusterObservationOperationLocator](b, ClusterObservationLocatorBytes)
	if err != nil || !v.shape() {
		return ClusterObservationOperationLocator{}, ErrClusterObservationProtocol
	}
	return v, nil
}
func EncodeClusterObservationOperationClaim(v ClusterObservationOperationClaim) ([]byte, error) {
	if !v.shape() {
		return nil, ErrClusterObservationProtocol
	}
	return encodeObservationRouting(v, ClusterObservationClaimBytes)
}
func DecodeClusterObservationOperationClaim(b []byte) (ClusterObservationOperationClaim, error) {
	v, err := decodeObservationRouting[ClusterObservationOperationClaim](b, ClusterObservationClaimBytes)
	if err != nil || !v.shape() {
		return ClusterObservationOperationClaim{}, ErrClusterObservationProtocol
	}
	return v, nil
}
