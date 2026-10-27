package contracts

import (
	"bytes"
	"encoding/json"
	"encoding/json/jsontext"
	"io"
	"net/url"
	"time"
)

const (
	ClusterObservationLocatorPath        = "/internal/cluster-observation/locator/v1"
	ClusterObservationClaimPath          = "/internal/cluster-observation/claim/v1"
	ClusterObservationLocatorFormat      = "cluster-observation-locator/v1"
	ClusterObservationClaimFormat        = "cluster-observation-claim/v1"
	ClusterObservationLocatorMediaType   = "application/vnd.asservat.cluster-observation-locator.v1+json"
	ClusterObservationClaimMediaType     = "application/vnd.asservat.cluster-observation-claim.v1+json"
	ClusterObservationLocatorTargetBytes = 2 << 10
	ClusterObservationLocatorBytes       = 4 << 10
	// The envelope counts against this same aggregate; there is no extra
	// allowance beyond the existing request bound plus the locator bound.
	ClusterObservationClaimBytes = ClusterObservationBytes + ClusterObservationLocatorBytes
)

// This closed GET target carries routing identity only. Decoding it supplies
// neither peer authentication nor a new freshness interval. HTTP admission must
// separately reject bodies, credentials and alternate methods/authorities.
type ClusterObservationLocatorQuery struct {
	Format, RootID, ClusterID, RequestID, Challenge string
	RequestedAt, NotAfter                           string
}

type ClusterObservationHolder struct {
	InstallationID string `json:"installationId"`
	ClusterID      string `json:"clusterId"`
	IssuerEpoch    string `json:"issuerEpoch"`
	PodUID         string `json:"podUid"`
	ProcessEpoch   string `json:"processEpoch"`
}

type ClusterObservationLocator struct {
	Format     string                   `json:"format"`
	RootID     string                   `json:"rootId"`
	ClusterID  string                   `json:"clusterId"`
	RequestID  string                   `json:"requestId"`
	Challenge  string                   `json:"challenge"`
	Holder     ClusterObservationHolder `json:"holder"`
	ExchangeID string                   `json:"exchangeId"`
	Sequence   uint64                   `json:"sequence"`
	ObservedAt string                   `json:"observedAt"`
	FreshUntil string                   `json:"freshUntil"`
}

// Exactly one selected POST may carry this envelope. No token is forwarded and
// an unknown result does not authorize a replacement claim. The nested request
// retains its existing wire format/digest; routing introduces no proof ordinal.
type ClusterObservationClaim struct {
	Format  string                    `json:"format"`
	Request ClusterObservationRequest `json:"request"`
	Locator ClusterObservationLocator `json:"locator"`
}

func routingUUID(s string) bool {
	if len(s) != 36 || s == "00000000-0000-0000-0000-000000000000" {
		return false
	}
	for i, c := range s {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if c != '-' {
				return false
			}
		} else if !(c >= 'a' && c <= 'f' || c >= '0' && c <= '9') {
			return false
		}
	}
	return true
}

func routingInterval(start, end string) (time.Time, time.Time, bool) {
	s, se := time.Parse(time.RFC3339Nano, start)
	e, ee := time.Parse(time.RFC3339Nano, end)
	return s, e, se == nil && ee == nil && !s.IsZero() && s.UTC().Format(time.RFC3339Nano) == start && e.UTC().Format(time.RFC3339Nano) == end && e.After(s) && !e.After(s.Add(5*time.Second))
}

func (q ClusterObservationLocatorQuery) shape() bool {
	_, _, ok := routingInterval(q.RequestedAt, q.NotAfter)
	return ok && q.Format == ClusterObservationLocatorFormat && routingUUID(q.RootID) && routingUUID(q.ClusterID) && routingUUID(q.RequestID) && routingUUID(q.Challenge)
}

func EncodeClusterObservationLocatorTarget(q ClusterObservationLocatorQuery) (string, error) {
	if !q.shape() {
		return "", ErrClusterObservationProtocol
	}
	v := url.Values{"format": {q.Format}, "rootID": {q.RootID}, "clusterID": {q.ClusterID}, "requestID": {q.RequestID}, "challenge": {q.Challenge}, "requestedAt": {q.RequestedAt}, "notAfter": {q.NotAfter}}
	target := ClusterObservationLocatorPath + "?" + v.Encode()
	if len(target) > ClusterObservationLocatorTargetBytes {
		return "", ErrClusterObservationProtocol
	}
	return target, nil
}

func DecodeClusterObservationLocatorTarget(target string) (ClusterObservationLocatorQuery, error) {
	var zero ClusterObservationLocatorQuery
	if len(target) == 0 || len(target) > ClusterObservationLocatorTargetBytes {
		return zero, ErrClusterObservationProtocol
	}
	u, err := url.ParseRequestURI(target)
	if err != nil || u.Scheme != "" || u.Host != "" || u.User != nil || u.Path != ClusterObservationLocatorPath || u.RawPath != "" || u.Fragment != "" || u.Opaque != "" {
		return zero, ErrClusterObservationProtocol
	}
	v, err := url.ParseQuery(u.RawQuery)
	if err != nil || len(v) != 7 {
		return zero, ErrClusterObservationProtocol
	}
	for _, key := range []string{"format", "rootID", "clusterID", "requestID", "challenge", "requestedAt", "notAfter"} {
		if len(v[key]) != 1 {
			return zero, ErrClusterObservationProtocol
		}
	}
	q := ClusterObservationLocatorQuery{v.Get("format"), v.Get("rootID"), v.Get("clusterID"), v.Get("requestID"), v.Get("challenge"), v.Get("requestedAt"), v.Get("notAfter")}
	canonical, err := EncodeClusterObservationLocatorTarget(q)
	if err != nil || canonical != target {
		return zero, ErrClusterObservationProtocol
	}
	return q, nil
}

func (v ClusterObservationLocator) shape() bool {
	_, _, ok := routingInterval(v.ObservedAt, v.FreshUntil)
	h := v.Holder
	return ok && v.Format == ClusterObservationLocatorFormat && v.Sequence != 0 && routingUUID(v.RootID) && routingUUID(v.ClusterID) && routingUUID(v.RequestID) && routingUUID(v.Challenge) && routingUUID(v.ExchangeID) && routingUUID(h.InstallationID) && routingUUID(h.ClusterID) && routingUUID(h.IssuerEpoch) && routingUUID(h.PodUID) && routingUUID(h.ProcessEpoch)
}

func (c ClusterObservationClaim) shape() bool {
	r, v := c.Request, c.Locator
	s, e, ok := routingInterval(r.RequestedAt, r.NotAfter)
	vs, ve, _ := routingInterval(v.ObservedAt, v.FreshUntil)
	if c.Format != ClusterObservationClaimFormat || r.Format != ClusterObservationFormat || !v.shape() || !ok || vs.Before(s) || ve.After(e) || r.RootID != v.RootID || r.ClusterID != v.ClusterID || r.RequestID != v.RequestID || r.Challenge != v.Challenge {
		return false
	}
	switch r.Purpose {
	case ClusterObservationNamespaceGuard, ClusterObservationNamespaces, ClusterObservationWorkloads, ClusterObservationWorkload, ClusterObservationGuardedWorkload, ClusterObservationPermissionNamespaces, ClusterObservationPermissionWorkloads, ClusterObservationPermissionWorkloadGuard:
	default:
		return false
	}
	// Retain both child limits in addition to the aggregate envelope limit.
	_, re := EncodeClusterObservationRequest(r)
	_, le := EncodeClusterObservationLocator(v)
	return re == nil && le == nil
}

// Sequence is an exact uint64. RFC 8785's default IEEE-754 number conversion
// would round values above 2^53; this purpose alone preserves raw integer
// spelling. Existing observation codecs and request digests are unchanged.
func encodeObservationRouting(v any, limit int) ([]byte, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, ErrClusterObservationProtocol
	}
	out := jsontext.Value(b)
	if out.Canonicalize(jsontext.CanonicalizeRawInts(false)) != nil || len(out) == 0 || len(out) > limit {
		clear(out)
		return nil, ErrClusterObservationProtocol
	}
	return out, nil
}

func decodeObservationRouting[T any](b []byte, limit int) (T, error) {
	var v, zero T
	if len(b) == 0 || len(b) > limit || !jsontext.Value(b).IsValid() {
		return zero, ErrClusterObservationProtocol
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(&v) != nil || d.Decode(new(any)) != io.EOF {
		return zero, ErrClusterObservationProtocol
	}
	normal, err := encodeObservationRouting(v, limit)
	defer clear(normal)
	actual := jsontext.Value(bytes.Clone(b))
	defer clear(actual)
	if err != nil || actual.Canonicalize(jsontext.CanonicalizeRawInts(false)) != nil || !bytes.Equal(actual, normal) {
		return zero, ErrClusterObservationProtocol
	}
	return v, nil
}

func EncodeClusterObservationLocator(v ClusterObservationLocator) ([]byte, error) {
	if !v.shape() {
		return nil, ErrClusterObservationProtocol
	}
	return encodeObservationRouting(v, ClusterObservationLocatorBytes)
}
func DecodeClusterObservationLocator(b []byte) (ClusterObservationLocator, error) {
	v, err := decodeObservationRouting[ClusterObservationLocator](b, ClusterObservationLocatorBytes)
	if err != nil || !v.shape() {
		return ClusterObservationLocator{}, ErrClusterObservationProtocol
	}
	return v, nil
}
func EncodeClusterObservationClaim(v ClusterObservationClaim) ([]byte, error) {
	if !v.shape() {
		return nil, ErrClusterObservationProtocol
	}
	return encodeObservationRouting(v, ClusterObservationClaimBytes)
}
func DecodeClusterObservationClaim(b []byte) (ClusterObservationClaim, error) {
	v, err := decodeObservationRouting[ClusterObservationClaim](b, ClusterObservationClaimBytes)
	if err != nil || !v.shape() {
		return ClusterObservationClaim{}, ErrClusterObservationProtocol
	}
	return v, nil
}
