package contracts

import (
	"bytes"
	"strconv"
	"strings"
	"testing"
)

func operationRoutingValues() (ClusterObservationOperationLocatorQuery, ClusterObservationOperationClaim) {
	q, c := routingWireValues()
	v := ClusterObservationOperationLocatorQuery(q)
	v.Format = ClusterObservationOperationLocatorFormat
	l := ClusterObservationOperationLocator(c.Locator)
	l.Format = ClusterObservationOperationLocatorFormat
	return v, ClusterObservationOperationClaim{Format: ClusterObservationOperationClaimFormat, Request: c.Request, Locator: l}
}
func TestObservationOperationRoutingVersionAndExactIntegers(t *testing.T) {
	q, c := operationRoutingValues()
	target, err := EncodeClusterObservationOperationLocatorTarget(q)
	got, decodeErr := DecodeClusterObservationOperationLocatorTarget(target)
	if err != nil || decodeErr != nil || got != q {
		t.Fatal("original v2 query", err, decodeErr)
	}
	legacyQ, legacyC := routingWireValues()
	legacyTarget, _ := EncodeClusterObservationLocatorTarget(legacyQ)
	if _, err = DecodeClusterObservationOperationLocatorTarget(legacyTarget); err == nil {
		t.Fatal("v1 query interpreted as v2")
	}
	if _, err = DecodeClusterObservationLocatorTarget(target); err == nil {
		t.Fatal("v2 query interpreted as v1")
	}
	for _, n := range []uint64{1, 1<<53 + 1, ^uint64(0)} {
		c.Locator.Sequence = n
		body, err := EncodeClusterObservationOperationClaim(c)
		v, e := DecodeClusterObservationOperationClaim(body)
		if err != nil || e != nil || v.Locator.Sequence != n {
			t.Fatal("exact sequence", n, err, e)
		}
		if !bytes.Contains(body, []byte(`"sequence":`+strconv.FormatUint(n, 10))) {
			t.Fatal("integer rounded")
		}
		if _, e = DecodeClusterObservationClaim(body); e == nil {
			t.Fatal("v2 claim interpreted as v1")
		}
		second, e := EncodeClusterObservationOperationClaim(v)
		if e != nil || !bytes.Equal(body, second) {
			t.Fatal("unstable canonical bytes")
		}
	}
	old, _ := EncodeClusterObservationClaim(legacyC)
	if _, err = DecodeClusterObservationOperationClaim(old); err == nil {
		t.Fatal("v1 claim interpreted as v2")
	}
}
func TestObservationOperationRoutingRejectsNoncanonicalAndUnknown(t *testing.T) {
	q, c := operationRoutingValues()
	target, _ := EncodeClusterObservationOperationLocatorTarget(q)
	for _, v := range []string{target + "&challenge=" + q.Challenge, target + "&unknown=1", strings.Replace(target, "%3A", ":", 1), strings.Replace(target, "/locator/v2", "/claim/v2", 1), strings.Repeat("x", ClusterObservationLocatorTargetBytes+1)} {
		if _, err := DecodeClusterObservationOperationLocatorTarget(v); err == nil {
			t.Fatal("noncanonical query")
		}
	}
	body, _ := EncodeClusterObservationOperationClaim(c)
	for _, v := range []string{strings.Replace(string(body), `"sequence":1`, `"sequence":1.0`, 1), strings.Replace(string(body), `"sequence":1`, `"sequence":18446744073709551616`, 1), strings.Replace(string(body), `"sequence":1`, `"sequence":1,"sequence":1`, 1), strings.Replace(string(body), `"sequence":1`, `"sequence":1,"token":"x"`, 1), strings.Replace(string(body), "locator/v2", "locator/v1", 1)} {
		if _, err := DecodeClusterObservationOperationClaim([]byte(v)); err == nil {
			t.Fatal("invalid claim accepted")
		}
	}
}
