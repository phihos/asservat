package contracts

import (
	"bytes"
	"strconv"
	"strings"
	"testing"
)

func localRoutingValues() (ClusterObservationLocalLocatorQuery, ClusterObservationLocalClaim) {
	q, c := operationRoutingValues()
	return ClusterObservationLocalLocatorQuery{PodUID: q.RootID, Query: q}, ClusterObservationLocalClaim{Format: ClusterObservationLocalClaimFormat, PodUID: q.RootID, Request: c.Request, Locator: c.Locator}
}
func TestLocalObservationRoutingExactPurposeAndIntegers(t *testing.T) {
	q, c := localRoutingValues()
	target, err := EncodeClusterObservationLocalLocatorTarget(q)
	got, de := DecodeClusterObservationLocalLocatorTarget(target)
	if err != nil || de != nil || got != q {
		t.Fatal("local canonical query", err, de)
	}
	if _, err = DecodeClusterObservationOperationLocatorTarget(target); err == nil {
		t.Fatal("local token purpose became owner mTLS purpose")
	}
	old, _ := EncodeClusterObservationOperationLocatorTarget(q.Query)
	if _, err = DecodeClusterObservationLocalLocatorTarget(old); err == nil {
		t.Fatal("mTLS purpose became local token purpose")
	}
	for _, n := range []uint64{1, 1<<53 + 1, ^uint64(0)} {
		c.Locator.Sequence = n
		body, err := EncodeClusterObservationLocalClaim(c)
		v, de := DecodeClusterObservationLocalClaim(body)
		if err != nil || de != nil || v.Locator.Sequence != n || !bytes.Contains(body, []byte(`"sequence":`+strconv.FormatUint(n, 10))) {
			t.Fatal("exact claim sequence", n, err, de)
		}
		again, _ := EncodeClusterObservationLocalClaim(v)
		if !bytes.Equal(body, again) {
			t.Fatal("unstable canonical bytes")
		}
		if _, err = DecodeClusterObservationOperationClaim(body); err == nil {
			t.Fatal("local claim decoded as owner claim")
		}
		reply := ClusterObservationLocalLocator{Format: ClusterObservationLocalLocatorFormat, PodUID: q.PodUID, Query: q.Query, Locator: &c.Locator}
		data, err := EncodeClusterObservationLocalLocator(reply)
		r, de := DecodeClusterObservationLocalLocator(data)
		if err != nil || de != nil || r.Locator == nil || r.Locator.Sequence != n {
			t.Fatal("exact locator sequence", n, err, de)
		}
	}
	absent := ClusterObservationLocalLocator{Format: ClusterObservationLocalLocatorFormat, PodUID: q.PodUID, Query: q.Query}
	body, err := EncodeClusterObservationLocalLocator(absent)
	v, de := DecodeClusterObservationLocalLocator(body)
	if err != nil || de != nil || v.Locator != nil || v.Query != q.Query {
		t.Fatal("explicit local absence", err, de)
	}
}
func TestLocalObservationRoutingRejectsAmbiguousOrWidenedInput(t *testing.T) {
	q, c := localRoutingValues()
	target, _ := EncodeClusterObservationLocalLocatorTarget(q)
	for _, bad := range []string{target + "&podUID=" + q.PodUID, target + "&token=x", strings.Replace(target, "%3A", ":", 1), strings.Replace(target, "/local/locator/", "/locator/", 1), strings.Repeat("x", ClusterObservationLocatorTargetBytes+1)} {
		if _, err := DecodeClusterObservationLocalLocatorTarget(bad); err == nil {
			t.Fatal("accepted noncanonical local target")
		}
	}
	body, _ := EncodeClusterObservationLocalClaim(c)
	for _, bad := range []string{strings.Replace(string(body), `"sequence":1`, `"sequence":1.0`, 1), strings.Replace(string(body), `"sequence":1`, `"sequence":18446744073709551616`, 1), strings.Replace(string(body), `"sequence":1`, `"sequence":1,"sequence":1`, 1), strings.Replace(string(body), `"podUID":`, `"token":"x","podUID":`, 1), strings.Replace(string(body), "local-cluster-observation-claim/v2", "cluster-observation-claim/v2", 1)} {
		if _, err := DecodeClusterObservationLocalClaim([]byte(bad)); err == nil {
			t.Fatal("accepted ambiguous local claim")
		}
	}
	for _, change := range []func(*ClusterObservationLocalLocator){func(v *ClusterObservationLocalLocator) { v.PodUID = "" }, func(v *ClusterObservationLocalLocator) { v.Query.Challenge = "00000000-0000-4000-8000-000000000999" }, func(v *ClusterObservationLocalLocator) { v.Locator.FreshUntil = "2030-01-01T00:00:00Z" }, func(v *ClusterObservationLocalLocator) { v.Locator.Sequence = 0 }} {
		l := c.Locator
		v := ClusterObservationLocalLocator{Format: ClusterObservationLocalLocatorFormat, PodUID: q.PodUID, Query: q.Query, Locator: &l}
		change(&v)
		if _, err := EncodeClusterObservationLocalLocator(v); err == nil {
			t.Fatal("accepted changed correlation/original interval")
		}
	}
}
