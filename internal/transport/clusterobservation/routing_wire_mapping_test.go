package clusterobservation

import (
	"bytes"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/fleet"
)

func TestObservationRoutingPublicMappingsPreserveOriginalBytes(t *testing.T) {
	now := time.Now().UTC()
	id := "11111111-1111-4111-8111-111111111111"
	q := fleet.ClusterObservationLocatorQuery{RequestID: id, Challenge: id, RootID: id, ClusterID: id, RequestedAt: now, NotAfter: now.Add(time.Second)}
	w := LocatorQueryWire(q)
	target, err := contracts.EncodeClusterObservationLocatorTarget(w)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := contracts.DecodeClusterObservationLocatorTarget(target)
	if err != nil || decoded != w {
		t.Fatal("original query conversion", err)
	}
	parsed, err := parseLocatorQuery(decoded, now)
	if err != nil || parsed != q {
		t.Fatal("query dates or identity changed", err)
	}
	binding := fleet.OwnerBinding{InstallationID: id, ClusterID: id, IssuerEpoch: id, PodUID: id, ProcessEpoch: id}
	for _, sequence := range []uint64{1, 1<<53 + 1, ^uint64(0)} {
		v := fleet.ClusterObservationLocator{RequestID: id, Challenge: id, RootID: id, ClusterID: id, Holder: binding, ExchangeID: id, Sequence: sequence, Interval: fleet.ClusterObservationInterval{ObservedAt: now, FreshUntil: q.NotAfter}}
		old, e := contracts.EncodeClusterObservationLocator(locatorWire(v))
		got, e2 := contracts.EncodeClusterObservationLocator(LocatorWire(v))
		if e != nil || e2 != nil || !bytes.Equal(old, got) {
			t.Fatal("existing locator bytes changed", e, e2)
		}
		wire, e := contracts.DecodeClusterObservationLocator(got)
		out, e2 := ParseLocator(wire, q, binding, now)
		if e != nil || e2 != nil || out != v {
			t.Fatal("exact sequence/identity conversion", e, e2)
		}
		wrong := binding
		wrong.ProcessEpoch = "22222222-2222-4222-8222-222222222222"
		if _, e = ParseLocator(wire, q, wrong, now); e == nil {
			t.Fatal("wire supplied independent holder authority")
		}
		wrongQuery := q
		wrongQuery.Challenge = wrong.ProcessEpoch
		if _, e = ParseLocator(wire, wrongQuery, binding, now); e == nil {
			t.Fatal("changed challenge accepted")
		}
		if _, e = ParseLocator(wire, q, binding, q.NotAfter); e == nil {
			t.Fatal("expired locator accepted")
		}
	}
}
