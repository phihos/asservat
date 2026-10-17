package clusterobservation

import (
	"asservat.local/asservat/internal/contracts"
	"testing"
)

func TestClusterObservationOrderDoesNotReadMetadataBeforeBracketedSource(t *testing.T) {
	var order exchangeOrder
	for n, step := range observationSteps {
		if order.complete() {
			t.Fatal("completed before final receipt", n)
		}
		if e := order.admit(step.kind, step.fromRegional, 1); e != nil {
			t.Fatal(n, e)
		}
	}
	if !order.complete() {
		t.Fatal("closed complete sequence rejected")
	}
	if e := order.admit(contracts.ClusterObservationHelloFrame, true, 1); e == nil || order.complete() {
		t.Fatal("conversation was silently restarted")
	}
	for _, n := range []int{1, 2, 3, 4} {
		o := exchangeOrder{}
		for _, step := range observationSteps[:n] {
			if e := o.admit(step.kind, step.fromRegional, 1); e != nil {
				t.Fatal(e)
			}
		}
		if e := o.admit(contracts.ClusterObservationReadFrame, false, 1); e == nil {
			t.Fatal("metadata before both source reads", n)
		}
		step := observationSteps[n]
		if e := o.admit(step.kind, step.fromRegional, 1); e == nil {
			t.Fatal("failed sequence rewound", n)
		}
	}
}

func TestClusterObservationOrderRequiresFinalChecksAndOriginalDirection(t *testing.T) {
	for _, n := range []int{7, 8, 9, 10} {
		o := exchangeOrder{}
		for _, step := range observationSteps[:n] {
			if e := o.admit(step.kind, step.fromRegional, 1); e != nil {
				t.Fatal(e)
			}
		}
		if e := o.admit(contracts.ClusterObservationReceiptFrame, false, 1); e == nil {
			t.Fatal("result acknowledged without post-result current checks", n)
		}
	}
	for n, step := range observationSteps {
		o := exchangeOrder{}
		for _, prior := range observationSteps[:n] {
			if e := o.admit(prior.kind, prior.fromRegional, 1); e != nil {
				t.Fatal(e)
			}
		}
		if e := o.admit(step.kind, !step.fromRegional, 1); e == nil {
			t.Fatal("peer crossed frame direction", n)
		}
	}
	o := exchangeOrder{bytes: contracts.ClusterObservationExchangeBytes - 5}
	if e := o.admit(contracts.ClusterObservationHelloFrame, true, 1); e == nil {
		t.Fatal("aggregate cap bypassed")
	}
}
