package bootstrap

import (
	"errors"
	"testing"
)

type deliveryStepFixture string

func (s deliveryStepFixture) Error() string     { return string(s) }
func (s deliveryStepFixture) FixedStep() string { return string(s) }

// Only a failure before the region could queue the work is repeated.
func TestSourceUndeliveredRetriesOnlyCertainNonDelivery(t *testing.T) {
	for step, want := range map[string]bool{"router": true, "answer/unavailable": true, "send-peer/denied": true, "receive-peer/denied": false, "receive-call/deadline": false} {
		if got := sourceUndelivered(deliveryStepFixture(step)); got != want {
			t.Fatal(step, got)
		}
	}
	if sourceUndelivered(errors.New("plain")) {
		t.Fatal("unlabelled failure repeated")
	}
}
