package v1alpha1

import (
	"encoding/json"
	"testing"
)

func TestAutomationEnvelopeEventCeilingWireCompatibility(t *testing.T) {
	legacy := `{"allowedActions":["syscallTrace"],"maxLifetimeSeconds":60,"maxExecutions":1,"maxBytes":1024,"maxObservedBytes":2048}`
	var envelope AutomationEnvelope
	if err := json.Unmarshal([]byte(legacy), &envelope); err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(envelope)
	if err != nil || string(encoded) != legacy || envelope.MaxObservedEvents != 0 {
		t.Fatal("legacy wire bytes changed", string(encoded), err)
	}
	envelope.MaxObservedEvents = 1000
	encoded, err = json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	var got AutomationEnvelope
	if err = json.Unmarshal(encoded, &got); err != nil || got.MaxObservedEvents != 1000 {
		t.Fatal("event ceiling lost on roundtrip", string(encoded), err)
	}
}
