package kubernetes

import (
	"bytes"
	"encoding/json"
	"testing"

	value "asservat.local/asservat/internal/domain/configuration"
)

func TestAutomationBindingEventCeilingAndLegacyDigest(t *testing.T) {
	d, err := NewAccessBindingSpecDecoder()
	if err != nil {
		t.Fatal(err)
	}
	obj := permissionBinding(1)
	spec := obj["spec"].(map[string]any)
	envelope := map[string]any{"allowedActions": []string{"syscallTrace"}, "maxLifetimeSeconds": 86400, "maxExecutions": 10, "maxBytes": 1048576, "maxObservedBytes": 2097152}
	spec["automation"] = envelope
	legacy, _ := json.Marshal(spec)
	original, err := d.DecodeAccessBindingSpec(legacy)
	if err != nil || original.Automation == nil || original.Automation.MaxObservedEvents != 0 {
		t.Fatal("legacy envelope", err)
	}
	for _, maximum := range []int64{0, 1, 1_000_000_000} {
		envelope["maxObservedEvents"] = maximum
		raw, _ := json.Marshal(spec)
		got, err := d.DecodeAccessBindingSpec(raw)
		if err != nil || got.Automation == nil || got.Automation.MaxObservedEvents != maximum {
			t.Fatal("event ceiling dropped", maximum, err)
		}
		if got.Resource.SpecDigest == original.Resource.SpecDigest {
			t.Fatal("authored event ceiling omitted from source digest")
		}
	}
	for _, invalid := range []any{-1, 1_000_000_001, 1.5, "100", nil} {
		envelope["maxObservedEvents"] = invalid
		raw, _ := json.Marshal(spec)
		if _, err := d.DecodeAccessBindingSpec(raw); err == nil {
			t.Fatal("invalid event ceiling accepted", invalid)
		}
	}
	delete(envelope, "maxObservedEvents")
	raw, _ := json.Marshal(spec)
	got, err := d.DecodeAccessBindingSpec(raw)
	if err != nil || !bytes.Equal(raw, legacy) || got.Resource.SpecDigest != original.Resource.SpecDigest {
		t.Fatal("legacy source bytes/digest changed", err)
	}
}

func TestAutomationBindingPreservesExplicitEnvelope(t *testing.T) {
	v, err := newPermissionValidator()
	if err != nil {
		t.Fatal(err)
	}
	obj := permissionBinding(1)
	spec := obj["spec"].(map[string]any)
	spec["automation"] = map[string]any{"allowedActions": []string{"packetCapture"}, "maxLifetimeSeconds": 86400, "maxExecutions": 10, "maxBytes": 1048576, "maxObservedBytes": 2097152}
	b, _ := json.Marshal(obj)
	parsed, err := objectEnvelope(b)
	if err != nil {
		t.Fatal(err)
	}
	binding, err := v.binding(parsed, value.Resource{})
	if err != nil {
		t.Fatal("explicit bounded automation envelope rejected", err)
	}
	encoded, _ := json.Marshal(binding)
	var got map[string]any
	_ = json.Unmarshal(encoded, &got)
	if got["Automation"] == nil {
		t.Fatal("reader discarded the automation envelope")
	}
}
