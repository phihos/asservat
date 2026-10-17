package kubernetes

import (
	"encoding/json"
	"testing"

	value "asservat.local/asservat/internal/domain/configuration"
)

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
