package kubernetes

import (
	"encoding/json"
	"strings"
	"testing"

	"asservat.local/asservat/internal/contracts"
)

func TestCapacitySetupOmissionPreservesOldRoleStateBytes(t *testing.T) {
	// Decode/reencode the previous zero-value shape, including its explicit
	// fields, without appending a capability to an older retained root.
	v := contracts.PublicRuntimeRoleState{}
	raw, err := json.Marshal(v)
	if err != nil || strings.Contains(string(raw), "capacitySetup") {
		t.Fatal("omitted setup changed legacy bytes")
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil {
		t.Fatal("invalid encoded state")
	}
	delete(fields, "capacitySetup")
	if len(fields) != 7 {
		t.Fatal("legacy role state shape changed")
	}
}
