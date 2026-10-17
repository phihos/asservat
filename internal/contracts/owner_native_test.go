package contracts

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestOwnerWireNativePortHistoricalOmission(t *testing.T) {
	var legacy OwnerConfiguration
	before, err := json.Marshal(legacy)
	if err != nil || strings.Contains(string(before), "nativePort") {
		t.Fatal("new field changed absent owner source representation")
	}
	legacy.NativePort = 9444
	after, err := json.Marshal(legacy)
	if err != nil || !strings.Contains(string(after), `"nativePort":9444`) {
		t.Fatal("present native port omitted from protected source")
	}
	legacy.NativePort = 0
	roundTrip, _ := json.Marshal(legacy)
	if string(roundTrip) != string(before) {
		t.Fatal("cleared native port changed historical representation")
	}
}
