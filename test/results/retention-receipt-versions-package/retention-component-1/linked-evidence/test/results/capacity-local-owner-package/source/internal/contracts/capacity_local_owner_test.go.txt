package contracts

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestCapacityLocalOwnerOmissionKeepsComponentEncoding(t *testing.T) {
	legacy := CapacityDeployment{Format: CapacityDeploymentFormat}
	raw, err := json.Marshal(legacy)
	if err != nil || bytes.Contains(raw, []byte("localOwner")) {
		t.Fatal("legacy omission changed", err)
	}
	parsed, err := DecodeCapacityDeployment(bytes.NewReader(raw))
	if err != nil || parsed.LocalOwner != nil {
		t.Fatal("legacy component decode changed", err)
	}
	legacy.LocalOwner = &CapacityLocalOwner{}
	next, err := json.Marshal(legacy)
	if err != nil || !bytes.Contains(next, []byte(`"localOwner":`)) {
		t.Fatal("present typed carrier omitted", err)
	}
	closed := strings.TrimSuffix(string(next), "}") + `,"localOwnerURL":"https://caller.invalid"}`
	if _, err = DecodeCapacityDeployment(strings.NewReader(closed)); err == nil {
		t.Fatal("caller endpoint accepted outside closed carrier")
	}
}
