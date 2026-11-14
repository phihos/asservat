package contracts

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestInstallerApprovalSettingsWireCompatibility(t *testing.T) {
	plain := InstallerPublicSettings{}
	old, err := json.Marshal(plain)
	if err != nil || bytes.Contains(old, []byte(`"approvals"`)) {
		t.Fatal("absent policy changes installation input", err)
	}
	plain.Approvals = &IdentityApprovals{RequireRecordingApproval: true, StepUp: &IdentityStepUp{ACRValues: []string{"2"}, MaxAgeSeconds: 300}}
	enabled, err := json.Marshal(plain)
	if err != nil || bytes.Equal(old, enabled) {
		t.Fatal("approval policy not digest-bound", err)
	}
	var decoded InstallerPublicSettings
	if err := json.Unmarshal(enabled, &decoded); err != nil || decoded.Approvals == nil || !decoded.Approvals.RequireRecordingApproval || decoded.Approvals.StepUp.MaxAgeSeconds != 300 {
		t.Fatal("approval policy not preserved", err)
	}
}
