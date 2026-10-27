package contracts

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

// ADR-183: the continuation input is closed, so no credential field can be added.
func TestInstallerContinuationIsClosed(t *testing.T) {
	ok := `{"format":"` + InstallerContinuationFormat + `","namespace":"asservat-system","workerProvider":{"authMount":"k","authMountAccessor":"a"},"ownerProvider":{"authMount":"o","authMountAccessor":"b"},"ownerIssuerRootsPEM":"","ownerPKIMount":"owner-pki","ownerConnections":4,"ownerConcurrency":2}`
	if _, err := DecodeInstallerContinuation(strings.NewReader(ok)); err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeInstallerContinuation(strings.NewReader(strings.Replace(ok, `"format"`, `"token":"x","format"`, 1))); err == nil {
		t.Fatal("accepted an unknown credential field")
	}
}

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
