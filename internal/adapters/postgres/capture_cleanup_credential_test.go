package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
)

func captureCleanupManifestFixture() contracts.CaptureCleanupCredentialManifest {
	// Synthetic public provenance only; no root or SQL credential is issued.
	c := capacityRuntimeManifestFixture()
	c.Input.Worker = contracts.PublicRuntimeWorkerBinding{
		Resources:       contracts.WorkerObjectReference{Name: "original-resource-journal", UID: "90000000-0000-4000-8000-000000000030"},
		ResourceSetupID: "90000000-0000-4000-8000-000000000031", ResourceBinding: strings.Repeat("d", 64), WorkerLayout: contracts.HubWorkerInstalledLayout,
	}
	m := contracts.CaptureCleanupCredentialManifest{Format: contracts.CaptureCleanupManifestFormat, Input: c.Input, RootUID: c.RootUID, SetupID: c.SetupID, CaptureSetup: c.Capacity}
	for n, purpose := range contracts.PublicRuntimeCaptureCleanupPurposes() {
		name, _ := PublicRuntimeRoleName(c.Input.InstallationID, purpose)
		r := c.Roles[0]
		r.Purpose = purpose
		r.Claim.OperationID = fmt.Sprintf("90000000-0000-4000-8000-%012d", 40+n)
		r.Receipt.RoleOID = uint32(243 + n)
		r.Receipt.RoleName = name
		m.Roles = append(m.Roles, r)
	}
	return m
}

func TestCaptureCleanupManifestKeepsOriginalThreeRoleCompartment(t *testing.T) {
	for _, mode := range []string{"original-expired-claims", "empty-namespace", "extra-role", "missing-role", "swapped-roles", "capacity-role", "same-oid", "same-operation", "setup-operation", "different-layout", "different-root", "different-installation", "different-database", "different-postmaster", "late-role", "long-role-claim", "long-setup-claim", "nanosecond-claim", "unknown-worker-layout", "missing-worker-journal", "missing-worker-binding", "future-setup"} {
		t.Run(mode, func(t *testing.T) {
			m := captureCleanupManifestFixture()
			switch mode {
			case "empty-namespace":
				m.Input.Namespace.Name = ""
			case "extra-role":
				m.Roles = append(m.Roles, m.Roles[0])
			case "missing-role":
				m.Roles = m.Roles[:2]
			case "swapped-roles":
				m.Roles[0], m.Roles[1] = m.Roles[1], m.Roles[0]
			case "capacity-role":
				m.Roles[0].Purpose = "capacity"
			case "same-oid":
				m.Roles[1].Receipt.RoleOID = m.Roles[0].Receipt.RoleOID
			case "same-operation":
				m.Roles[1].Claim.OperationID = m.Roles[0].Claim.OperationID
			case "setup-operation":
				m.Roles[0].Claim.OperationID = m.CaptureSetup.OperationID
			case "different-layout":
				m.Roles[0].Receipt.LayoutDigest = strings.Repeat("f", 64)
			case "different-root":
				m.CaptureSetup.RoleRootUID = m.SetupID
			case "different-installation":
				m.CaptureSetup.InstallationID = m.SetupID
			case "different-database":
				m.Roles[0].Claim.DatabaseOID++
			case "different-postmaster":
				m.Roles[0].Claim.PostmasterAt = m.Roles[0].Claim.PostmasterAt.Add(time.Second)
			case "late-role":
				m.Roles[0].Claim.ClaimedAt = m.CaptureSetup.ClaimedAt.Add(time.Second)
				m.Roles[0].Claim.Until = m.Roles[0].Claim.ClaimedAt.Add(time.Second)
			case "long-role-claim":
				m.Roles[0].Claim.Until = m.Roles[0].Claim.ClaimedAt.Add(5*time.Second + time.Microsecond)
			case "long-setup-claim":
				m.CaptureSetup.Until = m.CaptureSetup.ClaimedAt.Add(5*time.Second + time.Microsecond)
			case "nanosecond-claim":
				m.Roles[0].Claim.Until = m.Roles[0].Claim.Until.Add(-time.Nanosecond)
			case "unknown-worker-layout":
				m.Input.Worker.WorkerLayout += "-future"
			case "missing-worker-journal":
				m.Input.Worker.Resources.UID = ""
			case "missing-worker-binding":
				m.Input.Worker.ResourceBinding = ""
			case "future-setup":
				m.CaptureSetup.ClaimedAt = time.Now().UTC().Add(time.Hour).Truncate(time.Microsecond)
				m.CaptureSetup.Until = m.CaptureSetup.ClaimedAt.Add(time.Second)
			}
			if err := ValidateCaptureCleanupCredentialManifest(m, time.Now()); (mode == "original-expired-claims") != (err == nil) {
				t.Fatalf("historical compartment %s: %v", mode, err)
			}
			if VerifyCaptureCleanupCredential(context.Background(), nil, m, "capture-cleanup") == nil {
				t.Fatal("public provenance substituted for a current authenticated SQL role")
			}
		})
	}
}

func TestCaptureCleanupManifestDecoderRejectsAmbiguousInput(t *testing.T) {
	b, err := json.Marshal(captureCleanupManifestFixture())
	if err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{`{"unknown":true,` + string(b[1:]), `{"format":"duplicate",` + string(b[1:]), string(b) + string(b)} {
		if _, err := contracts.DecodeCaptureCleanupCredentialManifest(strings.NewReader(raw)); err == nil {
			t.Fatal("ambiguous or extended manifest accepted")
		}
	}
}
