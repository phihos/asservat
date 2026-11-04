package integration

import (
	"os/exec"
	"testing"
)

// Runs the same pure observation checker imported by the installed driver.
// Canonical public replies are synthetic; no browser/session authority is minted.
func TestInstalledProfileCaseRefreshProof(t *testing.T) {
	command := exec.CommandContext(t.Context(), "node", "../../web/scripts/installed-profile-case-proof-test.mjs")
	output, err := command.CombinedOutput()
	if err != nil || len(output) > 16<<10 {
		t.Fatalf("profile current-case observation proof: %v\n%s", err, output)
	}
	t.Logf("%s", output)
}
