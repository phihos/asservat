package postgres

import (
	"io/fs"
	"regexp"
	"strings"
	"testing"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/migrations"
)

// The actual SQL110 fixture exposed permission-denied on the NORMAL processing
// audit insert: PostgreSQL checks function EXECUTE dependencies even when a CASE
// branch is not selected. This dependency regression is structural; the owned
// real SQL fixture remains the authoritative normal-role execution test.
func TestReasonGlobalAuditChecksNeedNoPrivateFunctionPrivilege(t *testing.T) {
	raw, err := fs.ReadFile(migrations.Files(), "00110_recording_save_reasons.sql")
	if err != nil {
		t.Fatal(err)
	}
	up := strings.SplitN(string(raw), "-- +goose Down", 2)[0]
	checks := regexp.MustCompile(`(?m)^ALTER TABLE operation_audit ADD CONSTRAINT operation_audit_(?:intent|outcome)_check CHECK\((.+)\);$`).FindAllStringSubmatch(up, -1)
	if len(checks) != 2 {
		t.Fatal("expected both global audit size checks", len(checks))
	}
	calls := regexp.MustCompile(`\b([a-z_][a-z_0-9]*)\s*\(`)
	for _, check := range checks {
		for _, call := range calls.FindAllStringSubmatch(check[1], -1) {
			if call[1] != "jsonb_typeof" && call[1] != "octet_length" {
				t.Fatalf("global audit CHECK adds execution dependency on %q for unrelated writers", call[1])
			}
		}
	}
	for _, purpose := range contracts.PublicRuntimeRolePurposes() {
		grants, ok := publicRuntimeRoleGrants(purpose)
		if !ok {
			t.Fatal(purpose)
		}
		for _, grant := range grants {
			if grant.kind == "function" && grant.object == "capture_audit_intent_limit(jsonb)" {
				t.Fatal("private capture helper granted to runtime instead of preserving isolation", purpose)
			}
		}
	}
}
