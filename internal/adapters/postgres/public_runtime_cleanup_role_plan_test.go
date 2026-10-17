package postgres

import (
	"strings"
	"testing"
)

func TestCaptureCleanupPlansKeepPrivateSQLAndPurposeSeparation(t *testing.T) {
	for _, purpose := range []string{"capture-cleanup", "capture-verifier", "capture-finalizer"} {
		grants, ok := publicRuntimeRoleGrants(purpose)
		if !ok || len(grants) == 0 {
			t.Fatal("cleanup role unavailable", purpose)
		}
		seen := map[string]bool{}
		for _, g := range grants {
			if seen[g.key()] {
				t.Fatal("duplicate grant", purpose, g.key())
			}
			seen[g.key()] = true
			if g.kind == "table" && (strings.HasPrefix(g.object, "operation_audit") || g.object == "capture_audit_root" || g.object == "capture_operation") {
				t.Fatal("private lifecycle acquired backing or human audit access", purpose, g.key())
			}
			if g.kind == "table" && (g.privilege == "INSERT" || g.privilege == "DELETE") {
				t.Fatal("cleanup bypasses positive closure RPC", purpose, g.key())
			}
			if g.kind == "table" && g.privilege == "UPDATE" && g.column == "" {
				t.Fatal("cleanup acquired arbitrary row updates", purpose, g.key())
			}
		}
		claim := seen[(publicRuntimeGrant{"table", "capture_operation_lifecycle", "certificate_started", "UPDATE"}).key()]
		verify := seen[(publicRuntimeGrant{"table", "capture_operation_lifecycle", "certificate_verify_attempts", "UPDATE"}).key()]
		finalize := seen[(publicRuntimeGrant{"function", "finish_capture_operation_retirement(uuid,uuid,uuid)", "", "EXECUTE"}).key()]
		if claim != (purpose == "capture-cleanup") || verify != (purpose == "capture-verifier") || finalize != (purpose == "capture-finalizer") {
			t.Fatal("cleanup, verification and positive finalization merged", purpose)
		}
	}
	if _, ok := publicRuntimeCaptureCleanupGrants("capacity"); ok {
		t.Fatal("capacity inherited lifecycle privileges")
	}
}
