package postgres

import "testing"

func TestContextVerifierCanInsertButNeverRewriteNativeLength(t *testing.T) {
	for _, purpose := range []string{"context-verify", "context-verification-audit", "context-publish"} {
		grants, ok := publicRuntimeDutyGrants(purpose)
		if !ok {
			t.Fatalf("missing publication duty %s", purpose)
		}
		insert := map[string]bool{}
		for _, g := range grants {
			if g.object != "context_verification" {
				continue
			}
			if (g.privilege == "INSERT" || g.privilege == "UPDATE") && g.column == "" {
				t.Fatalf("%s gained broad verification write: %+v", purpose, g)
			}
			if g.column != "native_bytes" && g.column != "acquisition_started_at" && g.column != "acquisition_completed_at" {
				continue
			}
			if purpose != "context-verify" || g.kind != "table" || g.privilege != "INSERT" {
				t.Fatalf("%s can change verified native length: %+v", purpose, g)
			}
			insert[g.column] = true
		}
		for _, column := range []string{"native_bytes", "acquisition_started_at", "acquisition_completed_at"} {
			if (purpose == "context-verify") != insert[column] {
				t.Fatalf("%s %s insert=%v", purpose, column, insert[column])
			}
		}
	}
}
