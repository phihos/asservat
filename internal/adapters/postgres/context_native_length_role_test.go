package postgres

import "testing"

func TestContextVerifierCanInsertButNeverRewriteNativeLength(t *testing.T) {
	for _, purpose := range []string{"context-verify", "context-verification-audit", "context-publish"} {
		grants, ok := publicRuntimeDutyGrants(purpose)
		if !ok {
			t.Fatalf("missing publication duty %s", purpose)
		}
		insert := false
		for _, g := range grants {
			if g.object != "context_verification" {
				continue
			}
			if (g.privilege == "INSERT" || g.privilege == "UPDATE") && g.column == "" {
				t.Fatalf("%s gained broad verification write: %+v", purpose, g)
			}
			if g.column != "native_bytes" {
				continue
			}
			if purpose != "context-verify" || g.kind != "table" || g.privilege != "INSERT" {
				t.Fatalf("%s can change verified native length: %+v", purpose, g)
			}
			insert = true
		}
		if (purpose == "context-verify") != insert {
			t.Fatalf("%s native-length insert=%v", purpose, insert)
		}
	}
}
