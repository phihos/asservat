package postgres

import (
	"os"
	"strings"
	"testing"
)

// ReserveDownload recognises the stale-binding refusal by its message.
func TestStaleDownloadBindingMatchesTheMigration(t *testing.T) {
	b, err := os.ReadFile("../../../migrations/00054_protected_capacity.sql")
	if err != nil || !strings.Contains(string(b), "RAISE EXCEPTION '"+staleDownloadBinding+"' USING ERRCODE='23514'") {
		t.Fatal("refusal message changed", err)
	}
}
