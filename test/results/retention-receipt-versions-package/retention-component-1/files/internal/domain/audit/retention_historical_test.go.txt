package audit_test

import (
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	"testing"
)

func TestRetentionHistoricalReceiptPreservesRestrictiveReplay(t *testing.T) {
	root, event := "20000000-0000-4000-8000-000000000001", "20000000-0000-4000-8000-000000000002"
	for _, version := range []string{"original", "", "null"} {
		r := audit.Receipt{Key: audit.RetentionAcceptanceKey(root, event), Version: version, ETag: "original", Bytes: 64, SHA256: artifact.Digest{1}}
		if !r.HistoricalRetentionAcceptance(root, event) {
			t.Fatal("lost structural history", version)
		}
		bad := r
		bad.Key += "/replacement"
		if bad.HistoricalRetentionAcceptance(root, event) {
			t.Fatal("historical scope weakened")
		}
		bad = r
		bad.SHA256 = artifact.Digest{}
		if bad.HistoricalRetentionAcceptance(root, event) {
			t.Fatal("historical digest weakened")
		}
	}
}
