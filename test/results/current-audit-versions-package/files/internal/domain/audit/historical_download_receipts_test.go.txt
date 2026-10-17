package audit_test

import (
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	"testing"
)

func TestHistoricalDownloadReceiptsRemainParseableWithoutAuthority(t *testing.T) {
	id := "11111111-1111-4111-8111-111111111111"
	window := windowAuditFixture()
	for _, version := range []string{"", "null", "original"} {
		r := audit.Receipt{Key: audit.DownloadAuditKey(id, id, id, "intent"), Version: version, ETag: "original", Bytes: 17, SHA256: artifact.Digest{9}}
		if !r.ValidHistoricalDownload(id, id, id, "intent") {
			t.Fatal("old batch cannot be accounted", version)
		}
		r.Key = audit.DownloadWindowAuditKey(window.Window.Authority.Scope.RootID, window.Response.ID, window.Window.ID, "intent")
		if !r.ValidHistoricalDownloadWindow(window, "intent") {
			t.Fatal("old window cannot be accounted", version)
		}
		if version != "original" && r.ValidDownloadWindow(window, "intent") {
			t.Fatal("historical decoder supplied authority")
		}
	}
}
