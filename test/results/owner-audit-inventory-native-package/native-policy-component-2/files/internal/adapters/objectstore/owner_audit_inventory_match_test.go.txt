package objectstore

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"asservat.local/asservat/internal/domain/audit"
)

func TestOwnerAuditInventoryCompleteLatestDataMissingFromCurrent(t *testing.T) {
	for _, mode := range []string{"both-complete", "versions-truncated", "current-truncated", "latest-marker"} {
		t.Run(mode, func(t *testing.T) {
			c := ownerInventoryConfiguration()
			body := ownerInventoryBodies(c)
			body["current"] = "<ListBucketResult><IsTruncated>false</IsTruncated></ListBucketResult>"
			switch mode {
			case "versions-truncated":
				body["versions"] = strings.Replace(body["versions"], "<IsTruncated>false</IsTruncated>", "<IsTruncated>true</IsTruncated>", 1)
			case "current-truncated":
				body["current"] = strings.Replace(body["current"], "<IsTruncated>false</IsTruncated>", "<IsTruncated>true</IsTruncated>", 1)
			case "latest-marker":
				body["versions"] = "<ListVersionsResult><IsTruncated>false</IsTruncated>" + strings.Replace(ownerInventoryMarker(audit.OwnerConfigurationAuditKey(c), "original-marker"), "<IsLatest>false</IsLatest>", "<IsLatest>true</IsLatest>", 1) + "</ListVersionsResult>"
			}
			reader, calls := ownerInventoryFixture(t, c, func(k string, w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, body[k]) })
			got, err := reader.Read(context.Background())
			if err != nil || calls.Load() != 3 || got.Current != nil || got.CurrentUnmatched != (mode == "both-complete") {
				t.Fatal("complete latest/current discrepancy lost or incomplete absence invented", err, got)
			}
			if got.VersionsComplete != (mode != "versions-truncated") || got.CurrentComplete != (mode != "current-truncated") {
				t.Fatal("truncation changed")
			}
		})
	}
}
