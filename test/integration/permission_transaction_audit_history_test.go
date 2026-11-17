package integration

import (
	"context"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/postgres"
	"asservat.local/asservat/internal/application/evidence"
	"github.com/jackc/pgx/v5/pgxpool"
)

type permissionDownloadAuditFixture struct {
	runtime *postgres.Downloads
	request evidence.DownloadReservation
}

func qualifyPermissionDownloadAuditHistory(t *testing.T, ctx context.Context, admin *pgxpool.Pool, setup func(*testing.T) permissionDownloadAuditFixture) {
	t.Helper()
	for _, kind := range []string{"reset", "initial"} {
		for _, version := range []string{"", "null"} {
			label := version
			if label == "" {
				label = "empty"
			}
			t.Run("download-permission-"+kind+"-"+label, func(t *testing.T) {
				f := setup(t)
				authority := f.request.Authority
				event := permissionHistoryEvent(t, ctx, admin, authority.Scope.RootID, kind)
				withHistoricalAuthorityVersion(t, ctx, admin, authority.Scope.RootID, event, version, func() {
					if _, err := f.runtime.ReserveDownload(ctx, f.request); err == nil {
						t.Fatal("old permission receipt authorized post-lock download reservation")
					}
					var count int
					if err := admin.QueryRow(ctx, "SELECT count(*) FROM artifact_download WHERE root_id=$1 AND id=$2", authority.Scope.RootID, f.request.Session.ID).Scan(&count); err != nil || count != 0 {
						t.Fatal("denied download persisted a reservation", count, err)
					}
					if !authority.Valid(time.Now()) {
						t.Fatal("download denial crossed original admitted authority deadline")
					}
				})
				if _, err := f.runtime.ReserveDownload(ctx, f.request); err != nil {
					t.Fatal("exact restored permission receipt rejected original download authority", err)
				}
			})
		}
	}
}

func permissionHistoryEvent(t *testing.T, ctx context.Context, admin *pgxpool.Pool, root, kind string) string {
	t.Helper()
	var reset, initial string
	if err := admin.QueryRow(ctx, "SELECT epoch::text,initial_audit_id::text FROM permission_stream WHERE id=$1", root).Scan(&reset, &initial); err != nil || reset == "" || initial == "" || reset == initial {
		t.Fatal("original permission reset/initial events unavailable", err)
	}
	switch kind {
	case "reset":
		return reset
	case "initial":
		return initial
	default:
		t.Fatal("unknown fixed permission history purpose")
		return ""
	}
}
