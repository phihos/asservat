package integration

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Fixture administrator only: one exact capture lookup, fixed state words and
// counts. This grants no product read/repeat/download or cleanup authority and
// logs no identities, parameters, object locators or dependency error text.
func installedHistoryStorageDiagnostics(t *testing.T, ctx context.Context, pool *pgxpool.Pool, root, capture string) {
	t.Helper()
	call, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	var required, visible, completed bool
	var header, custody string
	var copies int64
	err := pool.QueryRow(call, `SELECT c.history_parameters_required,
 coalesce(h.state,'absent'),coalesce(h.visible,false),coalesce(a.state,''),
 h.writer_completion_json IS NOT NULL,
 (SELECT count(*) FROM custody_copy x WHERE x.attempt_id=h.attempt_id AND x.ciphertext_bytes IS NOT NULL)
 FROM context_capture c LEFT JOIN capture_history_parameter h ON h.root_id=c.root_id AND h.capture_id=c.id
 LEFT JOIN custody_attempt a ON a.id=h.attempt_id WHERE c.root_id=$1 AND c.id=$2`, root, capture).Scan(&required, &header, &visible, &custody, &completed, &copies)
	if err != nil {
		t.Log("installed history storage diagnostic unavailable")
		return
	}
	switch header {
	case "absent", "reserved", "write_claimed", "available", "deleting", "deleted":
	default:
		header = "invalid"
	}
	switch custody {
	case "", "reserved", "stored_unpublished", "deleting", "deleted":
	default:
		custody = "other"
	}
	t.Logf("installed history storage: required=%t header=%s visible=%t custody=%s writerCompleted=%t acknowledgedCopies=%d", required, header, visible, custody, completed, copies)
}
