package postgres

import (
	"context"
	"errors"
	"time"

	"asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrCaptureCleanupStorePending reports that the permission root has no
// capacity source row yet; setup writes it, so the caller retries.
var ErrCaptureCleanupStorePending = errors.New("capture cleanup store pending")

// ReadCaptureCleanupStoreID returns the operation audit store of the
// capture, normal and resolution lanes from the root's stored capacity
// qualification. The three lanes share one store; a mismatch is refused.
// The cleanup purposes have SELECT on capacity_source(root_id,
// qualification) only.
func ReadCaptureCleanupStoreID(ctx context.Context, pool *pgxpool.Pool, root string) (string, error) {
	if ctx == nil || ctx.Err() != nil || pool == nil || !authorization.UUID(root) {
		return "", cfg.ErrInvalid
	}
	call, end := context.WithTimeout(ctx, 5*time.Second)
	defer end()
	var capture, normal, resolution *string
	err := pool.QueryRow(call, `SELECT qualification#>>'{RootBacking,Capture,Policy,StoreID}', qualification#>>'{RootBacking,Normal,Policy,StoreID}', qualification#>>'{RootBacking,Resolution,Policy,StoreID}'
 FROM public.capacity_source WHERE root_id=$1::uuid`, root).Scan(&capture, &normal, &resolution)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrCaptureCleanupStorePending
	}
	if err != nil {
		return "", cfg.ErrUnavailable
	}
	return captureCleanupStore(capture, normal, resolution)
}

func captureCleanupStore(capture, normal, resolution *string) (string, error) {
	if capture == nil || normal == nil || resolution == nil || !authorization.UUID(*capture) || *normal != *capture || *resolution != *capture {
		return "", cfg.ErrInvalid
	}
	return *capture, nil
}
