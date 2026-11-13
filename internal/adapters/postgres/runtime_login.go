package postgres

import (
	"context"
	"time"

	cfg "asservat.local/asservat/internal/domain/configuration"
	"github.com/jackc/pgx/v5/pgxpool"
)

// VerifyRuntimeLogin checks that the pool is connected as the expected
// runtime role. Role attributes and grants are reconciled by setup; the
// runtime does not re-verify them.
func VerifyRuntimeLogin(ctx context.Context, pool *pgxpool.Pool, name string) error {
	if ctx == nil || ctx.Err() != nil || pool == nil || name == "" {
		return cfg.ErrInvalid
	}
	if pool.Config().ConnConfig.User != name {
		return cfg.ErrDenied
	}
	call, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	var exact bool
	if err := pool.QueryRow(call, `SELECT session_user=$1 AND current_user=session_user`, name).Scan(&exact); err != nil {
		return cfg.ErrUnavailable
	}
	if !exact {
		return cfg.ErrDenied
	}
	return nil
}
