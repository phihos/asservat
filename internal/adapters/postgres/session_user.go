package postgres

import (
	"context"
	"time"

	cfg "asservat.local/asservat/internal/domain/configuration"
	"github.com/jackc/pgx/v5/pgxpool"
)

// VerifySessionUser checks that the pool connects as the expected derived
// runtime role (Helm-native installation: credentials come from the mounted
// Secret; `setup` creates the roles and their grants).
func VerifySessionUser(ctx context.Context, pool *pgxpool.Pool, expected string) error {
	if ctx == nil || pool == nil || expected == "" || pool.Config().ConnConfig.User != expected {
		return cfg.ErrInvalid
	}
	call, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	var actual string
	if err := pool.QueryRow(call, "SELECT session_user::text").Scan(&actual); err != nil {
		return cfg.ErrUnavailable
	}
	if actual != expected {
		return cfg.ErrDenied
	}
	return nil
}
