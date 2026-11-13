package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrSessionRole reports a pool connected as another role than expected.
var ErrSessionRole = errors.New("postgres session role mismatch")

// VerifySessionRole checks that the pool's login is the expected runtime
// role (Helm-native installation: runtime keeps only session_user = derived
// name; grants are applied by the setup Job).
func VerifySessionRole(ctx context.Context, pool *pgxpool.Pool, expected string) error {
	if ctx == nil || pool == nil || expected == "" {
		return ErrSessionRole
	}
	call, end := context.WithTimeout(ctx, 5*time.Second)
	defer end()
	var same bool
	if err := pool.QueryRow(call, `SELECT session_user = $1 AND current_user = session_user`, expected).Scan(&same); err != nil {
		return errors.Join(ErrSessionRole, err)
	}
	if !same {
		return ErrSessionRole
	}
	return nil
}
