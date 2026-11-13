package integration

import (
	"context"
	"errors"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/fleet"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Each pool uses the existing scoped fixture login and exactly one connection.
// Its lifetime ends with this subtest, before the next fixture can begin.
func ownerBridgeScopedPool(t *testing.T, ctx context.Context, administrator *pgx.ConnConfig, role, password string) *pgxpool.Pool {
	t.Helper()
	config, err := pgxpool.ParseConfig("")
	if err != nil {
		t.Fatal(err)
	}
	config.ConnConfig = administrator.Copy()
	config.ConnConfig.User, config.ConnConfig.Password = role, password
	config.MaxConns, config.MinConns = 1, 0
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// Observe the exact owned wait edge, not a coincidental lock wait elsewhere.
// Polling observes SQL state only and never renews any operation/source interval.
func ownerBridgeWaitForBlocker(ctx context.Context, admin *pgxpool.Pool, blocker int32, waiter int32, application string) (int32, error) {
	probe, cancel := context.WithTimeout(ctx, 800*time.Millisecond)
	defer cancel()
	ticker := time.NewTicker(2 * time.Millisecond)
	defer ticker.Stop()
	for {
		var found int32
		err := admin.QueryRow(probe, `SELECT pid FROM pg_stat_activity
 WHERE datname=current_database() AND wait_event_type='Lock'
 AND $1::int=ANY(pg_blocking_pids(pid)) AND ($2::int=0 OR pid=$2)
 AND ($3::text='' OR application_name=$3)`, blocker, waiter, application).Scan(&found)
		if err == nil {
			return found, nil
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return 0, err
		}
		select {
		case <-probe.Done():
			return 0, errors.New("exact owned SQL blocker was not observed within original window")
		case <-ticker.C:
		}
	}
}

// One already-selected synthetic observation. Calling the reader does not move
// its start/end, and its public root bytes claim no native TLS qualification.
type ownerBridgeFixedOwnerSource struct {
	observation fleet.OwnerConfigurationObservation
}

func (s ownerBridgeFixedOwnerSource) ReadOwnerConfiguration(context.Context) (fleet.OwnerConfigurationObservation, error) {
	return s.observation, nil
}
