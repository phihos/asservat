package postgres

import (
	"context"
	"errors"
	"fmt"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"testing"
	"time"

	"asservat.local/asservat/internal/application/privacy"
	cfg "asservat.local/asservat/internal/domain/configuration"
)

// The ledger's cause word survives the permission mapping as a fixed step,
// and both keep matching their sentinels.
func TestLedgerCauseKeepsTheSentinelAndNamesTheCause(t *testing.T) {
	err := unavailableCause("begin-deadline")
	if !errors.Is(err, privacy.ErrUnavailable) {
		t.Fatal("ledger cause lost the custody sentinel")
	}
	mapped := permissionError(fmt.Errorf("wrapped: %w", err))
	var step interface{ FixedStep() string }
	if !errors.Is(mapped, cfg.ErrUnavailable) || !errors.As(mapped, &step) || step.FixedStep() != "begin-deadline" {
		t.Fatal("permission mapping lost the cause", mapped)
	}
	if permissionError(errors.New("other")) != cfg.ErrUnavailable {
		t.Fatal("an error without a cause changed")
	}
}

// A pool that cannot connect names how: a refused TCP dial, or a failing
// hook before connecting (the credential re-read).
func TestConnectCauseNamesTheFailingStage(t *testing.T) {
	for _, c := range []struct {
		name   string
		before func(context.Context, *pgx.ConnConfig) error
		want   string
	}{
		{"dial", nil, "dial"},
		{"named hook", func(context.Context, *pgx.ConnConfig) error { return namedHookError{} }, "credential"},
		{"unnamed hook", func(context.Context, *pgx.ConnConfig) error { return errors.New("hook") }, "acquire"},
	} {
		t.Run(c.name, func(t *testing.T) {
			config, err := pgxpool.ParseConfig("host=127.0.0.1 port=1 user=unused password=unused dbname=unused sslmode=disable connect_timeout=1")
			if err != nil {
				t.Fatal(err)
			}
			config.BeforeConnect = c.before
			pool, err := pgxpool.NewWithConfig(t.Context(), config)
			if err != nil {
				t.Fatal(err)
			}
			defer pool.Close()
			ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
			defer cancel()
			_, err = pool.BeginTx(ctx, pgx.TxOptions{})
			if err == nil || connectCause(err) != c.want {
				t.Fatal(connectCause(err), err)
			}
		})
	}
	if connectCause(errors.New("other")) != "acquire" {
		t.Fatal("unclassified error")
	}
}

type namedHookError struct{}

func (namedHookError) Error() string     { return "credential unavailable" }
func (namedHookError) FixedStep() string { return "credential" }
