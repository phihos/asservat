package integration

import (
	"context"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/migrations"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
)

func qualifyNativeLengthRollbackRefusal(t *testing.T, ctx context.Context, admin *pgxpool.Pool) {
	t.Helper()
	db := stdlib.OpenDB(*admin.Config().ConnConfig.Copy())
	defer db.Close()
	provider, err := goose.NewProvider(goose.DialectPostgres, db, migrations.Files(), goose.WithDisableGlobalRegistry(true))
	if err != nil {
		t.Fatal(err)
	}
	original, err := provider.GetDBVersion(ctx)
	if err != nil {
		t.Fatal(err)
	}
	expected, refusal := int64(130), "retained native-length verification prevents rollback"
	if original >= 134 {
		var retained bool
		if err := admin.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM context_verification WHERE acquisition_started_at IS NOT NULL)").Scan(&retained); err != nil {
			t.Fatal(err)
		}
		if retained {
			expected, refusal = 134, "retained acquisition-window verification prevents rollback"
		}
	}
	if original >= 135 {
		var retained bool
		if err := admin.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM context_execution WHERE phase='profileUnavailable')").Scan(&retained); err != nil {
			t.Fatal(err)
		}
		if retained {
			expected, refusal = 135, "retained profile-unavailable execution prevents rollback"
		}
	}
	// A later migration may down first; restore the original release even when
	// SQL130 refuses, so subsequent fixture cases see the compiled schema.
	defer func() {
		restore, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if _, err := provider.UpTo(restore, original); err != nil {
			t.Error("restore newer schema after expected refusal", err)
		}
	}()
	if _, err = provider.DownTo(ctx, 129); err == nil || !strings.Contains(err.Error(), refusal) {
		t.Fatal("retained verification metadata downgrade", err)
	}
	head, err := provider.GetDBVersion(ctx)
	if err != nil || head != expected {
		t.Fatal("refusal changed retained metadata/terminal head", head, expected, err)
	}
}
