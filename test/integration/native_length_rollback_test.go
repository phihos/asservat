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
	// A later migration may down first; restore the original release even when
	// SQL130 refuses, so subsequent fixture cases see the compiled schema.
	original, err := provider.GetDBVersion(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		restore, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if _, err := provider.UpTo(restore, original); err != nil {
			t.Error("restore newer schema after expected refusal", err)
		}
	}()
	if _, err = provider.DownTo(ctx, 129); err == nil || !strings.Contains(err.Error(), "retained native-length verification prevents rollback") {
		t.Fatal("retained verification metadata downgrade", err)
	}
	head, err := provider.GetDBVersion(ctx)
	if err != nil || head != 130 {
		t.Fatal("refusal changed SQL130 head", head, err)
	}
}
