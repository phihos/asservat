package integration

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/postgres"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/migrations"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
)

// Schema 5 kept the request digest and outcome, but not the original lease.
func qualifyHistoricalPermissionReplay(t *testing.T, ctx context.Context, admin, runtime *pgxpool.Pool) {
	t.Helper()
	name := "replay_" + custodyID()
	dbName := pgx.Identifier{name}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+dbName); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if _, err := admin.Exec(ctx, "DROP DATABASE "+dbName+" WITH (FORCE)"); err != nil {
			t.Error(err)
		}
	}()
	conn := admin.Config().ConnConfig.Copy()
	conn.Database = name
	db := stdlib.OpenDB(*conn)
	defer db.Close()
	g, err := goose.NewProvider(goose.DialectPostgres, db, migrations.Files(), goose.WithDisableGlobalRegistry(true))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = g.UpTo(ctx, 5); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	b := cfg.PermissionBatch{RootID: custodyID(), Epoch: custodyID(), RequestID: custodyID(), TrustDigest: artifact.Digest{1}, InputDigest: artifact.Digest{2}, ObservedAt: now, FreshUntil: now.Add(5 * time.Second)}
	data, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(data)
	record, err := json.Marshal(audit.AuthorityRecord{ID: b.RequestID, RootID: b.RootID, Epoch: b.Epoch, Kind: "permission-change", Sequence: 1, CreatedAt: now, InputDigest: b.InputDigest})
	if err != nil {
		t.Fatal(err)
	}
	eventDigest := sha256.Sum256(record)
	if _, err = db.ExecContext(ctx, `INSERT INTO permission_stream(id,epoch,sequence,trust_digest,lease_until,suspended,observed_at,fresh_until)
		VALUES($1,$2,1,$3,$4,false,$5,$4)`, b.RootID, b.Epoch, b.TrustDigest[:], b.FreshUntil, now); err != nil {
		t.Fatal(err)
	}
	if _, err = db.ExecContext(ctx, "INSERT INTO authority_audit(id,stream_id,epoch,sequence,event_kind,event_digest,record) VALUES($1,$2,$3,1,'permission-change',$4,$5)", b.RequestID, b.RootID, b.Epoch, eventDigest[:], record); err != nil {
		t.Fatal(err)
	}
	if _, err = db.ExecContext(ctx, "INSERT INTO permission_acceptance(request_id,stream_id,epoch,sequence,request_digest,audit_id,assignments,retired) VALUES($1,$2,$3,1,$4,$1,0,0)", b.RequestID, b.RootID, b.Epoch, digest[:]); err != nil {
		t.Fatal(err)
	}
	if _, err = g.Up(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err = db.ExecContext(ctx, "GRANT SELECT ON goose_db_version,permission_acceptance,permission_stream TO authority_runtime; GRANT UPDATE(id) ON permission_stream TO authority_runtime"); err != nil {
		t.Fatal(err)
	}
	rc := runtime.Config()
	rc.ConnConfig.Database = name
	pool, err := pgxpool.NewWithConfig(ctx, rc)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	permissions, err := postgres.NewPermissions(ctx, pool, b.RootID)
	if err != nil {
		t.Fatal(err)
	}
	got, err := permissions.AcceptPermissions(ctx, b)
	if err != nil || got.Sequence != 1 || got.AuditID != b.RequestID || !got.LeaseUntil.IsZero() {
		t.Fatalf("historical acceptance or unknown lease lost: %+v %v", got, err)
	}
	if _, err = permissions.RenewPermissions(ctx, got.PermissionFence); !errors.Is(err, cfg.ErrChanged) {
		t.Fatalf("migrated epoch renewed: %v", err)
	}
}
