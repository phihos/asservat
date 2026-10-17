package integration

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// The normal detach function deliberately leaves a still-live process alone.
// This fixture-only definer reaches its underlying trigger with the same exact
// cleanup login, so an unexecuted SQL branch cannot hide a name-resolution
// failure behind that earlier filter. No timestamp or production grant changes.
func qualifyConnectorLiveProfileCleanupGuard(t *testing.T, f *connectorSQLFixture) {
	t.Helper()
	t.Run("live-profile-cleanup-trigger-denies-with-original-row", func(t *testing.T) {
		root, peer := f.scenario.a.RootID, f.process.Binding.PeerID
		readOriginal := func() []byte {
			var raw []byte
			if err := f.admin.QueryRow(f.ctx, "SELECT to_jsonb(p)::text FROM connector_identity_profile p WHERE root_id=$1 AND peer_id=$2", root, peer).Scan(&raw); err != nil {
				t.Fatal(err)
			}
			return raw
		}
		original := readOriginal()
		f.refresh(t)
		var detached int64
		if err := f.pools["cleanup"].QueryRow(f.ctx, "SELECT detach_connector_identity($1,$2)", root, peer).Scan(&detached); err != nil || detached != 0 {
			t.Fatal("ordinary detach did not preserve the original live process", detached, err)
		}
		fn := pgx.Identifier{"connector_live_profile_probe_" + strings.ReplaceAll(custodyID(), "-", "")}.Sanitize()
		definition := "CREATE FUNCTION " + fn + "(r uuid, p uuid) RETURNS void LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $probe$ UPDATE public.connector_identity_profile SET fenced=true,candidate_id=NULL,accepted_id=NULL WHERE root_id=r AND peer_id=p $probe$"
		if _, err := f.admin.Exec(f.ctx, definition); err != nil {
			t.Fatal(err)
		}
		defer func() {
			if _, err := f.admin.Exec(f.ctx, "DROP FUNCTION "+fn+"(uuid,uuid)"); err != nil {
				t.Error("fixture-only cleanup probe removal failed", err)
			}
		}()
		var login string
		if err := f.pools["cleanup"].QueryRow(f.ctx, "SELECT session_user").Scan(&login); err != nil {
			t.Fatal(err)
		}
		if _, err := f.admin.Exec(f.ctx, "REVOKE ALL ON FUNCTION "+fn+"(uuid,uuid) FROM PUBLIC; GRANT EXECUTE ON FUNCTION "+fn+"(uuid,uuid) TO "+pgx.Identifier{login}.Sanitize()); err != nil {
			t.Fatal(err)
		}
		_, err := f.pools["cleanup"].Exec(f.ctx, "SELECT "+fn+"($1,$2)", root, peer)
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || pgErr.Code != "23514" || pgErr.Message != "connector accepted source still referenced" {
			t.Fatal("live-profile cleanup must reach its original reference denial, not a SQL compilation failure", err)
		}
		if !bytes.Equal(original, readOriginal()) {
			t.Fatal("denied cleanup rewrote the original connector profile")
		}
	})
}
