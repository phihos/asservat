package integration

import (
	"context"
	"crypto/tls"
	"errors"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/adapters/postgres"
	"asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Actual installed compiled SQL role and adapter. Provider ciphertext and all
// lifecycle timestamps are synthetic; this is not installed/IdP qualification.
func TestBrowserSessionCleanupWithRealServices(t *testing.T) {
	withCapacityProducerFixture(t, func(t *testing.T, ctx context.Context, admin *pgxpool.Pool, address string, tlsConfig *tls.Config, scope fleet.InstallationWitnessScope, claim string, administration fleet.Administration, objects *objectstore.AuthorityObjects) {
		f := newCapacitySQLFixture(t, ctx, admin, address, tlsConfig, scope, claim, administration, objects)
		role := f.roles["browser-settings"]
		root, other, epoch, old := custodyID(), custodyID(), custodyID(), custodyID()
		for _, r := range []string{root, other} {
			if _, err := admin.Exec(ctx, `INSERT INTO browser_session_root(id,epoch,enabled,max_logins,max_sessions,max_logout_events,issuer,client_id,origin,source_uid,source_generation,source_digest,observed_at,fresh_until,max_lifetime_seconds) VALUES($1,$2,false,1000,1000,1000,'https://id.example.test','console','https://console.example.test','synthetic-settings',1,sha256('synthetic-settings'::bytea),statement_timestamp()-interval '2 minutes',statement_timestamp()-interval '119 seconds',3600)`, r, epoch); err != nil {
				t.Fatal(err)
			}
		}
		// Expired and old-epoch rows remain housekeeping-eligible during suspension
		// and missing settings observations. No SQL timestamp is changed after use.
		if _, err := admin.Exec(ctx, `INSERT INTO browser_login(root_id,epoch,id,browser,ciphertext,created_at,expires_at)
   SELECT $1,$2,sha256(convert_to('expired-login-'||i,'UTF8')),sha256(convert_to('browser-'||i,'UTF8')),'synthetic-encrypted-login',statement_timestamp()-interval '2 minutes',statement_timestamp()-interval '1 minute' FROM generate_series(1,300)i`, root, epoch); err != nil {
			t.Fatal(err)
		}
		if _, err := admin.Exec(ctx, `INSERT INTO browser_session(root_id,epoch,id,issuer,client_id,subject,provider_session,ciphertext,created_at,authenticated_at,expires_at,refresh_at,version)
   SELECT $1,$2,sha256(convert_to('expired-session-'||i,'UTF8')),'https://id.example.test','console','synthetic-user','synthetic-provider','synthetic-encrypted-session',statement_timestamp()-interval '2 hours',statement_timestamp()-interval '2 hours',statement_timestamp()-interval '1 hour',statement_timestamp()-interval '90 minutes',1 FROM generate_series(1,300)i`, root, epoch); err != nil {
			t.Fatal(err)
		}
		if _, err := admin.Exec(ctx, `INSERT INTO browser_logout(root_id,epoch,id,issuer,client_id,subject,provider_session,issued_at,expires_at)
   SELECT $1,$2,sha256(convert_to('expired-logout-'||i,'UTF8')),'https://id.example.test','console','synthetic-user','',statement_timestamp()-interval '2 hours',statement_timestamp()-interval '1 hour' FROM generate_series(1,300)i`, root, epoch); err != nil {
			t.Fatal(err)
		}
		for _, r := range []string{root, other} {
			for _, e := range []string{epoch, old} {
				if _, err := admin.Exec(ctx, `INSERT INTO browser_login(root_id,epoch,id,browser,ciphertext,created_at,expires_at) VALUES($1,$2,sha256(convert_to($2::text,'UTF8')),sha256(convert_to($2::text,'UTF8')),'synthetic-live-login',statement_timestamp(),statement_timestamp()+interval '4 minutes')`, r, e); err != nil {
					t.Fatal(err)
				}
				if _, err := admin.Exec(ctx, `INSERT INTO browser_session(root_id,epoch,id,issuer,client_id,subject,provider_session,ciphertext,created_at,authenticated_at,expires_at,refresh_at,version) VALUES($1,$2,sha256(convert_to($2::text,'UTF8')),'https://id.example.test','console','synthetic-user','synthetic-provider','synthetic-live-session',statement_timestamp(),statement_timestamp(),statement_timestamp()+interval '1 hour',statement_timestamp()+interval '1 minute',1)`, r, e); err != nil {
					t.Fatal(err)
				}
				if _, err := admin.Exec(ctx, `INSERT INTO browser_logout(root_id,epoch,id,issuer,client_id,subject,provider_session,issued_at,expires_at) VALUES($1,$2,sha256(convert_to($2::text,'UTF8')),'https://id.example.test','console','synthetic-user','',statement_timestamp(),statement_timestamp()+interval '25 hours')`, r, e); err != nil {
					t.Fatal(err)
				}
			}
		}
		if _, err := admin.Exec(ctx, `INSERT INTO browser_session(root_id,epoch,id,issuer,client_id,subject,provider_session,ciphertext,created_at,authenticated_at,expires_at,refresh_at,version,refresh_claim,claim_until)
   SELECT $1,$2,sha256(convert_to(x,'UTF8')),'https://id.example.test','console','synthetic-user','synthetic-provider','synthetic-claimed-session',statement_timestamp()-interval '1 minute',statement_timestamp()-interval '1 minute',statement_timestamp()+interval '1 hour',statement_timestamp()+interval '1 minute',1,sha256(convert_to(x,'UTF8')),statement_timestamp()+d FROM (VALUES('abandoned',interval '-1 second'),('inflight',interval '5 minutes'))v(x,d)`, root, epoch); err != nil {
			t.Fatal(err)
		}
		cleanup, err := postgres.NewBrowserSettingsProjection(ctx, role, root)
		if err != nil {
			t.Fatal(err)
		}
		snapshot := func(r string) string {
			t.Helper()
			var out string
			if err := admin.QueryRow(ctx, `SELECT jsonb_build_object('root',(SELECT to_jsonb(r) FROM browser_session_root r WHERE id=$1),'login',(SELECT jsonb_agg(to_jsonb(l) ORDER BY id) FROM browser_login l WHERE root_id=$1),'session',(SELECT jsonb_agg(to_jsonb(s) ORDER BY id) FROM browser_session s WHERE root_id=$1),'logout',(SELECT jsonb_agg(to_jsonb(l) ORDER BY id) FROM browser_logout l WHERE root_id=$1))::text`, r).Scan(&out); err != nil {
				t.Fatal(err)
			}
			return out
		}
		// Pin just the original live rows/root, not rows intended for deletion.
		live := func() string {
			t.Helper()
			var out string
			if err := admin.QueryRow(ctx, `SELECT jsonb_build_object('root',(SELECT to_jsonb(r) FROM browser_session_root r WHERE id=$1),'login',(SELECT to_jsonb(l) FROM browser_login l WHERE root_id=$1 AND id=sha256(convert_to($2::text,'UTF8'))),'session',(SELECT to_jsonb(s) FROM browser_session s WHERE root_id=$1 AND id=sha256(convert_to($2::text,'UTF8'))),'logout',(SELECT to_jsonb(l) FROM browser_logout l WHERE root_id=$1 AND id=sha256(convert_to($2::text,'UTF8'))),'inflight',(SELECT to_jsonb(s) FROM browser_session s WHERE root_id=$1 AND id=sha256(convert_to('inflight','UTF8'))))::text`, root, epoch).Scan(&out); err != nil {
				t.Fatal(err)
			}
			return out
		}
		originalLive, originalOther := live(), snapshot(other)
		counts := func(want [3]int) {
			t.Helper()
			var got [3]int
			if err := admin.QueryRow(ctx, `SELECT (SELECT count(*) FROM browser_login WHERE root_id=$1),(SELECT count(*) FROM browser_session WHERE root_id=$1),(SELECT count(*) FROM browser_logout WHERE root_id=$1)`, root).Scan(&got[0], &got[1], &got[2]); err != nil || got != want {
				t.Fatalf("bounded prune counts=%v want=%v err=%v", got, want, err)
			}
		}
		counts([3]int{302, 304, 302})
		start := time.Now()
		if err = cleanup.Cleanup(ctx); err != nil {
			t.Fatal("compiled cleanup first pass", err)
		}
		t.Logf("compiled cleanup first768-row pass elapsed=%s", time.Since(start))
		counts([3]int{46, 48, 46})
		if err = cleanup.Cleanup(ctx); err != nil {
			t.Fatal("compiled cleanup second pass", err)
		}
		counts([3]int{1, 2, 1})
		if live() != originalLive || snapshot(other) != originalOther {
			t.Fatal("cleanup changed live credentials/root/other-root state")
		}
		// Once current epoch has changed, an old bound cleanup instance cannot act.
		stale, err := postgres.NewBrowserSessions(ctx, f.roles["hub-runtime"], identity.BrowserBinding{RootID: root, Epoch: old, Issuer: "https://id.example.test", ClientID: "console", Origin: "https://console.example.test"})
		if err != nil {
			t.Fatal(err)
		}
		if err = stale.Cleanup(ctx); err == nil {
			t.Fatal("old epoch cleanup remained current")
		}
		counts([3]int{1, 2, 1})
		for _, sql := range []string{"SELECT ciphertext FROM browser_login LIMIT 0", "SELECT ciphertext FROM browser_session LIMIT 0", "SELECT subject FROM browser_logout LIMIT 0", "INSERT INTO browser_session SELECT * FROM browser_session WHERE false", "UPDATE browser_session SET ciphertext='forged' WHERE false"} {
			_, err := role.Exec(ctx, sql)
			var pg *pgconn.PgError
			if !errors.As(err, &pg) || pg.Code != "42501" {
				t.Fatal("worker acquired credential read/write authority", sql, err)
			}
		}
		// Logout remains available during source suspension and deletes the exact
		// session immediately, independently of housekeeping's later60s cadence.
		ingress, err := postgres.NewBrowserSessions(ctx, f.roles["hub-runtime"], identity.BrowserBinding{RootID: root, Epoch: epoch, Issuer: "https://id.example.test", ClientID: "console", Origin: "https://console.example.test"})
		if err != nil {
			t.Fatal(err)
		}
		var sessionIDBytes []byte
		if err = admin.QueryRow(ctx, `SELECT sha256(convert_to($1::text,'UTF8'))`, epoch).Scan(&sessionIDBytes); err != nil {
			t.Fatal(err)
		}
		var sessionID [32]byte
		copy(sessionID[:], sessionIDBytes)
		if err = ingress.RevokeSession(ctx, sessionID); err != nil {
			t.Fatal("outage-safe local logout", err)
		}
		counts([3]int{1, 1, 1})
		if err = cleanup.Cleanup(ctx); err != nil {
			t.Fatal(err)
		}
		counts([3]int{1, 1, 1})
		// A blocked root lock must retain the caller's original deadline and
		// leave all rows unchanged until a later independent cleanup pass.
		if _, err = admin.Exec(ctx, `INSERT INTO browser_login(root_id,epoch,id,browser,ciphertext,created_at,expires_at) VALUES($1,$2,sha256('deadline-login'::bytea),sha256('deadline-browser'::bytea),'synthetic-encrypted-login',statement_timestamp()-interval '2 minutes',statement_timestamp()-interval '1 minute')`, root, epoch); err != nil {
			t.Fatal(err)
		}
		held, err := admin.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer held.Rollback(context.Background())
		if _, err = held.Exec(ctx, "SELECT id FROM browser_session_root WHERE id=$1 FOR UPDATE", root); err != nil {
			t.Fatal(err)
		}
		short, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
		err = cleanup.Cleanup(short)
		if err == nil || short.Err() == nil {
			t.Fatal("blocked cleanup outlived caller deadline", err)
		}
		cancel()
		counts([3]int{2, 1, 1})
		if err = held.Rollback(ctx); err != nil {
			t.Fatal(err)
		}
		if err = cleanup.Cleanup(ctx); err != nil {
			t.Fatal("later independent cleanup", err)
		}
		counts([3]int{1, 1, 1})
	})
}
