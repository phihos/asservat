package integration

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/json"
	"errors"
	"io/fs"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/adapters/postgres"
	"asservat.local/asservat/internal/domain/artifact"
	fleet "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/migrations"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
)

const fleetFreshnessObserveSQL = `SELECT public.observe_fleet_administration($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`

// Actual migration59 and SQL producer/activation adapters. Kubernetes witness,
// source identity and the local wrapping key are explicit synthetic fixtures.
// No trigger, ordinary observer or test read automatically seeds an observation.
func TestEnrollmentFleetFreshnessWithRealPostgres(t *testing.T) {
	path := os.Getenv("ASSERVAT_CUSTODY_FIXTURES")
	if path == "" {
		t.Skip("run selected owned fleet/custody fixture")
	}
	var fixture fixture
	raw, err := os.ReadFile(path)
	if err != nil || json.Unmarshal(raw, &fixture) != nil || fixture.Postgres == "" {
		t.Fatal("fixture unavailable")
	}
	clear(raw)
	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()
	admin, err := pgxpool.New(ctx, fixture.Postgres)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(admin.Close)
	name := "fleet_freshness_" + strings.ReplaceAll(custodyID(), "-", "")
	if _, err = admin.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{name}.Sanitize()); err != nil {
		t.Fatal("owned database", err)
	}
	var roles []string
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 10*time.Second)
		defer stop()
		if _, e := admin.Exec(cleanup, "DROP DATABASE "+pgx.Identifier{name}.Sanitize()); e != nil {
			t.Error("owned database not removed", e)
		}
		for _, role := range roles {
			if _, e := admin.Exec(cleanup, "DROP ROLE "+pgx.Identifier{role}.Sanitize()); e != nil {
				t.Error("owned role not removed", e)
			}
		}
	})
	config := admin.Config().Copy()
	config.ConnConfig.Database, config.MaxConns = name, 4
	db, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	// Goose creates the actual history table and applies the embedded product
	// corpus. Its only connection is joined before runtime adapters are opened.
	migrationDB := stdlib.OpenDB(*config.ConnConfig)
	migrationDB.SetMaxOpenConns(1)
	t.Cleanup(func() {
		if e := migrationDB.Close(); e != nil {
			t.Error(e)
		}
	})
	provider, err := goose.NewProvider(goose.DialectPostgres, migrationDB, migrations.Files(), goose.WithDisableGlobalRegistry(true))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = provider.UpTo(ctx, 58); err != nil {
		t.Fatal("actual schema58", err)
	}
	migration, err := fs.ReadFile(migrations.Files(), "00059_fleet_observation_separation.sql")
	if err != nil {
		t.Fatal(err)
	}
	qualifyFleetFreshnessMigrationACLs(t, ctx, db, migration)
	if _, err = provider.UpTo(ctx, 59); err != nil {
		t.Fatal("actual migration59", err)
	}
	// Current adapters pin the schema head; later migrations add unrelated
	// tables and leave migration 59's fleet objects unchanged.
	if _, err = provider.Up(ctx); err != nil {
		t.Fatal("current schema head", err)
	}
	if err = migrationDB.Close(); err != nil {
		t.Fatal(err)
	}

	endpoint, err := url.Parse(fixture.Postgres)
	if err != nil {
		t.Fatal(err)
	}
	address, roots := pgTLSBridge(t, endpoint.Host)
	pools := map[string]*pgxpool.Pool{}
	for _, purpose := range []string{"prepare", "audit", "activate", "observe"} {
		role := name + "_" + purpose
		if _, err = db.Exec(ctx, "CREATE ROLE "+pgx.Identifier{role}.Sanitize()+" LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 1 PASSWORD 'synthetic-fleet-freshness'"); err != nil {
			t.Fatal(err)
		}
		roles = append(roles, role)
		grant := func(sql string) {
			t.Helper()
			if _, e := db.Exec(ctx, sql+" TO "+pgx.Identifier{role}.Sanitize()); e != nil {
				t.Fatal("scoped fixture role", e)
			}
		}
		grant("GRANT USAGE ON SCHEMA public")
		grant("GRANT SELECT ON goose_db_version")
		switch purpose {
		case "prepare", "activate":
			grant("GRANT SELECT, MAINTAIN ON ALL TABLES IN SCHEMA public")
			if purpose == "prepare" {
				grant("GRANT INSERT ON fleet_initial_activation")
				grant("GRANT UPDATE(singleton) ON fleet_initial_activation")
				grant("GRANT INSERT(installation_id,issuer_epoch,source_uid,source_generation,source_digest,observed_at,fresh_until) ON fleet_trust")
			} else {
				grant("GRANT SELECT ON fleet_current_trust")
				grant("GRANT UPDATE(activated_at) ON fleet_initial_activation")
				grant("GRANT UPDATE(suspended,recovery_blocked,activated_postmaster_at,activated_database_oid,observed_at,fresh_until) ON fleet_trust")
				grant("GRANT INSERT(installation_id,semantic_version,issuer_epoch,source_uid,source_generation,source_digest,activated_postmaster_at,activated_database_oid,observed_at,fresh_until) ON fleet_observation")
			}
		case "audit":
			grant("GRANT SELECT ON fleet_initial_activation")
			grant("GRANT UPDATE(audit_receipt_json) ON fleet_initial_activation")
		case "observe":
			grant("GRANT SELECT ON fleet_trust,fleet_current_trust")
			grant("GRANT UPDATE(installation_id) ON fleet_current_trust")
			grant("GRANT EXECUTE ON FUNCTION observe_fleet_administration(uuid,bigint,timestamptz,oid,timestamptz,uuid,text,bigint,bytea,boolean,timestamptz,timestamptz),fence_fleet_observation(uuid,bigint,timestamptz,oid,timestamptz),reactivate_restarted_database(uuid)")
		}
		c, e := pgxpool.ParseConfig("postgres://" + role + ":synthetic-fleet-freshness@" + address + "/" + name + "?sslmode=disable")
		if e != nil {
			t.Fatal(e)
		}
		c.ConnConfig.TLSConfig, c.ConnConfig.Fallbacks, c.MaxConns = roots.Clone(), nil, 1
		pool, e := pgxpool.NewWithConfig(ctx, c)
		if e != nil {
			t.Fatal(e)
		}
		pools[purpose] = pool
		t.Cleanup(pool.Close)
	}
	objects := fleetFreshnessAuditObjects(t, ctx, fixture)
	lab := fleetFreshnessLab{db: db, pools: pools, objects: objects}
	t.Run("missing-root-never-seeds-current-observation", func(t *testing.T) {
		s := lab.setup(t, ctx, false)
		basis := s.basis(t, ctx)
		if basis.SemanticVersion != 0 {
			t.Fatal("expected distinct absent basis")
		}
		a := s.source()
		if e := s.observer.ObserveAdministration(ctx, basis, a); e != nil {
			t.Fatal("blocked root insertion", e)
		}
		s.requireObservationCount(t, ctx, 0)
		s.requireUnavailable(t, ctx)
		if _, e := db.Exec(ctx, `UPDATE fleet_trust SET suspended=false,recovery_blocked=false,activated_postmaster_at=pg_postmaster_start_time(),activated_database_oid=(SELECT oid FROM pg_database WHERE datname=current_database()) WHERE installation_id=$1`, a.InstallationID); e != nil {
			t.Fatal(e)
		}
		// An explicit administrator field mutation is intentionally insufficient.
		basis = s.basis(t, ctx)
		if e := s.observer.ObserveAdministration(ctx, basis, s.source()); e == nil {
			t.Fatal("observer repaired missing positive observation")
		}
		s.requireObservationCount(t, ctx, 0)
		s.requireUnavailable(t, ctx)
	})
	t.Run("actual-activation-seeds-once-and-replay-never-renews", func(t *testing.T) {
		s := lab.setup(t, ctx, true)
		before := s.snapshot(t, ctx)
		w, _ := s.witness.ReadInstallationWitness(ctx)
		if e := s.activation.ActivateInitialInstallation(ctx, w, s.source()); e != nil {
			t.Fatal("completed replay", e)
		}
		if s.snapshot(t, ctx) != before {
			t.Fatal("completed replay changed original observation")
		}
		s.requireObservationCount(t, ctx, 1)
		if _, e := db.Exec(ctx, "DELETE FROM fleet_observation WHERE installation_id=$1", s.a.InstallationID); e != nil {
			t.Fatal(e)
		}
		if e := s.activation.ActivateInitialInstallation(ctx, w, s.source()); e == nil {
			t.Fatal("completed replay repaired missing observation")
		}
		s.requireObservationCount(t, ctx, 0)
		s.requireUnavailable(t, ctx)
	})
	t.Run("pristine-inventory-rejects-unactivated-observation-row", func(t *testing.T) {
		s := lab.setup(t, ctx, false)
		basis := s.basis(t, ctx)
		if e := s.observer.ObserveAdministration(ctx, basis, s.source()); e != nil {
			t.Fatal(e)
		}
		// Deliberate administrator corruption for a negative inventory test;
		// this mismatched row cannot authorize recovery or serve as a seed.
		if _, e := db.Exec(ctx, `INSERT INTO fleet_observation(installation_id,semantic_version,issuer_epoch,source_uid,source_generation,source_digest,activated_postmaster_at,activated_database_oid,observed_at,fresh_until) SELECT installation_id,semantic_version,issuer_epoch,source_uid,source_generation,source_digest,pg_postmaster_start_time(),(SELECT oid FROM pg_database WHERE datname=current_database()),observed_at,fresh_until FROM fleet_trust WHERE installation_id=$1`, s.a.InstallationID); e != nil {
			t.Fatal(e)
		}
		w, _ := s.witness.ReadInstallationWitness(ctx)
		if _, e := s.preparation.PrepareInitialInstallation(ctx, w, s.source()); e == nil {
			t.Fatal("pristine inventory ignored fleet_observation")
		}
		var n int
		if e := db.QueryRow(ctx, "SELECT count(*) FROM fleet_initial_activation").Scan(&n); e != nil || n != 0 {
			t.Fatal("failed pristine check reserved an activation", n, e)
		}
		s.requireUnavailable(t, ctx)
	})
	t.Run("unchanged-renewal-coexists-with-current-share", func(t *testing.T) {
		s := lab.setup(t, ctx, true)
		held := fleetFreshnessHold(t, ctx, db, "SELECT installation_id FROM fleet_current_trust WHERE installation_id=$1 FOR SHARE", s.a.InstallationID)
		basis := s.basis(t, ctx)
		a := s.source()
		if e := s.observer.ObserveAdministration(ctx, basis, a); e != nil {
			t.Fatal("positive renewal blocked behind retained SHARE", e)
		}
		var at, until time.Time
		if e := db.QueryRow(ctx, "SELECT observed_at,fresh_until FROM fleet_current_trust WHERE installation_id=$1", a.InstallationID).Scan(&at, &until); e != nil || !at.Equal(a.ObservedAt) || !until.Equal(a.ObservedAt.Add(30*time.Second)) {
			// Migration 00074 stores the positive row for 30 seconds.
			t.Fatal("original positive interval changed", e)
		}
		// The consumer transaction remains open through the successful commit.
		if e := held.tx.QueryRow(ctx, "SELECT 1").Scan(new(int)); e != nil {
			t.Fatal("consumer did not retain its transaction", e)
		}
	})
	t.Run("restrictive-source-waits-for-current-share", func(t *testing.T) {
		s := lab.setup(t, ctx, true)
		held := fleetFreshnessHold(t, ctx, db, "SELECT installation_id FROM fleet_current_trust WHERE installation_id=$1 FOR SHARE", s.a.InstallationID)
		basis := s.basis(t, ctx)
		a := s.source()
		a.Suspended = true
		a.Revision.Generation++
		a.Revision.Digest[0]++
		pid := fleetFreshnessPID(t, ctx, pools["observe"])
		call := fleetFreshnessStart(t, ctx, func(c context.Context) error { return s.observer.ObserveAdministration(c, basis, a) })
		fleetFreshnessBlocked(t, ctx, db, pid, held.pid)
		held.close(t)
		if e := call.join(); e != nil {
			t.Fatal("bounded original restrictive observation", e)
		}
		s.requireUnavailable(t, ctx)
	})
	t.Run("failure-fence-waits-for-current-share", func(t *testing.T) {
		s := lab.setup(t, ctx, true)
		held := fleetFreshnessHold(t, ctx, db, "SELECT installation_id FROM fleet_current_trust WHERE installation_id=$1 FOR SHARE", s.a.InstallationID)
		basis := s.basis(t, ctx)
		started := time.Now()
		pid := fleetFreshnessPID(t, ctx, pools["observe"])
		call := fleetFreshnessStart(t, ctx, func(c context.Context) error { return s.observer.FenceAdministration(c, basis, started) })
		fleetFreshnessBlocked(t, ctx, db, pid, held.pid)
		held.close(t)
		if e := call.join(); e != nil {
			t.Fatal("original restrictive fence", e)
		}
		if s.basis(t, ctx).SemanticVersion != basis.SemanticVersion+1 {
			t.Fatal("restrictive fence did not advance original version")
		}
		s.requireUnavailable(t, ctx)
	})
	t.Run("initial-activation-table-order-does-not-invert-semantic-row", func(t *testing.T) {
		s := lab.setup(t, ctx, false)
		s.prepare(t, ctx)
		basis := s.basis(t, ctx)
		a := s.source()
		w, _ := s.witness.ReadInstallationWitness(ctx)
		held := fleetFreshnessHold(t, ctx, db, "SELECT installation_id FROM fleet_initial_activation WHERE installation_id=$1 FOR UPDATE", s.a.InstallationID)
		activatePID := fleetFreshnessPID(t, ctx, pools["activate"])
		activation := fleetFreshnessStart(t, ctx, func(c context.Context) error { return s.activation.ActivateInitialInstallation(c, w, a) })
		fleetFreshnessBlocked(t, ctx, db, activatePID, held.pid)
		observePID := fleetFreshnessPID(t, ctx, pools["observe"])
		observation := fleetFreshnessStart(t, ctx, func(c context.Context) error { return s.observer.ObserveAdministration(c, basis, a) })
		fleetFreshnessBlocked(t, ctx, db, observePID, activatePID)
		// Activation owns its actual complete inventory table locks. A reader
		// can still take this semantic row: the blocked observer owns no row yet.
		probe := fleetFreshnessHold(t, ctx, db, "SELECT installation_id FROM fleet_trust WHERE installation_id=$1 FOR UPDATE NOWAIT", s.a.InstallationID)
		probe.close(t)
		held.close(t)
		if e := activation.join(); e != nil {
			t.Fatal("actual activation failed after original blocker released", e)
		}
		if e := observation.join(); e == nil {
			t.Fatal("pre-activation basis adopted changed semantic root")
		}
		basis = s.basis(t, ctx)
		if e := s.observer.ObserveAdministration(ctx, basis, s.source()); e != nil {
			t.Fatal("independent current source failed after activation", e)
		}
	})
	for _, site := range []string{"table", "authority", "observation"} {
		t.Run("exact-lock-disposition-"+site, func(t *testing.T) {
			s := lab.setup(t, ctx, true)
			query := "SELECT installation_id FROM fleet_trust WHERE installation_id=$1 FOR UPDATE"
			if site == "table" {
				query = "LOCK TABLE fleet_trust IN SHARE ROW EXCLUSIVE MODE"
			}
			if site == "observation" {
				query = "SELECT installation_id FROM fleet_observation WHERE installation_id=$1 FOR UPDATE"
			}
			var held *fleetFreshnessLock
			if site == "table" {
				held = fleetFreshnessHold(t, ctx, db, query)
			} else {
				held = fleetFreshnessHold(t, ctx, db, query, s.a.InstallationID)
			}
			_ = held
			basis := s.basis(t, ctx)
			a := s.source()
			before := s.snapshot(t, ctx)
			disposition, e := s.rawObserve(ctx, basis, a)
			if site == "authority" {
				if e != nil || disposition != 3 {
					t.Fatal("exact semantic row abort not classified", disposition, e)
				}
			} else {
				var pg *pgconn.PgError
				if !errors.As(e, &pg) || pg.Code != "55P03" {
					t.Fatal("other lock site acquired authority contention exception", site, disposition, e)
				}
			}
			if s.snapshot(t, ctx) != before {
				t.Fatal("lock abort changed durable authority or observation")
			}
		})
	}
	t.Run("adapter-confirms-only-unchanged-authority-contention", func(t *testing.T) {
		s := lab.setup(t, ctx, true)
		fleetFreshnessHold(t, ctx, db, "SELECT installation_id FROM fleet_trust WHERE installation_id=$1 FOR UPDATE", s.a.InstallationID)
		basis := s.basis(t, ctx)
		before := s.snapshot(t, ctx)
		if e := s.observer.ObserveAdministration(ctx, basis, s.source()); !errors.Is(e, fleet.ErrObservationPersistenceContended) {
			t.Fatal("actual adapter lost exact unchanged contention classification", e)
		}
		if s.snapshot(t, ctx) != before {
			t.Fatal("classified aborted observation mutated SQL")
		}
	})
	t.Run("original-basis-expiry-survives-lock-wait", func(t *testing.T) {
		s := lab.setup(t, ctx, true)
		held := fleetFreshnessHold(t, ctx, db, "SELECT installation_id FROM fleet_trust WHERE installation_id=$1 FOR UPDATE", s.a.InstallationID)
		positive, stop := context.WithTimeout(ctx, 350*time.Millisecond)
		basis := s.basis(t, positive)
		stop()
		a := s.source()
		before := s.snapshot(t, ctx)
		pid := fleetFreshnessPID(t, ctx, pools["observe"])
		call := fleetFreshnessStart(t, ctx, func(c context.Context) error { return s.observer.ObserveAdministration(c, basis, a) })
		fleetFreshnessBlocked(t, ctx, db, pid, held.pid)
		fleetFreshnessWait(t, ctx, basis.FreshUntil)
		held.close(t)
		if e := call.join(); e == nil || errors.Is(e, fleet.ErrObservationPersistenceContended) {
			t.Fatal("expired original basis became successful/benign contention", e)
		}
		if s.snapshot(t, ctx) != before {
			t.Fatal("expired waiter persisted an observation")
		}
		current := s.basis(t, ctx)
		if e := s.observer.ObserveAdministration(ctx, current, s.source()); e != nil {
			t.Fatal("independent fresh observation failed", e)
		}
		before = s.snapshot(t, ctx)
		if e := s.observer.ObserveAdministration(ctx, basis, a); e == nil {
			t.Fatal("new observation rescued the original expired basis")
		}
		if s.snapshot(t, ctx) != before {
			t.Fatal("expired original request changed the newer observation")
		}
	})
	t.Run("expired-positive-basis-still-fences-original-semantic-root", func(t *testing.T) {
		s := lab.setup(t, ctx, true)
		positive, stop := context.WithTimeout(ctx, 250*time.Millisecond)
		basis := s.basis(t, positive)
		stop()
		started := time.Now().UTC().Truncate(time.Microsecond)
		fleetFreshnessWait(t, ctx, basis.FreshUntil)
		if e := s.observer.ObserveAdministration(ctx, basis, s.source()); e == nil {
			t.Fatal("expired positive basis renewed authority")
		}
		if e := s.observer.FenceAdministration(ctx, basis, started); e != nil {
			t.Fatal("expired positive basis prevented restrictive original fence", e)
		}
		if s.basis(t, ctx).SemanticVersion != basis.SemanticVersion+1 {
			t.Fatal("restrictive fence not recorded")
		}
		s.requireUnavailable(t, ctx)
	})
	t.Run("aba-and-repeated-fence-never-revive-old-basis", func(t *testing.T) {
		s := lab.setup(t, ctx, true)
		original := s.basis(t, ctx)
		if e := s.observer.FenceAdministration(ctx, original, time.Now()); e != nil {
			t.Fatal(e)
		}
		blocked := s.basis(t, ctx)
		if e := s.observer.FenceAdministration(ctx, blocked, time.Now()); e != nil {
			t.Fatal(e)
		}
		repeated := s.basis(t, ctx)
		if repeated.SemanticVersion != original.SemanticVersion+2 {
			t.Fatal("repeated suspension did not consume a new version")
		}
		if e := s.observer.ObserveAdministration(ctx, repeated, s.source()); e != nil {
			t.Fatal("independent current source could not restore ordinary observation", e)
		}
		restored := s.basis(t, ctx)
		if restored.SemanticVersion != repeated.SemanticVersion+1 {
			t.Fatal("unsuspension did not advance version")
		}
		before := s.snapshot(t, ctx)
		if e := s.observer.ObserveAdministration(ctx, original, s.source()); e == nil {
			t.Fatal("ABA adopted an original basis")
		}
		if e := s.observer.FenceAdministration(ctx, original, time.Now()); e != nil {
			t.Fatal("stale restrictive call should be a harmless no-op", e)
		}
		if s.snapshot(t, ctx) != before {
			t.Fatal("old basis changed restored authority")
		}
	})
	t.Run("runtime-cannot-write-base-or-positive-row", func(t *testing.T) {
		s := lab.setup(t, ctx, true)
		for _, query := range []string{
			"UPDATE fleet_trust SET fresh_until=fresh_until WHERE installation_id=$1",
			"UPDATE fleet_trust SET semantic_version=semantic_version+1 WHERE installation_id=$1",
			"UPDATE fleet_observation SET fresh_until=clock_timestamp()+interval '1 second' WHERE installation_id=$1",
			"DELETE FROM fleet_observation WHERE installation_id=$1",
		} {
			_, e := pools["observe"].Exec(ctx, query, s.a.InstallationID)
			var pg *pgconn.PgError
			if !errors.As(e, &pg) || pg.Code != "42501" {
				t.Fatal("observer direct-write denial changed", e)
			}
		}
	})
}

type fleetFreshnessLab struct {
	db      *pgxpool.Pool
	pools   map[string]*pgxpool.Pool
	objects *objectstore.InitialInstallationObjects
}
type fleetFreshnessScenario struct {
	*fleetFreshnessLab
	a                                         fleet.Administration
	witness                                   *initialWitnessFixture
	preparation, acknowledgements, activation *postgres.InitialInstallations
	observer                                  *postgres.FleetObservation
}

func (l *fleetFreshnessLab) setup(t *testing.T, ctx context.Context, activate bool) *fleetFreshnessScenario {
	t.Helper()
	scope := fleet.InstallationWitnessScope{InstallationID: custodyID(), IssuerEpoch: custodyID(), ClusterID: custodyID(), Namespace: "synthetic-freshness", NamespaceUID: custodyID(), Name: "witness", UID: custodyID(), WriterAccount: "installer", WriterAccountUID: custodyID()}
	s := &fleetFreshnessScenario{fleetFreshnessLab: l, witness: &initialWitnessFixture{scope: scope}, a: fleet.Administration{InstallationID: scope.InstallationID, IssuerEpoch: scope.IssuerEpoch, Issuer: "https://identity.invalid", Revision: identity.Revision{UID: "synthetic-fleet-source", Generation: 1, Digest: artifact.Digest{1}}, Clients: []string{"console"}, Groups: []string{"operators"}, DeliveryProfiles: []string{"ops"}, MaxActiveBootstraps: 8, MaxBootstrapHistory: 16, MaxClusters: 16}}
	var e error
	for name, dst := range map[string]**postgres.InitialInstallations{"prepare": &s.preparation, "audit": &s.acknowledgements, "activate": &s.activation} {
		*dst, e = postgres.NewInitialInstallations(ctx, l.pools[name], scope, artifact.Digest{2})
		if e != nil {
			t.Fatal(e)
		}
	}
	s.observer, e = postgres.NewFleetObservation(ctx, l.pools["observe"], scope.InstallationID)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		for _, table := range []string{"fleet_observation", "fleet_initial_activation", "fleet_trust"} {
			if _, e := l.db.Exec(cleanup, "DELETE FROM "+pgx.Identifier{table}.Sanitize()+" WHERE installation_id=$1", scope.InstallationID); e != nil {
				t.Error("owned scenario cleanup", e)
			}
		}
	})
	if activate {
		s.prepare(t, ctx)
		w, _ := s.witness.ReadInstallationWitness(ctx)
		if e = s.activation.ActivateInitialInstallation(ctx, w, s.source()); e != nil {
			t.Fatal("actual initial activation", e)
		}
		reader, err := postgres.NewRecoveryReader(ctx, s.pools["observe"], s.a.InstallationID)
		if err != nil {
			t.Fatal(err)
		}
		if current, err := reader.RecoveryState(ctx); err != nil || current.InstallationID != s.a.InstallationID || current.Revision != s.a.Revision {
			t.Fatal("actual scoped positive recovery read", err)
		}
	}
	return s
}
func (s *fleetFreshnessScenario) source() fleet.Administration {
	a := s.a
	a.ObservedAt = time.Now().UTC().Truncate(time.Microsecond)
	a.FreshUntil = a.ObservedAt.Add(5 * time.Second)
	return a
}
func (s *fleetFreshnessScenario) prepare(t *testing.T, ctx context.Context) {
	t.Helper()
	w, _ := s.witness.ReadInstallationWitness(ctx)
	r, e := s.preparation.PrepareInitialInstallation(ctx, w, s.source())
	if e != nil {
		t.Fatal("actual preparation", e)
	}
	if _, e = s.witness.ConsumeInstallationWitness(ctx, r.Claim); e != nil {
		t.Fatal(e)
	}
	receipt, e := s.objects.WriteInitialInstallation(ctx, r)
	if e != nil {
		t.Fatal("encrypted versioned initial audit", e)
	}
	if e = s.acknowledgements.AcknowledgeInitialInstallation(ctx, r, receipt); e != nil {
		t.Fatal("actual initial audit acknowledgement", e)
	}
	s.requireObservationCount(t, ctx, 0)
}
func (s *fleetFreshnessScenario) basis(t *testing.T, ctx context.Context) fleet.ObservationBasis {
	t.Helper()
	b, e := s.observer.ReadAdministrationBasis(ctx)
	if e != nil {
		t.Fatal("original SQL basis", e)
	}
	return b
}
func (s *fleetFreshnessScenario) requireObservationCount(t *testing.T, ctx context.Context, want int) {
	t.Helper()
	var n int
	if e := s.db.QueryRow(ctx, "SELECT count(*) FROM fleet_observation WHERE installation_id=$1", s.a.InstallationID).Scan(&n); e != nil || n != want {
		t.Fatal("positive record count", n, want, e)
	}
}
func (s *fleetFreshnessScenario) requireUnavailable(t *testing.T, ctx context.Context) {
	t.Helper()
	reader, e := postgres.NewRecoveryReader(ctx, s.pools["observe"], s.a.InstallationID)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = reader.RecoveryState(ctx); !errors.Is(e, fleet.ErrUnavailable) {
		t.Fatal("blocked observation did not return unavailable", e)
	}
}
func (s *fleetFreshnessScenario) snapshot(t *testing.T, ctx context.Context) string {
	t.Helper()
	var out string
	if e := s.db.QueryRow(ctx, `SELECT jsonb_build_object('semantic',to_jsonb(t),'observation',(SELECT to_jsonb(o) FROM fleet_observation o WHERE o.installation_id=t.installation_id))::text FROM fleet_trust t WHERE installation_id=$1`, s.a.InstallationID).Scan(&out); e != nil {
		t.Fatal(e)
	}
	return out
}
func (s *fleetFreshnessScenario) rawObserve(ctx context.Context, b fleet.ObservationBasis, a fleet.Administration) (int, error) {
	tx, e := s.pools["observe"].Begin(ctx)
	if e != nil {
		return 0, e
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), time.Second)
		defer stop()
		_ = tx.Rollback(cleanup)
	}()
	if _, e = tx.Exec(ctx, "SET LOCAL statement_timeout='5s'; SET LOCAL lock_timeout='1s'; SET LOCAL idle_in_transaction_session_timeout='5s'"); e != nil {
		return 0, e
	}
	var disposition int
	e = tx.QueryRow(ctx, fleetFreshnessObserveSQL, a.InstallationID, b.SemanticVersion, b.Database.StartedAt, b.Database.DatabaseOID, b.FreshUntil, a.IssuerEpoch, a.Revision.UID, a.Revision.Generation, a.Revision.Digest[:], a.Suspended, a.ObservedAt, a.FreshUntil).Scan(&disposition)
	if e == nil {
		e = tx.Commit(ctx)
	}
	return disposition, e
}

type fleetFreshnessLock struct {
	tx         pgx.Tx
	connection *pgxpool.Conn
	pid        uint32
	once       sync.Once
}

func fleetFreshnessHold(t *testing.T, ctx context.Context, pool *pgxpool.Pool, query string, args ...any) *fleetFreshnessLock {
	t.Helper()
	c, e := pool.Acquire(ctx)
	if e != nil {
		t.Fatal(e)
	}
	h := &fleetFreshnessLock{connection: c, pid: c.Conn().PgConn().PID()}
	t.Cleanup(func() { h.close(t) })
	h.tx, e = c.Begin(ctx)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = h.tx.Exec(ctx, "SET LOCAL statement_timeout='5s'; SET LOCAL lock_timeout='1s'; SET LOCAL idle_in_transaction_session_timeout='5s'"); e != nil {
		t.Fatal(e)
	}
	if _, e = h.tx.Exec(ctx, query, args...); e != nil {
		t.Fatal("original fixture lock", e)
	}
	return h
}
func (h *fleetFreshnessLock) close(t *testing.T) {
	t.Helper()
	h.once.Do(func() {
		if h.tx != nil {
			ctx, stop := context.WithTimeout(context.Background(), time.Second)
			defer stop()
			if e := h.tx.Rollback(ctx); e != nil && !errors.Is(e, pgx.ErrTxClosed) {
				t.Error("owned blocker rollback", e)
			}
		}
		h.connection.Release()
	})
}

type fleetFreshnessCall struct {
	cancel context.CancelFunc
	done   chan error
	once   sync.Once
	err    error
}

func fleetFreshnessStart(t *testing.T, parent context.Context, fn func(context.Context) error) *fleetFreshnessCall {
	t.Helper()
	ctx, cancel := context.WithTimeout(parent, 5*time.Second)
	c := &fleetFreshnessCall{cancel: cancel, done: make(chan error, 1)}
	go func() { c.done <- fn(ctx) }()
	t.Cleanup(func() { c.cancel(); c.join() })
	return c
}
func (c *fleetFreshnessCall) join() error {
	c.once.Do(func() { c.err = <-c.done; c.cancel() })
	return c.err
}
func fleetFreshnessPID(t *testing.T, ctx context.Context, p *pgxpool.Pool) uint32 {
	t.Helper()
	var pid uint32
	if e := p.QueryRow(ctx, "SELECT pg_backend_pid()").Scan(&pid); e != nil {
		t.Fatal(e)
	}
	return pid
}
func fleetFreshnessBlocked(t *testing.T, parent context.Context, db *pgxpool.Pool, pid, blocker uint32) {
	t.Helper()
	ctx, stop := context.WithTimeout(parent, time.Second)
	defer stop()
	tick := time.NewTicker(5 * time.Millisecond)
	defer tick.Stop()
	for {
		var yes bool
		if e := db.QueryRow(ctx, "SELECT $2::integer=ANY(pg_catalog.pg_blocking_pids($1::integer))", pid, blocker).Scan(&yes); e != nil {
			t.Fatal("actual PostgreSQL blocker unavailable", e)
		}
		if yes {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatal("expected original PostgreSQL blocker absent", pid, blocker)
		case <-tick.C:
		}
	}
}
func fleetFreshnessWait(t *testing.T, ctx context.Context, until time.Time) {
	t.Helper()
	timer := time.NewTimer(time.Until(until.Add(time.Millisecond)))
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
}

func fleetFreshnessAuditObjects(t *testing.T, ctx context.Context, f fixture) *objectstore.InitialInstallationObjects {
	t.Helper()
	bridge := tlsBridge(t, f.S3)
	creds := credentials.NewStaticCredentialsProvider("synthetic-only", "synthetic-only-secret", "")
	bucket := "fleet-freshness-" + strings.ReplaceAll(custodyID(), "-", "")
	client := s3.New(s3.Options{Region: "us-east-1", BaseEndpoint: aws.String(bridge.URL), UsePathStyle: true, Credentials: creds, HTTPClient: bridge.Client()})
	if _, e := client.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: &bucket}); e != nil {
		t.Fatal(e)
	}
	if _, e := client.PutBucketVersioning(ctx, &s3.PutBucketVersioningInput{Bucket: &bucket, VersioningConfiguration: &s3types.VersioningConfiguration{Status: s3types.BucketVersioningStatusEnabled}}); e != nil {
		t.Fatal(e)
	}
	store, e := objectstore.New(bridge.URL, "us-east-1", bucket, creds, bridge.Client())
	if e != nil {
		t.Fatal(e)
	}
	block, e := aes.NewCipher(make([]byte, 32))
	if e != nil {
		t.Fatal(e)
	}
	aead, e := cipher.NewGCM(block)
	if e != nil {
		t.Fatal(e)
	}
	keys := authorityTestKeys{a: aead}
	return &objectstore.InitialInstallationObjects{Store: store, Seal: keys, Open: keys}
}

func qualifyFleetFreshnessMigrationACLs(t *testing.T, ctx context.Context, db *pgxpool.Pool, migration []byte) {
	t.Run("migration-fences-existing-root-without-observation-backfill", func(t *testing.T) {
		tx, err := db.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() {
			cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
			defer stop()
			if e := tx.Rollback(cleanup); e != nil && !errors.Is(e, pgx.ErrTxClosed) {
				t.Error(e)
			}
		}()
		installation := custodyID()
		// Explicit synthetic legacy row, used only to demonstrate restrictive
		// upgrade behavior. It never supplies positive schema59 authority.
		if _, err = tx.Exec(ctx, `INSERT INTO fleet_trust(installation_id,issuer_epoch,source_uid,source_generation,source_digest,suspended,recovery_blocked,activated_postmaster_at,activated_database_oid,observed_at,fresh_until) VALUES($1,$2,'synthetic-legacy-source',1,$3,false,false,pg_postmaster_start_time(),(SELECT oid FROM pg_database WHERE datname=current_database()),clock_timestamp(),clock_timestamp()+interval '5 seconds')`, installation, custodyID(), make([]byte, 32)); err != nil {
			t.Fatal(err)
		}
		if _, err = tx.Exec(ctx, string(migration)); err != nil {
			t.Fatal("actual upgrade migration", err)
		}
		var fenced bool
		if err = tx.QueryRow(ctx, `SELECT t.semantic_version=2 AND t.suspended AND t.recovery_blocked AND v.recovery_blocked AND v.fresh_until='epoch'::timestamptz AND NOT EXISTS(SELECT FROM fleet_observation) FROM fleet_trust t JOIN fleet_current_trust v USING(installation_id) WHERE t.installation_id=$1`, installation).Scan(&fenced); err != nil || !fenced {
			t.Fatal("upgrade adopted legacy dates or fabricated positive observation", err)
		}
	})
	for _, mode := range []string{"legacy-table", "legacy-column", "legacy-public", "legacy-inherited", "legacy-trigger", "legacy-references", "retained-trigger", "retained-foreign-key", "global-writer-member", "default-table", "default-trigger", "default-references", "default-function"} {
		t.Run("migration-refuses-"+mode, func(t *testing.T) {
			tx, e := db.Begin(ctx)
			if e != nil {
				t.Fatal(e)
			}
			defer func() {
				cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
				defer stop()
				if e := tx.Rollback(cleanup); e != nil && !errors.Is(e, pgx.ErrTxClosed) {
					t.Error(e)
				}
			}()
			role := "fleet_acl_" + strings.ReplaceAll(custodyID(), "-", "")
			unrelated := role + "_other"
			exec := func(sql string) {
				t.Helper()
				if _, e := tx.Exec(ctx, sql); e != nil {
					t.Fatal("migration ACL setup", e)
				}
			}
			exec("CREATE ROLE " + pgx.Identifier{role}.Sanitize() + " NOLOGIN")
			exec("CREATE ROLE " + pgx.Identifier{unrelated}.Sanitize() + " NOLOGIN")
			exec("GRANT SELECT ON fleet_trust TO " + pgx.Identifier{unrelated}.Sanitize())
			switch mode {
			case "legacy-table":
				exec("GRANT INSERT,UPDATE ON fleet_trust TO " + pgx.Identifier{role}.Sanitize())
			case "legacy-column":
				exec("GRANT UPDATE(observed_at,fresh_until) ON fleet_trust TO " + pgx.Identifier{role}.Sanitize())
			case "legacy-public":
				exec("GRANT UPDATE(fresh_until) ON fleet_trust TO PUBLIC")
			case "legacy-inherited":
				exec("GRANT UPDATE(source_generation) ON fleet_trust TO " + pgx.Identifier{role}.Sanitize())
				exec("GRANT " + pgx.Identifier{role}.Sanitize() + " TO " + pgx.Identifier{unrelated}.Sanitize())
			case "legacy-trigger":
				exec("GRANT TRIGGER ON fleet_trust TO " + pgx.Identifier{role}.Sanitize())
			case "legacy-references":
				exec("GRANT REFERENCES(installation_id) ON fleet_trust TO " + pgx.Identifier{role}.Sanitize())
			case "retained-trigger":
				exec("GRANT USAGE,CREATE ON SCHEMA public TO " + pgx.Identifier{role}.Sanitize())
				exec("GRANT TRIGGER ON fleet_trust TO " + pgx.Identifier{role}.Sanitize())
				exec("SET LOCAL ROLE " + pgx.Identifier{role}.Sanitize())
				exec("CREATE FUNCTION " + pgx.Identifier{"public", role + "_fn"}.Sanitize() + "() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RETURN NEW; END$$")
				exec("CREATE TRIGGER " + pgx.Identifier{role + "_hook"}.Sanitize() + " BEFORE UPDATE ON public.fleet_trust FOR EACH ROW EXECUTE FUNCTION " + pgx.Identifier{"public", role + "_fn"}.Sanitize() + "()")
				exec("RESET ROLE")
				exec("REVOKE TRIGGER ON fleet_trust FROM " + pgx.Identifier{role}.Sanitize())
			case "retained-foreign-key":
				exec("GRANT USAGE,CREATE ON SCHEMA public TO " + pgx.Identifier{role}.Sanitize())
				exec("GRANT REFERENCES(installation_id) ON fleet_trust TO " + pgx.Identifier{role}.Sanitize())
				exec("SET LOCAL ROLE " + pgx.Identifier{role}.Sanitize())
				exec("CREATE TABLE " + pgx.Identifier{"public", role + "_child"}.Sanitize() + "(installation_id uuid REFERENCES public.fleet_trust(installation_id))")
				exec("RESET ROLE")
				exec("REVOKE REFERENCES(installation_id) ON fleet_trust FROM " + pgx.Identifier{role}.Sanitize())
			case "global-writer-member":
				exec("GRANT pg_write_all_data TO " + pgx.Identifier{role}.Sanitize())
			case "default-table":
				exec("ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT INSERT,UPDATE ON TABLES TO " + pgx.Identifier{role}.Sanitize())
			case "default-trigger":
				exec("ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT TRIGGER ON TABLES TO " + pgx.Identifier{role}.Sanitize())
			case "default-references":
				exec("ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT REFERENCES ON TABLES TO " + pgx.Identifier{role}.Sanitize())
			case "default-function":
				exec("ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT EXECUTE ON FUNCTIONS TO " + pgx.Identifier{role}.Sanitize())
			}
			snapshot := func() string {
				t.Helper()
				var out string
				if e := tx.QueryRow(ctx, `SELECT jsonb_build_object('table',(SELECT relacl::text FROM pg_class WHERE oid='public.fleet_trust'::regclass),'columns',(SELECT jsonb_agg(ARRAY[attname,attacl::text] ORDER BY attnum) FROM pg_attribute WHERE attrelid='public.fleet_trust'::regclass),'roles',(SELECT jsonb_agg(to_jsonb(r) ORDER BY oid) FROM pg_roles r WHERE rolname=ANY($1)),'members',(SELECT jsonb_agg(to_jsonb(m) ORDER BY roleid,member) FROM pg_auth_members m WHERE roleid IN (SELECT oid FROM pg_roles WHERE rolname=ANY($1)) OR member IN (SELECT oid FROM pg_roles WHERE rolname=ANY($1))),'defaults',(SELECT jsonb_agg(to_jsonb(d) ORDER BY oid) FROM pg_default_acl d),'triggers',(SELECT jsonb_agg(to_jsonb(g) ORDER BY oid) FROM pg_trigger g WHERE tgrelid='public.fleet_trust'::regclass),'references',(SELECT jsonb_agg(to_jsonb(c) ORDER BY oid) FROM pg_constraint c WHERE confrelid='public.fleet_trust'::regclass),'owned-relations',(SELECT jsonb_agg(to_jsonb(c) ORDER BY oid) FROM pg_class c WHERE relowner IN (SELECT oid FROM pg_roles WHERE rolname=ANY($1))))::text`, []string{role, unrelated}).Scan(&out); e != nil {
					t.Fatal(e)
				}
				return out
			}
			before := snapshot()
			exec("SAVEPOINT migration59")
			_, e = tx.Exec(ctx, string(migration))
			var pg *pgconn.PgError
			expected := "fleet observation migration requires retirement of existing direct fleet writer grants"
			if mode == "global-writer-member" {
				expected = "fleet observation migration requires retirement of global runtime writer membership"
			}
			if strings.HasPrefix(mode, "default-") {
				expected = "fleet observation migration rejects runtime authority from default privileges"
			}
			if strings.HasPrefix(mode, "retained-") {
				expected = "fleet observation migration requires retirement of untrusted fleet hooks"
			}
			if !errors.As(e, &pg) || pg.Code != "55000" || pg.Message != expected {
				t.Fatal("migration did not refuse the actual surviving writer prerequisite", mode, e)
			}
			exec("ROLLBACK TO SAVEPOINT migration59")
			if snapshot() != before {
				t.Fatal("rejected migration changed unrelated roles or existing grants")
			}
			var unchanged bool
			if e := tx.QueryRow(ctx, `SELECT to_regclass('public.fleet_observation') IS NULL AND NOT EXISTS(SELECT FROM pg_attribute WHERE attrelid='public.fleet_trust'::regclass AND attname='semantic_version') AND (SELECT version_id=58 AND is_applied FROM goose_db_version ORDER BY id DESC LIMIT 1)`).Scan(&unchanged); e != nil || !unchanged {
				t.Fatal("failed migration changed schema/history", e)
			}
			t.Log("actual migration59 refusal", mode, "SQLSTATE", pg.Code)
		})
	}
	t.Run("migration-preserves-unrelated-reader-and-lock-grants", func(t *testing.T) {
		tx, err := db.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() {
			cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
			defer stop()
			if e := tx.Rollback(cleanup); e != nil && !errors.Is(e, pgx.ErrTxClosed) {
				t.Error(e)
			}
		}()
		role := "fleet_reader_" + strings.ReplaceAll(custodyID(), "-", "")
		for _, sql := range []string{
			"CREATE ROLE " + pgx.Identifier{role}.Sanitize() + " NOLOGIN",
			"GRANT SELECT ON fleet_trust,fleet_current_trust TO " + pgx.Identifier{role}.Sanitize(),
			"GRANT UPDATE(installation_id) ON fleet_trust,fleet_current_trust TO " + pgx.Identifier{role}.Sanitize(),
		} {
			if _, err = tx.Exec(ctx, sql); err != nil {
				t.Fatal(err)
			}
		}
		var original uint32
		if err = tx.QueryRow(ctx, "SELECT oid FROM pg_roles WHERE rolname=$1", role).Scan(&original); err != nil {
			t.Fatal(err)
		}
		if _, err = tx.Exec(ctx, string(migration)); err != nil {
			t.Fatal("migration rejected unrelated reader/row-lock grants", err)
		}
		var retained bool
		if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT FROM pg_roles WHERE oid=$1 AND rolname=$2) AND has_table_privilege($1,'public.fleet_trust','SELECT') AND has_table_privilege($1,'public.fleet_current_trust','SELECT') AND has_column_privilege($1,'public.fleet_trust','installation_id','UPDATE') AND has_column_privilege($1,'public.fleet_current_trust','installation_id','UPDATE') AND NOT has_column_privilege($1,'public.fleet_trust','fresh_until','UPDATE') AND NOT has_table_privilege($1,'public.fleet_observation','INSERT')`, original, role).Scan(&retained); err != nil || !retained {
			t.Fatal("migration replaced role or rewrote unrelated privileges", err)
		}
	})
}
