package integration

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/postgres"
	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
	fleet "asservat.local/asservat/internal/domain/fleet"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Explicit synthetic Secret/CAS side for the real SQL matrix. The actual native
// protected Secret adapter needs separate qualification; this fixture is never an
// installed producer, namespace guard or grant of current recovery authority.
type publicRoleSQLRoot struct {
	mu                     sync.Mutex
	value                  contracts.PublicRuntimeRoleSnapshot
	lostClaim, lostReceipt bool
	claims, receipts       int
	beforeClaim            func()
}

func (r *publicRoleSQLRoot) snapshot(ctx context.Context) contracts.PublicRuntimeRoleSnapshot {
	b, _ := json.Marshal(r.value)
	defer clear(b)
	var v contracts.PublicRuntimeRoleSnapshot
	_ = json.Unmarshal(b, &v)
	n := time.Now().UTC().Truncate(time.Microsecond)
	v.ObservedAt, v.ValidUntil = n, n.Add(5*time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(v.ValidUntil) {
		v.ValidUntil = d
	}
	return v
}
func (r *publicRoleSQLRoot) OpenPublicRuntimeRoles(ctx context.Context) (contracts.PublicRuntimeRoleSnapshot, error) {
	return r.ReadPublicRuntimeRoles(ctx)
}
func (r *publicRoleSQLRoot) ReadPublicRuntimeRoles(ctx context.Context) (contracts.PublicRuntimeRoleSnapshot, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if ctx.Err() != nil {
		return contracts.PublicRuntimeRoleSnapshot{}, ctx.Err()
	}
	return r.snapshot(ctx), nil
}
func (r *publicRoleSQLRoot) ClaimPublicRuntimeRole(ctx context.Context, purpose string, db uint32, postmaster time.Time) (contracts.PublicRuntimeRoleSnapshot, bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if ctx.Err() != nil {
		return contracts.PublicRuntimeRoleSnapshot{}, false, ctx.Err()
	}
	for i := range r.value.State.Roles {
		role := &r.value.State.Roles[i]
		if role.Purpose != purpose {
			continue
		}
		if role.Claim != nil {
			return r.snapshot(ctx), false, nil
		}
		n := time.Now().UTC().Truncate(time.Microsecond)
		until := n.Add(5 * time.Second)
		if d, ok := ctx.Deadline(); ok && d.Before(until) {
			until = d
		}
		if r.value.State.Until.Before(until) {
			until = r.value.State.Until
		}
		until = until.Truncate(time.Microsecond)
		if !n.Before(until) {
			return contracts.PublicRuntimeRoleSnapshot{}, false, cfg.ErrUnavailable
		}
		role.Claim = asStored(&contracts.PublicRuntimeRoleClaim{OperationID: custodyID(), ClaimedAt: n, Until: until, DatabaseOID: db, PostmasterAt: postmaster})
		r.claims++
		if r.beforeClaim != nil {
			r.beforeClaim()
			r.beforeClaim = nil
		}
		if r.lostClaim {
			r.lostClaim = false
			return contracts.PublicRuntimeRoleSnapshot{}, false, cfg.ErrUnavailable
		}
		return r.snapshot(ctx), true, nil
	}
	return contracts.PublicRuntimeRoleSnapshot{}, false, cfg.ErrInvalid
}
func (r *publicRoleSQLRoot) CompletePublicRuntimeRole(ctx context.Context, original contracts.PublicRuntimeRoleSnapshot, purpose string, receipt contracts.PublicRuntimeRoleReceipt) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if r.lostReceipt {
		r.lostReceipt = false
		return cfg.ErrUnavailable
	}
	for i := range r.value.State.Roles {
		role := &r.value.State.Roles[i]
		if role.Purpose != purpose {
			continue
		}
		if role.Claim == nil || original.State.Roles[i].Claim == nil || *role.Claim != *original.State.Roles[i].Claim {
			return cfg.ErrChanged
		}
		if role.Receipt != nil {
			if *role.Receipt != receipt {
				return cfg.ErrChanged
			}
			return nil
		}
		r.receipts++
		role.Receipt = &receipt
		return nil
	}
	return cfg.ErrInvalid
}
func newPublicRoleSQLRoot(t *testing.T, input contracts.PublicRuntimeRoles) *publicRoleSQLRoot {
	t.Helper()
	n := time.Now().UTC().Truncate(time.Microsecond)
	r := &publicRoleSQLRoot{value: contracts.PublicRuntimeRoleSnapshot{State: contracts.PublicRuntimeRoleState{Format: contracts.PublicRuntimeRoleStateFormat, Input: input, OperationID: custodyID(), CreatedAt: n, Until: n.Add(30 * time.Minute)}, UID: custodyID(), ResourceVersion: "1"}}
	for _, p := range contracts.PublicRuntimeRolePurposes() {
		b := make([]byte, 32)
		if _, e := rand.Read(b); e != nil {
			t.Fatal(e)
		}
		r.value.State.Roles = append(r.value.State.Roles, contracts.PublicRuntimeRoleMaterial{Purpose: p, Password: base64.RawURLEncoding.EncodeToString(b)})
		clear(b)
	}
	return r
}
func publicRoleTLSConfig(t *testing.T, admin *pgxpool.Pool, address string, tlsConfig *tls.Config) *pgx.ConnConfig {
	t.Helper()
	c := admin.Config().ConnConfig.Copy()
	host, port, e := net.SplitHostPort(address)
	if e != nil {
		t.Fatal(e)
	}
	number, e := strconv.Atoi(port)
	if e != nil {
		t.Fatal(e)
	}
	c.Host, c.Port = host, uint16(number)
	c.TLSConfig = tlsConfig.Clone()
	c.TLSConfig.MinVersion = tls.VersionTLS13
	c.Fallbacks = nil
	c.ValidateConnect = nil
	c.AfterConnect = nil
	c.Tracer = nil
	return c
}

// The caller creates the original installation through InitialInstaller + real
// SQL/S3/KMS audit. Only its existing explicitly synthetic witness/source facts
// are reused here; no fixture UPDATE clears a recovery fence for this producer.
func qualifyPublicRuntimeRoles(t *testing.T, ctx context.Context, admin *pgxpool.Pool, address string, tlsConfig *tls.Config, scope fleet.InstallationWitnessScope, claim string, a fleet.Administration, mode string) {
	t.Helper()
	input := contracts.PublicRuntimeRoles{Format: contracts.PublicRuntimeRolesFormat, InstallationID: scope.InstallationID, InitialClaimID: claim, OwnerConfigurationUID: custodyID(), ClusterID: scope.ClusterID, Namespace: contracts.WorkerObjectReference{Name: scope.Namespace, UID: scope.NamespaceUID}, LayoutDigest: postgres.PublicRuntimeRoleLayoutDigest()}
	root := newPublicRoleSQLRoot(t, input)
	c := publicRoleTLSConfig(t, admin, address, tlsConfig)
	observerName := "public_role_observer_" + strings.ReplaceAll(custodyID(), "-", "")
	qname := pgx.Identifier{observerName}.Sanitize()
	// Match the production configuration observer's column-scoped recovery-lock
	// permission. SELECT FOR UPDATE on the view requires this even though the
	// observation never changes installation identity or recovery authority.
	if _, e := admin.Exec(ctx, "CREATE ROLE "+qname+" LOGIN PASSWORD 'synthetic-observer'; GRANT USAGE ON SCHEMA public TO "+qname+"; GRANT SELECT ON goose_db_version,fleet_trust,fleet_current_trust TO "+qname+"; GRANT UPDATE(installation_id) ON fleet_current_trust TO "+qname+"; GRANT EXECUTE ON FUNCTION observe_fleet_administration(uuid,bigint,timestamptz,oid,timestamptz,uuid,text,bigint,bytea,boolean,timestamptz,timestamptz),fence_fleet_observation(uuid,bigint,timestamptz,oid,timestamptz),reactivate_restarted_database(uuid) TO "+qname); e != nil {
		t.Fatal(e)
	}
	observerConfig, e := pgxpool.ParseConfig("")
	if e != nil {
		t.Fatal(e)
	}
	observerConfig.ConnConfig = c.Copy()
	observerConfig.ConnConfig.User, observerConfig.ConnConfig.Password = observerName, "synthetic-observer"
	observerConfig.MaxConns = 1
	observerConfig.MinConns = 0
	observerPool, e := pgxpool.NewWithConfig(ctx, observerConfig)
	if e != nil {
		t.Fatal(e)
	}
	observer, e := postgres.NewFleetObservation(ctx, observerPool, scope.InstallationID)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		observerPool.Close()
		clean, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		for _, purpose := range append(contracts.PublicRuntimeRolePurposes(), "fixture-observer") {
			name := observerName
			if purpose != "fixture-observer" {
				name, _ = postgres.PublicRuntimeRoleName(scope.InstallationID, purpose)
			}
			var exists bool
			if e := admin.QueryRow(clean, "SELECT EXISTS(SELECT 1 FROM pg_roles WHERE rolname=$1)", name).Scan(&exists); e != nil {
				t.Error(e)
				continue
			}
			if exists {
				qn := pgx.Identifier{name}.Sanitize()
				if _, e := admin.Exec(clean, "DROP OWNED BY "+qn+"; DROP ROLE "+qn); e != nil {
					t.Error(e)
				}
			}
		}
	})
	refresh := func() {
		a.ObservedAt = time.Now().UTC().Truncate(time.Microsecond)
		a.FreshUntil = a.ObservedAt.Add(5 * time.Second)
		if e := observer.ObserveAdministration(ctx, fleetBasisFixture(t, ctx, observer), a); e != nil {
			t.Fatal("current synthetic source observation", e)
		}
	}
	refresh()
	for _, query := range []string{
		"UPDATE fleet_trust SET recovery_blocked=false WHERE installation_id=$1",
		"UPDATE fleet_current_trust SET issuer_epoch=issuer_epoch WHERE installation_id=$1",
	} {
		if _, e := observerPool.Exec(ctx, query, scope.InstallationID); e == nil {
			t.Fatal("fixture observer gained activation or epoch authority")
		}
	}
	producer, e := postgres.NewPublicRuntimeSQLRoles(ctx, c, root, input)
	if e != nil {
		t.Fatal("post-activation constructor", e)
	}
	t.Cleanup(producer.Close)
	firstName, _ := postgres.PublicRuntimeRoleName(scope.InstallationID, "hub-runtime")
	switch mode {
	case "unknown-claim":
		root.lostClaim = true
		if _, e = producer.Provision(ctx); e == nil {
			t.Fatal("unknown claim granted SQL creation")
		}
		refresh()
		if _, e = producer.Provision(ctx); e == nil {
			t.Fatal("unknown claim retried SQL creation")
		}
		var count int
		if e = admin.QueryRow(ctx, "SELECT count(*) FROM pg_roles WHERE rolname=$1", firstName).Scan(&count); e != nil || count != 0 || root.claims != 1 {
			t.Fatal("unknown claim created role or replacement", e)
		}
		return
	case "held-lock":
		blocker, e := admin.Begin(ctx)
		if e != nil {
			t.Fatal(e)
		}
		defer blocker.Rollback(context.Background())
		if _, e = blocker.Exec(ctx, "SELECT pg_advisory_xact_lock(1095979854,hashtext($1))", scope.InstallationID); e != nil {
			t.Fatal(e)
		}
		short, cancel := context.WithTimeout(ctx, 80*time.Millisecond)
		_, e = producer.Provision(short)
		cancel()
		if e == nil {
			t.Fatal("role creation crossed original lock deadline")
		}
		if e = blocker.Rollback(ctx); e != nil {
			t.Fatal(e)
		}
		refresh()
		if _, e = producer.Provision(ctx); e == nil {
			t.Fatal("expired/spent claim restarted after lock release")
		}
		var count int
		if e = admin.QueryRow(ctx, "SELECT count(*) FROM pg_roles WHERE rolname=$1", firstName).Scan(&count); e != nil || count != 0 {
			t.Fatal("lock wait created role", e)
		}
		return
	case "recovery-after-lock":
		blocker, e := admin.Begin(ctx)
		if e != nil {
			t.Fatal(e)
		}
		defer blocker.Rollback(context.Background())
		if _, e = blocker.Exec(ctx, "UPDATE fleet_trust SET recovery_blocked=true WHERE installation_id=$1", scope.InstallationID); e != nil {
			t.Fatal(e)
		}
		claimed := make(chan struct{})
		root.beforeClaim = func() { close(claimed) }
		outcome := make(chan error, 1)
		go func() { _, e := producer.Provision(ctx); outcome <- e }()
		select {
		case <-claimed:
		case e := <-outcome:
			t.Fatal("did not reach claimed role before recovery lock", e)
		case <-time.After(time.Second):
			t.Fatal("role did not reach lock")
		}
		if e = blocker.Commit(ctx); e != nil {
			t.Fatal(e)
		}
		if e = <-outcome; e == nil {
			t.Fatal("role creation ignored post-lock recovery fence")
		}
		var count int
		if e = admin.QueryRow(ctx, "SELECT count(*) FROM pg_roles WHERE rolname=$1", firstName).Scan(&count); e != nil || count != 0 {
			t.Fatal("recovery change created role", e)
		}
		return
	case "lost-completion":
		root.lostReceipt = true
	}
	if mode == "lost-completion" {
		if _, e = producer.Provision(ctx); e == nil {
			t.Fatal("lost completion reported success")
		}
	}
	// Match production's independently observed fleet source during positive
	// complete-inventory calls. Each observation still lasts five seconds;
	// stopping joins the observer before any later fault/recovery assertions.
	provisionCurrent := func() (out contracts.PublicRuntimeRoleSnapshot, err error) {
		stop := keepFixtureFleetCurrent(ctx, observer, a)
		defer func() { err = errors.Join(err, stop()) }()
		return producer.Provision(ctx)
	}
	refresh()
	provisionStarted := time.Now()
	snapshot, e := provisionCurrent()
	if e != nil {
		// Failure-only fixture diagnostics distinguish an expired synthetic
		// fleet observation from an incomplete role inventory. They do not
		// refresh the source, retry provisioning or alter the failed interval.
		root.mu.Lock()
		claims, receipts := 0, 0
		for _, role := range root.value.State.Roles {
			if role.Claim != nil {
				claims++
			}
			if role.Receipt != nil {
				receipts++
			}
		}
		root.mu.Unlock()
		t.Logf("failed_role_provision_elapsed_ms=%d original_fleet_fresh_until=%s claims=%d receipts=%d expected=%d", time.Since(provisionStarted).Milliseconds(), a.FreshUntil.Format(time.RFC3339Nano), claims, receipts, len(contracts.PublicRuntimeRolePurposes()))
		read, cancel := context.WithTimeout(ctx, time.Second)
		var observed, fresh, current time.Time
		var suspended, blocked bool
		readErr := admin.QueryRow(read, `SELECT observed_at,fresh_until,clock_timestamp(),suspended,recovery_blocked FROM fleet_current_trust WHERE installation_id=$1`, scope.InstallationID).Scan(&observed, &fresh, &current, &suspended, &blocked)
		cancel()
		if readErr == nil {
			t.Logf("failed_role_provision_current_fleet observed_at=%s fresh_until=%s database_now=%s expired=%t suspended=%t recovery_blocked=%t", observed.Format(time.RFC3339Nano), fresh.Format(time.RFC3339Nano), current.Format(time.RFC3339Nano), !current.Before(fresh), suspended, blocked)
		} else {
			t.Log("failed_role_provision_current_fleet unavailable")
		}
		t.Fatal("provision/reconcile fixed roles", e)
	}
	var originalVerifier string
	if e = admin.QueryRow(ctx, "SELECT rolpassword FROM pg_authid WHERE rolname=$1", firstName).Scan(&originalVerifier); e != nil || !strings.HasPrefix(originalVerifier, "SCRAM-SHA-256$") {
		t.Fatal("missing SCRAM verifier")
	}
	refresh()
	again, e := provisionCurrent()
	if e != nil || root.claims != len(contracts.PublicRuntimeRolePurposes()) || again.State.OperationID != snapshot.State.OperationID {
		t.Fatal("restart renewed creation claims", e)
	}
	var unchanged bool
	if e = admin.QueryRow(ctx, "SELECT rolpassword=$2 FROM pg_authid WHERE rolname=$1", firstName, originalVerifier).Scan(&unchanged); e != nil || !unchanged {
		t.Fatal("lookup recreated password", e)
	}
	for _, role := range snapshot.State.Roles {
		current := c.Copy()
		current.User = role.Receipt.RoleName
		current.Password = role.Password
		current.RequireAuth = "scram-sha-256"
		conn, e := pgx.ConnectConfig(ctx, current)
		if e != nil {
			t.Fatal("runtime SCRAM authentication", e)
		}
		for _, statement := range []string{"UPDATE public.fleet_trust SET recovery_blocked=false", "INSERT INTO public.custody_pool(id) VALUES('10000000-0000-4000-8000-000000000001')", "CREATE TABLE public.forbidden_public_runtime(id int)"} {
			_, e = conn.Exec(ctx, statement)
			var denied *pgconn.PgError
			if !errors.As(e, &denied) || denied.Code != "42501" {
				conn.Close(ctx)
				t.Fatal("runtime role gained unrelated authority", role.Purpose, denied)
			}
		}
		qualifyPublicContextDraftRole(t, ctx, admin, conn, role.Purpose, input.InstallationID)
		if e = conn.Close(ctx); e != nil {
			t.Fatal(e)
		}
		manifest := contracts.PublicRuntimeCredentialManifest{Format: contracts.PublicRuntimeCredentialManifestFormat, Input: input, RootUID: snapshot.UID, SetupID: snapshot.State.OperationID}
		for _, r := range snapshot.State.Roles {
			// Runtime projection is deliberately narrower than the installer's
			// full inventory. Reconciler roles have their own protected manifests.
			if slices.Contains(contracts.PublicRuntimeHubRolePurposes(), r.Purpose) {
				manifest.Roles = append(manifest.Roles, contracts.PublicRuntimeCredentialProof{Purpose: r.Purpose, Claim: *r.Claim, Receipt: *r.Receipt})
			}
		}
		pc, e := pgxpool.ParseConfig("")
		if e != nil {
			t.Fatal(e)
		}
		limit, known := contracts.PublicRuntimeRolePoolLimit(role.Purpose)
		if !known {
			t.Fatal("unknown runtime pool limit", role.Purpose)
		}
		if role.Purpose == "hub-runtime" {
			limit = contracts.PublicRuntimeHubOrdinaryConnections
		}
		pc.ConnConfig, pc.MaxConns, pc.MinConns = current, int32(limit), 0
		runtime, e := pgxpool.NewWithConfig(ctx, pc)
		if e != nil {
			t.Fatal(e)
		}
		e = postgres.VerifyPublicRuntimeCredential(ctx, runtime, manifest, role.Purpose)
		if slices.Contains(contracts.PublicRuntimeHubRolePurposes(), role.Purpose) {
			if e != nil {
				runtime.Close()
				t.Fatal("runtime's own catalog/provenance check", role.Purpose, e)
			}
			// An incomplete pinned-role receipt must not be accepted even when the
			// shared credential is otherwise exact. No runtime layout adoption.
			old := manifest
			old.Roles = slices.DeleteFunc(slices.Clone(manifest.Roles), func(r contracts.PublicRuntimeCredentialProof) bool {
				return r.Purpose == "capture-intent-read" || r.Purpose == "worker-config-read"
			})
			if e = postgres.VerifyPublicRuntimeCredential(ctx, runtime, old, role.Purpose); !errors.Is(e, cfg.ErrInvalid) {
				runtime.Close()
				t.Fatal("old hub inventory accepted without original new-purpose receipts", role.Purpose, e)
			}
			changedLayout := manifest
			changedLayout.Input.LayoutDigest = strings.Repeat("0", 64)
			if e = postgres.VerifyPublicRuntimeCredential(ctx, runtime, changedLayout, role.Purpose); !errors.Is(e, cfg.ErrInvalid) {
				runtime.Close()
				t.Fatal("foreign compiled layout accepted", role.Purpose, e)
			}
			// The whole installer inventory must not become a hub projection.
			full := manifest
			full.Roles = nil
			for _, r := range snapshot.State.Roles {
				full.Roles = append(full.Roles, contracts.PublicRuntimeCredentialProof{Purpose: r.Purpose, Claim: *r.Claim, Receipt: *r.Receipt})
			}
			if e = postgres.VerifyPublicRuntimeCredential(ctx, runtime, full, role.Purpose); !errors.Is(e, cfg.ErrInvalid) {
				runtime.Close()
				t.Fatal("installer inventory accepted as hub credentials", role.Purpose, e)
			}
		} else if !errors.Is(e, cfg.ErrDenied) {
			runtime.Close()
			t.Fatal("reconciler role accepted as a hub credential", role.Purpose, e)
		}
		runtime.Close()
	}
	if mode == "lost-completion" {
		return
	}
	// The aggregate login ceiling covers all retained processes. Qualify its
	// exact installed value without opening 81 connections against this fixture's
	// 48-connection server. The shared pool fixture exercises actual per-process
	// saturation, both reserved lanes, cancellation and connection reuse.
	roleLimit, known := contracts.PublicRuntimeRoleConnectionLimit(snapshot.State.Roles[0].Purpose)
	if !known || roleLimit != 81 {
		t.Fatal("unexpected physical role ceiling", roleLimit)
	}
	var actualLimit int
	if e = admin.QueryRow(ctx, "SELECT rolconnlimit FROM pg_roles WHERE rolname=$1", firstName).Scan(&actualLimit); e != nil || actualLimit != roleLimit {
		t.Fatal("installed role-wide connection ceiling differs", actualLimit, e)
	}
	assertOriginalPoolLock := func() {
		t.Helper()
		var columnUpdate, tableUpdate bool
		if err := admin.QueryRow(ctx, "SELECT has_column_privilege($1, 'public.custody_pool', 'id', 'UPDATE'), has_table_privilege($1, 'public.custody_pool', 'UPDATE')", firstName).Scan(&columnUpdate, &tableUpdate); err != nil || !columnUpdate || tableUpdate {
			t.Fatal("original exact custody pool lock privilege changed", columnUpdate, tableUpdate, err)
		}
	}
	assertOriginalPoolLock()
	for _, mutation := range []struct{ name, grant, undo string }{
		{"connection-limit", "ALTER ROLE " + pgx.Identifier{firstName}.Sanitize() + " CONNECTION LIMIT 82", "ALTER ROLE " + pgx.Identifier{firstName}.Sanitize() + " CONNECTION LIMIT 81"},
		// Table-level REVOKE also removes original column grants; restore only
		// the installed API execution lock privilege after removing this fault.
		{"direct-extra", "GRANT UPDATE ON public.custody_pool TO " + pgx.Identifier{firstName}.Sanitize(), "REVOKE UPDATE ON public.custody_pool FROM " + pgx.Identifier{firstName}.Sanitize() + "; GRANT UPDATE(id) ON public.custody_pool TO " + pgx.Identifier{firstName}.Sanitize()},
		{"public-table", "GRANT SELECT ON public.custody_pool TO PUBLIC", "REVOKE SELECT ON public.custody_pool FROM PUBLIC"},
		{"public-column", "GRANT UPDATE(recovery_blocked) ON public.fleet_trust TO PUBLIC", "REVOKE UPDATE(recovery_blocked) ON public.fleet_trust FROM PUBLIC"},
		{"public-schema", "GRANT CREATE ON SCHEMA public TO PUBLIC", "REVOKE CREATE ON SCHEMA public FROM PUBLIC"},
		{"public-definer", "CREATE FUNCTION public.public_role_escape() RETURNS void LANGUAGE sql SECURITY DEFINER AS 'UPDATE public.fleet_trust SET recovery_blocked=false'", "DROP FUNCTION public.public_role_escape()"},
		{"direct-default", "ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO " + pgx.Identifier{firstName}.Sanitize(), "ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE SELECT ON TABLES FROM " + pgx.Identifier{firstName}.Sanitize()},
		{"public-default", "ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO PUBLIC", "ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE SELECT ON TABLES FROM PUBLIC"},
		{"type-owner", "CREATE TYPE public.public_role_owned_type AS ENUM ('fixed'); ALTER TYPE public.public_role_owned_type OWNER TO " + pgx.Identifier{firstName}.Sanitize(), "DROP TYPE public.public_role_owned_type"},
		{"membership", "GRANT " + qname + " TO " + pgx.Identifier{firstName}.Sanitize(), "REVOKE " + qname + " FROM " + pgx.Identifier{firstName}.Sanitize()},
	} {
		refresh()
		if _, e = admin.Exec(ctx, mutation.grant); e != nil {
			t.Fatal(e)
		}
		_, denied := producer.Provision(ctx)
		if _, e = admin.Exec(ctx, mutation.undo); e != nil {
			t.Fatal(e)
		}
		if denied == nil {
			t.Fatal("accepted excess direct/ambient authority", mutation.name)
		}
		assertOriginalPoolLock()
	}
	refresh()
	// A changed password in private storage cannot be adopted or repaired.
	root.mu.Lock()
	originalPassword := root.value.State.Roles[0].Password
	root.value.State.Roles[0].Password = root.value.State.Roles[1].Password
	root.mu.Unlock()
	if _, e = producer.Provision(ctx); e == nil {
		t.Fatal("wrong persisted password silently adopted")
	}
	root.mu.Lock()
	root.value.State.Roles[0].Password = originalPassword
	root.mu.Unlock()
	// Preserve the original leaf role OID through a same-name replacement fault.
	originalRole := pgx.Identifier{firstName + "_old"}.Sanitize()
	quoted := pgx.Identifier{firstName}.Sanitize()
	if _, e = admin.Exec(ctx, "ALTER ROLE "+quoted+" RENAME TO "+originalRole+"; CREATE ROLE "+quoted+" LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 1"); e != nil {
		t.Fatal(e)
	}
	refresh()
	_, replaced := producer.Provision(ctx)
	if _, e = admin.Exec(ctx, "DROP ROLE "+quoted+"; ALTER ROLE "+originalRole+" RENAME TO "+quoted); e != nil {
		t.Fatal(e)
	}
	if replaced == nil {
		t.Fatal("same-name replacement role accepted")
	}
	refresh()
	if _, e = provisionCurrent(); e != nil {
		t.Fatal("original exact roles unavailable after fault removal", e)
	}
	if _, e = admin.Exec(ctx, "UPDATE fleet_trust SET recovery_blocked=true WHERE installation_id=$1", scope.InstallationID); e != nil {
		t.Fatal(e)
	}
	if _, e = producer.Provision(ctx); e == nil {
		t.Fatal("current recovery fence ignored")
	}
	t.Log("actual SQL role creation/SCRAM/privilege matrix passed; Secret root CAS and protected configuration facts were explicit synthetic test inputs")
}

// asStored returns v as the protected Secret holds it, through the same JSON
// the snapshots use, so the root compares one time representation on every
// host. pgx and ctx.Deadline() return local-zone times, and on a UTC runner
// the JSON round trip turns those into time.UTC, which != and DeepEqual see
// as a changed claim (the first CI fleet runs).
func asStored[T any](v *T) *T {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	out := new(T)
	if err = json.Unmarshal(b, out); err != nil {
		panic(err)
	}
	return out
}
