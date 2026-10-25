package integration

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/postgres"
	auditapp "asservat.local/asservat/internal/application/audit"
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
type configurationRoleSQLRoot struct {
	mu                     sync.Mutex
	value                  contracts.ConfigurationRuntimeRoleSnapshot
	lostClaim, lostReceipt bool
	claims, receipts       int
	beforeClaim            func()
}

func (r *configurationRoleSQLRoot) snapshot(ctx context.Context) contracts.ConfigurationRuntimeRoleSnapshot {
	b, _ := json.Marshal(r.value)
	defer clear(b)
	var v contracts.ConfigurationRuntimeRoleSnapshot
	_ = json.Unmarshal(b, &v)
	n := time.Now().UTC().Truncate(time.Microsecond)
	v.ObservedAt, v.ValidUntil = n, n.Add(5*time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(v.ValidUntil) {
		v.ValidUntil = d
	}
	v.Sources.ObservedAt, v.Sources.FreshUntil = v.ObservedAt, v.ValidUntil
	v.Sources.Fleet.ObservedAt, v.Sources.Fleet.FreshUntil = v.ObservedAt, v.ValidUntil
	v.Sources.Owner.ObservedAt, v.Sources.Owner.FreshUntil = v.ObservedAt, v.ValidUntil
	return v
}
func (r *configurationRoleSQLRoot) OpenConfigurationRuntimeRoles(ctx context.Context) (contracts.ConfigurationRuntimeRoleSnapshot, error) {
	return r.ReadConfigurationRuntimeRoles(ctx)
}
func (r *configurationRoleSQLRoot) WithConfigurationRoleOperation(ctx context.Context, run func(context.Context) error) error {
	// Synthetic proof side only; the real scoped SQL effects still consume the
	// exact original operation deadline and original immutable claim.
	live, end := context.WithTimeout(ctx, 5*time.Second)
	defer end()
	return run(live)
}
func (r *configurationRoleSQLRoot) ReadConfigurationRuntimeRoles(ctx context.Context) (contracts.ConfigurationRuntimeRoleSnapshot, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if ctx.Err() != nil {
		return contracts.ConfigurationRuntimeRoleSnapshot{}, ctx.Err()
	}
	return r.snapshot(ctx), nil
}
func (r *configurationRoleSQLRoot) ClaimConfigurationRuntimeRole(ctx context.Context, purpose string, db uint32, postmaster time.Time) (contracts.ConfigurationRuntimeRoleSnapshot, bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if ctx.Err() != nil {
		return contracts.ConfigurationRuntimeRoleSnapshot{}, false, ctx.Err()
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
		// UTC like the product root: the snapshot copy round-trips through JSON,
		// and == on time.Time includes the location (fails under TZ=UTC).
		until = until.UTC().Truncate(time.Microsecond)
		if !n.Before(until) {
			return contracts.ConfigurationRuntimeRoleSnapshot{}, false, cfg.ErrUnavailable
		}
		sources := r.snapshot(ctx).Sources
		sources.ObservedAt, sources.Fleet.ObservedAt, sources.Owner.ObservedAt = n, n, n
		sources.FreshUntil, sources.Fleet.FreshUntil, sources.Owner.FreshUntil = until, until, until
		role.Claim = &contracts.ConfigurationRuntimeRoleClaim{OperationID: custodyID(), ClaimedAt: n, Until: until, DatabaseOID: db, PostmasterAt: postmaster.UTC(), Sources: sources}
		r.claims++
		if r.beforeClaim != nil {
			r.beforeClaim()
			r.beforeClaim = nil
		}
		if r.lostClaim {
			r.lostClaim = false
			return contracts.ConfigurationRuntimeRoleSnapshot{}, false, cfg.ErrUnavailable
		}
		return r.snapshot(ctx), true, nil
	}
	return contracts.ConfigurationRuntimeRoleSnapshot{}, false, cfg.ErrInvalid
}
func (r *configurationRoleSQLRoot) CompleteConfigurationRuntimeRole(ctx context.Context, original contracts.ConfigurationRuntimeRoleSnapshot, purpose string, receipt contracts.PublicRuntimeRoleReceipt) error {
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
func newConfigurationRoleSQLRoot(t *testing.T, input contracts.ConfigurationRuntimeRoles, issuer string) *configurationRoleSQLRoot {
	t.Helper()
	n := time.Now().UTC().Truncate(time.Microsecond)
	r := &configurationRoleSQLRoot{value: contracts.ConfigurationRuntimeRoleSnapshot{State: contracts.ConfigurationRuntimeRoleState{Format: contracts.ConfigurationRuntimeRoleStateFormat, Input: input, OperationID: custodyID(), CreatedAt: n, Until: n.Add(30 * time.Minute)}, UID: custodyID(), ResourceVersion: "1"}}
	r.value.Sources = contracts.ConfigurationRoleObservation{InstallationID: input.InstallationID, ClusterID: input.ClusterID, IssuerEpoch: issuer, NamespaceUID: input.Namespace.UID, DeploymentUID: input.Deployment.UID, AccountUID: input.ServiceAccount.UID, WorkloadDigest: strings.Repeat("1", 64), GuardDigest: strings.Repeat("2", 64), Fleet: contracts.ConfigurationRoleSourceRevision{UID: input.FleetSource.UID, Generation: 1, Digest: strings.Repeat("3", 64)}, Owner: contracts.ConfigurationRoleSourceRevision{UID: input.OwnerSource.UID, Generation: 1, Digest: strings.Repeat("4", 64)}}
	for _, p := range contracts.ConfigurationRuntimeRolePurposes() {
		b := make([]byte, 32)
		if _, e := rand.Read(b); e != nil {
			t.Fatal(e)
		}
		r.value.State.Roles = append(r.value.State.Roles, contracts.ConfigurationRuntimeRoleMaterial{Purpose: p, Password: base64.RawURLEncoding.EncodeToString(b)})
		clear(b)
	}
	return r
}

// Actual SQL/activation/role effects; this deliberately does not qualify the
// separate concrete Kubernetes source/Secret path or installed reconciliation.
func qualifyConfigurationRuntimeRoles(t *testing.T, ctx context.Context, admin *pgxpool.Pool, address string, tlsConfig *tls.Config, scope fleet.InstallationWitnessScope, claim string, a fleet.Administration, writer auditapp.OwnerConfigurationWriter, mode string) {
	t.Helper()
	input := contracts.ConfigurationRuntimeRoles{Format: contracts.ConfigurationRuntimeRolesFormat, InstallationID: scope.InstallationID, InitialClaimID: claim, ClusterID: scope.ClusterID, Namespace: contracts.WorkerObjectReference{Name: scope.Namespace, UID: scope.NamespaceUID}, Deployment: contracts.WorkerObjectReference{Name: "hub-worker", UID: custodyID()}, ServiceAccount: contracts.WorkerObjectReference{Name: "hub-worker", UID: custodyID()}, FleetSource: contracts.WorkerObjectReference{Name: "fleet", UID: a.Revision.UID}, OwnerSource: contracts.WorkerObjectReference{Name: "owner", UID: custodyID()}, LayoutDigest: postgres.ConfigurationRuntimeRoleLayoutDigest()}
	root := newConfigurationRoleSQLRoot(t, input, a.IssuerEpoch)
	configuration := configurationRoleSQLConfiguration(input, a.IssuerEpoch)
	root.value.Sources.Fleet.Generation = a.Revision.Generation
	root.value.Sources.Fleet.Digest = hex.EncodeToString(a.Revision.Digest[:])
	root.value.Sources.Owner.Digest = hex.EncodeToString(configuration.Revision.Digest[:])
	if mode == "source-rollback" {
		root.value.Sources.Fleet.Generation--
	}
	if mode == "source-mutation" {
		root.value.Sources.Fleet.Digest = strings.Repeat("5", 64)
	}
	c := publicRoleTLSConfig(t, admin, address, tlsConfig)
	t.Cleanup(func() {
		clean, end := context.WithTimeout(context.Background(), 5*time.Second)
		defer end()
		for _, purpose := range contracts.ConfigurationRuntimeRolePurposes() {
			name, _ := postgres.ConfigurationRuntimeRoleName(input.InstallationID, purpose)
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
	// Let the original stored observation expire in real time; no backdating or
	// new SQL source observation can manufacture the configuration prerequisite.
	if mode == "expired-observation" {
		var until time.Time
		if e := admin.QueryRow(ctx, "SELECT fresh_until FROM fleet_current_trust WHERE installation_id=$1", input.InstallationID).Scan(&until); e != nil {
			t.Fatal(e)
		}
		timer := time.NewTimer(time.Until(until.Add(time.Millisecond)))
		defer timer.Stop()
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-timer.C:
		}
		public := contracts.PublicRuntimeRoles{Format: contracts.PublicRuntimeRolesFormat, InstallationID: input.InstallationID, InitialClaimID: claim, ClusterID: input.ClusterID, Namespace: input.Namespace, OwnerConfigurationUID: input.OwnerSource.UID, LayoutDigest: postgres.PublicRuntimeRoleLayoutDigest()}
		denied, e := postgres.NewPublicRuntimeSQLRoles(ctx, c, newPublicRoleSQLRoot(t, public), public)
		if denied != nil {
			denied.Close()
		}
		if e == nil {
			t.Fatal("ordinary public role producer bypassed expired SQL source")
		}
	}
	producer, e := postgres.NewConfigurationRuntimeSQLRoles(ctx, c, root, input)
	if e != nil {
		t.Fatal("configuration credential bootstrap constructor", e)
	}
	t.Cleanup(producer.Close)
	first, _ := postgres.ConfigurationRuntimeRoleName(input.InstallationID, "configuration-fleet")
	if mode == "source-rollback" || mode == "source-mutation" {
		if _, e = producer.Provision(ctx); e == nil {
			t.Fatal("current source proof bypassed retained SQL source watermark")
		}
		var count int
		if e = admin.QueryRow(ctx, "SELECT count(*) FROM pg_roles WHERE rolname=$1", first).Scan(&count); e != nil || count != 0 {
			t.Fatal("contrary source created role", e)
		}
		return
	}

	if mode == "held-lock" {
		blocker, e := admin.Begin(ctx)
		if e != nil {
			t.Fatal(e)
		}
		defer blocker.Rollback(context.Background())
		if _, e = blocker.Exec(ctx, "SELECT pg_advisory_xact_lock(1095979854,hashtext($1))", input.InstallationID); e != nil {
			t.Fatal(e)
		}
		short, end := context.WithTimeout(ctx, 80*time.Millisecond)
		_, e = producer.Provision(short)
		end()
		if e == nil {
			t.Fatal("credential creation crossed original held-lock deadline")
		}
		if e = blocker.Rollback(ctx); e != nil {
			t.Fatal(e)
		}
		if _, e = producer.Provision(ctx); e == nil {
			t.Fatal("spent short claim restarted after lock release")
		}
		var count int
		if e = admin.QueryRow(ctx, "SELECT count(*) FROM pg_roles WHERE rolname=$1", first).Scan(&count); e != nil || count != 0 || root.claims != 1 {
			t.Fatal("held lock released original spend or created role", e)
		}
		return
	}
	if mode == "recovery-after-lock" {
		blocker, e := admin.Begin(ctx)
		if e != nil {
			t.Fatal(e)
		}
		defer blocker.Rollback(context.Background())
		if _, e = blocker.Exec(ctx, "UPDATE fleet_trust SET recovery_blocked=true WHERE installation_id=$1", input.InstallationID); e != nil {
			t.Fatal(e)
		}
		claimed := make(chan struct{})
		root.beforeClaim = func() { close(claimed) }
		done := make(chan error, 1)
		go func() { _, e := producer.Provision(ctx); done <- e }()
		select {
		case <-claimed:
		case e := <-done:
			t.Fatal("original claim not reached before recovery lock", e)
		case <-time.After(time.Second):
			t.Fatal("original claim unavailable")
		}
		if e = blocker.Commit(ctx); e != nil {
			t.Fatal(e)
		}
		if e = <-done; e == nil {
			t.Fatal("credential creation ignored current post-lock recovery")
		}
		var count int
		if e = admin.QueryRow(ctx, "SELECT count(*) FROM pg_roles WHERE rolname=$1", first).Scan(&count); e != nil || count != 0 {
			t.Fatal("recovery transition created role", e)
		}
		return
	}
	if mode == "source-after-lock" {
		blocker, err := admin.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer blocker.Rollback(context.Background())
		var pid int32
		if err = blocker.QueryRow(ctx, "SELECT pg_backend_pid()").Scan(&pid); err != nil {
			t.Fatal(err)
		}
		if _, err = blocker.Exec(ctx, "SELECT pg_advisory_xact_lock(1095979854,hashtext($1))", input.InstallationID); err != nil {
			t.Fatal(err)
		}
		live, cancel := context.WithCancel(ctx)
		done := make(chan struct{})
		var operationErr error
		go func() { defer close(done); _, operationErr = producer.Provision(live) }()
		defer func() { cancel(); <-done }()
		wait, end := context.WithTimeout(ctx, 700*time.Millisecond)
		defer end()
		for {
			var blocked bool
			if err = admin.QueryRow(wait, "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE $1::int=ANY(pg_blocking_pids(pid)))", pid).Scan(&blocked); err != nil {
				t.Fatal("actual role lock wait", err)
			}
			if blocked {
				break
			}
			select {
			case <-done:
				t.Fatal("role operation did not reach held lock", operationErr)
			case <-wait.Done():
				t.Fatal("role lock was not observed")
			case <-time.After(5 * time.Millisecond):
			}
		}
		root.mu.Lock()
		root.value.Sources.Owner.Generation++
		claims := root.claims
		root.mu.Unlock()
		if err = blocker.Rollback(ctx); err != nil {
			t.Fatal(err)
		}
		<-done
		if operationErr == nil || claims != 1 {
			t.Fatal("post-lock source recheck missing", operationErr, claims)
		}
		var count int
		if err = admin.QueryRow(ctx, "SELECT count(*) FROM pg_roles WHERE rolname=$1", first).Scan(&count); err != nil || count != 0 {
			t.Fatal("known post-lock source change created role", err)
		}
		return
	}
	if mode == "unknown-claim" {
		root.lostClaim = true
		if _, e = producer.Provision(ctx); e == nil {
			t.Fatal("unknown claim authorized CREATE")
		}
		if _, e = producer.Provision(ctx); e == nil {
			t.Fatal("unknown claim minted a second attempt")
		}
		var count int
		if e = admin.QueryRow(ctx, "SELECT count(*) FROM pg_roles WHERE rolname=$1", first).Scan(&count); e != nil || count != 0 || root.claims != 1 {
			t.Fatal("unknown claim changed original spend", e)
		}
		return
	}
	if mode == "changed-source" {
		root.beforeClaim = func() { root.value.Sources.Owner.Generation++ }
		if _, e = producer.Provision(ctx); e == nil {
			t.Fatal("changed source after claim authorized role")
		}
		var count int
		if e = admin.QueryRow(ctx, "SELECT count(*) FROM pg_roles WHERE rolname=$1", first).Scan(&count); e != nil || count != 0 {
			t.Fatal("changed source created role", e)
		}
		return
	}

	var observedBefore, freshBefore time.Time
	if e = admin.QueryRow(ctx, "SELECT observed_at,fresh_until FROM fleet_current_trust WHERE installation_id=$1", input.InstallationID).Scan(&observedBefore, &freshBefore); e != nil {
		t.Fatal(e)
	}
	original, e := producer.Provision(ctx)
	if e != nil {
		// The full cause chain (CI-only failure on main and branches).
		chain := []string{}
		for x := e; x != nil; x = errors.Unwrap(x) {
			chain = append(chain, x.Error())
		}
		t.Fatal("fixed configuration roles", chain)
	}

	var observedAfter, freshAfter time.Time
	if e = admin.QueryRow(ctx, "SELECT observed_at,fresh_until FROM fleet_current_trust WHERE installation_id=$1", input.InstallationID).Scan(&observedAfter, &freshAfter); e != nil || !observedBefore.Equal(observedAfter) || !freshBefore.Equal(freshAfter) {
		t.Fatal("credential bootstrap fabricated a fleet observation", e)
	}
	// This bootstrap must work without creating an accepted owner projection.
	var accepted int
	if e = admin.QueryRow(ctx, "SELECT count(*) FROM hub_owner_configuration WHERE installation_id=$1", input.InstallationID).Scan(&accepted); e != nil || accepted != 0 {
		t.Fatal("credential bootstrap fabricated owner acceptance", e)
	}
	manifest := contracts.ConfigurationRuntimeCredentialManifest{Format: contracts.ConfigurationRuntimeCredentialManifestFormat, Input: input, RootUID: original.UID, SetupID: original.State.OperationID}
	for _, r := range original.State.Roles {
		manifest.Roles = append(manifest.Roles, contracts.ConfigurationRuntimeCredentialProof{Purpose: r.Purpose, Claim: *r.Claim, Receipt: *r.Receipt})
	}
	if strings.HasPrefix(mode, "launched-") {
		qualifyConfigurationLaunchedInventory(t, ctx, admin, c, root, original, mode)
		return
	}
	if mode == "reconcile" || strings.HasPrefix(mode, "ack-") {
		qualifyConfigurationRoleReconciliation(t, ctx, admin, c, original, manifest, a, configuration, writer, mode)
		return
	}
	for _, r := range original.State.Roles {
		config, e := pgxpool.ParseConfig("")
		if e != nil {
			t.Fatal(e)
		}
		config.ConnConfig = c.Copy()
		config.ConnConfig.User, config.ConnConfig.Password = r.Receipt.RoleName, r.Password
		config.MaxConns, config.MinConns = 1, 0
		pool, e := pgxpool.NewWithConfig(ctx, config)
		if e != nil {
			t.Fatal(e)
		}
		if e = postgres.VerifyConfigurationRuntimeCredential(ctx, pool, manifest, r.Purpose); e != nil {
			pool.Close()
			t.Fatal("original configuration role/ACL verification", e)
		}
		tx, e := pool.Begin(ctx)
		if e != nil {
			pool.Close()
			t.Fatal(e)
		}
		var id string
		e = tx.QueryRow(ctx, "SELECT installation_id::text FROM fleet_current_trust WHERE installation_id=$1 FOR SHARE", input.InstallationID).Scan(&id)
		if e != nil || id != input.InstallationID {
			tx.Rollback(ctx)
			pool.Close()
			t.Fatal("actual recovery lock unavailable", e)
		}
		if e = tx.Rollback(ctx); e != nil {
			pool.Close()
			t.Fatal(e)
		}
		_, e = pool.Exec(ctx, "UPDATE fleet_trust SET recovery_blocked=false WHERE installation_id=$1", input.InstallationID)
		var denied *pgconn.PgError
		if !errors.As(e, &denied) || denied.Code != "42501" {
			pool.Close()
			t.Fatal("configuration credential acquired activation write", e)
		}

		if r.Purpose != "configuration-audit" {
			_, e = pool.Exec(ctx, "UPDATE hub_owner_configuration_revision SET audit_receipt_json=NULL WHERE false")
			if !errors.As(e, &denied) || denied.Code != "42501" {
				pool.Close()
				t.Fatal("source credential can acknowledge audit", e)
			}
		} else {
			_, e = pool.Exec(ctx, "UPDATE hub_owner_configuration SET observed_at=observed_at WHERE false")
			if !errors.As(e, &denied) || denied.Code != "42501" {
				pool.Close()
				t.Fatal("audit credential can write source observation", e)
			}
		}
		pool.Close()
	}
	t.Log("actual fixed configuration SQL credentials preserve current recovery and leave owner acceptance absent; protected source/Secret facts synthetic")
}
