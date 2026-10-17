package integration

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/postgres"
	auditapp "asservat.local/asservat/internal/application/audit"
	app "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Real TLS/SQL constructor, activation and lock checks. The initial witness and
// source are explicitly synthetic in this fixture. The callback models native
// I/O but cannot qualify Kubernetes enforcement or the composed guard bridge.
func qualifyInitialRuntimeBridgeSQL(t *testing.T, ctx context.Context, admin *pgxpool.Pool, administrator, runtime *pgx.ConnConfig, record audit.InitialInstallation, receipt audit.Receipt, mode string) {
	t.Helper()
	original := record
	config := administrator.Copy()
	var head int64
	if err := admin.QueryRow(ctx, "SELECT version_id FROM public.goose_db_version ORDER BY id DESC LIMIT 1").Scan(&head); err != nil {
		t.Fatal("read original schema head", err)
	}
	schema := func(version int64, applied bool) {
		t.Helper()
		if _, err := admin.Exec(ctx, `UPDATE public.goose_db_version SET version_id=$1,is_applied=$2 WHERE id=(SELECT max(id) FROM public.goose_db_version)`, version, applied); err != nil {
			t.Fatal("set dedicated schema fixture", err)
		}
	}
	if mode == "schema-unapplied" || mode == "schema-head" || mode == "schema-after-construction" {
		t.Cleanup(func() {
			clean, end := context.WithTimeout(context.Background(), 5*time.Second)
			defer end()
			if _, err := admin.Exec(clean, `UPDATE public.goose_db_version SET version_id=$1,is_applied=true WHERE id=(SELECT max(id) FROM public.goose_db_version)`, head); err != nil {
				t.Error("restore original schema fixture", err)
			}
		})
	}
	switch mode {
	case "runtime-role":
		config.User, config.Password = runtime.User, runtime.Password
	case "schema-unapplied":
		schema(head, false)
	case "schema-head":
		schema(head+1, true)
	case "database":
		record.Claim.Database.DatabaseOID++
	case "postmaster":
		record.Claim.Database.StartedAt = record.Claim.Database.StartedAt.Add(-time.Second)
	case "recovery":
		if _, err := admin.Exec(ctx, "UPDATE public.fleet_trust SET recovery_blocked=true WHERE installation_id=$1", record.Scope.InstallationID); err != nil {
			t.Fatal(err)
		}
	}
	producer, err := postgres.NewInitialRuntimeBridgeSQL(ctx, config, record, receipt)
	switch mode {
	case "runtime-role", "schema-unapplied", "schema-head", "database", "postmaster", "recovery":
		if producer != nil {
			producer.Close()
		}
		if err == nil {
			t.Fatal("ineligible bridge constructor accepted", mode)
		}
		if mode == "runtime-role" && !errors.Is(err, cfg.ErrDenied) {
			t.Fatal("ordinary runtime login was not denied at administrator boundary", err)
		}
		return
	}
	if err != nil {
		t.Fatal("intended post-activation administrator bridge constructor", err)
	}
	defer producer.Close()
	got, gotReceipt := producer.InitialRuntimeBridgeRecord()
	if !got.Claim.Same(original.Claim) || gotReceipt != receipt {
		t.Fatal("constructor changed original activation or receipt")
	}
	var calls atomic.Int32
	effect := func(call context.Context) error {
		calls.Add(1)
		until, ok := call.Deadline()
		if !ok || time.Until(until) <= 0 || time.Until(until) > 5*time.Second || call.Err() != nil {
			return errors.New("effect did not receive its original bounded context")
		}
		return nil
	}
	switch mode {
	case "administrator":
		for range 2 {
			if err = producer.WithInitialRuntimeBridge(ctx, effect); err != nil {
				t.Fatal("actual administrator bridge effect unavailable", err)
			}
		}
		if calls.Load() != 2 {
			t.Fatal("unexpected number of exact effect calls", calls.Load())
		}
		// The administrator facet must not weaken or replace the runtime pool
		// constructor's independent denial of the very same administrator.
		poolConfig, e := pgxpool.ParseConfig("")
		if e != nil {
			t.Fatal(e)
		}
		poolConfig.ConnConfig, poolConfig.MaxConns = administrator.Copy(), 1
		pool, e := pgxpool.NewWithConfig(ctx, poolConfig)
		if e != nil {
			t.Fatal(e)
		}
		defer pool.Close()
		if _, e = postgres.New(ctx, pool); e == nil {
			t.Fatal("runtime Ledger accepted installer administrator")
		}
	case "held-lock":
		tx, e := admin.Begin(ctx)
		if e != nil {
			t.Fatal(e)
		}
		defer tx.Rollback(context.Background())
		if _, e = tx.Exec(ctx, "SELECT installation_id FROM public.fleet_trust WHERE installation_id=$1 FOR UPDATE", record.Scope.InstallationID); e != nil {
			t.Fatal(e)
		}
		short, end := context.WithTimeout(ctx, 100*time.Millisecond)
		err = producer.WithInitialRuntimeBridge(short, effect)
		end()
		if err == nil || calls.Load() != 0 {
			t.Fatal("original deadline crossed held recovery lock", err, calls.Load())
		}
		if e = tx.Rollback(ctx); e != nil {
			t.Fatal(e)
		}
		if err = producer.WithInitialRuntimeBridge(ctx, effect); err != nil || calls.Load() != 1 {
			t.Fatal("fresh independent operation unavailable after positive lock release", err)
		}
	case "recovery-after-lock":
		tx, e := admin.Begin(ctx)
		if e != nil {
			t.Fatal(e)
		}
		defer tx.Rollback(context.Background())
		if _, e = tx.Exec(ctx, "UPDATE public.fleet_trust SET recovery_blocked=true WHERE installation_id=$1", record.Scope.InstallationID); e != nil {
			t.Fatal(e)
		}
		call, end := context.WithTimeout(ctx, 3*time.Second)
		defer end()
		result := make(chan error, 1)
		go func() { result <- producer.WithInitialRuntimeBridge(call, effect) }()
		// Observe the actual SQL wait before releasing the contrary state.
		waiting := false
		for limit := time.Now().Add(800 * time.Millisecond); time.Now().Before(limit); {
			if e = admin.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE application_name='asservat-runtime-guard-bridge' AND wait_event_type='Lock')`).Scan(&waiting); e != nil || waiting {
				break
			}
			time.Sleep(5 * time.Millisecond)
		}
		if !waiting || e != nil {
			end()
			<-result
			t.Fatal("bridge did not reach actual recovery lock", e)
		}
		if e = tx.Commit(ctx); e != nil {
			end()
			<-result
			t.Fatal(e)
		}
		err = <-result
		if err == nil || calls.Load() != 0 {
			t.Fatal("post-lock recovery block allowed native effect", err, calls.Load())
		}
	case "late-callback":
		short, end := context.WithTimeout(ctx, 100*time.Millisecond)
		defer end()
		originalUntil, _ := short.Deadline()
		err = producer.WithInitialRuntimeBridge(short, func(call context.Context) error {
			calls.Add(1)
			until, ok := call.Deadline()
			if !ok || !until.Equal(originalUntil) {
				return errors.New("caller deadline was changed")
			}
			<-call.Done()
			return nil // Unknown native completion cannot be inferred from nil.
		})
		if err == nil || calls.Load() != 1 {
			t.Fatal("late native reply accepted", err, calls.Load())
		}
	case "schema-after-construction":
		schema(head, false)
		if err = producer.WithInitialRuntimeBridge(ctx, effect); err == nil || calls.Load() != 0 {
			t.Fatal("schema change after construction allowed native effect", err, calls.Load())
		}
	default:
		t.Fatal("unknown bridge qualification mode", mode)
	}
}

// The native source below is explicitly synthetic and fixed before each call.
// The bridge, current SQL recovery/source, scoped observers, encrypted audit,
// locks and accepted owner reader are actual. No lookup refreshes source time.
func qualifyInitialRuntimeOwnerBridgeSQL(t *testing.T, ctx context.Context, admin *pgxpool.Pool, administrator *pgx.ConnConfig, record audit.InitialInstallation, receipt audit.Receipt, source fleet.Administration, auditWriter auditapp.OwnerConfigurationWriter, mode string) {
	t.Helper()
	bridge, err := postgres.NewInitialRuntimeBridgeSQL(ctx, administrator, record, receipt)
	if err != nil {
		t.Fatal("original owner bridge constructor", err)
	}
	defer bridge.Close()
	var storedUntil time.Time
	if err = admin.QueryRow(ctx, "SELECT fresh_until FROM public.fleet_current_trust WHERE installation_id=$1", record.Scope.InstallationID).Scan(&storedUntil); err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	effect := func(call context.Context) error {
		calls.Add(1)
		until, ok := call.Deadline()
		expected := identity.Earlier(source.FreshUntil, storedUntil)
		if parent, bounded := ctx.Deadline(); bounded {
			expected = identity.Earlier(expected, parent)
		}
		if !ok || !until.Equal(expected) || call.Err() != nil || !time.Now().Before(until) {
			return errors.New("owner callback changed the original source/caller/stored cutoff")
		}
		return nil
	}
	// A known successful call precedes every negative vector. A missing role,
	// expired setup or broken constructor cannot satisfy the denial assertions.
	if err = bridge.WithInitialRuntimeOwnerBridge(ctx, source, effect); err != nil || calls.Load() != 1 {
		t.Fatal("positive owner baseline unavailable", err, calls.Load())
	}
	calls.Store(0)
	want := cfg.ErrUnavailable
	switch mode {
	case "owner-current", "owner-current-end":
		if mode == "owner-current-end" && !storedUntil.Before(source.FreshUntil) {
			t.Fatal("original stored end was not earlier than independent native source")
		}
		if err = bridge.WithInitialRuntimeOwnerBridge(ctx, source, effect); err != nil || calls.Load() != 1 {
			t.Fatal("original-bound positive owner callback", err, calls.Load())
		}
		return
	case "owner-generation", "owner-digest", "owner-issuer":
		contrary := source
		switch mode {
		case "owner-generation":
			contrary.Revision.Generation++
		case "owner-digest":
			contrary.Revision.Digest[0] ^= 0xff
		case "owner-issuer":
			contrary.IssuerEpoch = custodyID()
		}
		if !contrary.Valid(time.Now()) || contrary.Revision.UID != source.Revision.UID {
			t.Fatal("contrary input must retain a valid original source UID and interval")
		}
		err = bridge.WithInitialRuntimeOwnerBridge(ctx, contrary, effect)
		want = cfg.ErrChanged
	case "owner-source-after-lock", "owner-recovery-after-lock", "owner-source-expired-after-lock", "owner-caller-expired-after-lock":
		err = qualifyOwnerBridgeSQLWait(t, ctx, admin, administrator, bridge, source, effect, mode)
		// A base-only source mutation leaves the positive observation bound to
		// the old semantic version. SQL59 projects blocked/expired authority;
		// that exact unavailable result must precede any callback.
	case "owner-late-callback":
		original := source
		original.ObservedAt = time.Now().UTC().Truncate(time.Microsecond)
		original.FreshUntil = original.ObservedAt.Add(200 * time.Millisecond)
		err = bridge.WithInitialRuntimeOwnerBridge(ctx, original, func(call context.Context) error {
			calls.Add(1)
			until, ok := call.Deadline()
			if !ok || !until.Equal(identity.Earlier(original.FreshUntil, storedUntil)) {
				return errors.New("late callback did not receive exact original end")
			}
			<-call.Done()
			return nil // A late nil result cannot authorize a completed effect.
		})
		if !errors.Is(err, cfg.ErrUnavailable) || calls.Load() != 1 {
			t.Fatal("late original callback accepted or did not enter", err, calls.Load())
		}
		return
	case "owner-concurrent-observers":
		qualifyOwnerBridgeConcurrentObservers(t, ctx, admin, administrator, bridge, record, source, auditWriter)
		return
	default:
		t.Fatal("unknown owner bridge SQL mode", mode)
	}
	if !errors.Is(err, want) || calls.Load() != 0 {
		t.Fatal("contrary/elapsed original owner operation reached callback or wrong refusal", mode, err, calls.Load())
	}
	if mode == "owner-source-after-lock" {
		// Separately accept a coherent changed source through the actual scoped
		// observer. No row is seeded and no original proof time is rewritten.
		// That current contrary tuple must retain the distinct changed result.
		pool := ownerBridgeScopedPool(t, ctx, administrator, "fleet_observe_runtime", "synthetic-fleet-observe")
		projection, e := postgres.NewFleetObservation(ctx, pool, source.InstallationID)
		if e != nil {
			t.Fatal(e)
		}
		changed := source
		changed.Revision.Generation++
		changed.ObservedAt = time.Now().UTC().Truncate(time.Microsecond)
		changed.FreshUntil = changed.ObservedAt.Add(5 * time.Second)
		if e = projection.ObserveAdministration(ctx, fleetBasisFixture(t, ctx, projection), changed); e != nil {
			t.Fatal("actual coherent changed source observation", e)
		}
		if !source.Valid(time.Now()) {
			t.Fatal("original source expired before changed-tuple assertion")
		}
		if e = bridge.WithInitialRuntimeOwnerBridge(ctx, source, effect); !errors.Is(e, cfg.ErrChanged) || calls.Load() != 0 {
			t.Fatal("coherent changed source lost exact refusal or invoked effects", e, calls.Load())
		}
	}
}

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

func qualifyOwnerBridgeSQLWait(t *testing.T, ctx context.Context, admin *pgxpool.Pool, administrator *pgx.ConnConfig, bridge *postgres.InitialRuntimeBridgeSQL, source fleet.Administration, effect func(context.Context) error, mode string) error {
	t.Helper()
	tx, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	call, cancel := context.WithCancel(ctx)
	var result chan error
	joined := false
	// On any Fatal/error: release the owned blocker, cancel and join the bridge
	// before its producer/pools can be closed by their outer defers/cleanups.
	defer func() {
		cancel()
		clean, end := context.WithTimeout(context.Background(), time.Second)
		defer end()
		if rollbackErr := tx.Rollback(clean); rollbackErr != nil && !errors.Is(rollbackErr, pgx.ErrTxClosed) {
			t.Error("owned blocker rollback", rollbackErr)
		}
		if result != nil && !joined {
			<-result
		}
	}()
	var blocker int32
	if err = tx.QueryRow(ctx, "SELECT pg_backend_pid() FROM public.fleet_trust WHERE installation_id=$1 FOR UPDATE", source.InstallationID).Scan(&blocker); err != nil {
		t.Fatal("hold actual source row", err)
	}
	original := source
	switch mode {
	case "owner-source-expired-after-lock":
		original.ObservedAt = time.Now().UTC().Truncate(time.Microsecond)
		original.FreshUntil = original.ObservedAt.Add(200 * time.Millisecond)
	case "owner-caller-expired-after-lock":
		short, stop := context.WithTimeout(call, 200*time.Millisecond)
		defer stop()
		call = short
	}
	result = make(chan error, 1)
	go func() { result <- bridge.WithInitialRuntimeOwnerBridge(call, original, effect) }()
	waitContext, stop := context.WithDeadline(call, original.FreshUntil)
	waiter, waitErr := ownerBridgeWaitForBlocker(waitContext, admin, blocker, 0, "asservat-runtime-guard-bridge")
	stop()
	if waitErr != nil {
		t.Fatal("bridge did not reach the intended owned source lock", waitErr)
	}
	t.Logf("actual owner bridge wait edge: waiter=%d blocker=%d", waiter, blocker)
	switch mode {
	case "owner-source-after-lock":
		_, err = tx.Exec(ctx, "UPDATE public.fleet_trust SET source_generation=source_generation+1 WHERE installation_id=$1", source.InstallationID)
		if err == nil {
			var blocked bool
			err = tx.QueryRow(ctx, `SELECT recovery_blocked AND observed_at='epoch'::timestamptz
 AND fresh_until='epoch'::timestamptz AND source_generation=$2
 FROM public.fleet_current_trust WHERE installation_id=$1`, source.InstallationID, source.Revision.Generation+1).Scan(&blocked)
			if err == nil && !blocked {
				err = errors.New("base-only source mutation did not invalidate its old positive binding")
			}
		}
	case "owner-recovery-after-lock":
		_, err = tx.Exec(ctx, "UPDATE public.fleet_trust SET recovery_blocked=true WHERE installation_id=$1", source.InstallationID)
	case "owner-source-expired-after-lock", "owner-caller-expired-after-lock":
		// Join the actual bounded call before releasing its observed blocker.
		// A new source is selected only after that old operation has ended.
		first := <-result
		joined = true
		if !errors.Is(first, cfg.ErrUnavailable) || original.Valid(time.Now()) && call.Err() == nil {
			t.Fatal("blocked original operation did not expire with its own interval", first)
		}
		if err = tx.Rollback(ctx); err != nil {
			t.Fatal(err)
		}
		pool := ownerBridgeScopedPool(t, ctx, administrator, "fleet_observe_runtime", "synthetic-fleet-observe")
		projection, e := postgres.NewFleetObservation(ctx, pool, source.InstallationID)
		if e != nil {
			t.Fatal(e)
		}
		newSource := source
		newSource.ObservedAt = time.Now().UTC().Truncate(time.Microsecond)
		newSource.FreshUntil = newSource.ObservedAt.Add(5 * time.Second)
		if e = projection.ObserveAdministration(ctx, fleetBasisFixture(t, ctx, projection), newSource); e != nil {
			t.Fatal("independent new observation after expired original operation", e)
		}
		// This is an assertion on the same expired identity/deadline, not a retry
		// to obtain admission: even new stored freshness must not invoke effects.
		return bridge.WithInitialRuntimeOwnerBridge(call, original, effect)
	}
	if err != nil {
		t.Fatal("contrary state in held source transaction", err)
	}
	if err = tx.Commit(ctx); err != nil {
		t.Fatal("commit contrary source/recovery state", err)
	}
	err = <-result
	joined = true
	return err
}

// One already-selected synthetic observation. Calling the reader does not move
// its start/end, and its public root bytes claim no native TLS qualification.
type ownerBridgeFixedOwnerSource struct {
	observation fleet.OwnerConfigurationObservation
}

func (s ownerBridgeFixedOwnerSource) ReadOwnerConfiguration(context.Context) (fleet.OwnerConfigurationObservation, error) {
	return s.observation, nil
}

func qualifyOwnerBridgeConcurrentObservers(t *testing.T, ctx context.Context, admin *pgxpool.Pool, administrator *pgx.ConnConfig, bridge *postgres.InitialRuntimeBridgeSQL, record audit.InitialInstallation, source fleet.Administration, auditWriter auditapp.OwnerConfigurationWriter) {
	t.Helper()
	configuration := fleet.OwnerConfiguration{
		Pool: fleet.OwnerPool{InstallationID: record.Scope.InstallationID, ClusterID: record.Scope.ClusterID, IssuerEpoch: record.Scope.IssuerEpoch,
			Namespace: record.Scope.Namespace, NamespaceUID: record.Scope.NamespaceUID, Service: "owner", ServiceUID: custodyID(),
			Deployment: "owner", DeploymentUID: custodyID(), ServiceAccount: "owner", AccountUID: custodyID(), Port: 8443},
		Revision: identity.Revision{UID: custodyID(), Generation: 1, Digest: artifact.Digest{1}}, ProtectionDigest: artifact.Digest{2},
		IssuerRoots: [][]byte{[]byte("synthetic public root; no native TLS assertion")},
	}
	// This owned fixture adds children to the activation's fleet row. Register
	// their cleanup before pools so pools close first and the parent's original
	// activation/fleet cleanup runs only after both foreign-key children are gone.
	t.Cleanup(func() {
		clean, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		for _, table := range []string{"hub_owner_configuration_revision", "hub_owner_configuration"} {
			if _, err := admin.Exec(clean, "DELETE FROM public."+table+" WHERE installation_id=$1 AND cluster_id=$2", source.InstallationID, record.Scope.ClusterID); err != nil {
				t.Error("remove owned owner-configuration fixture", table, err)
			}
		}
	})
	ownerFacet := func(role, password string) *postgres.OwnerConfigurations {
		t.Helper()
		pool := ownerBridgeScopedPool(t, ctx, administrator, role, password)
		facet, err := postgres.NewOwnerConfigurations(ctx, pool, record.Scope.InstallationID, record.Scope.ClusterID, record.Scope.NamespaceUID, configuration.Revision.UID)
		if err != nil {
			t.Fatal("scoped owner facet", err)
		}
		return facet
	}
	writer := ownerFacet("owner_configuration_runtime", "synthetic-owner-configuration")
	ack := ownerFacet("owner_configuration_audit_runtime", "synthetic-owner-configuration-audit")
	reader := ownerFacet("owner_configuration_read_runtime", "synthetic-owner-configuration-read")
	fleetPool := ownerBridgeScopedPool(t, ctx, administrator, "fleet_observe_runtime", "synthetic-fleet-observe")
	projection, err := postgres.NewFleetObservation(ctx, fleetPool, source.InstallationID)
	if err != nil {
		t.Fatal("scoped fleet facet", err)
	}
	var fleetPID int32
	if err = fleetPool.QueryRow(ctx, "SELECT pg_backend_pid()").Scan(&fleetPID); err != nil {
		t.Fatal(err)
	}
	ownerObservation := func() fleet.OwnerConfigurationObservation {
		at := time.Now().UTC().Truncate(time.Microsecond)
		return fleet.OwnerConfigurationObservation{Configuration: configuration, ObservedAt: at, FreshUntil: at.Add(5 * time.Second)}
	}
	observe := func(call context.Context, original fleet.OwnerConfigurationObservation) error {
		observer := &app.OwnerConfigurationObserver{Reader: ownerBridgeFixedOwnerSource{original}, Ledger: writer, Audit: auditWriter, Acknowledgements: ack, Now: time.Now}
		return observer.Observe(call)
	}
	initial := ownerObservation()
	if err = observe(ctx, initial); err != nil {
		t.Fatal("original real owner observation/encrypted audit/acknowledgement", err)
	}
	if accepted, e := reader.ReadOwnerConfiguration(ctx); e != nil || !accepted.Configuration.Equal(configuration) {
		t.Fatal("positive accepted owner baseline", e)
	}
	var originalAudit string
	if err = admin.QueryRow(ctx, "SELECT audit_receipt_json::text FROM public.hub_owner_configuration_revision WHERE installation_id=$1 AND cluster_id=$2 AND source_uid=$3 AND generation=$4", source.InstallationID, record.Scope.ClusterID, configuration.Revision.UID, configuration.Revision.Generation).Scan(&originalAudit); err != nil || originalAudit == "" {
		t.Fatal("read independently acknowledged owner audit identity", err)
	}
	var admitted, renewed, observedBefore, observedAfter bool
	err = bridge.WithInitialRuntimeOwnerBridge(ctx, source, func(call context.Context) error {
		originalEnd, bounded := call.Deadline()
		if !bounded {
			return errors.New("original owner bridge deadline missing")
		}
		var beforeVersion int64
		var beforeObserved, beforeUntil time.Time
		if e := admin.QueryRow(call, `SELECT t.semantic_version,v.observed_at,v.fresh_until
 FROM public.fleet_trust t JOIN public.fleet_current_trust v USING(installation_id)
 WHERE t.installation_id=$1`, source.InstallationID).Scan(&beforeVersion, &beforeObserved, &beforeUntil); e != nil {
			return e
		}
		expectedEnd := identity.Earlier(source.FreshUntil, beforeUntil)
		if parent, bounded := ctx.Deadline(); bounded {
			expectedEnd = identity.Earlier(expectedEnd, parent)
		}
		if !originalEnd.Equal(expectedEnd) {
			return errors.New("bridge did not retain the original source, caller and stored end")
		}
		first := ownerObservation()
		if e := observe(call, first); e != nil {
			return fmt.Errorf("ordinary owner observer under bridge: %w", e)
		}
		var firstHead time.Time
		if e := admin.QueryRow(call, "SELECT observed_at FROM public.hub_owner_configuration WHERE installation_id=$1 AND cluster_id=$2", source.InstallationID, record.Scope.ClusterID).Scan(&firstHead); e != nil || !firstHead.Equal(first.ObservedAt) || !firstHead.After(initial.ObservedAt) {
			return errors.New("ordinary owner observation did not advance while bridge was held")
		}
		observedBefore = true
		candidate := source
		candidate.ObservedAt = time.Now().UTC().Truncate(time.Microsecond)
		candidate.FreshUntil = candidate.ObservedAt.Add(5 * time.Second)
		observer := app.TrustObserver{Settings: fixedContentionAdministration{candidate}, Projection: projection, Now: time.Now}
		if e := observer.Reconcile(call); e != nil {
			return fmt.Errorf("unchanged positive fleet renewal under retained bridge SHARE: %w", e)
		}
		var afterVersion int64
		var afterObserved, afterUntil time.Time
		if e := admin.QueryRow(call, `SELECT t.semantic_version,v.observed_at,v.fresh_until
 FROM public.fleet_trust t JOIN public.fleet_current_trust v USING(installation_id)
 WHERE t.installation_id=$1`, source.InstallationID).Scan(&afterVersion, &afterObserved, &afterUntil); e != nil {
			return e
		}
		currentEnd, _ := call.Deadline()
		if afterVersion != beforeVersion || !afterObserved.Equal(candidate.ObservedAt) || !afterObserved.After(beforeObserved) || !afterUntil.Equal(candidate.FreshUntil) || !afterUntil.After(originalEnd) || !currentEnd.Equal(originalEnd) {
			return errors.New("positive renewal changed semantic identity or the in-flight original cutoff")
		}
		renewed = true
		// The separate scoped reader and owner observer must remain usable while
		// the bridge retains its original semantic/activation SHARE locks.
		accepted, readErr := reader.ReadOwnerConfiguration(call)
		if readErr != nil {
			var fixed *postgres.OwnerConfigurationReadFailure
			if errors.As(readErr, &fixed) {
				t.Logf("actual accepted-read refusal: check=%s reason=%s", fixed.Check(), fixed.Reason())
			}
			return fmt.Errorf("accepted owner read after positive fleet renewal: %w", readErr)
		}
		if !accepted.Configuration.Equal(configuration) || !accepted.ObservedAt.Equal(first.ObservedAt) || !accepted.Valid(time.Now()) {
			return errors.New("accepted owner read changed identity/original observation")
		}
		admitted = true
		second := ownerObservation()
		if e := observe(call, second); e != nil {
			return fmt.Errorf("second ordinary owner observation under unchanged bridge: %w", e)
		}
		var secondHead time.Time
		if e := admin.QueryRow(call, "SELECT observed_at FROM public.hub_owner_configuration WHERE installation_id=$1 AND cluster_id=$2", source.InstallationID, record.Scope.ClusterID).Scan(&secondHead); e != nil || !secondHead.Equal(second.ObservedAt) || !secondHead.After(firstHead) {
			return errors.New("second owner observation did not advance under held bridge")
		}
		var finalAudit string
		if e := admin.QueryRow(call, "SELECT audit_receipt_json::text FROM public.hub_owner_configuration_revision WHERE installation_id=$1 AND cluster_id=$2 AND source_uid=$3 AND generation=$4", source.InstallationID, record.Scope.ClusterID, configuration.Revision.UID, configuration.Revision.Generation).Scan(&finalAudit); e != nil || originalAudit != finalAudit {
			return errors.New("ordinary head observations replaced original acknowledged audit identity")
		}
		observedAfter = true
		return nil
	})
	if err != nil || !admitted || !renewed || !observedBefore || !observedAfter {
		t.Fatal("owner bridge independent read/observation availability", err, admitted, renewed, observedBefore, observedAfter)
	}
	freshSource := func() fleet.Administration {
		candidate := source
		candidate.ObservedAt = time.Now().UTC().Truncate(time.Microsecond)
		candidate.FreshUntil = candidate.ObservedAt.Add(5 * time.Second)
		return candidate
	}
	persist := func(call context.Context, candidate fleet.Administration) error {
		basis, e := projection.ReadAdministrationBasis(call)
		if e != nil {
			return e
		}
		return projection.ObserveAdministration(call, basis, candidate)
	}
	// The independent restrictive call outlives the bridge callback, but never
	// its own original five-second source/basis context. Release the bridge
	// before joining the writer; every failure path cancels and joins it first.
	restrict := func(kind string) error {
		current := freshSource()
		if e := persist(ctx, current); e != nil {
			return fmt.Errorf("independent current source before restrictive vector: %w", e)
		}
		basis, e := projection.ReadAdministrationBasis(ctx)
		if e != nil {
			return e
		}
		candidate := freshSource()
		candidate.Suspended = true
		started := time.Now()
		observationContext, stop := context.WithDeadline(ctx, identity.Earlier(basis.FreshUntil, candidate.FreshUntil))
		result := make(chan error, 1)
		launched, joined := false, false
		defer func() {
			stop()
			if launched && !joined {
				<-result
			}
		}()
		e = bridge.WithInitialRuntimeOwnerBridge(ctx, current, func(call context.Context) error {
			var bridgePID int32
			if e := admin.QueryRow(call, `SELECT pid FROM pg_stat_activity WHERE datname=current_database() AND application_name='asservat-runtime-guard-bridge' AND state='idle in transaction'`).Scan(&bridgePID); e != nil {
				return fmt.Errorf("identify actual retained restrictive blocker: %w", e)
			}
			launched = true
			go func() {
				if kind == "source" {
					result <- projection.ObserveAdministration(observationContext, basis, candidate)
				} else {
					result <- projection.FenceAdministration(observationContext, basis, started)
				}
			}()
			if _, e := ownerBridgeWaitForBlocker(call, admin, bridgePID, fleetPID, ""); e != nil {
				return fmt.Errorf("restrictive %s did not wait behind retained bridge: %w", kind, e)
			}
			t.Logf("actual restrictive %s wait edge: waiter=%d blocker=%d", kind, fleetPID, bridgePID)
			select {
			case e := <-result:
				joined = true
				return fmt.Errorf("restrictive %s completed before bridge release: %v", kind, e)
			default:
			}
			return nil
		})
		if e != nil {
			return e
		}
		if !launched {
			return errors.New("restrictive vector bridge skipped its callback")
		}
		e = <-result
		joined = true
		if e != nil {
			return fmt.Errorf("restrictive %s after original bridge release: %w", kind, e)
		}
		var version int64
		var suspended bool
		if e = admin.QueryRow(ctx, "SELECT semantic_version,suspended FROM public.fleet_trust WHERE installation_id=$1", source.InstallationID).Scan(&version, &suspended); e != nil || version != basis.SemanticVersion+1 || !suspended {
			return fmt.Errorf("restrictive %s did not commit the exact original version transition: %v", kind, e)
		}
		return nil
	}
	for _, kind := range []string{"source", "fence"} {
		if err = restrict(kind); err != nil {
			t.Fatal(err)
		}
	}
	// A successful newer observation cannot rescue an in-flight expired
	// operation. This is a separate short original source, never renewed work.
	current := freshSource()
	if err = persist(ctx, current); err != nil {
		t.Fatal("current source before original-end vector", err)
	}
	original := current
	original.FreshUntil = original.ObservedAt.Add(200 * time.Millisecond)
	var lateCalls int
	err = bridge.WithInitialRuntimeOwnerBridge(ctx, original, func(call context.Context) error {
		lateCalls++
		until, bounded := call.Deadline()
		if !bounded || !until.Equal(original.FreshUntil) {
			return errors.New("short original source cutoff changed")
		}
		renewal := freshSource()
		if e := persist(call, renewal); e != nil {
			return fmt.Errorf("positive renewal before original short expiry: %w", e)
		}
		var renewedUntil time.Time
		if e := admin.QueryRow(call, "SELECT fresh_until FROM public.fleet_current_trust WHERE installation_id=$1", source.InstallationID).Scan(&renewedUntil); e != nil || !renewedUntil.After(until) {
			return errors.New("expiry vector did not establish newer stored freshness")
		}
		currentEnd, _ := call.Deadline()
		if !currentEnd.Equal(until) {
			return errors.New("new stored freshness extended the original callback")
		}
		<-call.Done()
		return nil
	})
	if !errors.Is(err, cfg.ErrUnavailable) || lateCalls != 1 {
		t.Fatal("new positive observation rescued an expired original bridge", err, lateCalls)
	}
}
