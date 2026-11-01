package integration

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/adapters/postgres"
	app "asservat.local/asservat/internal/application/capacity"
	"asservat.local/asservat/internal/domain/artifact"
	capturevalue "asservat.local/asservat/internal/domain/capture"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/fleet"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

func qualifyCapacityProducerSQL(t *testing.T, ctx context.Context, admin *pgxpool.Pool, address string, tlsConfig *tls.Config, scope fleet.InstallationWitnessScope, claim string, administration fleet.Administration, objects *objectstore.AuthorityObjects) {
	t.Helper()
	if !t.Run("root-configuration-digest-state", func(t *testing.T) {
		qualifyCapacityRootConfigurationSQL(t, ctx, admin)
	}) {
		return
	}
	if !t.Run("lifecycle-policy-timestamp-wire", func(t *testing.T) { qualifyCapacityPolicyTimestampSQL(t, ctx, admin) }) {
		return
	}
	f := newCapacitySQLFixture(t, ctx, admin, address, tlsConfig, scope, claim, administration, objects)
	// Stop dependent cases after any prerequisite failure. A later missing row
	// must not hide the actual first failed role/SQL phase.
	if !t.Run("actual-paired-root-and-lost-receipt", func(t *testing.T) {
		f.root.lostSetupReceipt = true
		if _, err := f.producer.InitializeCapacity(ctx, f.input, f.protection); err == nil {
			t.Fatal("lost setup receipt returned success")
		}
		var sources, captures int
		if err := admin.QueryRow(ctx, `SELECT (SELECT count(*) FROM capacity_source WHERE root_id=$1),(SELECT count(*) FROM capture_audit_root WHERE root_id=$1)`, f.input.PermissionRootID).Scan(&sources, &captures); err != nil {
			t.Fatal(err)
		}
		if sources != 1 || captures != 1 {
			t.Fatalf("original paired SQL write missing: source=%d capture=%d", sources, captures)
		}
		original := *f.root.value.State.CapacitySetup
		f.refreshBase(t)
		receipt, err := f.producer.InitializeCapacity(ctx, f.input, f.protection)
		if err != nil {
			t.Fatal("exact committed setup recovery", err)
		}
		if receipt.OperationID != original.OperationID || !receipt.ClaimedAt.Equal(original.ClaimedAt) || !receipt.Until.Equal(original.Until) || f.root.setupClaims != 1 || f.root.setupReceipts != 1 {
			t.Fatal("setup recovery replaced original claim")
		}
		changed := f.input
		changed.SourceGuardDigest = capacityGuardHex([32]byte{99})
		if _, err = f.producer.InitializeCapacity(ctx, changed, f.protection); err == nil {
			t.Fatal("changed setup adopted original roots")
		}
	}) {
		return
	}
	f.open(t)
	if !t.Run("exact-purpose-roles-and-no-private-marker", func(t *testing.T) {
		checks := map[string][]string{
			"capacity":              {"SELECT * FROM capture_audit_root LIMIT 0", "UPDATE capture_audit_allocation SET valid_until=valid_until WHERE false", "SELECT public.back_capacity_root(NULL,NULL,NULL,NULL,NULL)", "SELECT public.capacity_role_ok(NULL,'capacity')", "UPDATE capacity_source SET root_mutation_xid=pg_current_xact_id() WHERE false"},
			"capacity-capture":      {"SELECT * FROM permission_stream LIMIT 0", "SELECT public.reserve_capacity_root(NULL,NULL,NULL,NULL,NULL)", "UPDATE capacity_workload SET mutation_xid=pg_current_xact_id() WHERE false"},
			"capacity-profile-read": {"UPDATE capacity_source SET suspended=false WHERE false", "SELECT public.reserve_capacity_root(NULL,NULL,NULL,NULL,NULL)"},
		}
		for purpose, queries := range checks {
			for _, query := range queries {
				_, err := f.roles[purpose].Exec(ctx, query)
				var driver *pgconn.PgError
				if !errors.As(err, &driver) || driver.Code != "42501" {
					t.Fatalf("expected actual scoped denial: purpose=%s sqlstate=%s", purpose, capacitySQLState(err))
				}
			}
		}
		for _, purpose := range []string{"capacity", "capacity-capture", "capture-cleanup", "capture-verifier", "capture-finalizer"} {
			var limit int
			var memberships int
			role := f.roles[purpose].Config().ConnConfig.User
			if err := admin.QueryRow(ctx, `SELECT rolconnlimit,(SELECT count(*) FROM pg_auth_members WHERE member=p.oid) FROM pg_roles p WHERE rolname=$1`, role).Scan(&limit, &memberships); err != nil || limit != 3 || memberships != 0 {
				t.Fatal("actual purpose connection/membership envelope differs", purpose, err)
			}
			f.assertThreeConnections(t, purpose)
		}
	}) {
		return
	}
	if !t.Run("capacity-current-owner-registry", func(t *testing.T) { f.checkCapacityOwnerRegistry(t) }) {
		return
	}
	var root app.RootConfiguration
	if !t.Run("three-root-phases-do-not-publish-early", func(t *testing.T) {
		o := f.rootObservation(t)
		start := time.Now()
		var err error
		root, err = f.roots.ReserveCapacityRoot(ctx, o)
		if err != nil {
			t.Fatal("root reserve", err)
		}
		if !root.Valid() || root.CaptureBackedAt != nil || root.ReadyAt != nil {
			t.Fatal("reserve published root")
		}
		var processingInitialized bool
		if err = admin.QueryRow(ctx, `SELECT initialized_at IS NOT NULL FROM processing_root WHERE root_id=$1`, f.input.PermissionRootID).Scan(&processingInitialized); err != nil || processingInitialized {
			t.Fatal("capacity initialized processing authority", err)
		}
		if _, err = f.roots.PublishCapacityRoot(ctx, o, root); err == nil {
			t.Fatal("general role published without capture backing")
		}
		root, err = f.captureRoots.BackCapacityRoot(ctx, o, root)
		if err != nil {
			t.Fatal("root capture backing", err)
		}
		if root.CaptureBackedAt == nil || root.ReadyAt != nil {
			t.Fatal("capture role published readiness")
		}
		root, err = f.roots.PublishCapacityRoot(ctx, o, root)
		if err != nil || !root.AdmissionReady(time.Now()) {
			t.Fatal("complete root publication", err)
		}
		t.Logf("root_three_phases_ms=%d original_remaining_ms=%d", time.Since(start).Milliseconds(), time.Until(o.FreshUntil).Milliseconds())
	}) {
		return
	}
	var first, second app.Enrollment
	var firstObservation app.EnrollmentObservation
	var assertFirstExpired func(*testing.T)
	if !t.Run("first-workload-unknown-capture-completion", func(t *testing.T) {
		o := f.workloadObservation(t, 0)
		start := time.Now()
		var err error
		first, err = f.enrollments.ReserveCapacityEnrollment(ctx, o)
		if err != nil {
			t.Fatal("workload reserve", err)
		}
		f.assertAdmission(t, 0, first, false)
		if _, err = f.enrollments.PublishCapacityEnrollment(ctx, o, first); err == nil {
			t.Fatal("published without original capture phase")
		}
		lost := &capacityLostCaptureReply{inner: f.captureEnrollments}
		if _, err = lost.BackCapacityCapture(ctx, o, first); err == nil {
			t.Fatal("injected lost committed reply returned success")
		}
		f.assertAdmission(t, 0, first, false)
		original := first
		// A new current invocation reads committed phase facts. It must not issue a
		// second capture write after the original committed response was lost.
		o = f.workloadObservation(t, 0)
		coordinator := app.EnrollmentCoordinator{Store: f.enrollments, Capture: lost, Accounts: f.accounts, Now: time.Now}
		first, err = coordinator.Reconcile(ctx, o)
		if err != nil {
			t.Fatal("exact committed continuation", err)
		}
		if first.ID != original.ID || first.AttemptID != original.AttemptID || first.AllocationID != original.AllocationID || !first.InitialUntil.Equal(original.InitialUntil) || lost.calls != 1 {
			t.Fatal("unknown reply repeated spend or original identity")
		}
		firstObservation = o
		assertFirstExpired = qualifyInitialBindingProjection(t, f, o, first)
		f.assertAdmission(t, 0, first, true)
		t.Logf("workload_three_phases_with_lookup_ms=%d original_remaining_ms=%d", time.Since(start).Milliseconds(), time.Until(o.FreshUntil).Milliseconds())
	}) {
		return
	}
	if !t.Run("second-workload-concurrent-reserve-and-expired-phase", func(t *testing.T) {
		// Two retained reconcilers have distinct one-connection pools. A single
		// shared pool would merely serialize callers before reaching SQL locks.
		credential := f.roles["capacity"].Config().ConnConfig
		otherPool := f.fixturePool(credential.User, credential.Password)
		other, err := postgres.NewCapacityEnrollments(ctx, otherPool, f.input.PermissionRootID, f.input.InstallationID, f.accounts)
		if err != nil {
			t.Fatal(err)
		}
		o := f.workloadObservation(t, 1)
		type outcome struct {
			v   app.Enrollment
			err error
		}
		out := make(chan outcome, 2)
		for _, writer := range []*postgres.CapacityEnrollments{f.enrollments, other} {
			go func() { v, err := writer.ReserveCapacityEnrollment(ctx, o); out <- outcome{v, err} }()
		}
		a, b := <-out, <-out
		if a.err != nil || b.err != nil || !reflect.DeepEqual(a.v, b.v) {
			t.Fatal("concurrent exact reserve did not converge", a.err, b.err)
		}
		second = a.v
		f.assertAdmission(t, 1, second, false)
		// Real elapsed original intervals; no UPDATE/backdating of persisted facts.
		expiredAt := second.InitialUntil
		if firstObservation.FreshUntil.After(expiredAt) {
			expiredAt = firstObservation.FreshUntil
		}
		capacityWaitUntil(t, ctx, expiredAt.Add(10*time.Millisecond))
		if assertFirstExpired != nil {
			assertFirstExpired(t)
		}
		if _, err := f.captureEnrollments.BackCapacityCapture(ctx, o, second); err == nil {
			t.Fatal("expired original phase issued an effect")
		}
		o = f.workloadObservation(t, 1)
		resumed, err := (&app.EnrollmentCoordinator{Store: f.enrollments, Capture: f.captureEnrollments, Accounts: f.accounts, Now: time.Now}).Reconcile(ctx, o)
		if err != nil {
			t.Fatal("fresh current compatible SQL continuation", err)
		}
		if resumed.ID != second.ID || resumed.AttemptID != second.AttemptID || resumed.AllocationID != second.AllocationID || !resumed.InitialUntil.Equal(second.InitialUntil) || !resumed.ReservedAt.Equal(second.ReservedAt) {
			t.Fatal("continuation reset original configuration")
		}
		second = resumed
		f.assertAdmission(t, 1, second, true)
		var accounts int
		if err = admin.QueryRow(ctx, `SELECT accounts FROM capacity_pool WHERE root_id=$1`, f.input.PermissionRootID).Scan(&accounts); err != nil || accounts != 2 {
			t.Fatal("concurrent continuation changed parent charge", accounts, err)
		}
	}) {
		return
	}
	t.Run("current-binding-refresh-does-not-recharge", func(t *testing.T) {
		before := f.accounting(t)
		o := f.workloadObservation(t, 0)
		if err := f.enrollments.RefreshCapacityEnrollment(ctx, o, first); err != nil {
			t.Fatal("current exact binding observation", err)
		}
		f.assertAdmission(t, 0, first, true)
		// ADR-200 revision (2026-10-23): the refreshed binding lives 30
		// seconds from its own observation, independent of the caller receipt.
		var lifetime bool
		if err := admin.QueryRow(ctx, `SELECT fresh_until-observed_at=interval '30 seconds' FROM context_storage_binding WHERE root_id=$1 AND allocation_id=$2`, f.input.PermissionRootID, first.AllocationID).Scan(&lifetime); err != nil || !lifetime {
			t.Fatal("refreshed binding lifetime", lifetime, err)
		}
		// Migration 00073: the accepted root source observation likewise lives
		// 30 seconds from its own observation.
		if err := admin.QueryRow(ctx, `SELECT fresh_until-observed_at=interval '30 seconds' FROM capacity_source WHERE root_id=$1 AND NOT suspended`, f.input.PermissionRootID).Scan(&lifetime); err != nil || !lifetime {
			t.Fatal("accepted source lifetime", lifetime, err)
		}
		after := f.accounting(t)
		if before != after {
			t.Fatal("binding observation changed fixed backing or charges")
		}
	})
	t.Run("held-source-original-caller-expiry", func(t *testing.T) {
		o := f.workloadObservation(t, 0)
		tx, err := admin.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(ctx)
		var locked string
		if err = tx.QueryRow(ctx, `SELECT root_id::text FROM capacity_source WHERE root_id=$1 FOR UPDATE`, f.input.PermissionRootID).Scan(&locked); err != nil {
			t.Fatal(err)
		}
		bounded, end := context.WithTimeout(ctx, 700*time.Millisecond)
		defer end()
		result := make(chan error, 1)
		joined := make(chan struct{})
		defer func() { end(); <-joined }()
		go func() { defer close(joined); _, e := f.enrollments.ReadCapacityEnrollment(bounded, o); result <- e }()
		f.waitBlocked(t, f.roles["capacity"].Config().ConnConfig.User, bounded)
		select {
		case err = <-result:
			if err == nil {
				t.Fatal("read escaped original held-lock deadline")
			}
		case <-ctx.Done():
			t.Fatal("held-lock child not joined")
		}
		if err = tx.Rollback(ctx); err != nil {
			t.Fatal(err)
		}
		after, err := f.enrollments.ReadCapacityEnrollment(ctx, f.workloadObservation(t, 0))
		if err != nil || after == nil || !reflect.DeepEqual(*after, first) {
			t.Fatal("expired read changed original enrollment", err)
		}
	})
	if t.Failed() {
		return
	}
	var session capacityManagedSession
	var sessionPrepared bool
	if !t.Run("actual-managed-context-publication-and-original-session", func(t *testing.T) {
		session = f.managedDownloadSession(t, root, first)
		sessionPrepared = true
	}) {
		return
	}
	// A filtered child did not prepare a session for the dependent renewal.
	if !sessionPrepared {
		return
	}
	if !t.Run("fill-provisional-account-envelope-with-retained-spend", func(t *testing.T) {
		for index := 2; index < len(f.workloads); index++ {
			o := f.workloadObservation(t, index)
			start := time.Now()
			enrolled, err := (&app.EnrollmentCoordinator{Store: f.enrollments, Capture: f.captureEnrollments, Accounts: f.accounts, Now: time.Now}).Reconcile(ctx, o)
			if err != nil {
				t.Fatalf("account index=%d original_elapsed_ms=%d unavailable: %v", index, time.Since(start).Milliseconds(), err)
			}
			f.additional = append(f.additional, enrolled)
			f.assertAdmission(t, index, enrolled, true)
			t.Logf("account_index=%d elapsed_ms=%d original_remaining_ms=%d", index, time.Since(start).Milliseconds(), time.Until(o.FreshUntil).Milliseconds())
		}
		var count int
		if err := admin.QueryRow(ctx, `SELECT accounts FROM capacity_pool WHERE root_id=$1`, f.input.PermissionRootID).Scan(&count); err != nil || count != capacityNativeAccounts {
			t.Fatal("provisional account envelope incomplete", count, err)
		}
	}) {
		return
	}
	f.qualifyRenewal(t, root, first, second, session)
	if !t.Failed() {
		f.qualifyRegionalExtension(t, first)
	}
}

func (f *capacitySQLFixture) assertThreeConnections(t *testing.T, purpose string) {
	t.Helper()
	ctx, end := context.WithTimeout(f.ctx, 5*time.Second)
	defer end()
	// Keep the exact original runtime pool connection checked out while two
	// additional connections represent the other process and serialized verifier.
	held, err := f.roles[purpose].Acquire(ctx)
	if err != nil {
		t.Fatal("first compartment connection", purpose, err)
	}
	defer held.Release()
	config := f.roles[purpose].Config().ConnConfig
	var joined []*pgx.Conn
	defer func() {
		clean, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		for _, c := range joined {
			if err := c.Close(clean); err != nil {
				t.Error("compartment connection cleanup", purpose, err)
			}
		}
	}()
	for i := 0; i < 2; i++ {
		c, err := pgx.ConnectConfig(ctx, config.Copy())
		if err != nil {
			t.Fatal("retained-process/verifier connection envelope", purpose, err)
		}
		joined = append(joined, c)
	}
	extra, err := pgx.ConnectConfig(ctx, config.Copy())
	if extra != nil {
		joined = append(joined, extra)
	}
	var driver *pgconn.PgError
	if !errors.As(err, &driver) || driver.Code != "53300" {
		t.Fatalf("excess compartment connection not denied: purpose=%s sqlstate=%s", purpose, capacitySQLState(err))
	}
}

type capacityLostCaptureReply struct {
	inner *postgres.CapacityCaptureEnrollments
	calls int
}

func (s *capacityLostCaptureReply) BackCapacityCapture(ctx context.Context, o app.EnrollmentObservation, e app.Enrollment) (app.Enrollment, error) {
	s.calls++
	v, err := s.inner.BackCapacityCapture(ctx, o, e)
	if err != nil {
		return v, err
	}
	return app.Enrollment{}, cfg.ErrUnavailable
}
func (s *capacityLostCaptureReply) ContinueCapacityCapture(ctx context.Context, o app.EnrollmentObservation, e app.Enrollment) (app.Enrollment, error) {
	s.calls++
	return s.inner.ContinueCapacityCapture(ctx, o, e)
}

func (f *capacitySQLFixture) assertAdmission(t *testing.T, index int, e app.Enrollment, want bool) {
	t.Helper()
	target := capacityNativeStorageTarget(f.input.ControlClusterID, f.namespace, f.workloads[index])
	if !target.Valid() {
		t.Fatal("native storage target invalid before readiness assertion")
	}
	f.assertLegacyAdmission(t, e, want)
	reader, err := postgres.NewContextStorageReader(f.ctx, f.roles["hub-runtime"], f.input.PermissionRootID)
	if err != nil {
		t.Fatal(err)
	}
	_, err = reader.ContextStorage(f.ctx, target)
	if errors.Is(err, capturevalue.ErrInvalid) {
		t.Fatal("invalid request did not exercise the SQL admission fence")
	}
	if (err == nil) != want {
		t.Fatalf("current storage reader readiness=%t want=%t error=%v", err == nil, want, err)
	}
	for _, purpose := range []string{"hub-runtime", "capture-admit"} {
		for _, kind := range []string{"context", "download"} {
			allocation := e.AllocationID
			if kind == "download" {
				allocation = e.DownloadAllocationID
			}
			var ready bool
			if err = f.roles[purpose].QueryRow(f.ctx, `SELECT COALESCE(clock_timestamp()<public.capacity_managed_admission_until($1,$2,$3,clock_timestamp()),false)`, f.input.PermissionRootID, allocation, kind).Scan(&ready); err != nil || ready != want {
				t.Fatalf("shared managed fence purpose=%s kind=%s ready=%t want=%t sqlstate=%s", purpose, kind, ready, want, capacitySQLState(err))
			}
		}
	}
}

// Exercise the ordinary custody consumer as well as the shared SQL read fence.
// Positive registration reserves real original bytes/objects but writes no
// evidence; those uncertain reservations remain charged through renewal.
func (f *capacitySQLFixture) assertLegacyAdmission(t *testing.T, e app.Enrollment, want bool) {
	t.Helper()
	if _, ok := f.registered[e.AllocationID]; want && ok {
		return
	}
	n := time.Now().UTC().Truncate(time.Microsecond)
	r := artifact.Registration{Location: artifact.Location{ClusterID: e.Key.ClusterID, ArtifactID: custodyID(), AttemptID: custodyID()}, StoreID: f.qualification.Backends[0].EvidenceStoreID, AllocationID: e.AllocationID, NativeLimit: 4096, AnchorAt: n, WriteUntil: n.Add(time.Second), ExpiresAt: n.Add(time.Minute), DeleteBy: n.Add(2 * time.Minute)}
	if err := f.admin.QueryRow(f.ctx, `SELECT p.revision,a.revision FROM custody_allocation a JOIN custody_pool p ON p.id=a.pool_id WHERE a.id=$1`, e.AllocationID).Scan(&r.PoolRevision, &r.AllocationRevision); err != nil {
		t.Fatal(err)
	}
	if err := r.Validate(); err != nil {
		t.Fatal("native legacy registration invalid before admission assertion", err)
	}
	_, err := f.legacy.Register(f.ctx, r)
	if errors.Is(err, artifact.ErrInvalid) {
		t.Fatal("invalid registration did not exercise the SQL admission fence")
	}
	if (err == nil) != want {
		t.Fatalf("legacy custody admission success=%t want=%t error=%v", err == nil, want, err)
	}
	if want {
		f.registered[e.AllocationID] = r
	}
}

func (f *capacitySQLFixture) accounting(t *testing.T) string {
	t.Helper()
	var b []byte
	err := f.admin.QueryRow(f.ctx, `SELECT jsonb_build_object('pools',(SELECT jsonb_agg(to_jsonb(x) ORDER BY id) FROM capacity_pool x WHERE root_id=$1),'clusters',(SELECT jsonb_agg(to_jsonb(x) ORDER BY pool_id,cluster_id) FROM capacity_cluster x WHERE root_id=$1),'namespaces',(SELECT jsonb_agg(to_jsonb(x) ORDER BY pool_id,cluster_id,namespace_uid) FROM capacity_namespace x WHERE root_id=$1),'workloads',(SELECT jsonb_agg(to_jsonb(x) ORDER BY id) FROM capacity_workload x WHERE root_id=$1))`, f.input.PermissionRootID).Scan(&b)
	if err != nil || !json.Valid(b) {
		t.Fatal("bounded accounting read unavailable", err)
	}
	return string(b)
}

func (f *capacitySQLFixture) waitBlocked(t *testing.T, role string, ctx context.Context) {
	t.Helper()
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for {
		var waiting bool
		if err := f.admin.QueryRow(f.ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE usename=$1 AND cardinality(pg_blocking_pids(pid))>0)`, role).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatal("intended SQL lock was not reached")
		case <-ticker.C:
		}
	}
}
func capacityWaitUntil(t *testing.T, ctx context.Context, until time.Time) {
	t.Helper()
	timer := time.NewTimer(time.Until(until))
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-ctx.Done():
		t.Fatal("original-time wait cancelled")
	}
}
func capacitySQLState(err error) string {
	var p *pgconn.PgError
	if errors.As(err, &p) {
		return p.Code
	}
	if err != nil {
		return "none"
	}
	return "success"
}
