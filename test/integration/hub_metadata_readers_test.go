package integration

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/postgres"
	app "asservat.local/asservat/internal/application/capacity"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/catalog"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Reuse the existing managed-capture fixture after real encrypted publication.
// The login, grants, rows and transactions are real; its protected Kubernetes
// observations and human identity remain synthetic. This is not installed proof.
func (f *capacitySQLFixture) qualifySharedMetadataReaders(t *testing.T, s captureAdmissionScenario, e artifact.ContextExpectation, enrollment app.Enrollment) {
	t.Helper()
	if !t.Run("compiled-shared-metadata-readers", func(t *testing.T) {
		// One new cold pool represents the hub's seven typed readers. The outer
		// fixture's independent setup pools remain unchanged for later scenarios.
		config := f.roles["hub-metadata-read"].Config()
		config.MaxConns, config.MinConns = 7, 0
		governor, err := postgres.NewSQLConnectionGovernor(32, 0)
		if err != nil || governor.Govern(config, false) != nil {
			t.Fatal("metadata connection governor unavailable", err)
		}
		pool, err := pgxpool.NewWithConfig(f.ctx, config)
		if err != nil {
			t.Fatal(err)
		}
		defer pool.Close() // joins cold connection disposal before this helper ends
		snapshot := f.root.value
		manifest := contracts.PublicRuntimeCredentialManifest{Format: contracts.PublicRuntimeCredentialManifestFormat, Input: snapshot.State.Input, RootUID: snapshot.UID, SetupID: snapshot.State.OperationID}
		for _, role := range snapshot.State.Roles {
			if slices.Contains(contracts.PublicRuntimeHubRolePurposes(), role.Purpose) {
				if role.Claim == nil || role.Receipt == nil {
					t.Fatal("original compiled role provenance missing")
				}
				manifest.Roles = append(manifest.Roles, contracts.PublicRuntimeCredentialProof{Purpose: role.Purpose, Claim: *role.Claim, Receipt: *role.Receipt})
			}
		}
		if err = postgres.VerifyPublicRuntimeCredential(f.ctx, pool, manifest, "hub-metadata-read"); err != nil {
			t.Fatal("actual metadata login/grant verification", err)
		}
		permission, err := postgres.NewPermissions(f.ctx, pool, s.a.RootID)
		if err != nil {
			t.Fatal(err)
		}
		retention, err := postgres.NewRetentionSources(f.ctx, pool, s.a.RootID)
		if err != nil {
			t.Fatal(err)
		}
		storage, err := postgres.NewContextStorageReader(f.ctx, pool, s.a.RootID)
		if err != nil {
			t.Fatal(err)
		}
		progress, err := postgres.NewContextProgressReads(f.ctx, pool, s.a.RootID, s.recovery.guard)
		if err != nil {
			t.Fatal(err)
		}
		cases, err := postgres.NewContextCaseReads(f.ctx, pool, s.a.RootID, s.recovery.guard)
		if err != nil {
			t.Fatal(err)
		}
		processing, err := postgres.NewProcessingReads(f.ctx, pool, s.a.RootID, s.recovery.guard)
		if err != nil {
			t.Fatal(err)
		}
		publications, err := postgres.NewContextPublications(f.ctx, pool, s.a.RootID)
		if err != nil {
			t.Fatal(err)
		}
		// Refresh only independent fixture sources before NEW read operations;
		// none of the following calls renews its identity, recovery or caller.
		f.refreshBase(t)
		if err = s.retention.observe(f.ctx); err != nil {
			t.Fatal(err)
		}
		if err = f.enrollments.RefreshCapacityEnrollment(f.ctx, f.workloadObservation(t, 0), enrollment); err != nil {
			t.Fatal(err)
		}
		call, cancel := context.WithTimeout(f.ctx, 5*time.Second)
		defer cancel()
		query := progressQuery(t, call, s)
		record, err := publications.ContextDownloadEvidence(call, e.Registration.Location.ArtifactID)
		if err != nil || record.CaptureID != e.CaptureUID {
			t.Fatal("published metadata input unavailable", err)
		}
		target := s.a.Plan.Input.Target.Target()
		checks := []struct {
			name string
			read func() error
		}{
			{"permission", func() error {
				out, err := permission.Permissions(call, target)
				if err == nil && (out.Target != target || !out.DeniesComplete || len(out.Allows) == 0 || !time.Now().Before(out.FreshUntil)) {
					return errors.New("permission projection mismatch")
				}
				return err
			}},
			{"retention", func() error {
				out, err := retention.AcceptedRetentionSource(call, s.a.RootID, s.retention.topology.source)
				if err == nil && (out.RootID != s.a.RootID || !out.Valid(time.Now())) {
					return errors.New("accepted retention projection mismatch")
				}
				return err
			}},
			{"storage", func() error {
				out, err := storage.ContextStorage(call, target)
				if err == nil && (out.Selection.AllocationID != e.Registration.AllocationID || !out.Binding.Matches(target) || !out.Binding.Valid(time.Now())) {
					return errors.New("managed storage projection mismatch")
				}
				return err
			}},
			{"progress", func() error {
				out, err := progress.ReadContextProgress(call, query)
				if err == nil && (out.CaptureID != e.CaptureUID || out.Phase != "Succeeded" || out.ReasonCode != "Published" || !out.Valid(time.Now())) {
					return errors.New("published progress projection mismatch")
				}
				return err
			}},
			{"case", func() error {
				out, err := cases.ResolveContextCase(call, catalog.CaseRouteQuery{RootID: s.a.RootID, CaseID: e.CaseID, Identity: query.Identity, Recovery: query.Recovery})
				if err == nil && (out.CaseID != e.CaseID || !out.Valid(time.Now()) || len(out.Routes) != 1 || out.Routes[0] != (catalog.ContextCaseRoute{CaptureID: e.CaptureUID, ArtifactID: e.Registration.Location.ArtifactID, Target: target})) {
					return errors.New("published case route mismatch")
				}
				return err
			}},
			{"processing", func() error {
				out, err := processing.ContextProcessing(call, record, query.Recovery)
				if err != nil {
					return err
				}
				if out.CaptureID != e.CaptureUID || out.Location != e.Registration.Location || !out.Valid(time.Now()) {
					return errors.New("processing lineage mismatch")
				}
				request := capture.ProcessingCoverageRequest{RootID: s.a.RootID, Location: e.Registration.Location, Target: target, AnchorAt: e.Registration.AnchorAt, DeleteBy: e.Registration.DeleteBy}
				covered, err := processing.ContextProcessingCoverage(call, request, query.Recovery)
				if err == nil && (covered.Request != request || !covered.Current(time.Now())) {
					return errors.New("processing coverage mismatch")
				}
				return err
			}},
			{"catalog", func() error {
				out, err := publications.RetainedAudience(call, e.Registration.Location.ArtifactID)
				if err != nil {
					return err
				}
				if out.ArtifactID != e.Registration.Location.ArtifactID || out.Target != target || len(out.Audience) == 0 {
					return errors.New("retained audience mismatch")
				}
				current, err := publications.ContextDownloadEvidence(call, out.ArtifactID)
				if err == nil && (current.CaptureID != e.CaptureUID || current.Retained.Registration.Location != e.Registration.Location || current.Version != record.Version) {
					return errors.New("published evidence projection mismatch")
				}
				return err
			}},
		}
		type result struct {
			name string
			err  error
		}
		start, results := make(chan struct{}), make(chan result, len(checks))
		for _, check := range checks {
			go func() { <-start; results <- result{check.name, check.read()} }()
		}
		close(start)
		for range checks {
			if got := <-results; got.err != nil {
				t.Error("concurrent compiled metadata reader", got.name, got.err)
			}
		}
		if t.Failed() {
			t.FailNow()
		}
		denied := query
		denied.Identity.Scopes = []string{"evidence:capture"}
		if out, err := progress.ReadContextProgress(call, denied); !errors.Is(err, capture.ErrDenied) || out.CaptureID != "" {
			t.Fatal("published metadata bypassed current identity scope", err)
		}
		for _, statement := range []string{
			`SELECT * FROM custody_copy LIMIT 0`,
			`UPDATE context_catalog SET published_at=published_at WHERE false`,
			`INSERT INTO context_capture SELECT * FROM context_capture WHERE false`,
			`DELETE FROM authority_audit WHERE false`,
			`UPDATE fleet_trust SET recovery_blocked=false WHERE false`,
			`SELECT advance_context_progress()`,
		} {
			if _, err = pool.Exec(call, statement); capacitySQLState(err) != "42501" {
				t.Fatalf("excluded metadata privilege: statement=%s sqlstate=%s", statement, capacitySQLState(err))
			}
		}
		qualifyMetadataPoolBound(t, call, pool)
		f.qualifyMetadataReadDeadline(t, pool, progress, query)
		t.Log("compiled_metadata_adapters=7 shared_pool_max=7 governor_limit=32 excluded_privileges_denied=true")
	}) {
		t.FailNow()
	}
}

func qualifyMetadataPoolBound(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()
	for round := 0; round < 2; round++ {
		var held []*pgxpool.Conn
		release := func() {
			for _, conn := range held {
				conn.Release()
			}
			held = nil
		}
		defer release()
		for range 7 {
			conn, err := pool.Acquire(ctx)
			if err != nil {
				t.Fatal("shared metadata pool could not acquire original seven slots", err)
			}
			held = append(held, conn)
		}
		if pool.Stat().AcquiredConns() != 7 || pool.Stat().TotalConns() != 7 {
			t.Fatal("shared metadata pool exceeded its original aggregate limit")
		}
		if round == 0 {
			wait, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
			extra, err := pool.Acquire(wait)
			cancel()
			if extra != nil {
				extra.Release()
			}
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Fatal("eighth metadata acquisition escaped its caller deadline", err)
			}
		}
		release()
	}
}

func (f *capacitySQLFixture) qualifyMetadataReadDeadline(t *testing.T, pool *pgxpool.Pool, reader *postgres.ContextProgressReads, original capture.ProgressQuery) {
	t.Helper()
	for _, kind := range []string{"caller", "identity", "cancellation"} {
		t.Run("original-"+kind+"-after-permission-lock", func(t *testing.T) {
			ctx, cancel := context.WithTimeout(f.ctx, 5*time.Second)
			defer cancel()
			tx, err := f.admin.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(f.ctx)
			var locked string
			if err = tx.QueryRow(ctx, `SELECT id::text FROM permission_stream WHERE id=$1 FOR UPDATE`, original.RootID).Scan(&locked); err != nil {
				t.Fatal(err)
			}
			query := original
			var call context.Context
			var stop context.CancelFunc
			if kind == "caller" {
				call, stop = context.WithTimeout(ctx, 400*time.Millisecond)
			} else {
				call, stop = context.WithCancel(ctx)
			}
			defer stop()
			if kind == "identity" {
				query.Identity.ValidUntil = time.Now().Add(400 * time.Millisecond)
			}
			result, joined := make(chan error, 1), make(chan struct{})
			defer func() { stop(); <-joined }()
			go func() {
				defer close(joined)
				out, err := reader.ReadContextProgress(call, query)
				if out.CaptureID != "" {
					err = errors.New("expired read returned capture metadata")
				}
				result <- err
			}()
			f.waitBlocked(t, pool.Config().ConnConfig.User, call)
			if kind == "cancellation" {
				stop()
			}
			if kind == "identity" {
				capacityWaitUntil(t, ctx, query.Identity.ValidUntil.Add(time.Millisecond))
				if err = tx.Rollback(ctx); err != nil {
					t.Fatal(err)
				}
			}
			select {
			case err = <-result:
				want := capture.ErrUnavailable
				if kind == "identity" {
					want = capture.ErrDenied
				}
				if !errors.Is(err, want) {
					t.Fatal("metadata read did not preserve original cutoff", kind, err)
				}
			case <-ctx.Done():
				t.Fatal("expired metadata read did not join")
			}
		})
	}
}
