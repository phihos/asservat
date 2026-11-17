package integration

import (
	"context"
	"errors"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/postgres"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/catalog"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Reuse the existing managed-capture fixture after real encrypted publication.
// The login, grants, rows and transactions are real; its protected Kubernetes
// observations and human identity remain synthetic. This is not installed proof.
func (f *capacitySQLFixture) qualifySharedMetadataReaders(t *testing.T, s captureAdmissionScenario, e artifact.ContextExpectation, enrollment capacityEnrollment) {
	t.Helper()
	if !t.Run("compiled-shared-metadata-readers", func(t *testing.T) {
		// One ordinary hub pool serves the seven typed readers. The outer
		// fixture's independent setup pools remain unchanged for later scenarios.
		config := f.roles["hub-runtime"].Config()
		pools := governedOrdinaryHubPools(t, f.ctx, config)
		pool := pools
		var err error
		defer pool.Close() // joins the ordinary pool before this helper ends
		// The login's grants are the compiled plan: setup reconciled them exactly.
		permission, err := postgres.NewPermissions(f.ctx, pool, s.a.RootID)
		if err != nil {
			t.Fatal(err)
		}
		retention, err := postgres.NewRetentionPolicies(f.ctx, pool)
		if err != nil {
			t.Fatal(err)
		}
		storage, err := postgres.NewContextStorageReader(f.ctx, pool, s.a.RootID)
		if err != nil {
			t.Fatal(err)
		}
		progress, err := postgres.NewContextProgressReads(f.ctx, pool, s.a.RootID)
		if err != nil {
			t.Fatal(err)
		}
		cases, err := postgres.NewContextCaseReads(f.ctx, pool, s.a.RootID)
		if err != nil {
			t.Fatal(err)
		}
		processing, err := postgres.NewProcessingReads(f.ctx, pool, s.a.RootID, s.recovery.installation)
		if err != nil {
			t.Fatal(err)
		}
		publications, err := postgres.NewContextPublications(f.ctx, pool, s.a.RootID)
		if err != nil {
			t.Fatal(err)
		}
		// Refresh only independent fixture sources before NEW read operations;
		// none of the following calls renews its identity or caller.
		f.refreshBase(t)
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
				_, err := retention.CurrentRetentionPolicies(call)
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
				out, err := cases.ResolveContextCase(call, catalog.CaseRouteQuery{RootID: s.a.RootID, CaseID: e.CaseID, Identity: query.Identity})
				if err == nil && (out.CaseID != e.CaseID || !out.Valid(time.Now()) || len(out.Routes) != 1 || out.Routes[0] != (catalog.ContextCaseRoute{Version: record.Version, CaptureID: e.CaptureUID, ArtifactID: e.Registration.Location.ArtifactID, NativeType: e.NativeType, Target: target})) {
					return errors.New("published case route mismatch")
				}
				return err
			}},
			{"processing", func() error {
				out, err := processing.ContextProcessing(call, record)
				if err != nil {
					return err
				}
				if out.CaptureID != e.CaptureUID || out.Location != e.Registration.Location || !out.Valid(time.Now()) {
					return errors.New("processing lineage mismatch")
				}
				request := capture.ProcessingCoverageRequest{RootID: s.a.RootID, Location: e.Registration.Location, Target: target, AnchorAt: e.Registration.AnchorAt, DeleteBy: e.Registration.DeleteBy}
				covered, err := processing.ContextProcessingCoverage(call, request)
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
			`UPDATE context_catalog SET published_at=published_at WHERE false`,
			`INSERT INTO context_capture SELECT * FROM context_capture WHERE false`,
			`DELETE FROM authority_audit WHERE false`,
			`UPDATE fleet_trust SET issuer_epoch=issuer_epoch WHERE false`,
			`SELECT advance_context_progress()`,
		} {
			if _, err = pool.Exec(call, statement); capacitySQLState(err) != "42501" {
				t.Fatalf("excluded metadata privilege: statement=%s sqlstate=%s", statement, capacitySQLState(err))
			}
		}
		// Both compiled execution cases qualify this shared pool helper
		// at its full 18+2 bound. Keep this fixture focused on all seven
		// readers while independent capacity setup pools remain in use.
		if pool.Config().MaxConns != contracts.PublicRuntimeHubOrdinaryConnections {
			t.Fatal("shared metadata pool size differs from the installed hub")
		}
		f.qualifyMetadataReadDeadline(t, pool, progress, query)
		t.Log("compiled_metadata_adapters=7 shared_hub_pool_max=18 governor_limit=32 excluded_privileges_denied=true")
	}) {
		t.FailNow()
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
