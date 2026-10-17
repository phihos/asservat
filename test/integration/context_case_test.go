package integration

import (
	"context"
	"errors"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/postgres"
	captureapp "asservat.local/asservat/internal/application/capture"
	catalogapp "asservat.local/asservat/internal/application/catalog"
	identities "asservat.local/asservat/internal/application/identity"
	privacyapp "asservat.local/asservat/internal/application/privacy"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/catalog"
	"asservat.local/asservat/internal/domain/identity"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Actual publication, SQL routing, current accepted permission provenance and
// retained-policy composition. Human/provider and installation bootstrap remain
// the existing explicit fixture inputs; no fixture identity enables runtime.
func qualifyContextCase(t *testing.T, ctx context.Context, admin *pgxpool.Pool, poolFor func(string, string) *pgxpool.Pool, s captureAdmissionScenario, e artifact.ContextExpectation, reader *postgres.ContextPublications, publish func() error) {
	t.Helper()
	pool := poolFor("context_case_read_runtime", "synthetic-context-case-read")
	defer pool.Close()
	routes, err := postgres.NewContextCaseReads(ctx, pool, s.a.RootID, s.recovery.guard)
	if err != nil {
		t.Fatal(err)
	}
	processing, err := postgres.NewProcessingReads(ctx, pool, s.a.RootID, s.recovery.guard)
	if err != nil {
		t.Fatal(err)
	}
	service := catalogapp.ContextCaseService{RootID: s.a.RootID, InstallationID: s.recovery.installation, Routes: routes, Permissions: s.p, Catalog: reader, Retention: privacyapp.RetentionResolver{RetainedPolicies: s.retention, Now: time.Now}, Recovery: s.recovery.reader, Processing: processing, Now: time.Now}
	current := func(edit func(*identity.Identity)) identities.CurrentIdentity {
		t.Helper()
		now := time.Now().UTC().Truncate(time.Microsecond)
		batch := s.batch
		batch.Initial = nil
		batch.ObservedAt = now
		batch.FreshUntil = now.Add(5 * time.Second)
		if err := s.p.RefreshPermissions(ctx, batch); err != nil {
			t.Fatal(err)
		}
		i := s.a.Eligibility.VerifiedIdentity
		i.Scopes = []string{"evidence:read"}
		i.VerifiedAt = now
		i.ValidUntil = now.Add(5 * time.Second)
		if edit != nil {
			edit(&i)
		}
		source, _, err := identities.NewBearerRequest(ctx, downloadTestIdentity{i}, "synthetic-reference", time.Now)
		if err != nil {
			t.Fatal(err)
		}
		return source
	}
	query := func() value.CaseRouteQuery {
		t.Helper()
		q := progressQuery(t, ctx, s)
		return value.CaseRouteQuery{RootID: s.a.RootID, CaseID: e.CaseID, Identity: q.Identity, Recovery: q.Recovery}
	}
	var count int
	if err = admin.QueryRow(ctx, "SELECT count(*) FROM context_case_locator WHERE root_id=$1 AND case_id=$2", s.a.RootID, e.CaseID).Scan(&count); err != nil || count != 0 {
		t.Fatal("unpublished custody became a case", count, err)
	}
	if got, err := routes.ResolveContextCase(ctx, query()); err != value.ErrUnavailable || len(got.Routes) != 0 {
		t.Fatal("unpublished route disclosed", got, err)
	}
	for _, sql := range []string{
		"INSERT INTO context_case_locator SELECT * FROM context_case_locator LIMIT 0",
		"UPDATE context_case_locator SET case_id=case_id",
		"DELETE FROM context_case_locator",
		"UPDATE context_catalog SET published_at=published_at",
		"UPDATE context_capture SET deadline=deadline",
		"SELECT expectation_json FROM context_capture LIMIT 0",
		"SELECT project_context_case_locator()",
		"SELECT protect_context_case_locator()",
	} {
		_, err := pool.Exec(ctx, sql)
		var pgerr *pgconn.PgError
		if !errors.As(err, &pgerr) || pgerr.Code != "42501" {
			t.Fatalf("case reader excess privilege %s: %v", sql, err)
		}
	}
	var pinned, private bool
	if err = admin.QueryRow(ctx, "SELECT proconfig=ARRAY['search_path=pg_catalog, pg_temp']::text[], NOT EXISTS(SELECT 1 FROM aclexplode(COALESCE(proacl,acldefault('f',proowner))) a WHERE a.grantee=0 AND a.privilege_type='EXECUTE') FROM pg_proc WHERE oid='project_context_case_locator()'::regprocedure").Scan(&pinned, &private); err != nil || !pinned || !private {
		t.Fatal("unprotected routing trigger", pinned, private, err)
	}
	if err = publish(); err != nil {
		t.Fatal(err)
	}
	got, err := service.GetContextCase(ctx, current(nil), e.CaseID)
	if err != nil || !got.Valid(time.Now()) || got.CaseID != e.CaseID || len(got.Artifacts) != 1 || got.Artifacts[0].ArtifactID != e.Registration.Location.ArtifactID || got.Artifacts[0].CaptureID != e.CaptureUID || !got.Artifacts[0].ExpiresAt.Equal(e.Registration.ExpiresAt) {
		t.Fatalf("authorized case: %+v %v", got, err)
	}
	verified, err := reader.ContextDownloadEvidence(ctx, e.Registration.Location.ArtifactID)
	if err != nil || got.Artifacts[0].Version != verified.Version {
		t.Fatal("case version is not verified artifact version", err)
	}
	if err = publish(); err != nil {
		t.Fatal(err)
	}
	if err = admin.QueryRow(ctx, "SELECT count(*) FROM context_case_locator WHERE root_id=$1 AND case_id=$2", s.a.RootID, e.CaseID).Scan(&count); err != nil || count != 1 {
		t.Fatal("publication replay duplicated case locator", count, err)
	}
	for _, sql := range []string{"UPDATE context_case_locator SET case_id=case_id WHERE capture_id=$1", "DELETE FROM context_case_locator WHERE capture_id=$1"} {
		if _, err = admin.Exec(ctx, sql, e.CaptureUID); err == nil {
			t.Fatal("locator mutation silently permitted")
		}
	}
	for _, name := range []string{"no-read-scope", "foreign-user", "other-owner-team", "unknown-case"} {
		source := current(func(i *identity.Identity) {
			switch name {
			case "no-read-scope":
				i.Scopes = []string{"evidence:capture"}
			case "foreign-user":
				i.Principal.Subject = "stranger"
				i.Groups = nil
			case "other-owner-team":
				i.Groups = []string{"other-owners"}
			}
		})
		caseID := e.CaseID
		if name == "unknown-case" {
			caseID = custodyID()
		}
		view, err := service.GetContextCase(ctx, source, caseID)
		if name == "other-owner-team" {
			if err != nil || len(view.Artifacts) != 1 {
				t.Fatal("original second owner lost ordinary evidence", err)
			}
		} else if err != value.ErrUnavailable || view.CaseID != "" {
			t.Fatal("unauthorized case metadata", name, view, err)
		}
	}
	progressPool := poolFor("context_progress_read_runtime", "synthetic-context-progress-read")
	defer progressPool.Close()
	progress, err := postgres.NewContextProgressReads(ctx, progressPool, s.a.RootID, s.recovery.guard)
	if err != nil {
		t.Fatal(err)
	}
	source := current(nil)
	p, err := progress.ReadContextProgress(ctx, progressQuery(t, ctx, s))
	if err != nil {
		t.Fatal(err)
	}
	link, err := (captureapp.ContextCaseNavigator{Cases: service, Now: time.Now}).ContextCaseNavigation(ctx, source, p)
	if err != nil || link.CaseID != e.CaseID || link.ValidUntil.After(p.ValidUntil) {
		t.Fatal("published authorized case link", link, err)
	}
	// Waiting on a recovery lock must not replace the original short identity.
	q := query()
	q.Identity.ValidUntil = time.Now().UTC().Add(100 * time.Millisecond)
	tx, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, "SELECT installation_id FROM fleet_trust WHERE installation_id=$1 FOR UPDATE", s.recovery.installation); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := routes.ResolveContextCase(ctx, q); done <- err }()
	time.Sleep(150 * time.Millisecond)
	if err = tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err = <-done; err != value.ErrUnavailable {
		t.Fatal("expired lock waiter received routes", err)
	}
	// A source suspension closes both metadata and navigation without a live Pod.
	source = current(nil)
	if _, err = admin.Exec(ctx, "UPDATE permission_stream SET suspended=true WHERE id=$1", s.a.RootID); err != nil {
		t.Fatal(err)
	}
	if view, err := service.GetContextCase(ctx, source, e.CaseID); err != value.ErrUnavailable || view.CaseID != "" {
		t.Fatal("suspended permission disclosed case", view, err)
	}
	if link, err := (captureapp.ContextCaseNavigator{Cases: service, Now: time.Now}).ContextCaseNavigation(ctx, source, p); err == nil || link.CaseID != "" {
		t.Fatal("suspended permission kept navigation", link, err)
	}
	// The private locator may be retained, but deleting evidence is never routed.
	if _, err = admin.Exec(ctx, "UPDATE custody_attempt SET state='deleting' WHERE id=$1", e.Registration.Location.AttemptID); err != nil {
		t.Fatal(err)
	}
	if got, err := routes.ResolveContextCase(ctx, query()); err != value.ErrUnavailable || len(got.Routes) != 0 {
		t.Fatal("deletion-pending case routed", got, err)
	}
}
