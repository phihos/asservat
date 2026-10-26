package integration

import (
	"context"
	"errors"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/postgres"
	"asservat.local/asservat/internal/application/planning"
	capture "asservat.local/asservat/internal/domain/capture"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// qualifyCaptureHistory (ADR-236) runs capture history on real PostgreSQL
// with migration 00089's typed target columns, the actual accepted
// permission projection and three actually admitted captures: newest-first
// keyset pages, the requester and current retained-audience members see
// them, a recreated workload UID and a principal without workload rights
// (such as a share-only recipient) see none, pre-migration rows and rows older
// than seven days are not history, and a suspended permission source denies
// both the list and the settings a repeat would restore.
func qualifyCaptureHistory(t *testing.T, ctx context.Context, admin *pgxpool.Pool, readPool *pgxpool.Pool, create func(*testing.T, int64) captureAdmissionScenario) {
	t.Helper()
	s := create(t, 3)
	refresh := func() {
		t.Helper()
		now := time.Now().UTC().Truncate(time.Microsecond)
		b := s.batch
		b.Initial = nil
		b.ObservedAt, b.FreshUntil = now, now.Add(5*time.Second)
		if err := s.p.RefreshPermissions(ctx, b); err != nil {
			t.Fatal(err)
		}
	}
	admit := func(key string) string {
		t.Helper()
		a := s.a
		in := a.Plan.Input
		in.CaptureID = custodyID()
		p, err := planning.CompileContext(in, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		a.Plan, a.IdempotencyKey = p, key
		a.Registration.Location.ArtifactID, a.Registration.Location.AttemptID = custodyID(), custodyID()
		a.CaseID, a.OccurrenceID = custodyID(), custodyID()
		if _, err = s.s.AdmitContext(ctx, a); err != nil {
			t.Fatal(err)
		}
		return in.CaptureID
	}
	first := admit("history-1")
	second := admit("history-2")
	third := admit("history-3")
	reader, err := postgres.NewContextProgressReads(ctx, readPool, s.a.RootID, s.recovery.guard)
	if err != nil {
		t.Fatal(err)
	}
	target := s.a.Plan.Input.Target.Target()
	as := func(subject string, groups []string) (capture.HistoryQuery, capture.SettingsQuery) {
		t.Helper()
		refresh()
		// As in the service: the identity is verified before recovery is read.
		i := s.a.Eligibility.VerifiedIdentity
		i.Principal.Subject, i.Groups, i.Scopes = subject, groups, []string{"evidence:read"}
		i.VerifiedAt = time.Now().UTC()
		i.ValidUntil = i.VerifiedAt.Add(5 * time.Second)
		time.Sleep(time.Millisecond)
		r, err := s.recovery.reader.RecoveryState(ctx)
		if err != nil {
			t.Fatal(err)
		}
		return capture.HistoryQuery{RootID: s.a.RootID, Target: target, Origins: []capture.HistoryOrigin{capture.HistoryManual}, Limit: 20, Identity: i, Recovery: r},
			capture.SettingsQuery{RootID: s.a.RootID, CaptureID: first, Identity: i, Recovery: r}
	}
	requester := s.a.Eligibility.VerifiedIdentity.Principal.Subject
	ids := func(p capture.HistoryPage) []string {
		var out []string
		for _, e := range p.Entries {
			out = append(out, e.CaptureID)
		}
		return out
	}
	same := func(a, b []string) bool {
		if len(a) != len(b) {
			return false
		}
		for i := range a {
			if a[i] != b[i] {
				return false
			}
		}
		return true
	}

	t.Run("requester-pages-newest-first", func(t *testing.T) {
		q, _ := as(requester, []string{"maintainers"})
		q.Limit = 2
		page, err := reader.ListCaptureHistory(ctx, q)
		if err != nil || !same(ids(page), []string{third, second}) || page.Next == nil || page.Next.CaptureID != second {
			t.Fatal("first page", ids(page), page.Next, err)
		}
		for _, e := range page.Entries {
			if e.Origin != capture.HistoryManual || e.Phase != "Pending" || e.EvidenceState != "pending" || !e.ExpiresAt.Equal(e.AcceptedAt.Add(capture.HistoryLifetime)) {
				t.Fatal("entry", e)
			}
		}
		q, _ = as(requester, []string{"maintainers"})
		q.Limit, q.After = 2, page.Next
		page, err = reader.ListCaptureHistory(ctx, q)
		if err != nil || !same(ids(page), []string{first}) || page.Next != nil {
			t.Fatal("second page", ids(page), page.Next, err)
		}
		q, _ = as(requester, []string{"maintainers"})
		q.Origins = []capture.HistoryOrigin{capture.HistoryPolicy}
		if page, err = reader.ListCaptureHistory(ctx, q); err != nil || len(page.Entries) != 0 {
			t.Fatal("manual captures listed as policy history", ids(page), err)
		}
	})
	t.Run("retained-audience-member-sees-and-reads-settings", func(t *testing.T) {
		// other-owners holds evidence-owner, part of each capture's audience.
		q, sq := as("synthetic-other-owner", []string{"other-owners"})
		page, err := reader.ListCaptureHistory(ctx, q)
		if err != nil || !same(ids(page), []string{third, second, first}) {
			t.Fatal("retained audience member", ids(page), err)
		}
		settings, err := reader.ReadCaptureSettings(ctx, sq)
		if err != nil || settings.CaptureID != first || settings.ClusterID != target.ClusterID || settings.NamespaceUID != target.NamespaceUID || settings.WorkloadUID != target.WorkloadUID ||
			settings.Namespace != s.a.Plan.Input.Target.Request.Namespace.Name || settings.WorkloadKind != "Deployment" || settings.WorkloadName != s.a.Plan.Input.Target.Request.Workload.Name ||
			settings.RequestedSeconds != s.a.Plan.Input.Retention.RequestedSeconds || len(settings.TargetJSON) == 0 || len(settings.DependencyJSON) == 0 || settings.Origin != capture.HistoryManual {
			t.Fatalf("settings %+v %v", settings, err)
		}
	})
	t.Run("recreated-workload-and-recipient-only-see-none", func(t *testing.T) {
		// The same names, recreated: another workload UID has no history.
		q, _ := as(requester, []string{"maintainers"})
		q.Target.WorkloadUID = custodyID()
		if page, err := reader.ListCaptureHistory(ctx, q); err != nil || len(page.Entries) != 0 || page.Next != nil {
			t.Fatal("recreated workload inherited history", ids(page), err)
		}
		// A principal without any workload assignment (a share-only recipient).
		q, sq := as("synthetic-recipient", nil)
		if page, err := reader.ListCaptureHistory(ctx, q); !errors.Is(err, capture.ErrDenied) || len(page.Entries) != 0 {
			t.Fatal("recipient-only principal saw history", ids(page), err)
		}
		if settings, err := reader.ReadCaptureSettings(ctx, sq); !errors.Is(err, capture.ErrDenied) || settings.CaptureID != "" {
			t.Fatal("recipient-only principal read settings", err)
		}
		// An unknown capture is the same refusal.
		_, sq = as(requester, []string{"maintainers"})
		sq.CaptureID = custodyID()
		if _, err := reader.ReadCaptureSettings(ctx, sq); !errors.Is(err, capture.ErrDenied) {
			t.Fatal("unknown capture", err)
		}
	})
	t.Run("history-identity-is-immutable-and-starts-at-the-migration", func(t *testing.T) {
		var cluster, namespace, workload, origin string
		if err := admin.QueryRow(ctx, "SELECT history_cluster_id::text,history_namespace_uid,history_workload_uid,history_origin FROM context_capture WHERE id=$1", first).Scan(&cluster, &namespace, &workload, &origin); err != nil ||
			cluster != target.ClusterID || namespace != target.NamespaceUID || workload != target.WorkloadUID || origin != "manual" {
			t.Fatal("history identity not recorded at acceptance", cluster, namespace, workload, origin, err)
		}
		_, err := admin.Exec(ctx, "UPDATE context_capture SET history_workload_uid='other' WHERE id=$1", first)
		var pgerr *pgconn.PgError
		if !errors.As(err, &pgerr) || pgerr.Code != "23514" {
			t.Fatal("history identity changed", err)
		}
		if _, err = readPool.Exec(ctx, "UPDATE context_capture SET history_workload_uid=history_workload_uid"); !errors.As(err, &pgerr) || pgerr.Code != "42501" {
			t.Fatal("history reader may update captures", err)
		}
		// A pre-migration row (no typed identity) and a row older than seven
		// days are not history. The fixture administrator alone rewrites them.
		tx, err := admin.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(ctx)
		for _, sql := range []string{"SET LOCAL session_replication_role=replica",
			"UPDATE context_capture SET history_cluster_id=NULL,history_namespace_uid=NULL,history_workload_uid=NULL,history_origin=NULL WHERE id='" + first + "'",
			"UPDATE context_capture SET created_at=created_at-interval '8 days',deadline=deadline-interval '8 days' WHERE id='" + second + "'"} {
			if _, err = tx.Exec(ctx, sql); err != nil {
				t.Fatal(sql, err)
			}
		}
		if err = tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		q, sq := as(requester, []string{"maintainers"})
		if page, err := reader.ListCaptureHistory(ctx, q); err != nil || !same(ids(page), []string{third}) {
			t.Fatal("pre-migration or expired rows listed", ids(page), err)
		}
		for _, id := range []string{first, second} {
			sq.CaptureID = id
			if _, err := reader.ReadCaptureSettings(ctx, sq); !errors.Is(err, capture.ErrDenied) {
				t.Fatal("settings outside history", id, err)
			}
		}
	})
	t.Run("suspended-permissions-deny-list-and-repeat-settings", func(t *testing.T) {
		q, sq := as(requester, []string{"maintainers"})
		sq.CaptureID = third
		if _, err := admin.Exec(ctx, "UPDATE permission_stream SET suspended=true WHERE id=$1", s.a.RootID); err != nil {
			t.Fatal(err)
		}
		if page, err := reader.ListCaptureHistory(ctx, q); !errors.Is(err, capture.ErrDenied) || len(page.Entries) != 0 {
			t.Fatal("suspended permissions listed history", err)
		}
		if _, err := reader.ReadCaptureSettings(ctx, sq); !errors.Is(err, capture.ErrDenied) {
			t.Fatal("suspended permissions restored settings", err)
		}
	})
}
