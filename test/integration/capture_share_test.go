package integration

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/postgres"
	captureapp "asservat.local/asservat/internal/application/capture"
	catalogapp "asservat.local/asservat/internal/application/catalog"
	identities "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/application/planning"
	privacyapp "asservat.local/asservat/internal/application/privacy"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/targets"
	"github.com/jackc/pgx/v5/pgxpool"
)

// captureShareFixture is one genuinely admitted, verified and audited
// capture of qualifyContextPublications, ready to publish.
type captureShareFixture struct {
	scenario captureAdmissionScenario
	e        artifact.ContextExpectation
	reader   *postgres.ContextPublications
	publish  func() (artifact.PublishedContext, error)
	replay   func() error
}

// qualifyCaptureShare (ADR-235) runs capture-time sharing through real
// PostgreSQL: a reviewed request whose requester lacks evidence-owner is
// refused before any capture exists; an owner's request stores the instruction
// with the accepted capture; publication materializes exactly one share (a
// replayed publication none) that its recipient reads through get_case; and a
// share that can no longer be materialized at publication leaves the capture
// published without one.
func qualifyCaptureShare(t *testing.T, ctx context.Context, admin *pgxpool.Pool, poolFor func(string, string) *pgxpool.Pool, create func(*testing.T, int64) captureAdmissionScenario, setup func(*testing.T, func(*testing.T, *captureAdmissionScenario) capture.Accepted) captureShareFixture) {
	t.Helper()
	previewPool := poolFor("context_preview_runtime", "synthetic-context-preview")
	t.Cleanup(previewPool.Close)
	hub := narrowRole(t, ctx, admin, "capture_share_hub_", "synthetic-capture-share-hub", func(role string) []string {
		grants, ok := postgres.PublicRuntimeRoleGrantSQL("hub-runtime", role)
		if !ok {
			t.Fatal("missing compiled hub grants")
		}
		return grants
	})
	hubPool := poolFor(hub, "synthetic-capture-share-hub")
	t.Cleanup(hubPool.Close)

	recipient := func(issuer string) []authorization.ShareRecipient {
		return []authorization.ShareRecipient{{Kind: "User", Issuer: issuer, ID: "synthetic-capture-recipient"}}
	}
	// reviewed admits the scenario through a stored preview carrying sharing,
	// as request_capture does; owner adds the evidence-owner group.
	reviewed := func(t *testing.T, s *captureAdmissionScenario, owner bool, notAfter time.Time) (capture.Accepted, error) {
		t.Helper()
		i := &s.a.Eligibility.VerifiedIdentity
		i.Scopes = append(slices.Clone(i.Scopes), "evidence:read", authorization.ShareScope)
		if owner {
			i.Groups = append(slices.Clone(i.Groups), "other-owners")
		}
		a, in := s.a, s.a.Plan.Input
		p := capture.ContextPreview{
			ID: custodyID(), AssessmentID: custodyID(), RootID: a.RootID, InstallationID: a.Recovery.InstallationID, IssuerEpoch: a.Recovery.IssuerEpoch,
			CaptureID: in.CaptureID, CaseID: a.CaseID, OccurrenceID: a.OccurrenceID, ArtifactID: a.Registration.Location.ArtifactID, AttemptID: a.Registration.Location.AttemptID,
			Actor:  in.Executor,
			Intent: capture.ContextIntent{Target: targets.WorkloadRequest{ClusterID: in.Target.Request.ClusterID, Namespace: in.Target.Request.Namespace.Name, Kind: in.Target.Request.Workload.Kind, Name: in.Target.Request.Workload.Name}, Diagnostic: capture.ContextDiagnosticName, RequestedSeconds: in.Retention.RequestedSeconds, Sharing: &capture.ContextSharing{Recipients: recipient(in.Executor.Issuer), NotAfter: notAfter}},
			Target: in.Target.Request, Pin: in.Target.Pin, ExecutionClass: in.Target.ExecutionClass,
			Storage:   capture.ContextStorageSelection{StoreID: a.Registration.StoreID, AllocationID: a.Registration.AllocationID, PoolRevision: a.Registration.PoolRevision, AllocationRevision: a.Registration.AllocationRevision, BindingRevision: a.Storage.Revision},
			Retention: capture.ContextRetentionReview{PurposeRef: in.Retention.PurposeRef, RequestedSeconds: in.Retention.RequestedSeconds, MaximumSeconds: in.Retention.MaximumSeconds, DeletionBudgetSeconds: in.Retention.DeletionBudgetSeconds, Policies: in.Retention.Policies},
			Audience:  a.Eligibility.DefaultAudience, CanonicalScope: a.Plan.CanonicalScope, ScopeDigest: a.Plan.ScopeDigest, CreatedAt: a.Plan.CompiledAt, Deadline: in.Deadline,
		}
		p.AssessmentRulesDigest = planning.ContextAssessmentRulesDigestForClass(p.ExecutionClass)
		if !captureapp.ValidContextPreview(p) {
			t.Fatal("invalid synthetic preview")
		}
		previews, err := postgres.NewContextPreviews(ctx, previewPool, a.RootID)
		if err != nil {
			t.Fatal(err)
		}
		if err = previews.CreateContextPreview(ctx, p); err != nil {
			t.Fatal(err)
		}
		s.a.SubmissionDigest = captureapp.ContextRequestDigest(p.ID)
		return s.s.AdmitReviewedContext(ctx, p.ID, s.a)
	}
	shares := func(t *testing.T, root string) []struct {
		ID, Key                string
		Management, Recipients string
		Created, Expires       time.Time
	} {
		t.Helper()
		rows, err := admin.Query(ctx, "SELECT id::text,idempotency_key,management::text,recipients::text,created_at,expires_at FROM evidence_share WHERE root_id=$1", root)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		var out []struct {
			ID, Key                string
			Management, Recipients string
			Created, Expires       time.Time
		}
		for rows.Next() {
			var r struct {
				ID, Key                string
				Management, Recipients string
				Created, Expires       time.Time
			}
			if err = rows.Scan(&r.ID, &r.Key, &r.Management, &r.Recipients, &r.Created, &r.Expires); err != nil {
				t.Fatal(err)
			}
			out = append(out, r)
		}
		return out
	}
	instruction := func(t *testing.T, captureID string) (shareID string) {
		t.Helper()
		var raw *string
		if err := admin.QueryRow(ctx, "SELECT share_instruction::text FROM context_capture WHERE id=$1", captureID).Scan(&raw); err != nil {
			t.Fatal(err)
		}
		var w struct {
			ShareID string `json:"share_id"`
		}
		if raw == nil || json.Unmarshal([]byte(*raw), &w) != nil || !authorization.UUID(w.ShareID) {
			t.Fatal("accepted capture lost its sharing instruction", raw)
		}
		if _, err := admin.Exec(ctx, "UPDATE context_capture SET share_instruction=NULL WHERE id=$1", captureID); err == nil {
			t.Fatal("sharing instruction is mutable")
		}
		return w.ShareID
	}
	progress := func(t *testing.T, s captureAdmissionScenario) capture.ContextProgressObservation {
		t.Helper()
		pool := poolFor("context_progress_read_runtime", "synthetic-context-progress-read")
		defer pool.Close()
		r, err := postgres.NewContextProgressReads(ctx, pool, s.a.RootID, s.recovery.guard)
		if err != nil {
			t.Fatal(err)
		}
		got, err := r.ReadContextProgress(ctx, progressQuery(t, ctx, s))
		if err != nil {
			t.Fatal(err)
		}
		return got
	}

	t.Run("requester-without-owner-authority-is-refused-before-execution", func(t *testing.T) {
		s := create(t, 1)
		if _, err := reviewed(t, &s, false, time.Time{}); !errors.Is(err, capture.ErrSharingDenied) {
			t.Fatal("non-owner attached a sharing instruction", err)
		}
		var captures, attempts int
		if err := admin.QueryRow(ctx, "SELECT (SELECT count(*) FROM context_capture WHERE root_id=$1),(SELECT count(*) FROM custody_attempt WHERE allocation_id=$2)", s.a.RootID, s.a.Registration.AllocationID).Scan(&captures, &attempts); err != nil || captures != 0 || attempts != 0 {
			t.Fatal("refused sharing request admitted effects", captures, attempts, err)
		}
	})

	t.Run("publication-creates-exactly-one-share-and-replay-none", func(t *testing.T) {
		f := setup(t, func(t *testing.T, s *captureAdmissionScenario) capture.Accepted {
			a, err := reviewed(t, s, true, time.Time{})
			if err != nil {
				t.Fatal(err)
			}
			return a
		})
		s := f.scenario
		shareID := instruction(t, f.e.CaptureUID)
		if got := shares(t, s.a.RootID); len(got) != 0 {
			t.Fatal("share exists before publication", got)
		}
		if got := progress(t, s); got.ShareID != shareID {
			t.Fatal("progress lost the sharing instruction", got.ShareID)
		}
		if _, err := f.publish(); err != nil {
			t.Fatal(err)
		}
		got := shares(t, s.a.RootID)
		if len(got) != 1 || got[0].ID != shareID || got[0].Key != "capture:"+f.e.CaptureUID || got[0].Expires.Sub(got[0].Created) > 24*time.Hour || !got[0].Expires.After(got[0].Created) {
			t.Fatal("publication did not create exactly one bounded share", got)
		}
		var management []artifact.AudienceAssignment
		if json.Unmarshal([]byte(got[0].Management), &management) != nil || len(management) != 1 || management[0].SubjectID != "other-owners" || management[0].Role != "evidence-owner" {
			t.Fatal("share does not pin the requester's owner assignment", got[0].Management)
		}
		if err := f.replay(); err != nil {
			t.Fatal("publication replay", err)
		}
		if again := shares(t, s.a.RootID); len(again) != 1 || again[0].ID != shareID {
			t.Fatal("publication replay created another share", again)
		}
		store, err := postgres.NewEvidenceShares(ctx, hubPool, s.a.RootID, s.recovery.guard)
		if err != nil {
			t.Fatal(err)
		}
		if exists, err := store.CaptureShareExists(ctx, shareID); err != nil || !exists {
			t.Fatal("hub grants cannot see the materialized share", exists, err)
		}
		// The materialized row is an ordinary share: its recipient reads the case.
		routes, err := postgres.NewContextCaseReads(ctx, hubPool, s.a.RootID, s.recovery.guard)
		if err != nil {
			t.Fatal(err)
		}
		processing, err := postgres.NewProcessingReads(ctx, hubPool, s.a.RootID, s.recovery.guard)
		if err != nil {
			t.Fatal(err)
		}
		cases := catalogapp.ContextCaseService{RootID: s.a.RootID, InstallationID: s.recovery.installation, Routes: routes, Permissions: s.p, Catalog: f.reader, Retention: privacyapp.RetentionResolver{RetainedPolicies: s.retention, Now: time.Now}, Recovery: s.recovery.reader, Processing: processing, Shares: store, Now: time.Now}
		b := s.batch
		b.Initial = nil
		now := time.Now().UTC().Truncate(time.Microsecond)
		b.ObservedAt, b.FreshUntil = now, now.Add(5*time.Second)
		if err := s.p.RefreshPermissions(ctx, b); err != nil {
			t.Fatal(err)
		}
		i := s.a.Eligibility.VerifiedIdentity
		i.Principal.Subject, i.Groups, i.Scopes = "synthetic-capture-recipient", nil, []string{"evidence:read"}
		i.VerifiedAt, i.ValidUntil = now, now.Add(5*time.Second)
		source, _, err := identities.NewBearerRequest(ctx, downloadTestIdentity{i}, "synthetic-reference", time.Now)
		if err != nil {
			t.Fatal(err)
		}
		view, err := cases.GetContextCase(ctx, source, f.e.CaseID)
		if err != nil || len(view.Artifacts) != 1 || !view.Artifacts[0].Shared || view.Artifacts[0].ArtifactID != f.e.Registration.Location.ArtifactID {
			t.Fatal("recipient cannot read the capture-time share", view, err)
		}
	})

	t.Run("unmaterializable-share-still-publishes-without-a-share", func(t *testing.T) {
		f := setup(t, func(t *testing.T, s *captureAdmissionScenario) capture.Accepted {
			// The instruction's end passes before publication.
			a, err := reviewed(t, s, true, time.Now().UTC().Add(2*time.Second).Truncate(time.Microsecond))
			if err != nil {
				t.Fatal(err)
			}
			return a
		})
		s := f.scenario
		shareID := instruction(t, f.e.CaptureUID)
		time.Sleep(2 * time.Second)
		b := s.batch
		b.Initial = nil
		now := time.Now().UTC().Truncate(time.Microsecond)
		b.ObservedAt, b.FreshUntil = now, now.Add(5*time.Second)
		if err := s.p.RefreshPermissions(ctx, b); err != nil {
			t.Fatal(err)
		}
		if _, err := f.publish(); err != nil {
			t.Fatal("an unmaterializable share blocked publication", err)
		}
		if got := shares(t, s.a.RootID); len(got) != 0 {
			t.Fatal("expired instruction materialized a share", got)
		}
		if got := progress(t, s); got.Phase != "Succeeded" || got.ShareID != shareID {
			t.Fatal("capture outcome changed by sharing", got.Phase, got.ShareID)
		}
	})
}
