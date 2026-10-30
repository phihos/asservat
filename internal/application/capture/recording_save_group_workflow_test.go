package capture

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"testing"
	"time"

	authapp "asservat.local/asservat/internal/application/authorization"
	deliveryapp "asservat.local/asservat/internal/application/delivery"
	identities "asservat.local/asservat/internal/application/identity"
	compiler "asservat.local/asservat/internal/application/planning"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	value "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/identity"
)

// Only SQL admission/audit/start/history effects are synthetic here. Real
// RecordingSaves, ContextInvestigation, ContextSubmission and request-owned
// bearer identity run together with their actual review/current-facts checks.
// Controlled clock costs are component replay, not measured regional latency.
type workflowSQL struct {
	*groupPreviewFixture
	ports          *groupedSubmissionPorts
	sourceRows     []RecordingCandidate
	admissionDelay time.Duration
}

func (f *workflowSQL) AdmitRecordingSaveGroup(ctx context.Context, in value.RecordingSaveGroupAdmission) (value.Accepted, error) {
	f.seen = append(f.seen, in)
	p := in.Preview
	parent := value.Accepted{State: value.PendingAudit, CaptureID: p.CaptureID, ScopeDigest: p.ScopeDigest, SubmissionDigest: in.SubmissionDigest, CreatedAt: in.Children[0].Plan.Input.Snapshot.Request.T0, MetadataValidUntil: f.now.Add(5 * time.Second), Group: &value.RecordingSaveGroupAccepted{CaseID: p.CaseID}}
	for n, c := range in.Children {
		input := c.Plan.Input
		target, r := input.Target, c.Registration
		retention := input.Retention
		lifecycle, err := compiler.SourceSnapshotLifecycle(input.Snapshot)
		if err != nil {
			return value.Accepted{}, err
		}
		var binding []byte
		q := input.Snapshot.Request
		// Use the already reviewed source binding bytes retained by the test factory.
		binding = f.bindings(q.SourceID)
		e := artifact.ContextExpectation{ExecutionClass: target.ExecutionClass, Registration: r, CaseID: c.CaseID, OccurrenceID: c.OccurrenceID, NodeUID: target.NodeUID, NodeBootID: target.NodeBootID, PodUID: target.Request.PodUID, Namespace: target.Request.Namespace.Name, NamespaceUID: target.Request.Namespace.UID, WorkloadUID: target.Request.Workload.UID, CollectorVersion: input.Capability.CollectorVersion, CollectorImageDigest: input.Capability.CollectorImageDigest, RecipeDigest: c.Plan.RecipeDigest, PlanDigest: c.Plan.ScopeDigest, CaptureUID: input.CaptureID, ActionID: input.Snapshot.ActionID, NativeType: artifact.PCAPNGArtifact, DataClass: "metadata", PurposeRef: retention.PurposeRef, Audience: c.Eligibility.DefaultAudience, RequestedAgeSeconds: retention.RequestedSeconds, MaximumAgeSeconds: retention.MaximumSeconds, DeletionBudgetSeconds: retention.DeletionBudgetSeconds, RetentionRules: retention.Policies, TriggeredAt: q.T0, Snapshot: &q, Lifecycle: lifecycle, SourceSnapshotManifest: &artifact.SourceSnapshotManifest{CanonicalScope: c.Plan.CanonicalScope, Binding: binding}}
		child := value.Accepted{State: value.PendingAudit, CaptureID: input.CaptureID, ScopeDigest: c.Plan.ScopeDigest, SubmissionDigest: c.SubmissionDigest, CreatedAt: parent.CreatedAt, Deadline: input.Deadline, Pin: target.Pin, Expectation: e}
		if err := e.Validate(); err != nil {
			f.ports.t.Fatal("synthetic admitted expectation", n, err)
		}
		parent.Group.Children = append(parent.Group.Children, child)
		if child.Deadline.After(parent.Deadline) {
			parent.Deadline = child.Deadline
		}
		raw, _ := json.Marshal(e)
		f.ports.intents[child.CaptureID] = audit.CaptureIntent{RootID: in.RootID, CaptureID: child.CaptureID, CaseID: e.CaseID, OccurrenceID: e.OccurrenceID, ArtifactID: r.Location.ArtifactID, AttemptID: r.Location.AttemptID, Actor: p.Group.Executor, Initiator: &p.Actor, Target: target.Target(), ScopeDigest: child.ScopeDigest, SubmissionDigest: child.SubmissionDigest, ExpectationDigest: sha256.Sum256(raw), PermissionEpoch: f.epoch, PermissionSequence: 1, IdentityRevision: c.Eligibility.VerifiedIdentity.Policy, CreatedAt: child.CreatedAt, Deadline: child.Deadline, ExpiresAt: r.ExpiresAt, DeleteBy: r.DeleteBy, ReservedBytes: r.ReservedBytes(), Group: &audit.CaptureGroupBinding{ParentCaptureID: parent.CaptureID, SelectionDigest: parent.ScopeDigest, ChildIndex: n, ChildCount: len(in.Children)}}
	}
	f.accepted[fixtureKey(p.Actor, in.IdempotencyKey)] = parent
	f.now = f.now.Add(f.admissionDelay)
	return parent, ctx.Err()
}
func (f *workflowSQL) bindings(id string) []byte {
	for _, row := range f.sourceRows {
		if row.Source.Binding.SourceID == id {
			raw, _ := json.Marshal(row.Source.Binding)
			return raw
		}
	}
	return nil
}

type workflowIdentity struct {
	f     *investigationFixture
	until time.Time
}

func (r workflowIdentity) Resolve(ctx context.Context, token string) (identity.Identity, error) {
	i, e := (fixtureIdentityResolver{r.f}).Resolve(ctx, token)
	i.ValidUntil = r.until
	i.Groups = []string{"current-team"}
	return i, e
}

type workflowHistory struct {
	f     *investigationFixture
	ports *groupedSubmissionPorts
	calls int
	t     *testing.T
}

func (h *workflowHistory) Persist(ctx context.Context, _ value.Accepted, _ identity.Identity, _ value.HistoryParameters, _ *value.HistoryLineage) error {
	h.calls++
	if len(h.ports.starts) == 0 {
		h.t.Errorf("advisory history preceded required starts: %d", len(h.ports.starts))
	}
	h.f.now = h.f.now.Add(2750 * time.Millisecond)
	return ctx.Err()
}
func TestGroupedSubmissionSixteenStartsBeforeAdvisoryHistory(t *testing.T) {
	for _, tc := range []struct {
		name             string
		admission, start time.Duration
		wantStarts       int
		closed           bool
	}{{"fast-serial-after-sql", 3200 * time.Millisecond, 100 * time.Millisecond, 16, false}, {"spent-sql-start-budget", 3410 * time.Millisecond, 300 * time.Millisecond, 6, true}} {
		t.Run(tc.name, func(t *testing.T) {
			x, inv, target, _ := newRecordingInventoryFixture(t, 16)
			f := x.f
			original := f.now
			current, _, err := identities.NewBearerRequestWithin(t.Context(), workflowIdentity{f, original.Add(time.Minute)}, "synthetic", func() time.Time { return f.now }, 15*time.Second)
			if err != nil {
				t.Fatal(err)
			}
			team, _, settings, _ := newTeamRecordingFixture(t)
			f.audience = team.audience
			f.cap.ExecutionClass = artifact.ContextAPIExecution
			f.svc.Approvals = settings
			accepted := inv.Accepted
			f.svc.Eligibility = authapp.CaptureEligibility{Human: authapp.Evaluator{Permissions: f, Now: func() time.Time { return f.now }}, Accepted: accepted, Current: accepted.(*teamRecordingAuthority), Now: func() time.Time { return f.now }}
			x.policy.Policy.IncidentPods = 16
			for n := range x.rows {
				source := &x.rows[n].Source
				source.Audience = []artifact.AudienceAssignment{f.audience}
				digest, _ := compiler.SourceAudienceDigest(source.Audience)
				source.Binding.AudienceDigest = [32]byte(digest)
				source.StartedAt = f.now.Add(-time.Second)
				source.Target.BindingDigest = deliveryapp.SourceBindingDigest(source.Binding)
			}
			ports := &groupedSubmissionPorts{t: t, intents: map[string]audit.CaptureIntent{}, policy: x.policy.Accepted.Authority.Executor, initiator: f.actor, until: original.Add(5 * time.Second)}
			fixture := &workflowSQL{groupPreviewFixture: &groupPreviewFixture{investigationFixture: f}, ports: ports, sourceRows: x.rows, admissionDelay: tc.admission}
			f.svc.Targets = fixture
			f.svc.Previews = fixture
			f.svc.RecordingGroups = fixture
			f.svc.RecordingSources = x
			f.svc.PolicyAccepted = accepted
			f.svc.RecordingPolicies = x
			f.svc.RecordingSaveEnabled = true
			service := RecordingSaves{Inventory: inv, Investigation: f.svc}
			page, err := inv.List(t.Context(), current, target, "", "", 100)
			if err != nil {
				t.Fatal(err)
			}
			handles := make([]string, len(page.Rows))
			for n, row := range page.Rows {
				handles[n] = row.Handle
			}
			preview, err := service.Preview(t.Context(), current, RecordingSavePreviewRequest{Handles: handles, Before: time.Second})
			if err != nil {
				t.Fatal(err)
			}
			history := &workflowHistory{f: f, ports: ports, t: t}
			submission := ContextSubmission{ContextInvestigation: f.svc, Intents: ports, Start: ports, History: history}
			ports.startHook = func(ctx context.Context, id string) error {
				next := f.now.Add(tc.start)
				if !next.Before(ports.until) {
					f.now = ports.until
					return value.ErrAcquisitionClosed
				}
				f.now = next
				return nil
			}
			out, err := submission.Request(t.Context(), current, preview.Preview.ID, "group-timing")
			if (err != nil) != tc.closed || tc.closed && !errors.Is(err, value.ErrAcquisitionClosed) || len(ports.starts) != tc.wantStarts || len(fixture.seen) != 1 || history.calls != 1 || !out.HistoryRecorded || !f.now.Before(out.MetadataValidUntil) {
				t.Fatalf("incomplete composed workflow err=%v starts=%d admission=%d history=%d metadata=%v now=%v", err, len(ports.starts), len(fixture.seen), history.calls, out.MetadataValidUntil, f.now)
			}
			if len(f.accepted) != 1 || !out.CreatedAt.Equal(original) || !out.Group.Children[0].Expectation.Snapshot.StartBy.Equal(original.Add(5*time.Second)) {
				t.Fatal("composition changed immutable group")
			}
			// New HTTP identity, passive exact replay: no acknowledgement, start, history.
			reads, starts := len(ports.reads), len(ports.starts)
			again, err := submission.Request(t.Context(), current, preview.Preview.ID, "group-timing")
			if err != nil || !again.Replay || len(ports.reads) != reads || len(ports.starts) != starts || history.calls != 1 {
				t.Fatal("passive replay acquired effects", err)
			}
		})
	}
}
