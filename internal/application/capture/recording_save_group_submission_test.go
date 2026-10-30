package capture

import (
	identities "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	value "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/identity"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

type groupedSubmissionPorts struct {
	t                       *testing.T
	intents                 map[string]audit.CaptureIntent
	reads, starts           []string
	policy, initiator       identity.Principal
	until                   time.Time
	failChild, changeIntent string
	changeCount             string
	failure                 error
}

func (f *groupedSubmissionPorts) AcknowledgedCaptureIntent(_ context.Context, id string) (audit.CaptureIntent, error) {
	f.reads = append(f.reads, id)
	r := f.intents[id]
	if id == f.changeIntent {
		r.ExpectationDigest = artifact.Digest{99}
	}
	if id == f.changeCount {
		g := *r.Group
		g.ChildCount++
		r.Group = &g
	}
	return r, nil
}
func (f *groupedSubmissionPorts) StartContext(ctx context.Context, current identities.CurrentIdentity, id string) error {
	f.t.Helper()
	if len(f.reads) != len(f.intents) {
		f.t.Fatal("start preceded complete cohort intent validation")
	}
	if _, ok := f.intents[id]; !ok {
		f.t.Fatal("parent or unknown capture dispatched", id)
	}
	end, ok := ctx.Deadline()
	if !ok || end.After(f.until) {
		f.t.Fatal("child renewed original dispatch bound", end, f.until)
	}
	policy, err := current.ResolveIdentity(ctx)
	if err != nil || policy.Principal != f.policy {
		f.t.Fatal("child lost original executor", policy, err)
	}
	live, ok := current.(interface {
		InitiatingIdentity(context.Context) (identity.Identity, error)
	})
	if !ok {
		f.t.Fatal("initiator port missing")
	}
	human, err := live.InitiatingIdentity(ctx)
	if err != nil || human.Principal != f.initiator {
		f.t.Fatal("child lost current initiator", human, err)
	}
	f.starts = append(f.starts, id)
	if id == f.failChild {
		return f.failure
	}
	return nil
}

// Structurally valid synthetic accepted control receipts exercise only the app
// dispatcher. They are not SQL admission, manifest/source qualification or grants.
func groupedSubmissionFixture(t *testing.T) (ContextSubmission, *groupedSubmissionPorts, identities.CurrentIdentity, identity.Identity, value.Accepted) {
	t.Helper()
	f, _, s, p := submissionTest(t)
	current := f.source(t, t.Context())
	caller, err := current.ResolveIdentity(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	seed, err := f.svc.Request(t.Context(), current, p.ID, "seed-child")
	if err != nil {
		t.Fatal(err)
	}
	_, accepted, _, _ := newTeamRecordingFixture(t)
	accepted.f = f
	parent := value.Accepted{State: value.PendingAudit, CaptureID: fixtureID(9000), ScopeDigest: sha256.Sum256([]byte(`{"schemaVersion":"recording-save/v1"}`)), SubmissionDigest: artifact.Digest{19}, CreatedAt: seed.CreatedAt, Deadline: seed.Deadline, Group: &value.RecordingSaveGroupAccepted{CaseID: seed.Expectation.CaseID}}
	ports := &groupedSubmissionPorts{t: t, intents: map[string]audit.CaptureIntent{}, policy: accepted.authority.Executor, initiator: caller.Principal, until: f.now.Add(5 * time.Second), failure: errors.New("independent child start unconfirmed")}
	for n := 0; n < 2; n++ {
		child := seed
		e := seed.Expectation
		child.CaptureID = fixtureID(9010 + n*10)
		child.ScopeDigest = parent.ScopeDigest
		child.SubmissionDigest = artifact.Digest{byte(20 + n)}
		child.Pin.UID = fixtureID(9050 + n)
		e.CaptureUID, e.PodUID, e.PlanDigest = child.CaptureID, child.Pin.UID, parent.ScopeDigest
		e.NativeType, e.ActionID = artifact.PCAPNGArtifact, "a0123456789abcdef01234567"
		e.OccurrenceID = fixtureID(9012 + n*10)
		e.Registration.Location.ArtifactID = fixtureID(9013 + n*10)
		e.Registration.Location.AttemptID = fixtureID(9014 + n*10)
		e.Registration.NativeLimit = 64 << 10
		binding := []byte(`{}`)
		q := artifact.SourceSnapshotRequest{SourceBindingDigest: sha256.Sum256(binding), SourceID: fixtureID(9015 + n*10), Fence: fixtureID(9016 + n*10), SnapshotID: fixtureID(9017 + n*10), SourceStartedAt: e.TriggeredAt, SourceHardUntil: e.Registration.WriteUntil, T0: e.TriggeredAt, IssuedAt: e.TriggeredAt, StartBy: e.TriggeredAt.Add(5 * time.Second), ProcessingUntil: e.Registration.WriteUntil, Before: time.Second, MaxBytes: e.Registration.NativeLimit}
		e.Snapshot = &q
		e.SourceSnapshotManifest = &artifact.SourceSnapshotManifest{CanonicalScope: []byte(`{"schemaVersion":"recording-save/v1"}`), Binding: binding}
		e.Lifecycle = &artifact.OngoingLifecycle{TriggerKind: "recordingSave", SourceSessionID: q.SourceID, SourceStartedAt: q.SourceStartedAt, SnapshotID: q.SnapshotID, RequestedBefore: q.Before, HistoryCoverage: "unknown", WindowCoverage: "unknown", GapReasons: []string{"unknownLoss"}, Origin: &artifact.RecordingSaveOrigin{PolicyUID: accepted.authority.PolicyUID, PolicyExecutionDigest: accepted.authority.ScopeDigest}}
		child.Expectation = e
		parent.Group.Children = append(parent.Group.Children, child)
		raw, _ := json.Marshal(e)
		target := f.target.Target()
		target.PodUID = e.PodUID
		r := audit.CaptureIntent{RootID: s.RootID, CaptureID: child.CaptureID, CaseID: e.CaseID, OccurrenceID: e.OccurrenceID, ArtifactID: e.Registration.Location.ArtifactID, AttemptID: e.Registration.Location.AttemptID, Actor: ports.policy, Initiator: &ports.initiator, Target: target, ScopeDigest: child.ScopeDigest, SubmissionDigest: child.SubmissionDigest, ExpectationDigest: sha256.Sum256(raw), PermissionEpoch: f.epoch, PermissionSequence: 1, IdentityRevision: caller.Policy, CreatedAt: child.CreatedAt, Deadline: child.Deadline, ExpiresAt: e.Registration.ExpiresAt, DeleteBy: e.Registration.DeleteBy, ReservedBytes: e.Registration.ReservedBytes(), Group: &audit.CaptureGroupBinding{ParentCaptureID: parent.CaptureID, SelectionDigest: parent.ScopeDigest, ChildIndex: n, ChildCount: 2}}
		if !r.Valid() || e.Validate() != nil {
			t.Fatal("invalid dispatcher baseline", r.Valid(), e.Validate())
		}
		ports.intents[child.CaptureID] = r
	}
	if !acceptedContext(parent, parent.SubmissionDigest) {
		t.Fatal("invalid parent dispatcher baseline")
	}
	s.Intents, s.Start, s.PolicyAccepted = ports, ports, accepted
	return s, ports, current, caller, parent
}
func TestGroupedSaveDispatchesExactChildrenDespiteSiblingFailure(t *testing.T) {
	s, ports, current, caller, parent := groupedSubmissionFixture(t)
	ports.failChild = parent.Group.Children[0].CaptureID
	err := s.dispatchRecordingSaveGroup(t.Context(), current, caller, parent, ports.until, func() error { return nil })
	if !errors.Is(err, ports.failure) || len(ports.starts) != 2 || ports.starts[0] != parent.Group.Children[0].CaptureID || ports.starts[1] != parent.Group.Children[1].CaptureID {
		t.Fatal("sibling failure collapsed cohort or hid uncertainty", err, ports.starts)
	}
}
func TestGroupedSaveValidatesAllChildIntentsBeforeAnyStart(t *testing.T) {
	s, ports, current, caller, parent := groupedSubmissionFixture(t)
	ports.changeIntent = parent.Group.Children[1].CaptureID
	if err := s.dispatchRecordingSaveGroup(t.Context(), current, caller, parent, ports.until, func() error { return nil }); !errors.Is(err, value.ErrUnavailable) || len(ports.starts) != 0 {
		t.Fatal("invalid second child allowed first start", err, ports.starts)
	}
}

func TestGroupedSaveRejectsIntentForDifferentCohortSize(t *testing.T) {
	s, ports, current, caller, parent := groupedSubmissionFixture(t)
	ports.changeCount = parent.Group.Children[1].CaptureID
	if err := s.dispatchRecordingSaveGroup(t.Context(), current, caller, parent, ports.until, func() error { return nil }); !errors.Is(err, value.ErrUnavailable) || len(ports.starts) != 0 {
		t.Fatal("intent for a different child count started cohort", err, ports.starts)
	}
}
