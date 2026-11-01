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
	"sync"
	"testing"
	"time"
)

type groupedSubmissionPorts struct {
	t                       *testing.T
	mu                      sync.Mutex
	intentHook              func(context.Context, string) error
	startHook               func(context.Context, string) error
	intents                 map[string]audit.CaptureIntent
	reads, starts           []string
	policy, initiator       identity.Principal
	until                   time.Time
	failChild, changeIntent string
	changeCount             string
	failure                 error
}

func (f *groupedSubmissionPorts) AcknowledgedCaptureIntent(ctx context.Context, id string) (audit.CaptureIntent, error) {
	if f.intentHook != nil {
		if err := f.intentHook(ctx, id); err != nil {
			return audit.CaptureIntent{}, err
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
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
	f.mu.Lock()
	own := false
	for _, read := range f.reads {
		own = own || read == id
	}
	f.mu.Unlock()
	if !own {
		f.t.Fatal("start preceded its own acknowledged intent")
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
	if f.startHook != nil {
		if err := f.startHook(ctx, id); err != nil {
			return err
		}
	}
	if id == f.failChild {
		return f.failure
	}
	return nil
}

// Structurally valid synthetic accepted control receipts exercise only the app
// dispatcher. They are not SQL admission, manifest/source qualification or grants.
func groupedSubmissionFixture(t *testing.T, sizes ...int) (ContextSubmission, *groupedSubmissionPorts, identities.CurrentIdentity, identity.Identity, value.Accepted) {
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
	count := 2
	if len(sizes) > 0 {
		count = sizes[0]
	}
	for n := 0; n < count; n++ {
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
		r := audit.CaptureIntent{RootID: s.RootID, CaptureID: child.CaptureID, CaseID: e.CaseID, OccurrenceID: e.OccurrenceID, ArtifactID: e.Registration.Location.ArtifactID, AttemptID: e.Registration.Location.AttemptID, Actor: ports.policy, Initiator: &ports.initiator, Target: target, ScopeDigest: child.ScopeDigest, SubmissionDigest: child.SubmissionDigest, ExpectationDigest: sha256.Sum256(raw), PermissionEpoch: f.epoch, PermissionSequence: 1, IdentityRevision: caller.Policy, CreatedAt: child.CreatedAt, Deadline: child.Deadline, ExpiresAt: e.Registration.ExpiresAt, DeleteBy: e.Registration.DeleteBy, ReservedBytes: e.Registration.ReservedBytes(), Group: &audit.CaptureGroupBinding{ParentCaptureID: parent.CaptureID, SelectionDigest: parent.ScopeDigest, ChildIndex: n, ChildCount: count}}
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
	err := s.dispatchRecordingSaveGroup(t.Context(), current, caller, parent, ports.until, func() (context.Context, time.Time, error) { return t.Context(), ports.until, nil })
	if !errors.Is(err, ports.failure) || len(ports.starts) != 2 {
		t.Fatal("sibling failure collapsed cohort or hid uncertainty", err, ports.starts)
	}
}
func TestGroupedSaveRejectsBadChildWithoutSuppressingSibling(t *testing.T) {
	s, ports, current, caller, parent := groupedSubmissionFixture(t)
	ports.changeIntent = parent.Group.Children[1].CaptureID
	if err := s.dispatchRecordingSaveGroup(t.Context(), current, caller, parent, ports.until, func() (context.Context, time.Time, error) { return t.Context(), ports.until, nil }); !errors.Is(err, value.ErrUnavailable) || len(ports.starts) != 1 {
		t.Fatal("invalid child suppressed otherwise valid sibling", err, ports.starts)
	}
}

func TestGroupedSaveRejectsIntentForDifferentCohortSize(t *testing.T) {
	s, ports, current, caller, parent := groupedSubmissionFixture(t)
	ports.changeCount = parent.Group.Children[1].CaptureID
	if err := s.dispatchRecordingSaveGroup(t.Context(), current, caller, parent, ports.until, func() (context.Context, time.Time, error) { return t.Context(), ports.until, nil }); !errors.Is(err, value.ErrUnavailable) || len(ports.starts) != 1 {
		t.Fatal("wrong count affected valid sibling", err, ports.starts)
	}
}

// Actual request-owned identity and submission coordinator. The accepted-only
// read is synthetic; it changes neither the accepted children nor their dates.
func TestGroupedSubmissionStartsReadySiblingWhileLastAuditBlocked(t *testing.T) {
	s, ports, _, _, parent := groupedSubmissionFixture(t)
	s.RecordingSaveEnabled = true
	f := s.ContextInvestigation.Replay.(*investigationFixture)
	current := f.source(t, t.Context())
	preview := fixtureID(9800)
	parent.SubmissionDigest = ContextRequestDigest(preview)
	parent.MetadataValidUntil = f.now.Add(5 * time.Second)
	f.accepted[fixtureKey(f.actor, "group")] = parent
	started := make(chan struct{})
	last := parent.Group.Children[1].CaptureID
	ports.intentHook = func(ctx context.Context, id string) error {
		if id != last {
			return nil
		}
		select {
		case <-started:
			return value.ErrUnavailable
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(100 * time.Millisecond):
			return value.ErrUnavailable
		}
	}
	ports.startHook = func(context.Context, string) error { close(started); return nil }
	_, err := s.Continue(t.Context(), current, preview, "group")
	if !errors.Is(err, value.ErrUnavailable) || len(ports.starts) != 1 {
		t.Fatalf("ready child suppressed by unrelated audit: starts=%v err=%v", ports.starts, err)
	}
}

func TestGroupedSubmissionCancellationJoinsAcknowledgements(t *testing.T) {
	s, ports, _, _, parent := groupedSubmissionFixture(t, 16)
	s.RecordingSaveEnabled = true
	f := s.Replay.(*investigationFixture)
	preview := fixtureID(9800)
	parent.SubmissionDigest = ContextRequestDigest(preview)
	parent.MetadataValidUntil = f.now.Add(5 * time.Second)
	f.accepted[fixtureKey(f.actor, "group")] = parent
	owner, cancel := context.WithCancel(t.Context())
	defer cancel()
	current := f.source(t, owner)
	entered := make(chan struct{}, 16)
	left := make(chan struct{}, 16)
	ports.intentHook = func(ctx context.Context, _ string) error {
		entered <- struct{}{}
		<-ctx.Done()
		left <- struct{}{}
		return ctx.Err()
	}
	done := make(chan error, 1)
	go func() { _, err := s.Continue(owner, current, preview, "group"); done <- err }()
	for range 16 {
		select {
		case <-entered:
		case <-time.After(time.Second):
			t.Fatal("acknowledgements did not enter")
		}
	}
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("cancelled request succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("request did not join cancelled workers")
	}
	if len(left) != 16 || len(ports.starts) != 0 {
		t.Fatal("request returned with unjoined workers or acquired after cancellation", len(left), ports.starts)
	}
}

func TestGroupedSubmissionRefreshRejectsChangedChild(t *testing.T) {
	for _, mode := range []string{"capture", "pin", "scope", "expectation", "order", "created", "deadline", "short-identity"} {
		t.Run(mode, func(t *testing.T) {
			s, ports, _, _, parent := groupedSubmissionFixture(t)
			s.RecordingSaveEnabled = true
			f := s.Replay.(*investigationFixture)
			preview := fixtureID(9800)
			parent.SubmissionDigest = ContextRequestDigest(preview)
			parent.MetadataValidUntil = f.now.Add(time.Millisecond)
			f.accepted[fixtureKey(f.actor, "group")] = parent
			replay := &phaseReplay{investigationFixture: f, initialUntil: parent.MetadataValidUntil}
			replay.after = func(a *value.Accepted, _ *bool, _ *error) {
				if replay.acceptedReads < 2 {
					return
				}
				raw, _ := json.Marshal(a.Group)
				a.Group = nil
				_ = json.Unmarshal(raw, &a.Group)
				c := &a.Group.Children[1]
				switch mode {
				case "capture":
					c.CaptureID = fixtureID(9990)
				case "pin":
					c.Pin.Name = "changed"
				case "scope":
					c.ScopeDigest[0]++
				case "expectation":
					c.Expectation.CollectorVersion = "changed"
				case "order":
					a.Group.Children[0], a.Group.Children[1] = a.Group.Children[1], a.Group.Children[0]
				case "created":
					c.CreatedAt = c.CreatedAt.Add(time.Microsecond)
				case "deadline":
					c.Deadline = c.Deadline.Add(time.Microsecond)
				case "short-identity":
					f.identityChange = "groups"
				}
			}
			s.Replay = replay
			ports.startHook = func(context.Context, string) error { f.now = f.now.Add(time.Millisecond); return nil }
			current := f.source(t, t.Context())
			out, err := s.Continue(t.Context(), current, preview, "group")
			if err == nil || out.CaptureID != parent.CaptureID || len(ports.starts) != 2 || replay.acceptedReads != 2 {
				t.Fatal("changed response renewed group or repeated effects", mode, err, len(ports.starts), replay.acceptedReads)
			}
		})
	}
}

func TestGroupedMetadataCarriesLaterShorterIdentityBound(t *testing.T) {
	s, ports, _, _, parent := groupedSubmissionFixture(t)
	s.RecordingSaveEnabled = true
	f := s.Replay.(*investigationFixture)
	resolver := &workflowIdentity{f: f, until: f.now.Add(time.Minute)}
	current, _, err := identities.NewBearerRequestWithin(t.Context(), resolver, "synthetic", func() time.Time { return f.now }, identity.RecordingSaveRequestWindow)
	if err != nil {
		t.Fatal(err)
	}
	preview := fixtureID(9800)
	parent.SubmissionDigest = ContextRequestDigest(preview)
	parent.MetadataValidUntil = f.now.Add(time.Microsecond)
	f.accepted[fixtureKey(f.actor, "group")] = parent
	replay := &phaseReplay{investigationFixture: f, initialUntil: parent.MetadataValidUntil}
	var shorter time.Time
	replay.after = func(_ *value.Accepted, _ *bool, _ *error) {
		if replay.acceptedReads == 2 {
			shorter = f.now.Add(time.Second)
			resolver.until = shorter
		}
	}
	s.Replay = replay
	ports.startHook = func(context.Context, string) error { f.now = f.now.Add(600 * time.Millisecond); return nil }
	out, err := s.Continue(t.Context(), current, preview, "group")
	if err != nil || len(ports.starts) != 2 || !out.MetadataValidUntil.Equal(shorter) {
		t.Fatal("final metadata widened known shorter current identity", err, out.MetadataValidUntil, shorter)
	}
}

func TestGroupedSubmissionShorterIdentityJoinsBlockedAcknowledgement(t *testing.T) {
	s, ports, _, _, parent := groupedSubmissionFixture(t)
	s.RecordingSaveEnabled = true
	s.Now = time.Now
	f := s.Replay.(*investigationFixture)
	owner, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	resolver := &workflowIdentity{f: f, until: time.Now().Add(15 * time.Second)}
	current, _, err := identities.NewBearerRequestWithin(owner, resolver, "synthetic", time.Now, identity.RecordingSaveRequestWindow)
	if err != nil {
		t.Fatal(err)
	}
	preview := fixtureID(9800)
	parent.SubmissionDigest = ContextRequestDigest(preview)
	parent.MetadataValidUntil = f.now.Add(5 * time.Second)
	f.accepted[fixtureKey(f.actor, "group")] = parent
	blocked, left := make(chan struct{}), make(chan struct{})
	shorter := make(chan time.Time, 1)
	last := parent.Group.Children[1].CaptureID
	ports.intentHook = func(ctx context.Context, id string) error {
		if id != last {
			return nil
		}
		close(blocked)
		<-ctx.Done()
		close(left)
		return ctx.Err()
	}
	ports.startHook = func(call context.Context, _ string) error {
		// Sample only after fixture construction and the actual first start. This
		// is a genuinely later shorter observation, not caller cancellation.
		resolver.until = time.Now().Add(time.Second)
		observed, err := current.ResolveIdentity(call)
		if err != nil || !observed.ValidUntil.Equal(resolver.until) {
			return value.ErrDenied
		}
		shorter <- observed.ValidUntil
		return nil
	}
	type outcome struct {
		accepted value.Accepted
		err      error
	}
	done := make(chan outcome, 1)
	go func() { a, e := s.Continue(owner, current, preview, "group"); done <- outcome{a, e} }()
	var until time.Time
	select {
	case until = <-shorter:
	case result := <-done:
		t.Fatal("first child did not reach start", result.err)
	case <-owner.Done():
		t.Fatal("first start not reached", owner.Err())
	}
	<-blocked
	if !until.Before(parent.Group.Children[0].Expectation.Snapshot.StartBy) {
		cancel()
		<-done
		t.Fatal("invalid short-identity baseline")
	}
	observe := time.NewTimer(time.Until(until.Add(200 * time.Millisecond)))
	defer observe.Stop()
	select {
	case result := <-done:
		if result.err == nil || result.accepted.CaptureID != parent.CaptureID || owner.Err() != nil {
			t.Fatal("shorter current identity replaced admission or used caller cancellation", result.err, owner.Err())
		}
	case <-observe.C:
		cancel()
		<-done // Own and join cleanup even for the old implementation's RED.
		t.Fatal("known shorter identity did not end blocked acknowledgement wait")
	}
	select {
	case <-left:
	default:
		t.Fatal("request returned before blocked acknowledgement joined")
	}
	if len(ports.starts) != 1 {
		t.Fatal("additional child started after shorter identity", ports.starts)
	}
}
