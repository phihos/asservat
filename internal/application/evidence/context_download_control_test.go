package evidence

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	identities "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/identity"
)

type downloadControlFixture struct {
	now                              time.Time
	i                                identity.Identity
	a                                artifact.DownloadAuthority
	source                           ContextDownloadSource
	plan                             ContextDownloadPlan
	session                          artifact.DownloadSession
	prepared                         artifact.PreparedDownload
	found, pending, runtimeAvailable bool
	continuationDeadline             time.Time
	calls                            []string
	fail                             string
	after                            func(string)
}

func (f *downloadControlFixture) step(name string) error {
	f.calls = append(f.calls, name)
	if f.after != nil {
		f.after(name)
	}
	if f.fail == name {
		return artifact.ErrDownloadUnavailable
	}
	return nil
}
func (f *downloadControlFixture) ResolveIdentity(context.Context) (identity.Identity, error) {
	return f.i, f.step("identity")
}
func (f *downloadControlFixture) RecoveryState(context.Context) (artifact.RecoveryProof, error) {
	return f.a.Environment.Recovery(), f.step("recovery")
}
func (f *downloadControlFixture) ResolveContextDownload(context.Context, artifact.DownloadRouteQuery) (artifact.DownloadRoute, error) {
	return artifact.DownloadRoute{Scope: f.a.Scope, ObservedAt: f.now, ValidUntil: f.now.Add(5 * time.Second)}, f.step("route")
}
func (f *downloadControlFixture) ReadContextDownloadSource(context.Context, artifact.DownloadAuthority) (ContextDownloadSource, error) {
	return f.source, f.step("source")
}
func (f *downloadControlFixture) CheckDownloadCurrent(_ context.Context, current identities.CurrentIdentity, scope artifact.DownloadScope) (artifact.DownloadAuthority, error) {
	_, err := current.ResolveIdentity(context.Background())
	if err != nil {
		return artifact.DownloadAuthority{}, err
	}
	if scope != f.a.Scope {
		return artifact.DownloadAuthority{}, artifact.ErrDownloadUnavailable
	}
	return f.a, f.step("authority")
}
func (f *downloadControlFixture) LookupDownloadKey(context.Context, artifact.DownloadKeyQuery) (artifact.DownloadKeyLookup, error) {
	return artifact.DownloadKeyLookup{Found: f.found, Session: f.session, ObservedAt: f.now, ValidUntil: f.now.Add(5 * time.Second)}, f.step("lookup-key")
}
func (f *downloadControlFixture) LookupDownload(context.Context, string, identity.Principal) (artifact.DownloadSession, error) {
	return f.session, f.step("lookup")
}
func (f *downloadControlFixture) ReserveDownload(_ context.Context, r DownloadReservation) (artifact.DownloadSession, error) {
	if !f.found {
		f.session = r.Session
		f.found = true
	}
	return f.session, f.step("reserve")
}
func (f *downloadControlFixture) ObserveDownload(_ context.Context, id string, a artifact.DownloadAuthority, p *artifact.DownloadPreparation) (artifact.DownloadObservation, error) {
	if id != f.session.ID || a.Scope != f.session.Scope {
		return artifact.DownloadObservation{}, artifact.ErrDownloadUnavailable
	}
	if p != nil && *p != f.prepared.Preparation {
		return artifact.DownloadObservation{}, artifact.ErrDownloadUnavailable
	}
	session := f.session
	if !session.State.Terminal() && !f.now.Before(session.Deadline) {
		session.State = artifact.DownloadExpired
	}
	return artifact.DownloadObservation{Session: session, ObservedAt: f.now, ValidUntil: f.now.Add(5 * time.Second)}, f.step("observe")
}
func (f *downloadControlFixture) ContextDownloadPlan(context.Context, artifact.DownloadScope) (ContextDownloadPlan, error) {
	return f.plan, f.step("plan")
}
func (f *downloadControlFixture) CheckContextDownloadRuntime(context.Context, artifact.DownloadScope) (time.Time, error) {
	err := f.step("runtime-check")
	if !f.runtimeAvailable {
		err = artifact.ErrDownloadUnavailable
	}
	return f.now.Add(5 * time.Second), err
}
func (f *downloadControlFixture) ReadPreparedContextDownload(context.Context, identities.CurrentIdentity, artifact.DownloadSession) (artifact.PreparedDownload, bool, error) {
	return f.prepared, f.prepared.Preparation.SessionID != "", f.step("metadata-read")
}
func (f *downloadControlFixture) ContinueContextDownload(ctx context.Context, _ identities.CurrentIdentity, s artifact.DownloadSession, _ ContextDownloadSource) (ContextDownloadContinuation, error) {
	f.continuationDeadline, _ = ctx.Deadline()
	if err := f.step("continue"); err != nil {
		return ContextDownloadContinuation{}, err
	}
	if !f.pending {
		f.session.State = artifact.DownloadReady
		f.session.Requests++
		f.session.Generation++
		m := contextDownloadMetadata(ContextDownloadRequest{Scope: s.Scope, Expectation: f.source.Expectation}, []byte("synthetic context"))
		f.prepared = artifact.PreparedDownload{Preparation: artifact.DownloadPreparation{SessionID: s.ID, BatchID: s.ID, Generation: 1}, Scope: s.Scope, Native: m}
	}
	return ContextDownloadContinuation{Pending: f.pending}, nil
}
func (f *downloadControlFixture) refresh(at time.Time) {
	f.now = at
	u := at.Add(5 * time.Second)
	f.i.VerifiedAt = at
	f.i.ValidUntil = u
	f.a.CheckedAt = at
	f.a.ValidUntil = u
	f.a.Environment.ObservedAt = at
	f.a.Environment.ValidUntil = u
	f.a.Retention.ObservedAt = at
	f.a.Retention.ValidUntil = u
	f.source.ObservedAt = at
	f.source.ValidUntil = u
	f.plan.ObservedAt = at
	f.plan.ValidUntil = u
}
func newDownloadControlFixture(t *testing.T) (*downloadControlFixture, ContextDownloadCoordinator) {
	t.Helper()
	base, _, r := downloadWorkerTest(t)
	n := base.now
	p := base.a.Scope
	rev := base.a.IdentityRevision
	proof := artifact.RetentionProof{RootID: p.RootID, ClusterID: p.ClusterID, NamespaceUID: p.NamespaceUID, WorkloadUID: p.WorkloadUID, PodUID: p.PodUID, Topology: rev, Policy: rev, Selectors: rev, SourceCount: 1, Sources: [2]artifact.RetentionSourceVersion{{ClusterID: p.ClusterID, ControlNamespaceUID: "control", Epoch: p.RootID, Hub: true, ProtectionDigest: artifact.Digest{1}, SnapshotDigest: artifact.Digest{2}, Acceptance: identity.Revision{UID: p.RootID, Generation: 1, Digest: artifact.Digest{3}}}}}
	f := &downloadControlFixture{now: n, a: base.a, runtimeAvailable: true, pending: true}
	f.a.Environment = artifact.DownloadEnvironment{RootID: p.RootID, InstallationID: p.RootID, Region: "synthetic", StoreID: r.Expectation.Registration.StoreID, RecoveryEpoch: p.RootID, Location: r.Expectation.Registration.Location, Principal: p.Principal, Revision: rev, RecoveryRevision: rev}
	f.a.Retention = proof
	f.i = identity.Identity{Principal: p.Principal, Policy: rev, Scopes: []string{"evidence:read", "evidence:download"}}
	f.source = ContextDownloadSource{Scope: p, Expectation: r.Expectation, Copies: r.Copies}
	f.plan = ContextDownloadPlan{Allocation: artifact.DownloadAllocation{ID: p.RootID, RootID: p.RootID, ClusterID: p.ClusterID, NamespaceUID: p.NamespaceUID, WorkloadUID: p.WorkloadUID, OutputLimit: 1 << 20, ReadLimit: 128 << 20, SessionLimit: 4, ValidUntil: n.Add(time.Hour)}, OutputLimit: 8192, ReadLimit: 16 << 20, RequestLimit: 4, Duration: 30 * time.Minute}
	f.refresh(n)
	if !f.a.Valid(n) || !f.source.Valid(n) || !f.plan.Valid(p, n) {
		t.Fatal("invalid synthetic control fixture")
	}
	return f, ContextDownloadCoordinator{RootID: p.RootID, InstallationID: p.RootID, Recovery: f, Routes: f, Sources: f, Authority: f, Sessions: f, Plans: f, Runtime: f, Now: func() time.Time { return f.now }, NewID: func() string { return "22222222-2222-4222-8222-222222222222" }}
}
func countDownloadCalls(f *downloadControlFixture, name string) int {
	n := 0
	for _, x := range f.calls {
		if x == name {
			n++
		}
	}
	return n
}
func TestContextDownloadNormalStartupContinuesOriginalKeyWithoutAnotherSession(t *testing.T) {
	f, s := newDownloadControlFixture(t)
	id := f.a.Scope.ArtifactID
	first, err := s.PrepareContextDownload(context.Background(), f, id, "first-key")
	if err != nil || !first.ContinuePreparation || first.Metadata != nil || first.Session.State != artifact.DownloadPreparing {
		t.Fatal(first, err)
	}
	before := first.Session
	f.refresh(f.now.Add(6 * time.Second))
	f.pending = false
	f.plan.Allocation.ID = "33333333-3333-4333-8333-333333333333"
	f.plan.OutputLimit = 16384
	next, err := s.PrepareContextDownload(context.Background(), f, id, "first-key")
	if err != nil || next.ContinuePreparation || next.Metadata == nil || next.Session.ID != before.ID || next.Session.AllocationID != before.AllocationID || !next.Session.Deadline.Equal(before.Deadline) || next.Session.OutputLimit != before.OutputLimit {
		t.Fatal(next, err)
	}
	if countDownloadCalls(f, "reserve") != 1 || countDownloadCalls(f, "plan") != 1 || countDownloadCalls(f, "continue") != 2 {
		t.Fatal(f.calls)
	}
}
func TestContextDownloadStatusAndReadyReplayDoNotPrepareAgain(t *testing.T) {
	f, s := newDownloadControlFixture(t)
	f.pending = false
	first, err := s.PrepareContextDownload(context.Background(), f, f.a.Scope.ArtifactID, "key")
	if err != nil {
		t.Fatal(err)
	}
	f.refresh(f.now.Add(6 * time.Second))
	f.session.Generation = 2
	f.session.State = artifact.DownloadStreaming
	f.a.AccessUntil = f.now.Add(20 * time.Second)
	f.a.DeleteBy = f.now.Add(30 * time.Second)
	got, err := s.GetContextDownload(context.Background(), f, first.Session.ID)
	if err != nil || got.Metadata == nil || got.Metadata.SHA256 != first.Metadata.SHA256 || got.Metadata.ReadUntil != f.a.AccessUntil || got.Metadata.DeleteBy != f.a.DeleteBy || got.ContinuePreparation {
		t.Fatal(got, err)
	}
	if _, err = s.PrepareContextDownload(context.Background(), f, f.a.Scope.ArtifactID, "key"); err != nil {
		t.Fatal(err)
	}
	if countDownloadCalls(f, "continue") != 1 || countDownloadCalls(f, "reserve") != 1 || countDownloadCalls(f, "source") != 1 {
		t.Fatal(f.calls)
	}
}
func TestContextDownloadMissingRuntimeAndFailuresHaveNoReservation(t *testing.T) {
	for _, which := range []string{"nil", "disabled", "lookup-key", "route", "authority", "plan"} {
		t.Run(which, func(t *testing.T) {
			f, s := newDownloadControlFixture(t)
			switch which {
			case "nil":
				s.Runtime = nil
			case "disabled":
				f.runtimeAvailable = false
			default:
				f.fail = which
			}
			if _, err := s.PrepareContextDownload(context.Background(), f, f.a.Scope.ArtifactID, "key"); err == nil {
				t.Fatal("unavailable service accepted")
			}
			if slices.Contains(f.calls, "reserve") || slices.Contains(f.calls, "continue") {
				t.Fatal(f.calls)
			}
		})
	}
}
func TestContextDownloadUnknownReservationAndPreparationStayUncertain(t *testing.T) {
	for _, which := range []string{"reserve", "continue"} {
		t.Run(which, func(t *testing.T) {
			f, s := newDownloadControlFixture(t)
			f.fail = which
			out, err := s.PrepareContextDownload(context.Background(), f, f.a.Scope.ArtifactID, "key")
			if err == nil || out.ContinuePreparation || out.Session.ID != "" || !f.found {
				t.Fatal(out, err)
			}
			id, deadline := f.session.ID, f.session.Deadline
			f.fail = ""
			out, err = s.PrepareContextDownload(context.Background(), f, f.a.Scope.ArtifactID, "key")
			if err != nil || out.Session.ID != id || out.Session.Deadline != deadline || countDownloadCalls(f, "reserve") != 1 {
				t.Fatal(out, err, f.calls)
			}
		})
	}
}
func TestContextDownloadCacheLossDoesNotSilentlyReprepareOrRevive(t *testing.T) {
	for _, state := range []artifact.DownloadState{artifact.DownloadReady} {
		t.Run(string(state), func(t *testing.T) {
			f, s := newDownloadControlFixture(t)
			f.pending = false
			if _, err := s.PrepareContextDownload(context.Background(), f, f.a.Scope.ArtifactID, "key"); err != nil {
				t.Fatal(err)
			}
			f.session.State = state
			f.prepared = artifact.PreparedDownload{}
			if _, err := s.GetContextDownload(context.Background(), f, f.session.ID); !errors.Is(err, ErrDownloadMetadataUnavailable) {
				t.Fatal(err)
			}
			if _, err := s.PrepareContextDownload(context.Background(), f, f.a.Scope.ArtifactID, "key"); !errors.Is(err, ErrDownloadMetadataUnavailable) {
				t.Fatal(err)
			}
			if countDownloadCalls(f, "continue") != 1 || countDownloadCalls(f, "reserve") != 1 || f.session.State != state {
				t.Fatal(f.calls)
			}
		})
	}
}
func TestContextDownloadFinalFreshnessAndIdentityFence(t *testing.T) {
	for _, which := range []string{"groups", "scope", "policy", "deadline", "cancel", "metadata"} {
		t.Run(which, func(t *testing.T) {
			f, s := newDownloadControlFixture(t)
			f.pending = false
			if _, err := s.PrepareContextDownload(context.Background(), f, f.a.Scope.ArtifactID, "key"); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			f.after = func(step string) {
				if step != "metadata-read" {
					return
				}
				switch which {
				case "groups":
					f.i.Groups = []string{"changed"}
				case "scope":
					f.i.Scopes = []string{"evidence:read"}
				case "policy":
					f.i.Policy.Generation++
				case "deadline":
					f.now = f.now.Add(6 * time.Second)
				case "cancel":
					cancel()
				case "metadata":
					f.prepared.Scope.Version[0]++
				}
			}
			if out, err := s.GetContextDownload(ctx, f, f.session.ID); err == nil || out.Metadata != nil {
				t.Fatal(out, err)
			}
		})
	}
}
func TestContextDownloadFinalShortenedIdentityDeadlineIsPreserved(t *testing.T) {
	f, s := newDownloadControlFixture(t)
	f.pending = false
	if _, err := s.PrepareContextDownload(context.Background(), f, f.a.Scope.ArtifactID, "key"); err != nil {
		t.Fatal(err)
	}
	shortened := f.now.Add(time.Second)
	f.after = func(step string) {
		if step == "observe" {
			f.i.ValidUntil = shortened
		}
	}
	out, err := s.GetContextDownload(context.Background(), f, f.session.ID)
	if err != nil || out.ValidUntil != shortened {
		t.Fatal(out.ValidUntil, err)
	}
}
func TestContextDownloadOriginalKeyDoesNotRetarget(t *testing.T) {
	f, s := newDownloadControlFixture(t)
	if _, err := s.PrepareContextDownload(context.Background(), f, f.a.Scope.ArtifactID, "key"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.PrepareContextDownload(context.Background(), f, "33333333-3333-4333-8333-333333333333", "key"); !errors.Is(err, artifact.ErrDownloadConflict) {
		t.Fatal(err)
	}
	if countDownloadCalls(f, "route") != 1 || countDownloadCalls(f, "reserve") != 1 {
		t.Fatal(f.calls)
	}
}

func TestContextDownloadScopeAndDeadlineFailuresPrecedeEffects(t *testing.T) {
	for _, which := range []string{"no-download", "foreign-client", "source-expired", "runtime-expired", "plan-expired"} {
		t.Run(which, func(t *testing.T) {
			f, s := newDownloadControlFixture(t)
			if which == "foreign-client" {
				if _, err := s.PrepareContextDownload(context.Background(), f, f.a.Scope.ArtifactID, "key"); err != nil {
					t.Fatal(err)
				}
				f.calls = nil
				f.i.Principal.ClientID = "another-client"
			}
			if which == "no-download" {
				f.i.Scopes = []string{"evidence:read"}
			}
			f.after = func(step string) {
				if (which == "source-expired" && step == "source") || (which == "runtime-expired" && step == "runtime-check") || (which == "plan-expired" && step == "plan") {
					f.now = f.now.Add(6 * time.Second)
				}
			}
			out, err := s.PrepareContextDownload(context.Background(), f, f.a.Scope.ArtifactID, "key")
			if err == nil || out.Metadata != nil || slices.Contains(f.calls, "continue") {
				t.Fatal(out, err, f.calls)
			}
			if which != "source-expired" && slices.Contains(f.calls, "reserve") {
				t.Fatal("expired authority reserved", f.calls)
			}
		})
	}
}

func TestContextDownloadTerminalStatusOutlivesTransferDeadlineWithoutRuntime(t *testing.T) {
	for _, state := range []artifact.DownloadState{artifact.DownloadCompleted, artifact.DownloadCancelled, artifact.DownloadExpired, artifact.DownloadDenied, artifact.DownloadFailed, artifact.DownloadPreparing, artifact.DownloadReady, artifact.DownloadStreaming, artifact.DownloadInterrupted} {
		t.Run(string(state), func(t *testing.T) {
			f, s := newDownloadControlFixture(t)
			if _, err := s.PrepareContextDownload(context.Background(), f, f.a.Scope.ArtifactID, "key"); err != nil {
				t.Fatal(err)
			}
			f.session.Deadline = f.now.Add(time.Second)
			f.session.State = state
			f.refresh(f.now.Add(2 * time.Second))
			f.calls = nil
			before := f.session
			s.Runtime = nil
			expected := state
			if !state.Terminal() {
				expected = artifact.DownloadExpired
			}
			get, err := s.GetContextDownload(context.Background(), f, f.session.ID)
			if err != nil || get.Session.State != expected || get.Metadata != nil || get.ContinuePreparation || !get.ValidUntil.After(f.now) {
				t.Fatal(get, err)
			}
			replay, err := s.PrepareContextDownload(context.Background(), f, f.a.Scope.ArtifactID, "key")
			if err != nil || replay.Session.State != expected || replay.Session.ID != before.ID || replay.Metadata != nil || replay.ContinuePreparation {
				t.Fatal(replay, err)
			}
			if f.session.State != before.State || f.session.Deadline != before.Deadline || f.session.Requests != before.Requests || f.session.Generation != before.Generation {
				t.Fatal("status mutated stored session")
			}
			for _, forbidden := range []string{"runtime-check", "metadata-read", "continue", "source", "reserve", "plan"} {
				if slices.Contains(f.calls, forbidden) {
					t.Fatal(f.calls)
				}
			}
		})
	}
}
func TestContextDownloadTerminalStatusStillRequiresCurrentAuthority(t *testing.T) {
	for _, failed := range []string{"identity", "authority", "observe"} {
		t.Run(failed, func(t *testing.T) {
			f, s := newDownloadControlFixture(t)
			if _, err := s.PrepareContextDownload(context.Background(), f, f.a.Scope.ArtifactID, "key"); err != nil {
				t.Fatal(err)
			}
			f.session.State = artifact.DownloadCompleted
			f.session.Deadline = f.now.Add(time.Second)
			f.refresh(f.now.Add(2 * time.Second))
			s.Runtime = nil
			f.fail = failed
			if out, err := s.GetContextDownload(context.Background(), f, f.session.ID); err == nil || out.Session.ID != "" {
				t.Fatal(out, err)
			}
		})
	}
}
func TestContextDownloadContinuationHonorsOriginalTransferDeadline(t *testing.T) {
	for _, duringSource := range []bool{false, true} {
		f, s := newDownloadControlFixture(t)
		if _, err := s.PrepareContextDownload(context.Background(), f, f.a.Scope.ArtifactID, "key"); err != nil {
			t.Fatal(err)
		}
		f.session.Deadline = f.now.Add(time.Second)
		f.calls = nil
		if duringSource {
			f.after = func(step string) {
				if step == "source" {
					f.now = f.now.Add(2 * time.Second)
				}
			}
		}
		out, err := s.PrepareContextDownload(context.Background(), f, f.a.Scope.ArtifactID, "key")
		if duringSource {
			if err == nil || out.ContinuePreparation || slices.Contains(f.calls, "continue") {
				t.Fatal("expired source read continued preparation", out, err, f.calls)
			}
		} else if err != nil || !out.ContinuePreparation || !f.continuationDeadline.Equal(f.session.Deadline) {
			t.Error("continuation extended original transfer deadline", out, f.continuationDeadline, err)
		}
	}
}
func TestContextDownloadReadyReplayDoesNotRequireStartupCheck(t *testing.T) {
	f, s := newDownloadControlFixture(t)
	f.pending = false
	if _, err := s.PrepareContextDownload(context.Background(), f, f.a.Scope.ArtifactID, "key"); err != nil {
		t.Fatal(err)
	}
	f.runtimeAvailable = false
	f.calls = nil
	if out, err := s.PrepareContextDownload(context.Background(), f, f.a.Scope.ArtifactID, "key"); err != nil || out.Metadata == nil {
		t.Fatal(out, err)
	}
	if slices.Contains(f.calls, "runtime-check") || slices.Contains(f.calls, "continue") {
		t.Fatal(f.calls)
	}
}

func TestContextDownloadTerminalViewRetainsCurrentShortenedEvidenceLimits(t *testing.T) {
	f, s := newDownloadControlFixture(t)
	if _, err := s.PrepareContextDownload(context.Background(), f, f.a.Scope.ArtifactID, "key"); err != nil {
		t.Fatal(err)
	}
	originalDeadline := f.session.Deadline
	f.session.State = artifact.DownloadCompleted
	s.Runtime = nil
	for _, duration := range []time.Duration{20 * time.Second, 10 * time.Second} {
		f.a.AccessUntil = f.now.Add(duration)
		f.a.DeleteBy = f.a.AccessUntil.Add(time.Minute)
		out, err := s.GetContextDownload(context.Background(), f, f.session.ID)
		if err != nil || out.Session.State != artifact.DownloadCompleted || out.Metadata != nil || out.AccessUntil != f.a.AccessUntil || out.DeleteBy != f.a.DeleteBy || !out.Session.Deadline.Equal(originalDeadline) {
			t.Fatal("terminal status lost current retention or rewrote original session deadline", out, err)
		}
		if !out.AccessUntil.Before(out.Session.Deadline) {
			t.Fatal("fixture did not shorten access below original transfer deadline")
		}
	}
}
