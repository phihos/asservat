package capacity

import (
	"context"
	"testing"
	"time"

	value "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/identity"
)

// Delay the guard's final checks past the newly learned cutoff while the
// original caller/source bound still has time left. The shorter observation
// must not become a successful result merely because it was live when read.
func queryFinalBoundGuard(now *time.Time, shortened *time.Time) QueryDeploymentGuard {
	return queryDeploymentGuardFunc(func(ctx context.Context, _ ContextQueryQualification, _ QueryDeploymentPin, next func(context.Context) error) error {
		err := next(ctx)
		if !shortened.IsZero() {
			timer := time.NewTimer(time.Until(shortened.Add(5 * time.Millisecond)))
			defer timer.Stop()
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-timer.C:
			}
			*now = shortened.Add(5 * time.Millisecond)
		}
		return err
	})
}

func TestQueryCapacityRejectsShorterFinalSourceBound(t *testing.T) {
	for _, kind := range []string{"source", "backing"} {
		t.Run(kind, func(t *testing.T) {
			s, f, now := queryCapacityServiceFixture(t)
			var shortened time.Time
			f.final = func(last *QueryCapacitySource) {
				shortened = time.Now().Add(30 * time.Millisecond)
				if kind == "source" {
					last.FreshUntil = shortened
				} else {
					last.BackingUntil = shortened
				}
			}
			s.Deployments.Worker = queryFinalBoundGuard(now, &shortened)
			if _, err := s.ContextProjectionPolicy(context.Background()); err == nil {
				t.Fatal("final shorter source expired while guard completed, but policy succeeded")
			}
			if shortened.IsZero() || now.Before(shortened) {
				t.Fatal("regression did not cross final observation deadline")
			}
		})
	}
}

func queryCurrentPlanFixture(t *testing.T, s ProtectedContextQueryCapacity, f *queryCapacityReadFake, now time.Time) (value.ContextProjectionAuthority, value.ContextQueryPlan) {
	t.Helper()
	id := s.RootID
	rev := f.source.Qualification.ContextQuery.PolicyRevision
	until := f.source.BackingUntil
	principal := identity.Principal{Issuer: "issuer", Subject: "developer", ClientID: "console", Kind: identity.Human}
	location := artifact.Location{ClusterID: id, ArtifactID: id, AttemptID: id}
	scope := value.ContextProjectionScope{RootID: id, CaseID: id, ArtifactID: id, CaptureID: id, ClusterID: id, NamespaceUID: "namespace", WorkloadUID: "workload", PodUID: "pod", Version: artifact.Digest{1}, SourceProjectionDigest: value.ContextSourceProjectionDigest(), SourceFormat: artifact.ContextFormat, DisplayVersion: value.ContextDisplayVersion, Selection: value.LineSelection{LineStart: 1, MaxLines: 200}, Principal: principal}
	profile := f.source.Qualification.ContextQuery.Profile
	environment := value.ContextProjectionEnvironment{RootID: id, InstallationID: s.InstallationID, Region: "local", StoreID: profile.Path.StoreID, Location: location, Principal: principal, PolicyRevision: rev, Path: profile.Path, ObservedAt: now, ValidUntil: until, Recovery: f.source.Recovery,
		Processing: artifact.DownloadProcessingProof{RootID: id, Epoch: id, CaptureID: id, Location: location, Sequence: 1, StateDigest: artifact.Digest{1}, ObservedAt: now, ValidUntil: until}}
	retention := artifact.RetentionProof{RootID: id, ClusterID: id, NamespaceUID: "namespace", WorkloadUID: "workload", PodUID: "pod", Topology: rev, Policy: rev, Selectors: rev, SourceCount: 1, ObservedAt: now, ValidUntil: until}
	retention.Sources[0] = artifact.RetentionSourceVersion{ClusterID: id, ControlNamespaceUID: "control", Epoch: id, Hub: true, ProtectionDigest: artifact.Digest{1}, SnapshotDigest: artifact.Digest{2}, Acceptance: rev}
	authority := value.ContextProjectionAuthority{Scope: scope, Environment: environment, Retention: retention, PermissionRevision: rev, IdentityRevision: rev, DecisionDigest: artifact.Digest{3}, CheckedAt: now, ValidUntil: until, AccessUntil: now.Add(time.Minute), DeleteBy: now.Add(2 * time.Minute)}
	plan := value.ContextQueryPlan{AcceptanceID: f.source.AcceptanceID, AccountID: id, AllocationID: id, RootID: id, InstallationID: s.InstallationID, ClusterID: id, NamespaceUID: "namespace", WorkloadUID: "workload", AllocationRevision: 1, PoolSource: rev, PolicySource: rev, Principal: principal, Profile: profile, ObservedAt: now, ValidUntil: until, HardUntil: now.Add(time.Minute), EffectsUntil: now.Add(3 * time.Minute), CleanupUntil: now.Add(4 * time.Minute), RetireBy: now.Add(time.Hour)}
	if !authority.Valid(now) || !plan.Valid(scope, now) {
		t.Fatal("invalid synthetic current plan")
	}
	return authority, plan
}

func TestQueryCapacityRejectsShorterFinalPlanBound(t *testing.T) {
	s, f, now := queryCapacityServiceFixture(t)
	authority, plan := queryCurrentPlanFixture(t, s, f, *now)
	var shortened time.Time
	reads, effects := 0, 0
	f.plan = func() (value.ContextQueryPlan, error) {
		reads++
		out := plan
		if reads > 1 {
			shortened = time.Now().Add(30 * time.Millisecond)
			out.ValidUntil = shortened
		}
		return out, nil
	}
	s.Deployments.Worker = queryFinalBoundGuard(now, &shortened)
	err := s.WithCurrentQueryBacking(context.Background(), plan, authority, func(context.Context) error { effects++; return nil })
	if err == nil || reads != 2 || effects != 1 || shortened.IsZero() || now.Before(shortened) {
		t.Fatalf("shorter final plan was not fenced through guard completion: error=%v reads=%d effects=%d", err, reads, effects)
	}
}

func TestQueryCapacityRejectsShorterInitialPlanBeforeEffectsOrFinalRead(t *testing.T) {
	for _, operation := range []string{"plan", "backing"} {
		t.Run(operation, func(t *testing.T) {
			s, f, now := queryCapacityServiceFixture(t)
			authority, plan := queryCurrentPlanFixture(t, s, f, *now)
			f.plan = func() (value.ContextQueryPlan, error) {
				out := plan
				out.ValidUntil = time.Now().Add(30 * time.Millisecond)
				return out, nil
			}
			// If the shorter initial plan is accepted, the outer final source
			// read would block under the longer source context.
			f.waitFinal = true
			ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
			defer cancel()
			start, effects := time.Now(), 0
			var err error
			if operation == "plan" {
				_, err = s.ContextQueryPlan(ctx, authority)
			} else {
				err = s.WithCurrentQueryBacking(ctx, plan, authority, func(context.Context) error { effects++; return nil })
			}
			if err == nil || effects != 0 || f.reads != 1 || time.Since(start) >= 200*time.Millisecond {
				t.Fatalf("shorter plan reached effects or an overlong source read: error=%v effects=%d sourceReads=%d", err, effects, f.reads)
			}
		})
	}
}

func TestQueryCapacityAcceptsPlanWithinEarlierCallerBound(t *testing.T) {
	for _, operation := range []string{"plan", "backing"} {
		t.Run(operation, func(t *testing.T) {
			s, f, now := queryCapacityServiceFixture(t)
			authority, plan := queryCurrentPlanFixture(t, s, f, *now)
			// The plan is shorter than the original backing, but the caller
			// already bounded every operation more tightly. This stays usable.
			plan.ValidUntil = now.Add(500 * time.Millisecond)
			reads := 0
			f.plan = func() (value.ContextQueryPlan, error) {
				reads++
				out := plan
				if reads > 1 {
					out.ValidUntil = now.Add(400 * time.Millisecond)
				}
				return out, nil
			}
			callerUntil := now.Add(200 * time.Millisecond)
			ctx, cancel := context.WithDeadline(context.Background(), callerUntil)
			defer cancel()
			effects := 0
			if operation == "plan" {
				out, err := s.ContextQueryPlan(ctx, authority)
				if err != nil || !out.ValidUntil.Equal(callerUntil) {
					t.Fatal("plan lost earlier caller bound", err)
				}
			} else {
				err := s.WithCurrentQueryBacking(ctx, plan, authority, func(c context.Context) error {
					effects++
					if deadline, ok := c.Deadline(); !ok || deadline.After(callerUntil) {
						t.Fatal("effect extended original caller bound")
					}
					return nil
				})
				if err != nil || effects != 1 {
					t.Fatal("current plan under earlier caller refused", err)
				}
			}
		})
	}
}
