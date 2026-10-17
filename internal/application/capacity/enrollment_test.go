package capacity

import (
	"context"
	"errors"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/identity"
)

type enrollmentAccounts struct {
	version string
	digest  artifact.Digest
}

func (m enrollmentAccounts) AccountVersion() string { return m.version }
func (m enrollmentAccounts) CaptureAccount(root, allocation string) (artifact.Digest, error) {
	return m.digest, nil
}

type enrollmentStore struct {
	row       *Enrollment
	now       *time.Time
	calls     []string
	hook      func(string, context.Context)
	fail      string
	lostAfter string
}

func (s *enrollmentStore) step(name string, ctx context.Context) error {
	s.calls = append(s.calls, name)
	if s.hook != nil {
		s.hook(name, ctx)
	}
	if s.fail == name {
		return errors.New("synthetic lost response")
	}
	return ctx.Err()
}
func (s *enrollmentStore) ReadCapacityEnrollment(ctx context.Context, o EnrollmentObservation) (*Enrollment, error) {
	if e := s.step("read", ctx); e != nil {
		return nil, e
	}
	if s.row == nil {
		return nil, nil
	}
	v := *s.row
	return &v, nil
}
func (s *enrollmentStore) ReserveCapacityEnrollment(ctx context.Context, o EnrollmentObservation) (Enrollment, error) {
	if e := s.step("reserve", ctx); e != nil {
		return Enrollment{}, e
	}
	_, v := enrollmentFixture(*s.now)
	s.row = &v
	if s.lostAfter == "reserve" {
		return Enrollment{}, errors.New("synthetic lost commit reply")
	}
	return v, nil
}
func (s *enrollmentStore) result(name string, ctx context.Context, v Enrollment, capture bool) (Enrollment, error) {
	if e := s.step(name, ctx); e != nil {
		return Enrollment{}, e
	}
	n := *s.now
	if capture {
		v.CaptureBackedAt = &n
	} else {
		v.ReadyAt = &n
	}
	s.row = &v
	if s.lostAfter == name {
		return Enrollment{}, errors.New("synthetic lost commit reply")
	}
	return v, nil
}
func (s *enrollmentStore) BackCapacityCapture(ctx context.Context, o EnrollmentObservation, v Enrollment) (Enrollment, error) {
	return s.result("capture", ctx, v, true)
}
func (s *enrollmentStore) ContinueCapacityCapture(ctx context.Context, o EnrollmentObservation, v Enrollment) (Enrollment, error) {
	return s.result("continue-capture", ctx, v, true)
}
func (s *enrollmentStore) PublishCapacityEnrollment(ctx context.Context, o EnrollmentObservation, v Enrollment) (Enrollment, error) {
	return s.result("publish", ctx, v, false)
}
func (s *enrollmentStore) ContinueCapacityPublication(ctx context.Context, o EnrollmentObservation, v Enrollment) (Enrollment, error) {
	return s.result("continue-publish", ctx, v, false)
}

func enrollmentFixture(n time.Time) (EnrollmentObservation, Enrollment) {
	key := WorkloadCapacityKey{"30000000-0000-4000-8000-000000000001", capacityTestCluster, "namespace-uid", "workload-uid"}
	rev := identity.Revision{UID: "trust-uid", Generation: 1, Digest: artifact.Digest{3}}
	o := EnrollmentObservation{Key: key, SourceRevision: 1, SourceDigest: artifact.Digest{1}, PlanDigest: artifact.Digest{2}, NamespaceGuardDigest: artifact.Digest{5}, NamespaceResourceVersion: "namespace-rv", WorkloadResourceVersion: "workload-rv", PermissionEpoch: "30000000-0000-4000-8000-000000000003", PermissionSequence: 2, PermissionTrust: artifact.Digest{3}, ObservedAt: n, FreshUntil: n.Add(4 * time.Second), Recovery: artifact.RecoveryProof{InstallationID: "30000000-0000-4000-8000-000000000004", IssuerEpoch: "30000000-0000-4000-8000-000000000005", Revision: rev, ObservedAt: n, FreshUntil: n.Add(5 * time.Second)}}
	source, namespace, _ := capacitySelectionFixture()
	source.ObservedAt = n
	source.FreshUntil = n.Add(4 * time.Second)
	namespace.ObservedAt = n
	namespace.FreshUntil = n.Add(4 * time.Second)
	accepted := AcceptedCapacitySource{Format: CapacityAcceptedSourceFormat, RootID: key.RootID, InstallationID: o.Recovery.InstallationID, QualificationID: o.Recovery.InstallationID, Revision: 1, QualificationDigest: artifact.Digest{4}, ProtectionDigest: artifact.Digest{5}, Observation: sourceObservationFixture(source), ObservedAt: n, FreshUntil: source.FreshUntil}
	selected, e := SelectBudget(source, namespace, []string{"team"}, n)
	if e != nil {
		panic("invalid synthetic capacity selection")
	}
	plan, e := CompileEnrollmentPlan(accepted, selected, "original", n)
	if e != nil {
		panic("invalid synthetic capacity plan")
	}
	o.Plan = plan
	o.PlanDigest = plan.Digest()
	o.SourceDigest = plan.value.SourceDigest
	o.NamespaceLabels = map[string]string{"team": "one"}
	v := Enrollment{Format: CapacityEnrollmentFormat, Key: key, ID: "30000000-0000-4000-8000-000000000006", AttemptID: "30000000-0000-4000-8000-000000000007", AllocationID: "30000000-0000-4000-8000-000000000008", DownloadAllocationID: "30000000-0000-4000-8000-000000000009", SourceDigest: o.SourceDigest, PlanDigest: o.PlanDigest, Revision: 1, InitialObservedAt: n, InitialUntil: o.FreshUntil, ReservedAt: n, AccountVersion: "original", AccountDigest: artifact.Digest{4}}
	return o, v
}
func TestCapacityEnrollmentPreservesPartialIdentityAndCurrentBounds(t *testing.T) {
	for _, mode := range []string{"first", "expired-partial", "expired-capture-backed", "ready", "unknown-reserve", "unknown-capture", "unknown-publish", "changed-plan", "wrong-account", "expired-read", "cancel-read"} {
		t.Run(mode, func(t *testing.T) {
			n := time.Now().UTC().Truncate(time.Microsecond)
			o, v := enrollmentFixture(n)
			s := &enrollmentStore{now: &n}
			if mode != "first" && mode != "unknown-reserve" {
				s.row = &v
			}
			if mode == "expired-partial" || mode == "expired-capture-backed" {
				v.InitialObservedAt = n.Add(-time.Hour)
				v.InitialUntil = v.InitialObservedAt.Add(4 * time.Second)
				v.ReservedAt = v.InitialObservedAt
				if mode == "expired-capture-backed" {
					closed := v.ReservedAt.Add(time.Second)
					v.CaptureBackedAt = &closed
				}
			}
			if mode == "ready" {
				closed := n
				v.CaptureBackedAt = &closed
				v.ReadyAt = &closed
			}
			if mode == "changed-plan" {
				v.PlanDigest[0]++
			}
			if mode == "wrong-account" {
				v.AccountDigest[0]++
			}
			if mode == "unknown-reserve" {
				s.fail = "reserve"
			}
			if mode == "unknown-capture" {
				s.fail = "capture"
			}
			if mode == "unknown-publish" {
				s.fail = "publish"
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if mode == "expired-read" {
				s.hook = func(name string, _ context.Context) {
					if name == "read" {
						n = o.FreshUntil
					}
				}
			}
			if mode == "cancel-read" {
				s.hook = func(name string, _ context.Context) {
					if name == "read" {
						cancel()
					}
				}
			}
			c := EnrollmentCoordinator{Store: s, Capture: s, Accounts: enrollmentAccounts{"original", artifact.Digest{4}}, Now: func() time.Time { return n }}
			out, e := c.Reconcile(ctx, o)
			success := mode == "first" || mode == "ready" || mode == "expired-partial" || mode == "expired-capture-backed"
			if success {
				if e != nil || out.ReadyAt == nil {
					t.Fatalf("ready unavailable: %v, calls %v", e, s.calls)
				}
				if mode != "first" && !sameEnrollment(out, v) {
					t.Fatal("continuation rewrote original identity/dates")
				}
			} else if e == nil {
				t.Fatal("unavailable enrollment succeeded")
			}
			want := map[string][]string{"first": {"read", "reserve", "capture", "publish"}, "expired-partial": {"read", "continue-capture", "continue-publish"}, "expired-capture-backed": {"read", "continue-publish"}, "ready": {"read"}, "unknown-reserve": {"read", "reserve"}, "unknown-capture": {"read", "capture"}, "unknown-publish": {"read", "capture", "publish"}, "changed-plan": {"read"}, "wrong-account": {"read"}, "expired-read": {"read"}, "cancel-read": {"read"}}[mode]
			if len(s.calls) != len(want) {
				t.Fatalf("calls %v, want %v", s.calls, want)
			}
			for i := range want {
				if s.calls[i] != want[i] {
					t.Fatalf("calls %v, want %v", s.calls, want)
				}
			}
		})
	}
}
func TestCapacityEnrollmentNeverRenewsReadDeadline(t *testing.T) {
	n := time.Now().UTC().Truncate(time.Microsecond)
	o, v := enrollmentFixture(n)
	ctx, cancel := context.WithDeadline(context.Background(), n.Add(time.Second))
	defer cancel()
	s := &enrollmentStore{now: &n, row: &v}
	s.hook = func(_ string, call context.Context) {
		deadline, ok := call.Deadline()
		if !ok || !deadline.Equal(n.Add(time.Second)) {
			t.Fatal("caller deadline reset")
		}
	}
	c := EnrollmentCoordinator{Store: s, Capture: s, Accounts: enrollmentAccounts{"original", artifact.Digest{4}}, Now: func() time.Time { return n }}
	if _, e := c.Reconcile(ctx, o); e != nil {
		t.Fatal(e)
	}
}

func TestCapacityEnrollmentLostCommitResolvesExactOriginalPhase(t *testing.T) {
	for _, phase := range []string{"reserve", "capture", "publish"} {
		t.Run(phase, func(t *testing.T) {
			n := time.Now().UTC().Truncate(time.Microsecond)
			o, _ := enrollmentFixture(n)
			s := &enrollmentStore{now: &n, lostAfter: phase}
			c := EnrollmentCoordinator{Store: s, Capture: s, Accounts: enrollmentAccounts{"original", artifact.Digest{4}}, Now: func() time.Time { return n }}
			if _, e := c.Reconcile(context.Background(), o); e == nil {
				t.Fatal("lost reply reported success")
			}
			if s.row == nil {
				t.Fatal("fixture did not commit before losing reply")
			}
			original := *s.row
			// This is an independent current source/recovery observation. The old
			// request grant has elapsed and remains unchanged in the stored receipt.
			n = n.Add(time.Minute)
			fresh, _ := enrollmentFixture(n)
			s.lostAfter = ""
			out, e := c.Reconcile(context.Background(), fresh)
			if e != nil || out.ReadyAt == nil || !sameEnrollment(out, original) {
				t.Fatalf("exact continuation unavailable: %v", e)
			}
			counts := map[string]int{}
			for _, name := range s.calls {
				counts[name]++
			}
			if counts[phase] != 1 || counts["reserve"] != 1 {
				t.Fatalf("reissued committed SQL phase: %v", s.calls)
			}
			if phase == "publish" && (counts["continue-capture"] != 0 || counts["continue-publish"] != 0) {
				t.Fatal("completed replay mutated original backing")
			}
		})
	}
}
