package capacity

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	cfg "asservat.local/asservat/internal/domain/configuration"
)

type capacityWorkFacts struct {
	capacityRuntimeReader
	now         time.Time
	workload    CapacityWorkloadObservation
	permissions AcceptedCapacityPermissions
	phase       func(string, context.Context)
}

func (s *enrollmentStore) RefreshCapacityEnrollment(ctx context.Context, _ EnrollmentObservation, expected Enrollment) error {
	if s.row == nil || !sameEnrollment(*s.row, expected) || expected.ReadyAt == nil {
		return cfg.ErrUnavailable
	}
	return s.step("observe", ctx)
}

func (f *capacityWorkFacts) step(ctx context.Context, name string) error {
	if f.phase != nil {
		f.phase(name, ctx)
	}
	return ctx.Err()
}
func (f *capacityWorkFacts) RecoveryState(ctx context.Context) (artifact.RecoveryProof, error) {
	return f.recovery, f.step(ctx, "recovery")
}
func (f *capacityWorkFacts) ReadCapacityPermissions(ctx context.Context, _ artifact.RecoveryProof) (AcceptedCapacityPermissions, error) {
	return f.permissions, f.step(ctx, "permissions")
}
func (f *capacityWorkFacts) CapacityNamespaceProtection(ctx context.Context) (CapacityNamespaceProtection, error) {
	return f.guard, f.step(ctx, "guard")
}
func (f *capacityWorkFacts) ReadCapacityWorkload(ctx context.Context, _ cfg.NamespaceRef, _ cfg.WorkloadRef, _ []string) (CapacityWorkloadObservation, error) {
	return f.workload, f.step(ctx, "workload")
}

func capacityWorkFixture() (*CapacityWorkReconciler, *capacityWorkFacts, AcceptedCapacitySource, CapacityClusterReaders, *enrollmentStore) {
	a, g, w, p, old, original := enrollmentObservationFacts()
	n := time.Now().UTC().Truncate(time.Microsecond)
	shift := n.Sub(original)
	for _, pair := range [][2]*time.Time{{&a.ObservedAt, &a.FreshUntil}, {&a.Observation.Snapshot.ObservedAt, &a.Observation.Snapshot.FreshUntil}, {&g.ObservedAt, &g.FreshUntil}, {&w.ObservedAt, &w.FreshUntil}, {&w.Namespace.ObservedAt, &w.Namespace.FreshUntil}, {&p.ObservedAt, &p.FreshUntil}, {&old.Recovery.ObservedAt, &old.Recovery.FreshUntil}} {
		*pair[0] = pair[0].Add(shift)
		*pair[1] = pair[1].Add(shift)
	}
	f := &capacityWorkFacts{now: n, workload: w, permissions: p, capacityRuntimeReader: capacityRuntimeReader{guard: g, recovery: old.Recovery}}
	q, _ := capacityQualificationFixture()
	q.ID, q.Digest = a.QualificationID, a.QualificationDigest
	q.RootBacking.RootID, q.RootBacking.InstallationID = a.RootID, a.InstallationID
	q.RootBacking.QualificationID, q.RootBacking.QualificationDigest = q.ID, q.Digest
	q.NamespaceGuards = []CapacityNamespaceQualification{{ClusterID: g.ClusterID, Digest: g.Digest, Keys: append([]string(nil), g.Keys...)}}
	o, _, err := ComposeEnrollmentObservation(a, g, w, p, f.recovery, "original", n)
	if err != nil {
		panic(err)
	}
	_, receipt := enrollmentFixture(n)
	receipt.Key, receipt.SourceDigest, receipt.PlanDigest = o.Key, o.SourceDigest, o.PlanDigest
	receipt.InitialObservedAt, receipt.InitialUntil, receipt.ReservedAt = o.ObservedAt, o.FreshUntil, n
	receipt.CaptureBackedAt, receipt.ReadyAt = &n, &n
	store := &enrollmentStore{row: &receipt, now: &f.now}
	now := func() time.Time { return f.now }
	s := &CapacityWorkReconciler{Qualification: q, Recovery: f, Permissions: f, Bindings: store, Now: now,
		Enrollment: &EnrollmentCoordinator{Store: store, Capture: store, Accounts: enrollmentAccounts{"original", receipt.AccountDigest}, Now: now}}
	return s, f, a, CapacityClusterReaders{ClusterID: g.ClusterID, Guard: f, Workloads: f}, store
}

func TestCapacityWorkReconcilerRechecksDiscoveryAndEveryOriginalDeadline(t *testing.T) {
	for _, mode := range []string{"ready", "recovery", "permissions", "guard", "workload", "read", "observe", "unknown-observe", "cancel-observe", "namespace-replaced", "workload-replaced", "foreign-guard", "unapproved-key"} {
		t.Run(mode, func(t *testing.T) {
			s, f, source, cluster, store := capacityWorkFixture()
			namespace, candidate := f.workload.Namespace.Namespace, f.workload.Workload
			until := f.now.Add(200 * time.Millisecond)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			f.recovery.FreshUntil = until
			f.phase = func(name string, ctx context.Context) {
				if name != "recovery" {
					d, ok := ctx.Deadline()
					if !ok || d.After(until) {
						t.Error("subsequent read lost original recovery bound")
					}
				}
				if name == mode {
					f.now = until
				}
			}
			store.hook = func(name string, ctx context.Context) {
				d, ok := ctx.Deadline()
				if !ok || d.After(until) {
					t.Error("SQL operation lost original recovery deadline")
				}
				if name == mode {
					f.now = until
				}
				if name == "observe" && mode == "cancel-observe" {
					cancel()
				}
			}
			switch mode {
			case "namespace-replaced":
				f.workload.Namespace.Namespace.UID = "replacement"
			case "workload-replaced":
				f.workload.Workload.UID = "replacement"
			case "foreign-guard":
				f.guard.Digest[0]++
			case "unapproved-key":
				f.guard.Keys = []string{"foreign"}
			case "unknown-observe":
				store.fail = "observe"
			}
			original := *store.row
			err := s.ReconcileWorkload(ctx, source, cluster, namespace, candidate)
			want := []string(nil)
			if mode == "read" {
				want = []string{"read"}
			} else if mode == "ready" || mode == "observe" || mode == "unknown-observe" || mode == "cancel-observe" {
				want = []string{"read", "observe"}
			}
			if mode == "ready" {
				if err != nil {
					t.Fatal("current exact binding observation failed", err, store.calls)
				}
			} else if err == nil {
				t.Fatal("changed, unknown, canceled or expired facts succeeded", store.calls)
			}
			stages := map[string]string{"foreign-guard": "guard-pin", "unapproved-key": "guard-pin", "workload-replaced": "workload", "observe": "refresh-fresh"}
			var step interface{ FixedStep() string }
			if want, ok := stages[mode]; ok && (!errors.As(err, &step) || step.FixedStep() != want || !errors.Is(err, cfg.ErrUnavailable)) {
				t.Fatal("refusal does not name its stage", err, want)
			}
			if !slices.Equal(store.calls, want) || !sameEnrollment(original, *store.row) {
				t.Fatal("unexpected phase or original enrollment changed", store.calls, want)
			}
		})
	}
}

type capacityGuardedFacts struct {
	*capacityWorkFacts
	calls int
}

func (f *capacityGuardedFacts) ReadCapacityGuardedWorkload(ctx context.Context, _ cfg.NamespaceRef, _ cfg.WorkloadRef, keys []string) (CapacityNamespaceProtection, CapacityWorkloadObservation, error) {
	f.calls++
	if !slices.Equal(keys, f.guard.Keys) {
		return CapacityNamespaceProtection{}, CapacityWorkloadObservation{}, cfg.ErrInvalid
	}
	return f.guard, f.workload, f.step(ctx, "guarded")
}

// ADR-197: a regional cluster's guard and workload come from one combined
// observation under the pinned keys; the same checks then apply.
func TestCapacityWorkReconcilerUsesOneGuardedObservation(t *testing.T) {
	s, f, source, cluster, _ := capacityWorkFixture()
	guarded := &capacityGuardedFacts{capacityWorkFacts: f}
	separate := 0
	f.phase = func(name string, _ context.Context) {
		if name == "guard" || name == "workload" {
			separate++
		}
	}
	cluster.Guarded = guarded
	if err := s.ReconcileWorkload(context.Background(), source, cluster, f.workload.Namespace.Namespace, f.workload.Workload); err != nil {
		t.Fatal(err)
	}
	if guarded.calls != 1 || separate != 0 {
		t.Fatal("guarded observation not used alone", guarded.calls, separate)
	}
	f.guard.Digest = artifact.Digest{9}
	if err := s.ReconcileWorkload(context.Background(), source, cluster, f.workload.Namespace.Namespace, f.workload.Workload); err == nil {
		t.Fatal("guarded observation of another guard accepted")
	}
}

// ADR-197: a regional guarded read happens first, on its own window; the
// facts then pass the same pin and freshness checks inside the source
// interval taken afterwards, with no second read.
func TestCapacityWorkReconcilerChecksPreReadGuardedFacts(t *testing.T) {
	s, f, source, cluster, _ := capacityWorkFixture()
	guarded := &capacityGuardedFacts{capacityWorkFacts: f}
	cluster.Guarded = guarded
	facts, err := s.ReadGuardedCandidate(context.Background(), cluster, f.workload.Namespace.Namespace, f.workload.Workload)
	if err != nil || guarded.calls != 1 {
		t.Fatal("guarded read", err, guarded.calls)
	}
	if err = s.ReconcileGuardedWorkload(context.Background(), source, cluster, f.workload.Namespace.Namespace, f.workload.Workload, facts); err != nil || guarded.calls != 1 {
		t.Fatal("pre-read facts not reconciled alone", err, guarded.calls)
	}
	other := facts
	other.Guard.Digest = artifact.Digest{9}
	var step interface{ FixedStep() string }
	if err = s.ReconcileGuardedWorkload(context.Background(), source, cluster, f.workload.Namespace.Namespace, f.workload.Workload, other); !errors.As(err, &step) || step.FixedStep() != "guard-pin" {
		t.Fatal("pre-read facts of another guard accepted", err)
	}
	expired := facts
	expired.Workload.FreshUntil = f.now
	if err = s.ReconcileGuardedWorkload(context.Background(), source, cluster, f.workload.Namespace.Namespace, f.workload.Workload, expired); err == nil {
		t.Fatal("expired pre-read workload accepted")
	}
}
