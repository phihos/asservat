package capacity

import (
	"asservat.local/asservat/internal/domain/identity"
	"context"
	"encoding/json"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	cfg "asservat.local/asservat/internal/domain/configuration"
)

// CapacityReconciler is scheduled by the existing protected A-HWORK Lease.
// The Lease is not effect authority. Three bounded serial loops separately
// observe the source, maintain root backing, and enumerate/enroll workloads.
// SQL retains every current source/recovery/permission fence after its locks.
// No candidate or caller credential survives this process lifetime.
type CapacityReconciler struct {
	Source   *CapacitySourceObserver
	Work     *CapacityWorkReconciler
	Clusters []CapacityClusterReaders
	// SourceReport, when set, receives each source observation's outcome
	// (nil on success) from the single source loop. Diagnostics only.
	SourceReport func(error)
	// Stalled, when set, is told once when one workload-loop step is still
	// running two source intervals after it started: the loop is shared by
	// all clusters, so one stuck step starves every other cluster. ADR-197
	// runs 20a/20c went silent after enrolling. Diagnostics only.
	Stalled func(clusterID, stage string)
	// Demands, when set, adds the ADR-200 demand lane: workloads whose
	// admission asked for a fresh binding are reconciled first, back to
	// back, while the demand lasts. DemandReport sees each outcome, its
	// elapsed time and the guarded read's freshness left when it returned.
	Demands      CapacityRefreshDemandReader
	DemandReport func(err error, elapsed, left time.Duration, stages string)
	// DemandContext optionally adds a diagnostic recorder to a demand
	// refresh's context and returns its fixed stage marks.
	DemandContext func(context.Context) (context.Context, func() string)
	running       atomic.Bool
}

// CapacitySourceInvocation is only the existing source invocation boundary.
// The installed bootstrap wrapper may schedule and bracket the exact observer;
// this port neither creates a new authority DTO nor supplies a source proof.
type CapacitySourceInvocation interface {
	Observe(context.Context) (AcceptedCapacitySource, error)
}

// Only a detached bounded source snapshot is shared. Reads preserve its exact
// original dates. A failure or known revision change cancels already-started
// work immediately; a successful same-revision heartbeat cannot renew it.
type capacityCurrentSource struct {
	mu     sync.Mutex
	bytes  []byte
	value  AcceptedCapacitySource
	ctx    context.Context
	cancel context.CancelFunc
}

func (s *capacityCurrentSource) clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cancel != nil {
		s.cancel()
	}
	s.bytes, s.cancel, s.ctx = nil, nil, nil
	s.value = AcceptedCapacitySource{}
}

func (s *capacityCurrentSource) publish(root context.Context, v AcceptedCapacitySource, now time.Time) error {
	if root == nil || root.Err() != nil || !v.Valid(now) {
		s.clear()
		return cfg.ErrUnavailable
	}
	b, err := json.Marshal(v)
	if err != nil || len(b) > CapacitySourceBytes+4096 {
		s.clear()
		return cfg.ErrUnavailable
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.bytes) != 0 && (v.Revision < s.value.Revision || v.ObservedAt.Before(s.value.ObservedAt)) {
		if s.cancel != nil {
			s.cancel()
		}
		s.bytes, s.cancel, s.ctx = nil, nil, nil
		return cfg.ErrUnavailable
	}
	changed := s.ctx == nil || v.RootID != s.value.RootID || v.InstallationID != s.value.InstallationID || v.QualificationID != s.value.QualificationID || v.QualificationDigest != s.value.QualificationDigest || v.Revision != s.value.Revision || v.Observation.Digest != s.value.Observation.Digest || v.ProtectionDigest != s.value.ProtectionDigest
	if changed {
		if s.cancel != nil {
			s.cancel()
		}
		s.ctx, s.cancel = context.WithCancel(root)
	}
	s.bytes, s.value = b, v
	return nil
}

func (s *capacityCurrentSource) read(now time.Time) (context.Context, AcceptedCapacitySource, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out AcceptedCapacitySource
	if s.ctx == nil || s.ctx.Err() != nil || len(s.bytes) == 0 || json.Unmarshal(s.bytes, &out) != nil || !out.Valid(now) {
		return nil, out, false
	}
	return s.ctx, out, true
}

func capacitySerialLoop(ctx context.Context, pause time.Duration, call func(context.Context)) {
	for ctx.Err() == nil {
		live, end := context.WithTimeout(ctx, CapacitySourceInterval)
		call(live)
		end()
		timer := time.NewTimer(pause)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

func (s *CapacityReconciler) Run(ctx context.Context) error {
	return s.run(ctx, nil)
}

// RunWithSourceInvocation is the fresh installed worker's typed scheduling
// composition. The concrete Source still supplies all original validation and
// bindings; ordinary Run uses it directly and retains its existing cadence.
func (s *CapacityReconciler) RunWithSourceInvocation(ctx context.Context, source CapacitySourceInvocation) error {
	if source == nil {
		return cfg.ErrInvalid
	}
	return s.run(ctx, source)
}

func (s *CapacityReconciler) run(ctx context.Context, source CapacitySourceInvocation) error {
	if s == nil || ctx == nil || ctx.Err() != nil || s.Source == nil || s.Source.Now == nil || s.Source.Source == nil || s.Source.Protection == nil || s.Source.Recovery == nil || s.Source.Journal == nil || s.Work == nil || s.Work.Now == nil || s.Work.Recovery == nil || s.Work.Permissions == nil || s.Work.Processing == nil || s.Work.Root == nil || s.Work.Enrollment == nil || s.Work.Bindings == nil || !s.Work.Qualification.Valid() || s.Source.RootID != s.Work.Qualification.RootBacking.RootID || s.Source.InstallationID != s.Work.Qualification.RootBacking.InstallationID || s.Source.QualificationID != s.Work.Qualification.ID || s.Source.QualificationDigest != s.Work.Qualification.Digest || len(s.Clusters) != len(s.Work.Qualification.NamespaceGuards)+len(s.Work.Regional) {
		return cfg.ErrInvalid
	}
	seen := map[string]bool{}
	for _, c := range s.Clusters {
		if s.Work.namespacePin(c.ClusterID) == nil || seen[c.ClusterID] || c.Workloads == nil || c.Guard == nil {
			return cfg.ErrInvalid
		}
		seen[c.ClusterID] = true
	}
	if !s.running.CompareAndSwap(false, true) {
		return cfg.ErrInvalid
	}
	root, cancel := context.WithCancel(ctx)
	defer cancel()
	var current capacityCurrentSource
	defer current.clear()
	var owners sync.WaitGroup
	owners.Add(3)
	if s.Demands != nil {
		owners.Add(1)
	}
	go func() {
		defer owners.Done()
		observe := func(call context.Context) {
			reader := source
			if reader == nil {
				reader = s.Source
			}
			v, err := reader.Observe(call)
			if err == nil {
				err = call.Err()
			}
			if err == nil {
				err = current.publish(root, v, s.Work.Now())
			}
			if err != nil {
				current.clear()
			}
			if s.SourceReport != nil {
				s.SourceReport(err)
			}
		}
		if source == nil {
			capacitySerialLoop(root, time.Second, observe)
			return
		}
		// Only a scheduling context exists before entering the fixed installed
		// invocation. Its concrete observer creates the original finite source
		// interval after admission. Existing parent deadlines remain unchanged.
		for root.Err() == nil {
			observe(root)
			timer := time.NewTimer(time.Second)
			select {
			case <-root.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
		}
	}()
	go func() {
		defer owners.Done()
		capacitySerialLoop(root, time.Second, func(call context.Context) {
			if original, v, ok := current.read(s.Work.Now()); ok {
				until, _ := call.Deadline()
				live, end := context.WithDeadline(original, until)
				defer end()
				_ = s.Work.ReconcileRoot(live, v)
			}
		})
	}()
	go func() {
		defer owners.Done()
		cursors := make([]capacityDiscoveryCursor, len(s.Clusters))
		ended := make([]time.Time, len(s.Clusters))
		reported := make([]time.Time, len(s.Clusters))
		steps, candidates := make([]int64, len(s.Clusters)), make([]int64, len(s.Clusters))
		next := 0
		var stage atomic.Pointer[string]
		mark := func(v string) { stage.Store(&v) }
		capacitySerialLoop(root, 250*time.Millisecond, func(call context.Context) {
			i := next
			next = (next + 1) % len(s.Clusters)
			if p := s.Clusters[i].Pace; p > 0 {
				if s.Work.Now().Before(ended[i].Add(p)) {
					return
				}
				defer func() { ended[i] = s.Work.Now() }()
			}
			mark("discover")
			if s.Stalled != nil {
				id := s.Clusters[i].ClusterID
				t := time.AfterFunc(2*CapacitySourceInterval, func() { s.Stalled(id, *stage.Load()) })
				defer t.Stop()
			}
			ns, candidate, found, err := cursors[i].next(call, s.Clusters[i].Workloads)
			steps[i]++
			if found {
				candidates[i]++
			}
			if report := s.Clusters[i].Progress; report != nil && (reported[i].IsZero() || !s.Work.Now().Before(reported[i].Add(30*time.Second))) {
				reported[i] = s.Work.Now()
				c := cursors[i]
				report(CapacityDiscoveryProgress{Steps: steps[i], Candidates: candidates[i], NamespaceIndex: c.namespaceIndex, NamespaceCount: len(c.namespaces), KindIndex: c.kindIndex, WorkloadIndex: c.workloadIndex, WorkloadCount: len(c.workloads)})
			}
			if err != nil || !found || call.Err() != nil {
				return
			}
			// The candidate LIST does not confer freshness. The exact read gets a
			// separate original source interval; no already-issued permit changes.
			started := s.Work.Now()
			_, err = s.reconcileCandidate(call, &current, s.Clusters[i], ns, candidate, mark)
			if report := s.Clusters[i].Report; report != nil {
				report(err, s.Work.Now().Sub(started))
			}
		})
	}()
	if s.Demands != nil {
		go func() {
			defer owners.Done()
			s.runDemands(root, &current)
		}()
	}
	<-root.Done()
	current.clear()
	// Cancel first, then join actual owners. Returning on a shutdown timer
	// would release the fixed SQL/process envelope with work still running.
	owners.Wait()
	return root.Err()
}

// reconcileCandidate runs one candidate through the regional guarded path
// (ADR-197: the guarded read first, then the current source) or the ordinary
// path. mark names the running stage for the stall watchdog. It also returns
// how much freshness the guarded read had left when it returned (zero on the
// ordinary path), which bounds every later step.
func (s *CapacityReconciler) reconcileCandidate(call context.Context, current *capacityCurrentSource, c CapacityClusterReaders, ns cfg.NamespaceRef, candidate cfg.WorkloadRef, mark func(string)) (time.Duration, error) {
	var facts *CapacityGuardedFacts
	var left time.Duration
	if c.Guarded != nil {
		mark("guarded-read")
		v, err := s.Work.ReadGuardedCandidate(call, c, ns, candidate)
		if err != nil {
			return 0, err
		}
		facts = &v
		left = identity.Earlier(v.Guard.FreshUntil, v.Workload.FreshUntil).Sub(s.Work.Now())
	}
	original, v, ok := current.read(s.Work.Now())
	if !ok {
		return left, capacityStage("source", cfg.ErrUnavailable)
	}
	until, _ := call.Deadline()
	live, end := context.WithDeadline(original, until)
	defer end()
	if facts != nil {
		mark("guarded-reconcile")
		return left, s.Work.ReconcileGuardedWorkload(live, v, c, ns, candidate, *facts)
	}
	mark("reconcile")
	return left, s.Work.ReconcileWorkload(live, v, c, ns, candidate)
}

// runDemands is the ADR-200 demand lane. Each step reads the active demands
// and reconciles one of them, round robin, with no pace: a regional refresh
// takes about one exchange, and the binding stays fresh for five seconds
// from its observation. Discovery keeps enrolling new workloads beside it.
func (s *CapacityReconciler) runDemands(root context.Context, current *capacityCurrentSource) {
	turn := 0
	capacitySerialLoop(root, 250*time.Millisecond, func(call context.Context) {
		demands, err := s.Demands.ReadCapacityRefreshDemands(call)
		if err != nil || len(demands) == 0 || call.Err() != nil {
			return
		}
		d := demands[turn%len(demands)]
		turn++
		for _, c := range s.Clusters {
			if c.ClusterID != d.ClusterID {
				continue
			}
			started := s.Work.Now()
			observed := func() string { return "" }
			if s.DemandContext != nil {
				call, observed = s.DemandContext(call)
			}
			// Fixed stage names with each stage's duration, for diagnostics.
			var stages []string
			stage, at := "", started
			left, err := s.reconcileCandidate(call, current, c, d.Namespace, d.Workload, func(next string) {
				if stage != "" {
					stages = append(stages, stage+"="+s.Work.Now().Sub(at).Round(10*time.Millisecond).String())
				}
				stage, at = next, s.Work.Now()
			})
			if stage != "" {
				stages = append(stages, stage+"="+s.Work.Now().Sub(at).Round(10*time.Millisecond).String())
			}
			if o := observed(); o != "" {
				stages = append(stages, o)
			}
			if s.DemandReport != nil {
				s.DemandReport(err, s.Work.Now().Sub(started), left, strings.Join(stages, " "))
			}
			return
		}
	})
}
