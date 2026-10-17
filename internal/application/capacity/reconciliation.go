package capacity

import (
	"context"
	"encoding/json"
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
	running  atomic.Bool
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
	go func() {
		defer owners.Done()
		observe := func(call context.Context) {
			reader := source
			if reader == nil {
				reader = s.Source
			}
			v, err := reader.Observe(call)
			if err != nil || call.Err() != nil || current.publish(root, v, s.Work.Now()) != nil {
				current.clear()
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
		next := 0
		capacitySerialLoop(root, 250*time.Millisecond, func(call context.Context) {
			i := next
			next = (next + 1) % len(s.Clusters)
			if p := s.Clusters[i].Pace; p > 0 {
				if s.Work.Now().Before(ended[i].Add(p)) {
					return
				}
			}
			if w := s.Clusters[i].MinSourceWindow; w > 0 && cursors[i].pending() {
				if _, v, ok := current.read(s.Work.Now()); !ok || v.FreshUntil.Sub(s.Work.Now()) < w {
					if report := s.Clusters[i].Report; report != nil {
						report(capacityStage("source-window", cfg.ErrUnavailable), 0)
					}
					return
				}
			}
			if s.Clusters[i].Pace > 0 {
				defer func() { ended[i] = s.Work.Now() }()
			}
			ns, candidate, found, err := cursors[i].next(call, s.Clusters[i].Workloads)
			if err != nil || !found || call.Err() != nil {
				return
			}
			// The candidate LIST does not confer freshness. The exact read gets a
			// separate original source interval; no already-issued permit changes.
			if original, v, ok := current.read(s.Work.Now()); ok {
				until, _ := call.Deadline()
				live, end := context.WithDeadline(original, until)
				defer end()
				started := s.Work.Now()
				err := s.Work.ReconcileWorkload(live, v, s.Clusters[i], ns, candidate)
				if report := s.Clusters[i].Report; report != nil {
					report(err, s.Work.Now().Sub(started))
				}
			}
		})
	}()
	<-root.Done()
	current.clear()
	// Cancel first, then join actual owners. Returning on a shutdown timer
	// would release the fixed SQL/process envelope with work still running.
	owners.Wait()
	return root.Err()
}
