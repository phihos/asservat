package kubernetes

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/configuration"
	coordination "k8s.io/api/coordination/v1"
	"k8s.io/client-go/tools/leaderelection"
	"k8s.io/client-go/tools/leaderelection/resourcelock"
)

// ReconciliationLeader schedules one process at a time in the usual lease
// failure model. It is not fencing or authority: every observation still uses
// current admission proof, original freshness and monotonic SQL transitions.
type ReconciliationLeader struct {
	lock    *reconciliationLock
	running atomic.Bool
}

type reconciliationLock struct {
	client              *PermissionClient
	name, uid, identity string
	lease               *coordination.Lease
}

var _ resourcelock.Interface = (*reconciliationLock)(nil)

func NewReconciliationLeader(c *PermissionClient, name, uid, process string) (*ReconciliationLeader, error) {
	if c == nil || !installationRefValid(name, uid) || !authorization.UUID(uid) || !authorization.UUID(process) {
		return nil, value.ErrInvalid
	}
	return &ReconciliationLeader{lock: &reconciliationLock{client: c, name: name, uid: uid, identity: process}}, nil
}

func (l *reconciliationLock) path() string {
	return "/apis/coordination.k8s.io/v1/namespaces/" + l.client.control.Name + "/leases/" + l.name
}
func (l *reconciliationLock) namespace(ctx context.Context) error {
	n, err := l.client.namespace(ctx, l.client.control)
	if err != nil || n.Deleting {
		return value.ErrUnavailable
	}
	return nil
}
func (l *reconciliationLock) valid(v *coordination.Lease) bool {
	if v == nil || v.Name != l.name || string(v.UID) != l.uid || v.Namespace != l.client.control.Name || v.ResourceVersion == "" || v.DeletionTimestamp != nil || v.APIVersion != "coordination.k8s.io/v1" || v.Kind != "Lease" {
		return false
	}
	r := resourcelock.LeaseSpecToLeaderElectionRecord(&v.Spec)
	return len(r.HolderIdentity) <= 128 && r.LeaseDurationSeconds >= 0 && r.LeaseDurationSeconds <= 30 && r.LeaderTransitions >= 0 && r.PreferredHolder == "" && r.Strategy == ""
}
func (l *reconciliationLock) Get(ctx context.Context) (*resourcelock.LeaderElectionRecord, []byte, error) {
	if err := l.namespace(ctx); err != nil {
		return nil, nil, err
	}
	b, err := l.client.raw(ctx, l.path(), nil)
	var v coordination.Lease
	if err != nil || len(b) > 64<<10 || json.Unmarshal(b, &v) != nil || !l.valid(&v) {
		return nil, nil, value.ErrUnavailable
	}
	l.lease = &v
	r := resourcelock.LeaseSpecToLeaderElectionRecord(&v.Spec)
	b, err = json.Marshal(r)
	return r, b, err
}
func (l *reconciliationLock) Create(context.Context, resourcelock.LeaderElectionRecord) error {
	// Installation creates the exact pinned Lease. Runtime has no create/delete.
	return value.ErrUnavailable
}
func (l *reconciliationLock) Update(ctx context.Context, r resourcelock.LeaderElectionRecord) error {
	if !l.valid(l.lease) || r.HolderIdentity != l.identity || r.LeaseDurationSeconds != 15 || r.LeaderTransitions < 0 {
		return value.ErrInvalid
	}
	if err := l.namespace(ctx); err != nil {
		return err
	}
	v := l.lease.DeepCopy()
	v.Spec = resourcelock.LeaderElectionRecordToLeaseSpec(&r)
	b, err := l.client.api.Put().AbsPath(l.path()).Param("fieldValidation", "Strict").Body(v).MaxRetries(0).Do(ctx).Raw()
	var updated coordination.Lease
	if err != nil || len(b) > 64<<10 || json.Unmarshal(b, &updated) != nil || !l.valid(&updated) {
		return value.ErrUnavailable
	}
	l.lease = &updated
	return nil
}
func (l *reconciliationLock) RecordEvent(string) {} // no event writer credential
func (l *reconciliationLock) Identity() string   { return l.identity }
func (l *reconciliationLock) Describe() string   { return "asservat configuration reconciliation" }

// Run cancels and joins observation work after lease loss. Do not release the
// Lease before work has stopped: let the existing fifteen-second record expire.
// A callback arriving after shutdown is denied before it can access providers.
func (s *ReconciliationLeader) Run(ctx context.Context, work func(context.Context) error) error {
	if s == nil || s.lock == nil || s.lock.client == nil || ctx == nil || work == nil || ctx.Err() != nil || !s.running.CompareAndSwap(false, true) {
		return value.ErrInvalid
	}
	root, cancel := context.WithCancel(ctx)
	defer cancel()
	var mu sync.Mutex
	closed, started := false, false
	done := make(chan error, 1)
	e, err := leaderelection.NewLeaderElector(leaderelection.LeaderElectionConfig{
		Lock: s.lock, LeaseDuration: 15 * time.Second, RenewDeadline: 10 * time.Second, RetryPeriod: 2 * time.Second, ReleaseOnCancel: false,
		Callbacks: leaderelection.LeaderCallbacks{
			OnStartedLeading: func(leader context.Context) {
				mu.Lock()
				if closed {
					mu.Unlock()
					return
				}
				started = true
				mu.Unlock()
				done <- work(leader)
				cancel()
			},
			OnStoppedLeading: cancel,
		},
	})
	if err != nil {
		return value.ErrInvalid
	}
	e.Run(root)
	cancel()
	mu.Lock()
	closed = true
	wait := started
	mu.Unlock()
	var worked error
	if wait {
		// Cancellation does not release the callback's SQL/process ownership.
		// Keep this original owner charged until the actual work joins; an
		// external supervisor may terminate a stuck process, but a timeout is
		// not successful local shutdown.
		worked = <-done
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	// The result stays unavailable; it only names what ended it: the work's
	// own fixed step, or "lease" when leadership ended or work never started.
	stop := &leaderStop{step: "lease", err: value.ErrUnavailable}
	var inner interface{ FixedStep() string }
	if worked != nil && !errors.Is(worked, context.Canceled) && errors.As(worked, &inner) {
		stop.step, stop.err = inner.FixedStep(), errors.Join(value.ErrUnavailable, worked)
	}
	return stop
}

// leaderStop carries a fixed step name for the process stop message.
type leaderStop struct {
	step string
	err  error
}

func (e *leaderStop) Error() string     { return "reconciliation stopped at " + e.step }
func (e *leaderStop) Unwrap() error     { return e.err }
func (e *leaderStop) FixedStep() string { return e.step }
