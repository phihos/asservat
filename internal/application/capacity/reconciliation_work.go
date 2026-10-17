package capacity

import (
	"context"
	"errors"
	"slices"
	"time"

	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/privacy"
)

// These are the existing independent processing configuration and exact local
// metadata facets. Capacity configuration does not initialize processing state
// or acquire a human permission, collector credential, or recovery authority.
type CapacityProcessingReader interface {
	DownloadPolicy(context.Context) (privacy.DownloadPolicy, error)
}
type CapacityBindingObservations interface {
	RefreshCapacityEnrollment(context.Context, EnrollmentObservation, Enrollment) error
}

type CapacityClusterReaders struct {
	ClusterID string
	Workloads CapacityWorkloadReader
	Guard     CapacityNamespaceProtectionReader
	// Guarded, when set, observes the guard and then the workload under the
	// pinned keys in one remote observation (ADR-197): a regional cluster's
	// two separate observations do not fit one source window.
	Guarded CapacityGuardedWorkloadReader
	// Pace is the least time between the end of one of this cluster's loop
	// iterations and the start of the next. A regional (v2) observation costs
	// about a hundred hub-side API calls, so its cluster never retries
	// back-to-back (ADR-197); zero keeps the local cluster's cadence.
	Pace time.Duration
	// MinSourceWindow, when set, starts a candidate's reconciliation only
	// while the current accepted source has at least this much freshness
	// left. Every attempt stays bounded by that source's original interval,
	// and a regional (v2) guarded read takes two to three seconds of it, so
	// starting with less only wastes the read (ADR-197). Waiting renews
	// nothing; the candidate stays queued for the next tick.
	MinSourceWindow time.Duration
	// Report, when set, receives each workload reconciliation's outcome and
	// elapsed time. A refusal names its fixed stage (FixedStep).
	Report func(error, time.Duration)
}

// capacityStageError names the fixed ReconcileWorkload stage that refused.
type capacityStageError struct {
	stage string
	err   error
}

func (e *capacityStageError) Error() string { return e.stage }
func (e *capacityStageError) Unwrap() error { return e.err }

// FixedStep appends a nested fixed step, so labels compose across layers.
func (e *capacityStageError) FixedStep() string {
	var inner interface{ FixedStep() string }
	if errors.As(e.err, &inner) {
		return e.stage + "/" + inner.FixedStep()
	}
	return e.stage
}

func capacityStage(stage string, err error) error { return &capacityStageError{stage, err} }

// CapacityGuardedWorkloadReader observes the namespace guard and one
// workload under exactly the given keys, as one observation.
type CapacityGuardedWorkloadReader interface {
	ReadCapacityGuardedWorkload(context.Context, cfg.NamespaceRef, cfg.WorkloadRef, []string) (CapacityNamespaceProtection, CapacityWorkloadObservation, error)
}

// CapacityWorkReconciler is the effect portion of the installed A-HWORK
// reconciler. Discovery supplies names/UIDs only. Every candidate gets fresh
// protected facts under one original interval before the existing SQL phases.
type CapacityWorkReconciler struct {
	Qualification CapacityQualification
	Recovery      CapacityRecoveryReader
	Permissions   CapacityPermissionReader
	Processing    CapacityProcessingReader
	Root          *RootBackingCoordinator
	Enrollment    *EnrollmentCoordinator
	Bindings      CapacityBindingObservations
	Now           func() time.Time
	// Regional are the write-once regional cluster qualifications read at
	// start (ADR-197). They extend Qualification.NamespaceGuards; SQL checks
	// the same pins again under its locks.
	Regional []CapacityNamespaceQualification
}

// namespacePin is the cluster's original pin, else its regional one.
func (s *CapacityWorkReconciler) namespacePin(cluster string) *CapacityNamespaceQualification {
	for _, pins := range [][]CapacityNamespaceQualification{s.Qualification.NamespaceGuards, s.Regional} {
		for i := range pins {
			if pins[i].ClusterID == cluster {
				return &pins[i]
			}
		}
	}
	return nil
}

type capacityWorkInterval struct {
	ctx   context.Context
	end   context.CancelFunc
	until time.Time
	now   func() time.Time
}

func newCapacityWorkInterval(ctx context.Context, source AcceptedCapacitySource, now func() time.Time) (*capacityWorkInterval, error) {
	if ctx == nil || ctx.Err() != nil || now == nil || !source.Valid(now()) {
		return nil, cfg.ErrUnavailable
	}
	until := source.FreshUntil
	if d, ok := ctx.Deadline(); ok && d.Before(until) {
		until = d
	}
	live, end := context.WithDeadline(ctx, until)
	return &capacityWorkInterval{live, end, until, now}, nil
}

func (l *capacityWorkInterval) narrow(until time.Time) bool {
	if until.Before(l.until) {
		l.until = until
		next, end := context.WithDeadline(l.ctx, until)
		old := l.end
		l.end = func() { end(); old() }
		l.ctx = next
	}
	return l.ctx.Err() == nil && l.now().Before(l.until)
}

func (s *CapacityWorkReconciler) sourceValid(v AcceptedCapacitySource) bool {
	return s != nil && s.Now != nil && s.Recovery != nil && s.Qualification.Valid() && v.Valid(s.Now()) &&
		v.RootID == s.Qualification.RootBacking.RootID && v.InstallationID == s.Qualification.RootBacking.InstallationID &&
		v.QualificationID == s.Qualification.ID && v.QualificationDigest == s.Qualification.Digest
}

func (s *CapacityWorkReconciler) ReconcileRoot(ctx context.Context, source AcceptedCapacitySource) error {
	if !s.sourceValid(source) || s.Processing == nil || s.Root == nil {
		return cfg.ErrUnavailable
	}
	l, err := newCapacityWorkInterval(ctx, source, s.Now)
	if err != nil {
		return err
	}
	defer func() { l.end() }()
	recovery, err := s.Recovery.RecoveryState(l.ctx)
	if err != nil || !recovery.Valid(s.Now()) || !l.narrow(recovery.FreshUntil) {
		return cfg.ErrUnavailable
	}
	policy, err := s.Processing.DownloadPolicy(l.ctx)
	if err != nil || !policy.Valid(s.Now()) || !l.narrow(policy.FreshUntil) {
		return cfg.ErrUnavailable
	}
	observation, err := NewRootBackingObservation(s.Qualification, source, policy, recovery, s.Now())
	if err != nil || !l.narrow(observation.FreshUntil) {
		return cfg.ErrUnavailable
	}
	_, err = s.Root.Reconcile(l.ctx, observation)
	if err != nil || !l.narrow(observation.FreshUntil) {
		return cfg.ErrUnavailable
	}
	return nil
}

func (s *CapacityWorkReconciler) ReconcileWorkload(ctx context.Context, source AcceptedCapacitySource, cluster CapacityClusterReaders, namespace cfg.NamespaceRef, candidate cfg.WorkloadRef) error {
	if !s.sourceValid(source) || s.Permissions == nil || s.Enrollment == nil || s.Enrollment.Accounts == nil || s.Bindings == nil || cluster.Workloads == nil || cluster.Guard == nil {
		return capacityStage("inputs", cfg.ErrUnavailable)
	}
	pin := s.namespacePin(cluster.ClusterID)
	if pin == nil {
		return capacityStage("pin", cfg.ErrUnavailable)
	}
	l, err := newCapacityWorkInterval(ctx, source, s.Now)
	if err != nil {
		return capacityStage("interval", err)
	}
	defer func() { l.end() }()
	recovery, err := s.Recovery.RecoveryState(l.ctx)
	if err != nil || !recovery.Valid(s.Now()) || recovery.InstallationID != source.InstallationID || !l.narrow(recovery.FreshUntil) {
		return capacityStage("recovery", cfg.ErrUnavailable)
	}
	permissions, err := s.Permissions.ReadCapacityPermissions(l.ctx, recovery)
	if err != nil || !permissions.Valid(s.Now()) || permissions.RootID != source.RootID || !l.narrow(permissions.FreshUntil) {
		return capacityStage("permissions", cfg.ErrUnavailable)
	}
	var guard CapacityNamespaceProtection
	var workload CapacityWorkloadObservation
	if cluster.Guarded != nil {
		guard, workload, err = cluster.Guarded.ReadCapacityGuardedWorkload(l.ctx, namespace, candidate, pin.Keys)
		if err != nil {
			return capacityStage("guarded-read", cfg.ErrUnavailable)
		}
	} else if guard, err = cluster.Guard.CapacityNamespaceProtection(l.ctx); err != nil {
		return capacityStage("guard-read", cfg.ErrUnavailable)
	}
	if !guard.Valid(s.Now()) || guard.ClusterID != pin.ClusterID || guard.Digest != pin.Digest || !slices.Equal(guard.Keys, pin.Keys) {
		return capacityStage("guard-pin", cfg.ErrUnavailable)
	}
	if !l.narrow(guard.FreshUntil) {
		return capacityStage("guard-fresh", cfg.ErrUnavailable)
	}
	if cluster.Guarded == nil {
		workload, err = cluster.Workloads.ReadCapacityWorkload(l.ctx, namespace, candidate, guard.Keys)
	}
	if err != nil || !workload.Valid(s.Now()) || workload.Namespace.ClusterID != cluster.ClusterID || workload.Namespace.Namespace != namespace || workload.Workload != candidate {
		return capacityStage("workload", cfg.ErrUnavailable)
	}
	if !l.narrow(workload.FreshUntil) || !l.narrow(workload.Namespace.FreshUntil) {
		return capacityStage("workload-fresh", cfg.ErrUnavailable)
	}
	observation, _, err := ComposeEnrollmentObservation(source, guard, workload, permissions, recovery, s.Enrollment.Accounts.AccountVersion(), s.Now())
	if err != nil {
		return capacityStage("compose", err)
	}
	if !l.narrow(observation.FreshUntil) {
		return capacityStage("observation-fresh", cfg.ErrUnavailable)
	}
	enrolled, err := s.Enrollment.Reconcile(l.ctx, observation)
	if err != nil {
		return capacityStage("enroll", errors.Join(cfg.ErrUnavailable, err))
	}
	if !l.narrow(observation.FreshUntil) {
		return capacityStage("enroll-fresh", cfg.ErrUnavailable)
	}
	// Completed enrollment remains a historical receipt. A new independent
	// workload observation must explicitly refresh the existing binding; it
	// cannot overwrite original phase facts or acquire replacement account IDs.
	if err = s.Bindings.RefreshCapacityEnrollment(l.ctx, observation, enrolled); err != nil {
		if !l.narrow(observation.FreshUntil) {
			return capacityStage("refresh-fresh", cfg.ErrUnavailable)
		}
		return capacityStage("refresh", err)
	}
	if !l.narrow(observation.FreshUntil) {
		return capacityStage("refresh-fresh", cfg.ErrUnavailable)
	}
	return nil
}
