package capacity

import (
	"context"
	"errors"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
)

const CapacityEnrollmentFormat = "protected-capacity-enrollment/v1"

var ErrEnrollmentPending = errors.New("capacity enrollment is incomplete")

// CaptureAccounts is implemented by the purpose-only installation key reader.
// It needs neither the operation-input key nor a human identity. The capacity
// package deliberately does not depend on the audit application component.
type CaptureAccounts interface {
	AccountVersion() string
	CaptureAccount(root, allocation string) (artifact.Digest, error)
}

// EnrollmentObservation is a current observation, not a persisted permit. SQL
// independently checks this exact accepted source, permission and recovery
// fence after acquiring the original account/parent locks.
type EnrollmentObservation struct {
	Key                                               WorkloadCapacityKey
	SourceRevision                                    int64
	SourceDigest, PlanDigest                          artifact.Digest
	Plan                                              EnrollmentPlan `json:"-"`
	NamespaceGuardDigest                              artifact.Digest
	NamespaceLabels                                   map[string]string
	NamespaceResourceVersion, WorkloadResourceVersion string
	PermissionEpoch                                   string
	PermissionSequence                                int64
	PermissionTrust                                   artifact.Digest
	Recovery                                          artifact.RecoveryProof
	ObservedAt, FreshUntil                            time.Time
}

func (v EnrollmentObservation) Valid(now time.Time) bool {
	if len(v.NamespaceLabels) < 1 || len(v.NamespaceLabels) > 256 {
		return false
	}
	for k, value := range v.NamespaceLabels {
		if !identity.Text(k, 253) || (value != "" && !identity.Text(value, 63)) {
			return false
		}
	}
	return v.Key.Valid() && v.SourceRevision > 0 && v.SourceRevision < 1<<60 && v.SourceDigest != (artifact.Digest{}) && v.Plan.Matches(v.Key, v.Recovery.InstallationID, v.SourceDigest, v.PlanDigest) && v.NamespaceGuardDigest != (artifact.Digest{}) && identity.Text(v.NamespaceResourceVersion, 128) && identity.Text(v.WorkloadResourceVersion, 128) && authorization.UUID(v.PermissionEpoch) && v.PermissionSequence >= 0 && v.PermissionTrust != (artifact.Digest{}) && v.Recovery.Valid(now) && identity.Fresh(v.ObservedAt, v.FreshUntil, now, CapacitySourceInterval) && !v.FreshUntil.After(v.Recovery.FreshUntil) && v.ObservedAt.Nanosecond()%1000 == 0 && v.FreshUntil.Nanosecond()%1000 == 0
}

// Enrollment retains three once-set configuration facts. InitialUntil always
// describes the first observation; it is never overwritten by a continuation.
// No receipt means that phase is unavailable, not that an earlier SQL call had
// no effect. Server-generated candidate IDs become permanent only in the first
// committed SQL transaction; concurrent candidates cannot replace that winner.
type Enrollment struct {
	Format                                            string
	Key                                               WorkloadCapacityKey
	ID, AttemptID, AllocationID, DownloadAllocationID string
	SourceDigest, PlanDigest                          artifact.Digest
	Revision                                          int64
	InitialObservedAt, InitialUntil                   time.Time
	ReservedAt                                        time.Time
	CaptureBackedAt, ReadyAt                          *time.Time
	AccountVersion                                    string
	AccountDigest                                     artifact.Digest
}

func (v Enrollment) Valid() bool {
	if v.Format != CapacityEnrollmentFormat || !v.Key.Valid() || !authorization.UUID(v.ID) || !authorization.UUID(v.AttemptID) || !authorization.UUID(v.AllocationID) || !authorization.UUID(v.DownloadAllocationID) || v.ID == v.AttemptID || v.AllocationID == v.DownloadAllocationID || v.SourceDigest == (artifact.Digest{}) || v.PlanDigest == (artifact.Digest{}) || v.Revision < 1 || v.Revision >= 1<<60 || v.InitialObservedAt.IsZero() || !v.InitialUntil.After(v.InitialObservedAt) || v.InitialUntil.After(v.InitialObservedAt.Add(CapacitySourceInterval)) || v.ReservedAt.Before(v.InitialObservedAt) || !v.ReservedAt.Before(v.InitialUntil) || !identity.Text(v.AccountVersion, 64) || v.AccountDigest == (artifact.Digest{}) {
		return false
	}
	for _, d := range []time.Time{v.InitialObservedAt, v.InitialUntil, v.ReservedAt} {
		if d.Nanosecond()%1000 != 0 {
			return false
		}
	}
	if v.CaptureBackedAt != nil && (v.CaptureBackedAt.Before(v.ReservedAt) || v.CaptureBackedAt.Nanosecond()%1000 != 0) {
		return false
	}
	if v.ReadyAt != nil && (v.CaptureBackedAt == nil || v.ReadyAt.Before(*v.CaptureBackedAt) || v.ReadyAt.Nanosecond()%1000 != 0) {
		return false
	}
	return true
}
func (v Enrollment) matches(o EnrollmentObservation) bool {
	return v.Valid() && v.Key == o.Key && v.SourceDigest == o.SourceDigest && v.PlanDigest == o.PlanDigest
}
func sameEnrollment(a, b Enrollment) bool {
	return a.Format == b.Format && a.Key == b.Key && a.ID == b.ID && a.AttemptID == b.AttemptID && a.AllocationID == b.AllocationID && a.DownloadAllocationID == b.DownloadAllocationID && a.SourceDigest == b.SourceDigest && a.PlanDigest == b.PlanDigest && a.Revision == b.Revision && a.InitialObservedAt.Equal(b.InitialObservedAt) && a.InitialUntil.Equal(b.InitialUntil) && a.ReservedAt.Equal(b.ReservedAt) && a.AccountVersion == b.AccountVersion && a.AccountDigest == b.AccountDigest
}

type CapacityEnrollmentStore interface {
	// Read resolves earlier SQL outcomes under the same parent/account locks.
	// A nil receipt is an exact absence observation and grants no effect.
	ReadCapacityEnrollment(context.Context, EnrollmentObservation) (*Enrollment, error)
	ReserveCapacityEnrollment(context.Context, EnrollmentObservation) (Enrollment, error)
	PublishCapacityEnrollment(context.Context, EnrollmentObservation, Enrollment) (Enrollment, error)
	ContinueCapacityPublication(context.Context, EnrollmentObservation, Enrollment) (Enrollment, error)
}
type CapacityCaptureBacking interface {
	BackCapacityCapture(context.Context, EnrollmentObservation, Enrollment) (Enrollment, error)
	ContinueCapacityCapture(context.Context, EnrollmentObservation, Enrollment) (Enrollment, error)
}

// EnrollmentCoordinator completes one exact workload per current observation.
// It owns no queue, detached retry, account ID generator or authority refresher.
// Its two ports must be composed from the separate fixed SQL credentials.
type EnrollmentCoordinator struct {
	Store    CapacityEnrollmentStore
	Capture  CapacityCaptureBacking
	Accounts CaptureAccounts
	Now      func() time.Time
}

func (s *EnrollmentCoordinator) Reconcile(ctx context.Context, o EnrollmentObservation) (Enrollment, error) {
	var zero Enrollment
	if s == nil || s.Store == nil || s.Capture == nil || s.Accounts == nil || s.Now == nil || ctx == nil || ctx.Err() != nil || !o.Valid(s.Now()) || o.Plan.AccountVersion() != s.Accounts.AccountVersion() {
		return zero, capacityStage("observation", cfg.ErrUnavailable)
	}
	live, cancel := context.WithDeadline(ctx, o.FreshUntil)
	defer cancel()
	current := func() bool { return live.Err() == nil && o.Valid(s.Now()) }
	v, err := s.Store.ReadCapacityEnrollment(live, o)
	if err != nil || !current() {
		return zero, capacityStage("read", errors.Join(cfg.ErrUnavailable, err))
	}
	if v == nil {
		x, e := s.Store.ReserveCapacityEnrollment(live, o)
		if e != nil || !current() {
			return zero, capacityStage("reserve", errors.Join(cfg.ErrUnavailable, e))
		}
		v = &x
	}
	if !v.matches(o) || v.AccountVersion != s.Accounts.AccountVersion() {
		return zero, capacityStage("mismatch", cfg.ErrChanged)
	}
	digest, err := s.Accounts.CaptureAccount(o.Key.RootID, v.AllocationID)
	if err != nil || digest != v.AccountDigest || !current() {
		return zero, capacityStage("account", errors.Join(cfg.ErrUnavailable, err))
	}
	if v.ReadyAt != nil {
		return *v, nil
	}
	advance := func(next Enrollment, err error) error {
		if err != nil || !current() {
			return cfg.ErrUnavailable
		}
		if !next.matches(o) || !sameEnrollment(*v, next) || v.CaptureBackedAt != nil && (next.CaptureBackedAt == nil || !v.CaptureBackedAt.Equal(*next.CaptureBackedAt)) {
			return cfg.ErrChanged
		}
		*v = next
		return nil
	}
	if v.CaptureBackedAt == nil {
		var next Enrollment
		if s.Now().Before(v.InitialUntil) {
			next, err = s.Capture.BackCapacityCapture(live, o, *v)
		} else {
			next, err = s.Capture.ContinueCapacityCapture(live, o, *v)
		}
		if e := advance(next, err); e != nil {
			return zero, capacityStage("capture", errors.Join(e, err))
		}
		if v.CaptureBackedAt == nil || v.ReadyAt != nil {
			return zero, capacityStage("capture-phase", cfg.ErrChanged)
		}
	}
	var next Enrollment
	if s.Now().Before(v.InitialUntil) {
		next, err = s.Store.PublishCapacityEnrollment(live, o, *v)
	} else {
		next, err = s.Store.ContinueCapacityPublication(live, o, *v)
	}
	if e := advance(next, err); e != nil {
		return zero, capacityStage("publish", errors.Join(e, err))
	}
	if v.ReadyAt == nil {
		return zero, ErrEnrollmentPending
	}
	return *v, nil
}
