package postgres

import (
	"bytes"
	"context"
	"encoding/json"
	"time"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	"github.com/jackc/pgx/v5/pgxpool"
)

// These finite per-session ceilings are immutable protected installation inputs.
// SQL allocations and separately accepted backing must already exist. This read
// facet can neither provision them nor choose a newer/larger/default candidate.
type ContextDownloadPlanLimits struct {
	OutputLimit, ReadLimit, RequestLimit int64
	Duration                             time.Duration
}

func (l ContextDownloadPlanLimits) valid() bool {
	return l.OutputLimit >= artifact.MaxContextBytes && l.OutputLimit <= artifact.MaxDownloadOutput && l.ReadLimit >= 2*evidence.ContextDownloadReadWork && l.ReadLimit <= artifact.MaxDownloadReadWork && l.RequestLimit >= 2 && l.RequestLimit <= artifact.MaxDownloadRequests && l.Duration > 0 && l.Duration <= 8*time.Hour
}

type ContextDownloadPlans struct {
	ledger             *Ledger
	root, installation string
	profile            authorization.DownloadWorkerProfile
	configuration      *WorkerConfigurations
	limits             ContextDownloadPlanLimits
}

func NewContextDownloadPlans(ctx context.Context, pool *pgxpool.Pool, root, installation string, profile authorization.DownloadWorkerProfile, configuration *WorkerConfigurations, limits ContextDownloadPlanLimits) (*ContextDownloadPlans, error) {
	if !authorization.UUID(root) || !authorization.UUID(installation) || !profile.Valid() || profile.StoreCredentialSecret == "" || profile.InstallationID != installation || configuration == nil || !limits.valid() {
		return nil, artifact.ErrInvalid
	}
	ledger, e := New(ctx, pool)
	if e != nil {
		return nil, e
	}
	return &ContextDownloadPlans{ledger: ledger, root: root, installation: installation, profile: profile, configuration: configuration, limits: limits}, nil
}
func (s *ContextDownloadPlans) ContextDownloadPlan(ctx context.Context, scope artifact.DownloadScope) (evidence.ContextDownloadPlan, error) {
	var out evidence.ContextDownloadPlan
	if s == nil || ctx == nil || ctx.Err() != nil || !scope.Valid() || scope.RootID != s.root {
		return out, artifact.ErrDownloadUnavailable
	}
	original := time.Now().Add(artifact.DownloadLease)
	call, end := context.WithDeadline(ctx, original)
	defer end()
	configured, e := s.configuration.CurrentWorkerConfiguration(call, s.profile)
	if e != nil {
		return out, artifact.ErrDownloadUnavailable
	}
	original = identity.Earlier(original, configured)
	call, narrow := context.WithDeadline(call, original)
	defer narrow()
	e = s.ledger.transaction(call, func(q *custodydb.Queries) error {
		start, e := q.CurrentTime(call)
		if e != nil {
			return e
		}
		trust, e := q.ShareFleetTrust(call, id(s.installation))
		if e != nil {
			return e
		}
		rows, e := q.ReadContextDownloadAllocations(call, custodydb.ReadContextDownloadAllocationsParams{RootID: id(s.root), ClusterID: id(scope.ClusterID), NamespaceUid: scope.NamespaceUID, WorkloadUid: scope.WorkloadUID})
		if e != nil || len(rows) != 1 {
			return artifact.ErrDownloadUnavailable
		}
		allocation := downloadAllocation(rows[0])
		if !allocation.Valid() || !allocation.Covers(scope) || rows[0].ReservedSessions >= allocation.SessionLimit || s.limits.OutputLimit > allocation.OutputLimit-rows[0].ReservedOutput || s.limits.ReadLimit > allocation.ReadLimit-rows[0].ReservedRead {
			return artifact.ErrDownloadUnavailable
		}
		control, e := q.ReadDownloadControlAllocation(call, custodydb.ReadDownloadControlAllocationParams{ID: rows[0].ID, RootID: id(s.root)})
		if e != nil {
			return e
		}
		native, e := q.ReadNativeBacking(call, custodydb.ReadNativeBackingParams{AllocationID: rows[0].ID, RootID: id(s.root)})
		if e != nil {
			return e
		}
		stop, e := q.ReadDownloadStopBacking(call, custodydb.ReadDownloadStopBackingParams{AllocationID: rows[0].ID, RootID: id(s.root)})
		if e != nil {
			return e
		}
		pool, e := q.ReadDownloadStopPool(call, id(s.root))
		if e != nil {
			return e
		}
		now, e := q.CurrentTime(call)
		if e != nil {
			return e
		}
		current, e := recoveryState(trust, start.Time, now.Time)
		if e != nil {
			return e
		}
		until, e := s.configuration.CurrentWorkerConfiguration(call, s.profile)
		if e != nil {
			return e
		}
		now, e = q.CurrentTime(call)
		if e != nil {
			return e
		}
		if !contextPlanBacking(s.limits, allocation, control, native, stop, pool, s.installation, now.Time) {
			return artifact.ErrDownloadUnavailable
		}
		// Every contributing original deadline survives the configuration and SQL
		// waits. This snapshot grants no effect; reservation rechecks current backing.
		hard := identity.Earlier(allocation.ValidUntil, identity.Earlier(control.ValidUntil.Time, identity.Earlier(native.ValidUntil.Time, pool.ValidUntil.Time)))
		out = evidence.ContextDownloadPlan{HardUntil: hard, Allocation: allocation, OutputLimit: s.limits.OutputLimit, ReadLimit: s.limits.ReadLimit, RequestLimit: s.limits.RequestLimit, Duration: s.limits.Duration, ObservedAt: start.Time, ValidUntil: downloadObservationDeadline(call, start.Time, original, until, current.FreshUntil, hard)}
		if !current.Valid(now.Time) || !out.Valid(scope, now.Time) || call.Err() != nil {
			return artifact.ErrDownloadUnavailable
		}
		return nil
	})
	if e != nil || call.Err() != nil || !out.Valid(scope, time.Now()) {
		return evidence.ContextDownloadPlan{}, artifact.ErrDownloadUnavailable
	}
	return out, nil
}
func contextPlanBacking(l ContextDownloadPlanLimits, a artifact.DownloadAllocation, c custodydb.DownloadControlAllocation, n custodydb.DownloadNativeBacking, b custodydb.DownloadStopBacking, p custodydb.DownloadStopPool, installation string, now time.Time) bool {
	control := downloadControl(c)
	var native authorization.NativeBacking
	var stop audit.DownloadStopLifecyclePolicy
	if !l.valid() || !a.Valid() || !control.Valid() || json.Unmarshal(n.PolicyJson, &native) != nil || !native.Valid() || json.Unmarshal(p.LifecyclePolicy, &stop) != nil || !stop.Valid() {
		return false
	}
	if uid(c.ID) != a.ID || uid(c.RootID) != a.RootID || uid(n.AllocationID) != a.ID || uid(n.RootID) != a.RootID || native.AllocationID != a.ID || native.RootID != a.RootID || native.Rows != n.RowsLimit || native.Keys != n.KeysLimit || native.TransitionsPerRow != n.TransitionsPerRow || native.BackupHorizonSeconds != n.BackupHorizonSeconds || native.CleanupSeconds != n.CleanupSeconds || !native.ValidUntil.Equal(n.ValidUntil.Time) || !native.RetireBy.Equal(n.RetireBy.Time) || n.Overdue || native.TransitionsPerRow < 8 {
		return false
	}
	if uid(b.AllocationID) != a.ID || uid(b.RootID) != a.RootID || uid(p.RootID) != a.RootID || uid(p.InstallationID) != installation || stop.RootID != a.RootID || stop.InstallationID != installation || stop.StoreID != uid(p.StoreID) || stop.PolicyID != uid(p.PolicyID) || stop.BackupProfileID != uid(p.BackupProfileID) || !bytes.Equal(stop.PolicyDigest[:], p.PolicyDigest) || !bytes.Equal(stop.BackupProfileDigest[:], p.BackupProfileDigest) {
		return false
	}
	// One first-context response fits one window. Original unknown reservations
	// remain charged; this read cannot recycle them or promise all later races win.
	if l.OutputLimit > a.OutputLimit || l.ReadLimit > a.ReadLimit || c.ReservedResponses >= c.ResponseLimit || c.ReservedWindows >= c.WindowLimit || c.AuditByteLimit-c.ReservedAuditBytes < 2*artifact.DownloadWindowAuditBytes || n.ChargedRows >= n.RowsLimit || n.ChargedKeys >= n.KeysLimit || b.Charged >= b.Slots || b.Slots > p.Slots || p.Allocated > p.Slots || p.RetainedSeconds < 60 || p.RetainedSeconds > 316224000 || p.BackupHorizonSeconds != stop.BackupHorizonSeconds || p.RetainedSeconds <= 2*stop.BackupHorizonSeconds+3*stop.CleanupBudgetSeconds+stop.ProofWindowSeconds+30 {
		return false
	}
	cipher, keys, backup, wal := stop.SlotBacking()
	if p.Slots < 1 || p.CipherBytes/p.Slots < cipher || p.KeyAttempts/p.Slots < keys || p.BackupBytes/p.Slots < backup || p.WalBytes/p.Slots < wal {
		return false
	}
	for _, end := range []time.Time{a.ValidUntil, c.ValidUntil.Time, n.ValidUntil.Time, p.ValidUntil.Time} {
		if !now.Before(end) {
			return false
		}
	}
	return true
}

var _ evidence.ContextDownloadPlans = (*ContextDownloadPlans)(nil)
