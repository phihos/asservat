package analysis

import (
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
)

// ContextQueryCost is an exact snapshot of independently accepted C-07 backing,
// not caller-selectable resources or proof that a qualification was performed.
// Its producer accounts for each admitted poll/control transition, including
// failed and unknown transactions, and the qualified row/index/WAL/backup layout.
type ContextQueryCost struct {
	Workers, ReadBatches, ReadBytes, StructuredBytes, WireBytes int64
	UnwrapAttempts, ProviderRequests, AuthenticationRequests    int64
	SigningAttempts, AuditObjects, SQLRows, SQLBytes            int64
	WALBytes, BackupBytes                                       int64
}

func (c ContextQueryCost) Valid() bool {
	if c.Workers != 1 || c.ReadBatches != ContextMaxReadBatches ||
		c.ReadBytes != ContextMaxReadBatches*ContextBatchReadWork ||
		c.StructuredBytes != ContextMaxReadBatches*ContextResultBytes ||
		c.WireBytes != ContextMaxReadBatches*ContextWireBytes || c.UnwrapAttempts != 3*ContextMaxReadBatches {
		return false
	}
	for _, n := range []int64{c.ProviderRequests, c.AuthenticationRequests, c.SigningAttempts, c.AuditObjects, c.SQLRows, c.SQLBytes, c.WALBytes, c.BackupBytes} {
		if n <= 0 || n > 1<<60 {
			return false
		}
	}
	return c.ProviderRequests >= c.UnwrapAttempts
}

// ContextQueryWorkerLimits keeps actual process/copy/provider obligations
// separate from the result lifetime. In particular no download certificate
// period is inherited and query expiry proves no remote retirement.
type ContextQueryWorkerLimits struct {
	CPUMilli, MemoryBytes, WorkerTransientBytes, HubTransientBytes int64
	ProviderConcurrency, AuthenticationConcurrency                 int64
	Runtime, CredentialLifetime, ProviderEffectLifetime, Cleanup   time.Duration
}

func (w ContextQueryWorkerLimits) Valid() bool {
	for _, n := range []int64{w.CPUMilli, w.MemoryBytes, w.WorkerTransientBytes, w.HubTransientBytes, w.ProviderConcurrency, w.AuthenticationConcurrency} {
		if n <= 0 || n > 1<<60 {
			return false
		}
	}
	return w.Runtime > 0 && w.CredentialLifetime > 0 && w.ProviderEffectLifetime > 0 && w.Cleanup > 0 &&
		w.WorkerTransientBytes <= w.MemoryBytes
}

type ContextQueryResourceProfile struct {
	ID                                string
	Source, Qualification             identity.Revision
	Path                              ContextProjectionPath
	Lifetime                          time.Duration
	Worker                            ContextQueryWorkerLimits
	Cost                              ContextQueryCost
	PollLimit, ControlTransitionLimit int64
}

func (p ContextQueryResourceProfile) Valid() bool {
	return authorization.UUID(p.ID) && p.Source.Valid() && p.Qualification.Valid() &&
		p.Path.Valid() && p.Lifetime > 0 && p.Lifetime <= ContextMaxQueryTime && p.Worker.Valid() &&
		p.Worker.Runtime >= p.Lifetime && p.Cost.Valid() && p.PollLimit > 0 && p.PollLimit <= 1<<60 &&
		p.ControlTransitionLimit > 0 && p.ControlTransitionLimit <= 1<<60
}

// ContextQueryPlan is read from current protected accepted backing. Admission
// must independently match these references and costs under SQL locks; a valid
// struct, qualification digest or historical plan does not grant capacity.
type ContextQueryPlan struct {
	AcceptanceID, AccountID, AllocationID, RootID, InstallationID string
	ClusterID, NamespaceUID, WorkloadUID                          string
	AllocationRevision                                            int64
	PoolSource, PolicySource                                      identity.Revision
	Principal                                                     identity.Principal
	Profile                                                       ContextQueryResourceProfile
	ObservedAt, ValidUntil, HardUntil, EffectsUntil               time.Time
	CleanupUntil, RetireBy                                        time.Time
}

func (p ContextQueryPlan) Matches(s ContextProjectionScope) bool {
	return s.Valid() && authorization.UUID(p.AcceptanceID) && authorization.UUID(p.AccountID) &&
		authorization.UUID(p.AllocationID) && authorization.UUID(p.InstallationID) &&
		p.RootID == s.RootID && p.ClusterID == s.ClusterID && p.NamespaceUID == s.NamespaceUID &&
		p.WorkloadUID == s.WorkloadUID && p.Principal == s.Principal &&
		p.AllocationRevision > 0 && p.AllocationRevision <= 1<<60 && p.PoolSource.Valid() && p.PolicySource.Valid() &&
		p.Profile.Valid() && p.Profile.Path.TargetClusterID == s.ClusterID &&
		!p.ObservedAt.IsZero() && p.ValidUntil.After(p.ObservedAt) && !p.ValidUntil.After(p.ObservedAt.Add(5*time.Second)) &&
		!p.HardUntil.Before(p.ValidUntil) && !p.EffectsUntil.Before(p.HardUntil) &&
		!p.CleanupUntil.Before(p.EffectsUntil.Add(p.Profile.Worker.Cleanup)) && !p.RetireBy.Before(p.CleanupUntil)
}

func (p ContextQueryPlan) Valid(s ContextProjectionScope, now time.Time) bool {
	return p.Matches(s) && identity.Fresh(p.ObservedAt, p.ValidUntil, now, 5*time.Second)
}

// ContextQuery contains only immutable routing/accounting state. It contains no
// native fields, output bytes, plain-text hash, human credential or read permit.
// WorkerID fixes the sole possible worker even before its admission is known.
type ContextQuery struct {
	ID, OperationID, WorkerID                         string
	Scope                                             ContextProjectionScope
	Plan                                              ContextQueryPlan
	RecoveryIssuerEpoch                               string
	RecoveryRevision                                  identity.Revision
	CreatedAt, Deadline, WorkerUntil, CredentialUntil time.Time
	ProviderUntil, CleanupUntil                       time.Time
}

// Immutable query instants use the transaction store's fixed microsecond
// precision. Flooring is conservative and never changes a current observation.
func contextQueryTime(t time.Time) time.Time { return t.UTC().Truncate(time.Microsecond) }

func (q ContextQuery) Valid() bool {
	for _, t := range []time.Time{q.CreatedAt, q.Deadline, q.WorkerUntil, q.CredentialUntil, q.ProviderUntil, q.CleanupUntil} {
		if !t.Equal(contextQueryTime(t)) {
			return false
		}
	}

	if !authorization.UUID(q.ID) || !authorization.UUID(q.OperationID) || !authorization.UUID(q.WorkerID) ||
		!q.Plan.Matches(q.Scope) || !authorization.UUID(q.RecoveryIssuerEpoch) || !q.RecoveryRevision.Valid() || q.CreatedAt.IsZero() ||
		!q.Deadline.After(q.CreatedAt) || q.Deadline.After(q.CreatedAt.Add(q.Plan.Profile.Lifetime)) ||
		q.Deadline.After(q.Plan.HardUntil) {
		return false
	}
	w := q.Plan.Profile.Worker
	if !q.WorkerUntil.Equal(contextQueryTime(q.CreatedAt.Add(w.Runtime))) || !q.CredentialUntil.Equal(contextQueryTime(q.CreatedAt.Add(w.CredentialLifetime))) ||
		!q.ProviderUntil.Equal(contextQueryTime(q.CreatedAt.Add(w.ProviderEffectLifetime))) {
		return false
	}
	end := q.WorkerUntil
	for _, t := range []time.Time{q.CredentialUntil, q.ProviderUntil} {
		if t.After(end) {
			end = t
		}
	}
	return !end.After(q.Plan.EffectsUntil) && q.CleanupUntil.Equal(contextQueryTime(end.Add(w.Cleanup))) && !q.CleanupUntil.After(q.Plan.CleanupUntil)
}

func NewContextQuery(id, operationID, workerID string, a ContextProjectionAuthority, p ContextQueryPlan, now time.Time) (ContextQuery, error) {
	q := ContextQuery{ID: id, OperationID: operationID, WorkerID: workerID, Scope: a.Scope, Plan: p,
		RecoveryIssuerEpoch: a.Environment.Recovery.IssuerEpoch, RecoveryRevision: a.Environment.Recovery.Revision, CreatedAt: contextQueryTime(now)}
	if !a.Valid(now) || !p.Valid(a.Scope, now) || p.Profile.Path != a.Environment.Path || p.InstallationID != a.Environment.InstallationID {
		return ContextQuery{}, ErrUnavailable
	}
	var err error
	q.Deadline, err = ContextQueryDeadline(q.CreatedAt, p.Profile.Lifetime, identity.Earlier(a.AccessUntil, p.HardUntil))
	if err != nil {
		return ContextQuery{}, err
	}
	q.Deadline = contextQueryTime(q.Deadline)
	w := p.Profile.Worker
	q.WorkerUntil, q.CredentialUntil, q.ProviderUntil = contextQueryTime(q.CreatedAt.Add(w.Runtime)), contextQueryTime(q.CreatedAt.Add(w.CredentialLifetime)), contextQueryTime(q.CreatedAt.Add(w.ProviderEffectLifetime))
	end := q.WorkerUntil
	for _, t := range []time.Time{q.CredentialUntil, q.ProviderUntil} {
		if t.After(end) {
			end = t
		}
	}
	q.CleanupUntil = contextQueryTime(end.Add(w.Cleanup))
	if !q.Valid() {
		return ContextQuery{}, ErrInvalid
	}
	return q, nil
}

// Current binds each fresh authority to original query identity and bounds.
// Later observations may shorten delivery; they cannot renew query, worker or
// cleanup dates. SQL additionally checks monotonic current state after locks.
func (q ContextQuery) Current(a ContextProjectionAuthority, now time.Time) bool {
	return q.Valid() && a.Valid(now) && q.Scope == a.Scope && now.Before(q.Deadline) &&
		q.Plan.InstallationID == a.Environment.InstallationID && q.Plan.Profile.Path == a.Environment.Path &&
		q.RecoveryIssuerEpoch == a.Environment.Recovery.IssuerEpoch && q.RecoveryRevision == a.Environment.Recovery.Revision
}

type ContextQueryWorker struct {
	QueryID, WorkerID, PeerID, PodUID, ProcessEpoch string
	Certificate                                     artifact.Digest
	Configuration                                   identity.Revision
}

func (w ContextQueryWorker) Matches(q ContextQuery) bool {
	return q.Valid() && w.QueryID == q.ID && w.WorkerID == q.WorkerID && authorization.UUID(w.PeerID) &&
		authorization.UUID(w.PodUID) && authorization.UUID(w.ProcessEpoch) && w.Certificate != (artifact.Digest{}) &&
		w.Configuration == q.Plan.Profile.Path.WorkerConfiguration
}

// ContextQueryCall is a minimized snapshot of the existing C-08 invocation.
// The SQL facets independently require its exact acknowledged intent; this DTO
// cannot stand in for that acknowledgement or current identity.
type ContextQueryCall struct {
	ID, RootID, Tool, InputFormat, MACVersion string
	InputDigest, PrincipalDigest              artifact.Digest
	Principal                                 identity.Principal
	StartedAt, Until, WriteUntil              time.Time
}

func (r ContextQueryCall) Valid(now time.Time) bool {
	return authorization.UUID(r.ID) && authorization.UUID(r.RootID) && r.InputFormat == "context-query-input/v1" &&
		identity.Text(r.MACVersion, 64) && r.InputDigest != (artifact.Digest{}) && r.PrincipalDigest != (artifact.Digest{}) &&
		(r.Tool == "get_file_excerpt" || r.Tool == "get_query_result") && r.Principal.Valid() &&
		identity.Fresh(r.StartedAt, r.Until, now, 5*time.Second) && !r.WriteUntil.Before(r.Until) &&
		!r.WriteUntil.After(r.StartedAt.Add(30*time.Second))
}

// ContextQueryRequest names an already audited live invocation, not a reusable
// credential. Its opaque application owner retains the original cancellation.
type ContextQueryRequest struct {
	Call                     ContextQueryCall
	OwnerID, HubProcessEpoch string
}

func (r ContextQueryRequest) Valid(now time.Time) bool {
	return r.Call.Valid(now) && authorization.UUID(r.OwnerID) && authorization.UUID(r.HubProcessEpoch)
}

type ContextReadBatch struct {
	QueryID, ID, OperationID       string
	Generation                     int64
	Worker                         ContextQueryWorker
	Request                        ContextQueryRequest
	StartedAt, Until, CleanupUntil time.Time
}

func (b ContextReadBatch) Matches(q ContextQuery) bool {
	return q.Valid() && b.QueryID == q.ID && authorization.UUID(b.ID) && b.OperationID == b.Request.Call.ID &&
		b.Worker.Matches(q) && b.Request.Valid(b.StartedAt) && b.Request.Call.RootID == q.Scope.RootID && b.Request.Call.Principal == q.Scope.Principal &&
		b.Generation >= 1 && b.Generation <= ContextMaxReadBatches && !b.StartedAt.Before(q.CreatedAt) &&
		b.Until.After(b.StartedAt) && !b.Until.After(q.Deadline) && !b.Until.After(b.Request.Call.Until) &&
		b.CleanupUntil.Equal(q.CleanupUntil)
}

func (b ContextReadBatch) Current(q ContextQuery, a ContextProjectionAuthority, now time.Time) bool {
	return b.Matches(q) && q.Current(a, now) && b.Request.Valid(now) && now.Before(b.Until)
}

// ContextReadStart is the acknowledged one-use claim result. It is not a peer
// capability by itself: C-14 must independently check the exact claim, live
// request owner, original batch and current purpose-specific key authority.
type ContextReadStart struct {
	Batch   ContextReadBatch
	ClaimID string
	Fresh   bool
}

// Equal ignores time location/monotonic representation, never immutable bounds.
func (q ContextQuery) Equal(other ContextQuery) bool {
	normalize := func(v ContextQuery) ContextQuery {
		for _, t := range []*time.Time{&v.CreatedAt, &v.Deadline, &v.WorkerUntil, &v.CredentialUntil, &v.ProviderUntil, &v.CleanupUntil,
			&v.Plan.ObservedAt, &v.Plan.ValidUntil, &v.Plan.HardUntil, &v.Plan.EffectsUntil, &v.Plan.CleanupUntil, &v.Plan.RetireBy} {
			*t = t.UTC()
		}
		return v
	}
	return normalize(q) == normalize(other)
}

func (b ContextReadBatch) Equal(other ContextReadBatch) bool {
	normalize := func(v ContextReadBatch) ContextReadBatch {
		for _, t := range []*time.Time{&v.StartedAt, &v.Until, &v.CleanupUntil, &v.Request.Call.StartedAt, &v.Request.Call.Until, &v.Request.Call.WriteUntil} {
			*t = t.UTC()
		}
		return v
	}
	return normalize(b) == normalize(other)
}
