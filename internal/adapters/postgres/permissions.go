package postgres

import (
	"bytes"
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"maps"
	"slices"
	"time"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"

	authapp "asservat.local/asservat/internal/application/authorization"
	configapp "asservat.local/asservat/internal/application/configuration"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	"asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Permissions accepts only protected reconciler input. It is not a second
// permission authoring API. Runtime composition gives each role its narrow port.
type Permissions struct {
	ledger *Ledger
	root   string
}

var _ configapp.PermissionStore = (*Permissions)(nil)
var _ authapp.ProjectionReader = (*Permissions)(nil)

func NewPermissions(ctx context.Context, pool *pgxpool.Pool, root string) (*Permissions, error) {
	if !authorization.UUID(root) {
		return nil, cfg.ErrInvalid
	}
	l, err := New(ctx, pool)
	if err != nil {
		return nil, cfg.ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if why := schemaCompatible(ctx, pool); why != "" {
		return nil, schemaRefusal(cfg.ErrUnavailable, why)
	}
	return &Permissions{l, root}, nil
}
func permissionError(err error) error {
	if err == nil {
		return nil
	}
	for _, e := range []error{cfg.ErrInvalid, cfg.ErrChanged, cfg.ErrLimit, cfg.ErrDenied, cfg.ErrRetentionHistoryBehind, cfg.ErrRetentionObservationObsolete} {
		if errors.Is(err, e) {
			return e
		}
	}
	// Keep the ledger's closed cause word for the reconciler's step label.
	var cause ledgerCause
	if errors.As(err, &cause) {
		return permissionCause{cause.cause}
	}
	return cfg.ErrUnavailable
}

// permissionCause is cfg.ErrUnavailable with the ledger's closed cause word.
type permissionCause struct{ cause string }

func (e permissionCause) Error() string     { return cfg.ErrUnavailable.Error() }
func (e permissionCause) Unwrap() error     { return cfg.ErrUnavailable }
func (e permissionCause) FixedStep() string { return e.cause }
func fence(s custodydb.PermissionStream) cfg.PermissionFence {
	f := cfg.PermissionFence{RootID: uid(s.ID), Epoch: uid(s.Epoch), Sequence: s.Sequence, LeaseUntil: s.LeaseUntil.Time, Initialized: s.Sequence > 0}
	copy(f.TrustDigest[:], s.TrustDigest)
	return f
}
func (p *Permissions) transaction(ctx context.Context, f func(*custodydb.Queries) error) error {
	return permissionError(p.ledger.transaction(ctx, f))
}

// A read-only projection sees either committed batch in full. Readers of a
// healthy cluster need not wait for an unrelated fleet mutation to commit.
func (p *Permissions) snapshot(ctx context.Context, f func(*custodydb.Queries) error) error {
	call, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return permissionError(p.ledger.runTransaction(call, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly}, f))
}

func sameFence(s custodydb.PermissionStream, f cfg.PermissionFence) bool {
	return s.ID == id(f.RootID) && s.Epoch == id(f.Epoch) && bytes.Equal(s.TrustDigest, f.TrustDigest[:])
}
func liveStream(ctx context.Context, q *custodydb.Queries, s custodydb.PermissionStream, f cfg.PermissionFence) error {
	n, err := q.CurrentTime(ctx)
	if err != nil {
		return err
	}
	if !sameFence(s, f) || !n.Time.Before(s.LeaseUntil.Time) {
		return cfg.ErrChanged
	}
	return nil
}
func currentPermissionRows(ctx context.Context, q *custodydb.Queries, root string) (map[string]custodydb.PermissionBasis, []custodydb.PermissionAssignment, error) {
	bases, err := q.ListPermissionBases(ctx, id(root))
	if err != nil {
		return nil, nil, err
	}
	rows, err := q.ListCurrentPermissionAssignments(ctx, id(root))
	if err != nil {
		return nil, nil, err
	}
	out := map[string]custodydb.PermissionBasis{}
	for _, b := range bases {
		out[b.BasisKey] = b
	}
	return out, rows, nil
}
func insertAuthority(ctx context.Context, q *custodydb.Queries, r audit.AuthorityRecord) error {
	if !r.Valid() {
		return cfg.ErrInvalid
	}
	// Batch membership and source history live in indexed transaction-linked rows.
	data, err := json.Marshal(r)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(data)
	return q.InsertAuthorityAudit(ctx, custodydb.InsertAuthorityAuditParams{ID: id(r.ID), StreamID: id(r.RootID), Epoch: id(r.Epoch), Sequence: r.Sequence, EventKind: r.Kind, EventDigest: sum[:], Record: data})
}

func (p *Permissions) BeginPermissions(ctx context.Context, root, epoch string, trust artifact.Digest) (cfg.PermissionFence, error) {
	var out cfg.PermissionFence
	if root != p.root || !authorization.UUID(epoch) || trust == (artifact.Digest{}) {
		return out, cfg.ErrInvalid
	}
	err := p.transaction(ctx, func(q *custodydb.Queries) error {
		if err := q.LockPermissionWriter(ctx, id(root)); err != nil {
			return err
		}
		if err := q.InsertPermissionStream(ctx, custodydb.InsertPermissionStreamParams{ID: id(root), Epoch: id(epoch), TrustDigest: trust[:]}); err != nil {
			return err
		}
		s, err := q.LockPermissionStream(ctx, id(root))
		if err != nil {
			return err
		}
		n, err := q.CurrentTime(ctx)
		if err != nil {
			return err
		}
		if s.Epoch == id(epoch) {
			if !bytes.Equal(s.TrustDigest, trust[:]) {
				return cfg.ErrChanged
			}
			previous, e := q.ReadAuthorityAudit(ctx, id(epoch))
			if e == nil {
				if previous.StreamID != id(root) || previous.EventKind != "permission-reset" {
					return cfg.ErrChanged
				}
				out = fence(s)
				return nil
			}
			if !errors.Is(e, pgx.ErrNoRows) {
				return e
			}
		} else {
			if n.Time.Before(s.LeaseUntil.Time) {
				return cfg.ErrChanged
			}
			if err = q.ResetPermissionStream(ctx, custodydb.ResetPermissionStreamParams{ID: id(root), Epoch: id(epoch), TrustDigest: trust[:]}); err != nil {
				return err
			}
		}
		record := audit.AuthorityRecord{ID: epoch, RootID: root, Epoch: epoch, Kind: "permission-reset", InputDigest: trust, CreatedAt: n.Time}
		// A routine restart suspends authority but keeps candidate history for
		// reconciliation against exact observed versions. Trust replacement retires
		// everything; equal final values alone never establish continuity.
		if !bytes.Equal(s.TrustDigest, trust[:]) {
			bases, err := q.ListPermissionBases(ctx, s.ID)
			if err != nil {
				return err
			}
			keys := make([]string, len(bases))
			for i, b := range bases {
				keys[i] = b.BasisKey
			}
			if err = q.RecordPermissionBasisChanges(ctx, custodydb.RecordPermissionBasisChangesParams{StreamID: s.ID, EventID: id(epoch), Keys: keys, Retired: true}); err != nil {
				return err
			}
			if _, err = q.RetirePermissionStream(ctx, custodydb.RetirePermissionStreamParams{StreamID: id(root), RetirementAuditID: id(epoch)}); err != nil {
				return err
			}
			if err = retireReviewStream(ctx, q, root, &record); err != nil {
				return err
			}
		}
		if err = insertAuthority(ctx, q, record); err != nil {
			return err
		}
		s, err = q.LockPermissionStream(ctx, id(root))
		out = fence(s)
		return err
	})
	return out, err
}
func (p *Permissions) RenewPermissions(ctx context.Context, f cfg.PermissionFence) (cfg.PermissionFence, error) {
	var out cfg.PermissionFence
	if f.RootID != p.root {
		return out, cfg.ErrInvalid
	}
	err := p.transaction(ctx, func(q *custodydb.Queries) error {
		s, err := q.LockPermissionStream(ctx, id(p.root))
		if err != nil {
			return err
		}
		if err = liveStream(ctx, q, s, f); err != nil {
			return err
		}
		until, err := q.RenewPermissionStream(ctx, custodydb.RenewPermissionStreamParams{ID: s.ID, Epoch: s.Epoch, Observing: f.Initialized, Sequence: f.Sequence})
		if err != nil {
			return err
		}
		s.LeaseUntil = until
		out = fence(s)
		return nil
	})
	return out, err
}
func (p *Permissions) SuspendPermissions(ctx context.Context, f cfg.PermissionFence) error {
	if f.RootID != p.root {
		return cfg.ErrInvalid
	}
	return p.transaction(ctx, func(q *custodydb.Queries) error {
		s, err := q.LockPermissionStream(ctx, id(p.root))
		if err != nil {
			return err
		}
		if !sameFence(s, f) {
			return cfg.ErrChanged
		}
		// Retain candidate history; the next epoch must requalify continuity.
		return q.SuspendPermissionStream(ctx, s.ID)
	})
}

func normalizedBatch(b cfg.PermissionBatch) cfg.PermissionBatch {
	b.ObservedAt = b.ObservedAt.UTC()
	b.FreshUntil = b.FreshUntil.UTC()
	b.UnavailableClusters = slices.Sorted(slices.Values(b.UnavailableClusters))
	b.UnavailableSources = slices.Sorted(slices.Values(b.UnavailableSources))
	b.ReviewSources = slices.Clone(b.ReviewSources)
	slices.SortFunc(b.ReviewSources, func(x, y cfg.ReviewSource) int { return cmp.Compare(x.Resource.UID, y.Resource.UID) })
	b.Bases = slices.Clone(b.Bases)
	for i := range b.Bases {
		p := &b.Bases[i]
		p.NotAfter = p.NotAfter.UTC()
		p.Subjects = slices.Clone(p.Subjects)
		p.Roles = slices.Clone(p.Roles)
		p.Scope.Workloads = append([]cfg.WorkloadRef{}, p.Scope.Workloads...)
		if p.Automation != nil {
			a := *p.Automation
			a.AllowedActions = slices.Clone(a.AllowedActions)
			slices.Sort(a.AllowedActions)
			p.Automation = &a
		}
		slices.Sort(p.Roles)
		slices.SortFunc(p.Subjects, func(a, b cfg.Subject) int {
			if n := cmp.Compare(a.Kind, b.Kind); n != 0 {
				return n
			}
			if n := cmp.Compare(a.Issuer, b.Issuer); n != 0 {
				return n
			}
			return cmp.Compare(a.ID, b.ID)
		})
		slices.SortFunc(p.Scope.Workloads, func(a, b cfg.WorkloadRef) int { return cmp.Compare(a.UID, b.UID) })
	}
	slices.SortFunc(b.Bases, func(a, b cfg.PermissionBasis) int { return cmp.Compare(a.Key(), b.Key()) })
	return b
}
func projectionDigest(b cfg.PermissionBatch) []byte {
	// Clock and request IDs cannot change the identity of an observed projection.
	b.RootID = ""
	b.Epoch = ""
	b.RequestID = ""
	b.ExpectedSequence = 0
	b.ObservedAt = time.Time{}
	b.FreshUntil = time.Time{}
	b.Bases = slices.Clone(b.Bases)
	for i := range b.Bases {
		b.Bases[i].Continuous = false
	}
	return digest(b)
}

// permissionStreamUntil is the stored lifetime of an accepted permission
// stream observation (ADR-200 revision, 2026-10-23): 30 seconds after its own
// observation, so a late hub-worker refresh does not lapse every admission.
// The batch itself keeps its original interval through the final database clock check.
func permissionStreamUntil(observed time.Time) time.Time {
	return observed.Add(authorization.PermissionObservationInterval)
}

func validBatch(b cfg.PermissionBatch, now time.Time) error {
	if err := b.Validate(now); err != nil {
		return err
	}
	if b.ExpectedSequence >= 2147483647 {
		return cfg.ErrLimit
	}
	for _, p := range b.Bases {
		if configapp.PermissionScopeDigest(p) != p.ScopeDigest {
			return cfg.ErrInvalid
		}
	}
	return nil
}
func equivalentBasis(old custodydb.PermissionBasis, next cfg.PermissionBasis) bool {
	// Kubernetes increments generation for every spec edit. A changed
	// resourceVersion at the same generation therefore cannot by itself
	// revoke an assignment. Basis identity, scope and spec are checked
	// independently, as is the namespace metadata behind inherited grants.
	if old.Generation != next.Resource.Generation && next.Resource.Kind != "PermissionSource" && old.ResourceVersion != next.Resource.ResourceVersion && !next.Continuous {
		return false
	}
	if !bytes.Equal(old.ScopeDigest, next.ScopeDigest[:]) || old.Effect != next.Effect || old.Kind != next.Resource.Kind {
		return false
	}
	// A jumped generation may hide A -> B -> A, even when the final digest matches.
	if next.Resource.Generation < old.Generation || next.Resource.Generation > old.Generation+1 {
		return false
	}
	if next.Resource.Generation == old.Generation && !bytes.Equal(old.SpecDigest, next.Resource.SpecDigest[:]) {
		return false
	}
	if next.Resource.Kind == "PermissionSource" && old.ObservationVersion != next.ObservationVersion && !next.Continuous {
		return false
	}
	return true
}

// A single SQL recordset carries the variable-size workload and automation
// fields. PostgreSQL expands it once for the whole accepted batch.
type permissionBasisWrite struct {
	Key         string                            `json:"key"`
	UID         string                            `json:"uid"`
	Kind        string                            `json:"kind"`
	Generation  int64                             `json:"generation"`
	RV          string                            `json:"rv"`
	Spec        string                            `json:"spec"`
	Scope       string                            `json:"scope"`
	Cluster     string                            `json:"cluster"`
	Namespace   string                            `json:"namespace"`
	Workloads   []string                          `json:"workloads,omitempty"`
	Effect      string                            `json:"effect"`
	Expiry      *time.Time                        `json:"expiry,omitempty"`
	Observation string                            `json:"observation"`
	Automation  *authorization.AutomationEnvelope `json:"automation,omitempty"`
}

type memberKey struct{ basis, kind, issuer, subject, role string }

func member(a custodydb.PermissionAssignment) memberKey {
	return memberKey{a.BasisKey, a.SubjectKind, a.Issuer, a.SubjectID, a.Role}
}

func (p *Permissions) AcceptPermissions(ctx context.Context, b cfg.PermissionBatch) (cfg.PermissionAcceptance, error) {
	var out cfg.PermissionAcceptance
	if b.RootID != p.root {
		return out, cfg.ErrInvalid
	}
	// Freshness is checked against the database clock inside the transaction.
	if err := validBatch(b, b.ObservedAt); err != nil {
		return out, err
	}
	b = normalizedBatch(b)
	projected := projectionDigest(b)
	// The projection covers every normalized field except the request envelope
	// and continuity flags. Hash those alongside it for idempotent retry.
	until := b.FreshUntil
	continuity := make([]bool, len(b.Bases))
	for i, basis := range b.Bases {
		until = cfg.PermissionDeadline(until, basis.NotAfter)
		continuity[i] = basis.Continuous
	}
	requestDigest := digest(struct {
		Projection           []byte
		Root, Epoch, Request string
		Sequence             int64
		Observed, Until      time.Time
		Continuous           []bool
	}{projected, b.RootID, b.Epoch, b.RequestID, b.ExpectedSequence, b.ObservedAt, b.FreshUntil, continuity})
	// An expired request may still resolve the outcome of its original commit.
	expired := !time.Now().Before(until)
	var cancel context.CancelFunc
	if expired {
		ctx, cancel = context.WithTimeout(ctx, 5*time.Second)
	} else {
		ctx, cancel = context.WithDeadline(ctx, until)
	}
	defer cancel()
	err := permissionError(p.ledger.runTransaction(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted}, func(q *custodydb.Queries) error {
		// Only competing writers serialize while staging. Public operations can
		// use the committed projection until the final stream-row update.
		if err := q.LockPermissionWriter(ctx, id(p.root)); err != nil {
			return err
		}
		state, err := q.ReadPermissionStreamClock(ctx, id(p.root))
		if err != nil {
			return err
		}
		s := state.PermissionStream
		previous, e := q.ReadPermissionAcceptance(ctx, id(b.RequestID))
		if e == nil {
			if previous.StreamID != s.ID || previous.Epoch != id(b.Epoch) || (!bytes.Equal(previous.RequestDigest, requestDigest) && !bytes.Equal(previous.RequestDigest, digest(b))) {
				return cfg.ErrChanged
			}
			out = cfg.PermissionAcceptance{PermissionFence: cfg.PermissionFence{RootID: b.RootID, Epoch: b.Epoch, Sequence: previous.Sequence, TrustDigest: b.TrustDigest, Initialized: true, LeaseUntil: previous.LeaseUntil.Time}, AuditID: uid(previous.AuditID), Assignments: int(previous.Assignments), Retired: int(previous.Retired)}
			return nil
		}
		if !errors.Is(e, pgx.ErrNoRows) {
			return e
		}
		if expired {
			return cfg.ErrInvalid
		}
		requested := cfg.PermissionFence{RootID: b.RootID, Epoch: b.Epoch, TrustDigest: b.TrustDigest}
		n := state.ReadAt
		if !sameFence(s, requested) || !n.Time.Before(s.LeaseUntil.Time) || s.Sequence != b.ExpectedSequence {
			return cfg.ErrChanged
		}
		if !cfg.PermissionObservationCurrent(b.ObservedAt, until, n.Time) {
			return cfg.ErrInvalid
		}
		bases, rows, err := currentPermissionRows(ctx, q, p.root)
		if err != nil {
			return err
		}
		next := map[string]cfg.PermissionBasis{}
		// A wanted member keeps its existing assignment when the basis is continuous.
		wanted := map[memberKey]bool{}
		for _, basis := range b.Bases {
			next[basis.Key()] = basis
			for _, subject := range basis.Subjects {
				for _, role := range basis.Roles {
					wanted[memberKey{basis.Key(), subject.Kind, subject.Issuer, subject.ID, role}] = false
				}
			}
		}
		record := audit.AuthorityRecord{ID: b.RequestID, RootID: p.root, Epoch: b.Epoch, Sequence: s.Sequence + 1, Kind: "permission-change", CreatedAt: n.Time, InputDigest: b.InputDigest}
		record.Namespaces = b.Namespaces
		record.RemoteNamespaces = b.RemoteNamespaces
		record.Workloads = b.Workloads
		oldKeys := map[string]bool{}
		newKeys := map[string]bool{}
		var retired []pgtype.UUID
		for _, a := range rows {
			basis, exists := next[a.BasisKey]
			old := bases[a.BasisKey]
			key := member(a)
			if _, wantedMember := wanted[key]; exists && wantedMember && equivalentBasis(old, basis) {
				wanted[key] = true
				continue
			}
			// An unavailable source keeps its accepted assignments without
			// renewing them: their basis keeps its older seen_sequence, so no
			// projection or capacity scope lets them grant (ADR-242).
			if !exists && old.Kind == "PermissionSource" && (b.SourcesUnavailable || slices.Contains(b.UnavailableSources, old.Uid)) {
				continue
			}
			retired = append(retired, a.ID)
			oldKeys[a.BasisKey] = true
		}
		if len(retired) > 0 {
			if err := q.RetirePermissionAssignments(ctx, custodydb.RetirePermissionAssignmentsParams{Ids: retired, AuditID: id(record.ID)}); err != nil {
				return err
			}
		}
		basisWrites := make([]permissionBasisWrite, 0, len(b.Bases))
		additions := custodydb.InsertPermissionAssignmentsParams{StreamID: s.ID, EventID: id(record.ID)}
		for _, basis := range b.Bases {
			workloads := make([]string, 0, len(basis.Scope.Workloads))
			// ADR-335 D4: a uid pins one instance; otherwise the workload
			// matches by kind and name (workload_name).
			for _, w := range basis.Scope.Workloads {
				if w.UID == "" {
					workloads = append(workloads, w.Kind+"/"+w.Name)
				} else {
					workloads = append(workloads, w.UID)
				}
			}
			key := basis.Key()
			old, exists := bases[key]
			if !exists || old.Generation != basis.Resource.Generation || !bytes.Equal(old.ScopeDigest, basis.ScopeDigest[:]) || !bytes.Equal(old.SpecDigest, basis.Resource.SpecDigest[:]) {
				newKeys[key] = true
				if exists {
					oldKeys[key] = true
				}
			}
			row := permissionBasisWrite{Key: key, UID: basis.Resource.UID, Kind: basis.Resource.Kind, Generation: basis.Resource.Generation, RV: basis.Resource.ResourceVersion, Spec: hex.EncodeToString(basis.Resource.SpecDigest[:]), Scope: hex.EncodeToString(basis.ScopeDigest[:]), Cluster: basis.Scope.ClusterID, Namespace: basis.Scope.Namespace.UID, Workloads: workloads, Effect: basis.Effect, Observation: basis.ObservationVersion, Automation: basis.Automation}
			if !basis.NotAfter.IsZero() {
				row.Expiry = &basis.NotAfter
			}
			basisWrites = append(basisWrites, row)
			for _, subject := range basis.Subjects {
				for _, role := range basis.Roles {
					if wanted[memberKey{key, subject.Kind, subject.Issuer, subject.ID, role}] {
						continue
					}
					newKeys[key] = true
					additions.Bases = append(additions.Bases, key)
					additions.Kinds = append(additions.Kinds, subject.Kind)
					additions.Issuers = append(additions.Issuers, subject.Issuer)
					additions.Subjects = append(additions.Subjects, subject.ID)
					additions.Roles = append(additions.Roles, role)
				}
			}
		}
		note := func(keys map[string]bool, retired bool) error {
			if len(keys) == 0 {
				return nil
			}
			return q.RecordPermissionBasisChanges(ctx, custodydb.RecordPermissionBasisChangesParams{StreamID: s.ID, EventID: id(record.ID), Keys: slices.Collect(maps.Keys(keys)), Retired: retired})
		}
		if err = note(oldKeys, true); err != nil {
			return err
		}
		if len(basisWrites) > 0 {
			encoded, err := json.Marshal(basisWrites)
			if err != nil {
				return err
			}
			if err = q.UpsertPermissionBases(ctx, custodydb.UpsertPermissionBasesParams{StreamID: s.ID, EventID: id(record.ID), Sequence: record.Sequence, Bases: encoded}); err != nil {
				return err
			}
		}
		if len(additions.Bases) > 0 {
			if err = q.InsertPermissionAssignments(ctx, additions); err != nil {
				return err
			}
		}
		if err = note(newKeys, false); err != nil {
			return err
		}
		if err = acceptReviewSources(ctx, q, s, b, &record); err != nil {
			return err
		}
		if err = insertAuthority(ctx, q, record); err != nil {
			return err
		}
		if err = q.InsertPermissionAcceptance(ctx, custodydb.InsertPermissionAcceptanceParams{RequestID: id(b.RequestID), StreamID: s.ID, Epoch: s.Epoch, Sequence: record.Sequence, RequestDigest: requestDigest, AuditID: id(record.ID), Assignments: int32(len(wanted)), Retired: int32(len(retired)), LeaseUntil: s.LeaseUntil}); err != nil {
			return err
		}
		if err = q.CheckPermissionConstraints(ctx); err != nil {
			return err
		}
		current, err := q.LockPermissionStream(ctx, s.ID)
		if err != nil {
			return err
		}
		if current.Sequence != s.Sequence || current.Suspended != s.Suspended || !sameFence(current, requested) {
			return cfg.ErrChanged
		}
		if err = q.UpdatePermissionStream(ctx, custodydb.UpdatePermissionStreamParams{ID: s.ID, UnavailableClusters: b.UnavailableClusters, Sequence: record.Sequence, ProjectionDigest: projected, ObservedAt: ts(b.ObservedAt), FreshUntil: ts(permissionStreamUntil(b.ObservedAt))}); err != nil {
			return err
		}
		n, err = q.CurrentTime(ctx)
		if err != nil {
			return err
		}
		if !n.Time.Before(current.LeaseUntil.Time) || !n.Time.Before(s.LeaseUntil.Time) {
			return cfg.ErrChanged
		}
		if !cfg.PermissionObservationCurrent(b.ObservedAt, until, n.Time) {
			return cfg.ErrInvalid
		}
		s.Sequence = record.Sequence
		out = cfg.PermissionAcceptance{PermissionFence: fence(s), AuditID: record.ID, Assignments: len(wanted), Retired: len(retired)}
		return nil
	}))
	return out, err
}

func (p *Permissions) RefreshPermissions(ctx context.Context, b cfg.PermissionBatch) error {
	if b.RootID != p.root {
		return cfg.ErrInvalid
	}
	if err := validBatch(b, b.ObservedAt); err != nil {
		return err
	}
	projected := projectionDigest(normalizedBatch(b))
	return p.transaction(ctx, func(q *custodydb.Queries) error {
		s, err := q.LockPermissionStream(ctx, id(p.root))
		if err != nil {
			return err
		}
		if err = liveStream(ctx, q, s, cfg.PermissionFence{RootID: b.RootID, Epoch: b.Epoch, TrustDigest: b.TrustDigest}); err != nil {
			return err
		}
		if s.Suspended || s.Sequence != b.ExpectedSequence || !bytes.Equal(s.ProjectionDigest, projected) {
			return cfg.ErrChanged
		}
		n, err := q.CurrentTime(ctx)
		if err != nil {
			return err
		}
		if !b.Current(n.Time) {
			return cfg.ErrInvalid
		}
		if err = q.UpdatePermissionStream(ctx, custodydb.UpdatePermissionStreamParams{ID: s.ID, UnavailableClusters: b.UnavailableClusters, Sequence: s.Sequence, ProjectionDigest: s.ProjectionDigest, ObservedAt: ts(b.ObservedAt), FreshUntil: ts(permissionStreamUntil(b.ObservedAt))}); err != nil {
			return err
		}
		n, err = q.CurrentTime(ctx)
		if err != nil {
			return err
		}
		if !n.Time.Before(s.LeaseUntil.Time) {
			return cfg.ErrChanged
		}
		if !b.Current(n.Time) {
			return cfg.ErrInvalid
		}
		return nil
	})
}

// SQL validates observations on the database clock. Application decisions
// use their local clock. Sampling both during the existing stream read keeps
// the remaining lifetime and can only narrow the original absolute deadline.
type permissionClockOffset time.Duration

func readPermissionStreamClock(ctx context.Context, q *custodydb.Queries, root string) (custodydb.PermissionStream, permissionClockOffset, error) {
	start := time.Now()
	row, err := q.ReadPermissionStreamClock(ctx, id(root))
	return row.PermissionStream, clockOffsetAt(start, row.ReadAt.Time), err
}
func clockOffsetAt(local, database time.Time) permissionClockOffset {
	return permissionClockOffset(min(time.Duration(0), local.Sub(database)))
}

func (offset permissionClockOffset) at(t time.Time) time.Time {
	if t.IsZero() {
		return t
	}
	return t.Add(time.Duration(offset))
}
func (offset permissionClockOffset) projection(p *authorization.Projection) {
	p.ObservedAt, p.FreshUntil = offset.at(p.ObservedAt), offset.at(p.FreshUntil)
	p.DeniesObservedAt, p.DeniesFreshUntil = offset.at(p.DeniesObservedAt), offset.at(p.DeniesFreshUntil)
	for _, rows := range [][]authorization.CurrentAssignment{p.Allows, p.Denies} {
		for i := range rows {
			rows[i].ObservedAt, rows[i].FreshUntil = offset.at(rows[i].ObservedAt), offset.at(rows[i].FreshUntil)
		}
	}
}
func (p *Permissions) Permissions(ctx context.Context, target authorization.Target) (authorization.Projection, error) {
	var out authorization.Projection
	if !target.Valid() {
		return out, cfg.ErrInvalid
	}
	err := p.snapshot(ctx, func(q *custodydb.Queries) error {
		s, offset, err := readPermissionStreamClock(ctx, q, p.root)
		if err != nil {
			return err
		}
		out, err = permissionProjection(ctx, q, s, target)
		offset.projection(&out)
		return err
	})
	if err != nil {
		return authorization.Projection{}, err
	}
	return out, nil
}

// WorkloadPermissions reads only whole-workload assignments, excluding
// decision-time single-Pod reviews. It shares the current accepted stream,
// locks and audited assignment projection with concrete-Pod permission reads.
func (p *Permissions) WorkloadPermissions(ctx context.Context, target authorization.WorkloadTarget) (authorization.WorkloadProjection, error) {
	if !target.Valid() {
		return authorization.WorkloadProjection{}, cfg.ErrInvalid
	}
	var concrete authorization.Projection
	err := p.snapshot(ctx, func(q *custodydb.Queries) error {
		stream, offset, err := readPermissionStreamClock(ctx, q, p.root)
		if err != nil {
			return err
		}
		concrete, err = permissionProjection(ctx, q, stream, authorization.Target{ClusterID: target.ClusterID, NamespaceUID: target.NamespaceUID, WorkloadUID: target.WorkloadUID})
		offset.projection(&concrete)
		return err
	})
	if err != nil {
		return authorization.WorkloadProjection{}, err
	}
	return authorization.WorkloadProjection{Target: target, Revision: concrete.Revision, ObservedAt: concrete.ObservedAt, FreshUntil: concrete.FreshUntil, DeniesComplete: concrete.DeniesComplete, DeniesObservedAt: concrete.DeniesObservedAt, DeniesFreshUntil: concrete.DeniesFreshUntil, Allows: concrete.Allows, Denies: concrete.Denies}, nil
}

// permissionProjection runs with the permission stream already locked. It may
// be reused by named admission facets after taking their remaining SQL locks.
func permissionProjection(ctx context.Context, q *custodydb.Queries, s custodydb.PermissionStream, target authorization.Target) (authorization.Projection, error) {
	var out authorization.Projection
	n, err := q.CurrentTime(ctx)
	if err != nil {
		return authorization.Projection{}, err
	}
	if slices.Contains(s.UnavailableClusters, target.ClusterID) || s.Sequence < 1 || s.Suspended || !n.Time.Before(s.LeaseUntil.Time) || !identity.Fresh(s.ObservedAt.Time, s.FreshUntil.Time, n.Time, authorization.PermissionObservationInterval) || len(s.ProjectionDigest) != 32 {
		return authorization.Projection{}, cfg.ErrUnavailable
	}
	rows, err := q.SelectPermissionAssignments(ctx, custodydb.SelectPermissionAssignmentsParams{StreamID: s.ID, ClusterID: id(target.ClusterID), NamespaceUid: target.NamespaceUID, Column4: target.WorkloadUID})
	if err != nil {
		return authorization.Projection{}, err
	}
	until := identity.Earlier(s.FreshUntil.Time, s.LeaseUntil.Time)
	out = authorization.Projection{Target: target, Revision: identity.Revision{UID: uid(s.Epoch), Generation: s.Sequence}, ObservedAt: s.ObservedAt.Time, FreshUntil: until, DeniesComplete: true, DeniesObservedAt: s.ObservedAt.Time, DeniesFreshUntil: until}
	copy(out.Revision.Digest[:], s.ProjectionDigest)
	for _, a := range rows {
		if a.SeenSequence != s.Sequence {
			// Only an unavailable source's kept allow may lag the stream
			// (ADR-242); it grants nothing until accepted again. Any other
			// stale row means the projection is inconsistent.
			if a.SourceKind == "PermissionSource" && a.Effect == "Allow" {
				continue
			}
			return authorization.Projection{}, cfg.ErrUnavailable
		}
		deadline := until
		if a.NotAfter.Valid {
			deadline = identity.Earlier(deadline, a.NotAfter.Time)
		}
		if !n.Time.Before(deadline) {
			continue
		}
		audience := artifact.AudienceAssignment{Kind: a.SubjectKind, Issuer: a.Issuer, SubjectID: a.SubjectID, Role: a.Role, BasisKind: a.SourceKind, BasisUID: a.SourceUid, AssignmentID: uid(a.ID)}
		copy(audience.BasisDigest[:], a.BasisDigest)
		row := authorization.CurrentAssignment{Audience: audience, ObservedAt: s.ObservedAt.Time, FreshUntil: deadline}
		if a.Effect == "Deny" {
			out.Denies = append(out.Denies, row)
		} else {
			out.Allows = append(out.Allows, row)
		}
	}
	// ADR-245: fresh decision-time allows of this exact Pod, each one
	// principal's own recorded review by a current, acknowledged source.
	if target.PodUID != "" {
		reviews, err := q.SelectPermissionReviews(ctx, custodydb.SelectPermissionReviewsParams{StreamID: s.ID, Epoch: s.Epoch, SeenSequence: s.Sequence, ClusterID: id(target.ClusterID), NamespaceUid: target.NamespaceUID, WorkloadUid: target.WorkloadUID, PodUid: target.PodUID})
		if err != nil {
			return authorization.Projection{}, err
		}
		for _, r := range reviews {
			deadline := identity.Earlier(until, r.FreshUntil.Time)
			if !n.Time.Before(deadline) {
				continue
			}
			audience := artifact.AudienceAssignment{Kind: "User", Issuer: r.Issuer, SubjectID: r.SubjectID, Role: r.Role, BasisKind: "PermissionSource", BasisUID: r.SourceUid, AssignmentID: uid(r.ID)}
			copy(audience.BasisDigest[:], r.BasisDigest)
			out.Allows = append(out.Allows, authorization.CurrentAssignment{Audience: audience, ObservedAt: r.DecidedAt.Time, FreshUntil: deadline, Reviewed: true})
		}
	}
	n, err = q.CurrentTime(ctx)
	if err != nil {
		return authorization.Projection{}, err
	}
	if !n.Time.Before(until) {
		return authorization.Projection{}, cfg.ErrUnavailable
	}
	return out, nil
}
