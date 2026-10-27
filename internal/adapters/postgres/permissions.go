package postgres

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"slices"
	"time"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	auditapp "asservat.local/asservat/internal/application/audit"
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
var _ auditapp.AuthorityLedger = (*Permissions)(nil)

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
	f := cfg.PermissionFence{RootID: uid(s.ID), Epoch: uid(s.Epoch), Sequence: s.Sequence, LeaseUntil: s.LeaseUntil.Time, Initialized: s.InitialAuditID.Valid}
	copy(f.TrustDigest[:], s.TrustDigest)
	return f
}
func (p *Permissions) transaction(ctx context.Context, f func(*custodydb.Queries) error) error {
	return permissionError(p.ledger.transaction(ctx, f))
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
func assignmentAudience(a custodydb.PermissionAssignment, b custodydb.PermissionBasis) artifact.AudienceAssignment {
	out := artifact.AudienceAssignment{Kind: a.SubjectKind, Issuer: a.Issuer, SubjectID: a.SubjectID, Role: a.Role, BasisKind: b.Kind, BasisUID: b.Uid, AssignmentID: uid(a.ID)}
	copy(out.BasisDigest[:], a.BasisDigest)
	return out
}
func change(a custodydb.PermissionAssignment, b custodydb.PermissionBasis, kind string) audit.AssignmentChange {
	c := audit.AssignmentChange{ID: uid(a.ID), Change: kind, Audience: assignmentAudience(a, b)}
	copy(c.ScopeDigest[:], b.ScopeDigest)
	return c
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
	if len(bases) > 1024 || len(rows) > 4096 {
		return nil, nil, cfg.ErrLimit
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
	data, err := json.Marshal(r)
	if err != nil || len(data) > 8<<20 {
		return cfg.ErrLimit
	}
	return q.InsertAuthorityAudit(ctx, custodydb.InsertAuthorityAuditParams{ID: id(r.ID), StreamID: id(r.RootID), Epoch: id(r.Epoch), Sequence: r.Sequence, EventKind: r.Kind, EventDigest: digest(r), Record: data})
}

func (p *Permissions) BeginPermissions(ctx context.Context, root, epoch string, trust artifact.Digest) (cfg.PermissionFence, error) {
	var out cfg.PermissionFence
	if root != p.root || !authorization.UUID(epoch) || trust == (artifact.Digest{}) {
		return out, cfg.ErrInvalid
	}
	err := p.transaction(ctx, func(q *custodydb.Queries) error {
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
		bases, rows, err := currentPermissionRows(ctx, q, root)
		if err != nil {
			return err
		}
		record := audit.AuthorityRecord{ID: epoch, RootID: root, Epoch: epoch, Kind: "permission-reset", InputDigest: trust, CreatedAt: n.Time}
		// A routine restart suspends authority but keeps candidate history for
		// reconciliation against exact observed versions. Trust replacement retires
		// everything; equal final values alone never establish continuity.
		if !bytes.Equal(s.TrustDigest, trust[:]) {
			for _, a := range rows {
				record.Changes = append(record.Changes, change(a, bases[a.BasisKey], "retired"))
			}
			if _, err = q.RetirePermissionStream(ctx, custodydb.RetirePermissionStreamParams{StreamID: id(root), RetirementAuditID: id(epoch)}); err != nil {
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
		until, err := q.RenewPermissionStream(ctx, custodydb.RenewPermissionStreamParams{ID: s.ID, Epoch: s.Epoch})
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
	b.UnavailableSources = slices.Sorted(slices.Values(b.UnavailableSources))
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
	b.Initial = nil
	b.ObservedAt = time.Time{}
	b.FreshUntil = time.Time{}
	for i := range b.Bases {
		b.Bases[i].Continuous = false
	}
	return digest(b)
}

// permissionStreamUntil is the stored lifetime of an accepted permission
// stream observation (ADR-200 revision, 2026-10-23): 30 seconds after its own
// observation, so a late hub-worker refresh does not lapse every admission.
// The batch itself keeps its original interval, which validBatch still checks.
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
	// A PermissionSource confers authority only through its spec, whose every
	// transition advances metadata.generation; the generation checks below
	// therefore prove its continuity, and a status or metadata write that
	// changes only its resourceVersion keeps assignments (ADR-242). The
	// namespace metadata it maps has no generation: its own resourceVersion
	// must match exactly unless the namespace watch was continuous.
	if next.Resource.Kind != "PermissionSource" && old.ResourceVersion != next.Resource.ResourceVersion && !next.Continuous {
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
	requestDigest := digest(b)
	projected := projectionDigest(normalizedBatch(b))
	err := p.transaction(ctx, func(q *custodydb.Queries) error {
		s, err := q.LockPermissionStream(ctx, id(p.root))
		if err != nil {
			return err
		}
		previous, e := q.ReadPermissionAcceptance(ctx, id(b.RequestID))
		if e == nil {
			if previous.StreamID != s.ID || previous.Epoch != id(b.Epoch) || !bytes.Equal(previous.RequestDigest, requestDigest) {
				return cfg.ErrChanged
			}
			out = cfg.PermissionAcceptance{PermissionFence: cfg.PermissionFence{RootID: b.RootID, Epoch: b.Epoch, Sequence: previous.Sequence, TrustDigest: b.TrustDigest, Initialized: true}, AuditID: uid(previous.AuditID), Assignments: int(previous.Assignments), Retired: int(previous.Retired)}
			return nil
		}
		if !errors.Is(e, pgx.ErrNoRows) {
			return e
		}
		requested := cfg.PermissionFence{RootID: b.RootID, Epoch: b.Epoch, TrustDigest: b.TrustDigest}
		if err = liveStream(ctx, q, s, requested); err != nil {
			return err
		}
		if s.Sequence != b.ExpectedSequence || (s.ObservedAt.Valid && !b.ObservedAt.After(s.ObservedAt.Time)) {
			return cfg.ErrChanged
		}
		n, err := q.CurrentTime(ctx)
		if err != nil {
			return err
		}
		if err = validBatch(b, n.Time); err != nil {
			return err
		}
		if !s.InitialAuditID.Valid && (b.Initial == nil || !b.Initial.Valid(n.Time) || b.Initial.BindingCount < len(b.Bases)) {
			return cfg.ErrDenied
		}
		bases, rows, err := currentPermissionRows(ctx, q, p.root)
		if err != nil {
			return err
		}
		next := map[string]cfg.PermissionBasis{}
		wanted := map[memberKey]bool{}
		for _, basis := range b.Bases {
			next[basis.Key()] = basis
			for _, subject := range basis.Subjects {
				for _, role := range basis.Roles {
					wanted[memberKey{basis.Key(), subject.Kind, subject.Issuer, subject.ID, role}] = true
				}
			}
		}
		record := audit.AuthorityRecord{ID: b.RequestID, RootID: p.root, Epoch: b.Epoch, Sequence: s.Sequence + 1, Kind: "permission-change", CreatedAt: n.Time, InputDigest: b.InputDigest}
		if !s.InitialAuditID.Valid {
			initial := b.Initial
			record.Bootstrap = &audit.PermissionBootstrap{ClusterID: initial.ClusterID, NamespaceUID: initial.Control.UID, BindingsDigest: initial.BindingsDigest, BindingCount: initial.BindingCount}
			if r := initial.Review; r != nil {
				record.Bootstrap.ReviewUID = r.Resource.UID
				record.Bootstrap.ReviewVersion = r.Resource.ResourceVersion
				record.Bootstrap.ReviewDigest = r.Resource.SpecDigest
				record.Bootstrap.Reviewer = r.Reviewer
				record.Bootstrap.ReviewedAt = r.ReviewedAt
				record.Bootstrap.ExpiresAt = r.ExpiresAt
			}
		}
		record.Namespaces = b.Namespaces
		retained := map[memberKey]bool{}
		retired := 0
		for _, a := range rows {
			basis, exists := next[a.BasisKey]
			old := bases[a.BasisKey]
			if exists && wanted[member(a)] && equivalentBasis(old, basis) {
				retained[member(a)] = true
				continue
			}
			// An unavailable source keeps its accepted assignments without
			// renewing them: their basis keeps its older seen_sequence, so no
			// projection or capacity scope lets them grant (ADR-242).
			if !exists && old.Kind == "PermissionSource" && (b.SourcesUnavailable || slices.Contains(b.UnavailableSources, old.Uid)) {
				continue
			}
			if err = q.RetirePermissionAssignment(ctx, custodydb.RetirePermissionAssignmentParams{ID: a.ID, RetirementAuditID: id(record.ID)}); err != nil {
				return err
			}
			record.Changes = append(record.Changes, change(a, old, "retired"))
			retired++
		}
		for _, basis := range b.Bases {
			workloads := make([]string, 0, len(basis.Scope.Workloads))
			for _, w := range basis.Scope.Workloads {
				workloads = append(workloads, w.UID)
			}
			expiry := pgtype.Timestamptz{}
			if !basis.NotAfter.IsZero() {
				expiry = ts(basis.NotAfter)
			}
			params := custodydb.UpsertPermissionBasisParams{StreamID: s.ID, BasisKey: basis.Key(), Uid: basis.Resource.UID, Kind: basis.Resource.Kind, Generation: basis.Resource.Generation, ResourceVersion: basis.Resource.ResourceVersion, SpecDigest: basis.Resource.SpecDigest[:], ScopeDigest: basis.ScopeDigest[:], ClusterID: id(basis.Scope.ClusterID), NamespaceUid: basis.Scope.Namespace.UID, WorkloadUids: workloads, Effect: basis.Effect, NotAfter: expiry, SeenSequence: record.Sequence, ObservationVersion: basis.ObservationVersion}
			if basis.Automation != nil {
				params.AutomationJson, err = json.Marshal(basis.Automation)
				if err != nil {
					return err
				}
				params.AutomationAuditID = id(record.ID)
				record.Automation = append(record.Automation, audit.AutomationDelegation{BasisKey: basis.Key(), Revision: identity.Revision{UID: basis.Resource.UID, Generation: basis.Resource.Generation, Digest: basis.Resource.SpecDigest}, ScopeDigest: basis.ScopeDigest, Envelope: *basis.Automation})
			}
			if err = q.UpsertPermissionBasis(ctx, params); err != nil {
				return err
			}
			for _, subject := range basis.Subjects {
				for _, role := range basis.Roles {
					key := memberKey{basis.Key(), subject.Kind, subject.Issuer, subject.ID, role}
					if retained[key] {
						continue
					}
					a, err := q.InsertPermissionAssignment(ctx, custodydb.InsertPermissionAssignmentParams{StreamID: s.ID, BasisKey: basis.Key(), SubjectKind: subject.Kind, Issuer: subject.Issuer, SubjectID: subject.ID, Role: role, BasisDigest: basis.Resource.SpecDigest[:], ActivationAuditID: id(record.ID)})
					if err != nil {
						return err
					}
					record.Changes = append(record.Changes, change(a, custodydb.PermissionBasis{Kind: basis.Resource.Kind, Uid: basis.Resource.UID, ScopeDigest: basis.ScopeDigest[:]}, "added"))
				}
			}
		}
		if err = insertAuthority(ctx, q, record); err != nil {
			return err
		}
		if !s.InitialAuditID.Valid {
			if err = q.InitializePermissionStream(ctx, custodydb.InitializePermissionStreamParams{ID: s.ID, InitialAuditID: id(record.ID)}); err != nil {
				return err
			}
		}
		if err = q.InsertPermissionAcceptance(ctx, custodydb.InsertPermissionAcceptanceParams{RequestID: id(b.RequestID), StreamID: s.ID, Epoch: s.Epoch, Sequence: record.Sequence, RequestDigest: requestDigest, AuditID: id(record.ID), Assignments: int32(len(wanted)), Retired: int32(retired)}); err != nil {
			return err
		}
		if err = q.UpdatePermissionStream(ctx, custodydb.UpdatePermissionStreamParams{ID: s.ID, Sequence: record.Sequence, ProjectionDigest: projected, ObservedAt: ts(b.ObservedAt), FreshUntil: ts(permissionStreamUntil(b.ObservedAt))}); err != nil {
			return err
		}
		if err = liveStream(ctx, q, s, requested); err != nil {
			return err
		}
		n, err = q.CurrentTime(ctx)
		if err != nil {
			return err
		}
		if err = validBatch(b, n.Time); err != nil {
			return err
		}
		if !s.InitialAuditID.Valid && !b.Initial.Valid(n.Time) {
			return cfg.ErrDenied
		}
		s.InitialAuditID = id(record.ID)
		s.Sequence = record.Sequence
		out = cfg.PermissionAcceptance{PermissionFence: fence(s), AuditID: record.ID, Assignments: len(wanted), Retired: retired}
		return nil
	})
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
		if s.Suspended || s.Sequence != b.ExpectedSequence || !bytes.Equal(s.ProjectionDigest, projected) || !b.ObservedAt.After(s.ObservedAt.Time) {
			return cfg.ErrChanged
		}
		n, err := q.CurrentTime(ctx)
		if err != nil {
			return err
		}
		if err = validBatch(b, n.Time); err != nil {
			return err
		}
		if err = q.UpdatePermissionStream(ctx, custodydb.UpdatePermissionStreamParams{ID: s.ID, Sequence: s.Sequence, ProjectionDigest: s.ProjectionDigest, ObservedAt: ts(b.ObservedAt), FreshUntil: ts(permissionStreamUntil(b.ObservedAt))}); err != nil {
			return err
		}
		n, err = q.CurrentTime(ctx)
		if err != nil {
			return err
		}
		if !n.Time.Before(s.LeaseUntil.Time) {
			return cfg.ErrChanged
		}
		return validBatch(b, n.Time)
	})
}

func (p *Permissions) Permissions(ctx context.Context, target authorization.Target) (authorization.Projection, error) {
	var out authorization.Projection
	if !target.Valid() {
		return out, cfg.ErrInvalid
	}
	err := p.transaction(ctx, func(q *custodydb.Queries) error {
		s, err := q.SharePermissionStream(ctx, id(p.root))
		if err != nil {
			return err
		}
		out, err = permissionProjection(ctx, q, s, target)
		return err
	})
	if err != nil {
		return authorization.Projection{}, err
	}
	return out, nil
}

// permissionProjection runs with the permission stream already locked. It may
// be reused by named admission facets after taking their remaining SQL locks.
func permissionProjection(ctx context.Context, q *custodydb.Queries, s custodydb.PermissionStream, target authorization.Target) (authorization.Projection, error) {
	var out authorization.Projection
	n, err := q.CurrentTime(ctx)
	if err != nil {
		return authorization.Projection{}, err
	}
	if !s.InitialAuditID.Valid || s.Suspended || !n.Time.Before(s.LeaseUntil.Time) || !identity.Fresh(s.ObservedAt.Time, s.FreshUntil.Time, n.Time, authorization.PermissionObservationInterval) || len(s.ProjectionDigest) != 32 {
		return authorization.Projection{}, cfg.ErrUnavailable
	}
	reset, err := q.ReadAuthorityAudit(ctx, s.Epoch)
	if err != nil {
		return authorization.Projection{}, err
	}
	initial, err := q.ReadAuthorityAudit(ctx, s.InitialAuditID)
	if err != nil {
		return authorization.Projection{}, err
	}
	rows, err := q.SelectPermissionAssignments(ctx, custodydb.SelectPermissionAssignmentsParams{StreamID: s.ID, ClusterID: id(target.ClusterID), NamespaceUid: target.NamespaceUID, Column4: target.WorkloadUID})
	if err != nil {
		return authorization.Projection{}, err
	}
	if len(rows) > 256 {
		return authorization.Projection{}, cfg.ErrLimit
	}
	until := identity.Earlier(s.FreshUntil.Time, s.LeaseUntil.Time)
	out = authorization.Projection{Target: target, Revision: identity.Revision{UID: uid(s.Epoch), Generation: s.Sequence}, ObservedAt: s.ObservedAt.Time, FreshUntil: until, DeniesComplete: true, DeniesObservedAt: s.ObservedAt.Time, DeniesFreshUntil: until}
	copy(out.Revision.Digest[:], s.ProjectionDigest)
	rootAudited := currentAuthorityAudit(reset, s.ID, s.Epoch) && currentAuthorityAudit(initial, s.ID, s.InitialAuditID)
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
		} else if rootAudited &&
			currentAuthorityAuditReceipt(uid(s.ID), uid(a.ActivationAuditID), a.AcknowledgedAt.Valid, a.ObjectKey, a.ObjectVersion, a.ObjectEtag, a.ObjectBytes, a.ObjectSha256) {
			out.Allows = append(out.Allows, row)
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
