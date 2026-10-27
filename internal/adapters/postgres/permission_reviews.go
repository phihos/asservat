package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"time"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	authapp "asservat.local/asservat/internal/application/authorization"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	"asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/domain/targets"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// maxReviewAssignments bounds the current per-principal assignments of one
// decision-time source; a principal beyond it gains nothing from the source.
const maxReviewAssignments = 4096

// acceptReviewSources applies a batch's decision-time sources within its
// acceptance (ADR-245). An equivalent source version keeps its per-principal
// assignments and its original accepting event; any other change, and a
// source absent from a batch whose source list was read, retires them. An
// unreadable source list keeps every row without renewing it, so none
// grants until a current list is accepted.
func acceptReviewSources(ctx context.Context, q *custodydb.Queries, s custodydb.PermissionStream, b cfg.PermissionBatch, record *audit.AuthorityRecord) error {
	rows, err := q.ListPermissionReviewSources(ctx, s.ID)
	if err != nil {
		return err
	}
	if len(rows) > 64 {
		return cfg.ErrLimit
	}
	next := map[string]cfg.ReviewSource{}
	for _, r := range b.ReviewSources {
		next[r.Resource.UID] = r
	}
	kept := map[string]bool{}
	upsert := func(r cfg.ReviewSource, accepted string) error {
		data, err := json.Marshal(r)
		if err != nil {
			return err
		}
		return q.UpsertPermissionReviewSource(ctx, custodydb.UpsertPermissionReviewSourceParams{StreamID: s.ID, Uid: r.Resource.UID, Epoch: id(b.Epoch), SeenSequence: record.Sequence, Generation: r.Resource.Generation, ResourceVersion: r.Resource.ResourceVersion, SpecDigest: r.Resource.SpecDigest[:], AuthorityDigest: reviewAuthorityDigest(r), ClusterID: id(r.ClusterID), Role: r.Role, SourceJson: data, AcceptedAuditID: id(accepted)})
	}
	for _, row := range rows {
		n, present := next[row.Uid]
		if !present && b.SourcesUnavailable {
			continue
		}
		var old cfg.ReviewSource
		if present && json.Unmarshal(row.SourceJson, &old) == nil && cfg.EquivalentReview(old, n) {
			if err = upsert(n, uid(row.AcceptedAuditID)); err != nil {
				return err
			}
			kept[row.Uid] = true
			continue
		}
		retired, err := q.RetirePermissionReviewSource(ctx, custodydb.RetirePermissionReviewSourceParams{StreamID: s.ID, SourceUid: row.Uid, RetirementAuditID: id(record.ID)})
		if err != nil {
			return err
		}
		if retired > 0 {
			record.ReviewRetirements = append(record.ReviewRetirements, audit.ReviewRetirement{SourceUID: row.Uid, Retired: retired})
		}
		if !present {
			if err = q.DeletePermissionReviewSource(ctx, custodydb.DeletePermissionReviewSourceParams{StreamID: s.ID, Uid: row.Uid}); err != nil {
				return err
			}
		}
	}
	for _, r := range b.ReviewSources {
		if kept[r.Resource.UID] {
			continue
		}
		if err = upsert(r, record.ID); err != nil {
			return err
		}
	}
	record.ReviewSources = slices.Clone(b.ReviewSources)
	return nil
}

// reviewAuthorityDigest identifies whose access a review source confers
// (ReviewSource.SameAuthority's fields); it is the capacity scope digest.
func reviewAuthorityDigest(r cfg.ReviewSource) []byte {
	return digest(struct {
		Format                                string
		Type, ClusterID, Role, Check, Mapping string
	}{"permission-review-authority/v1", r.Type, r.ClusterID, r.Role, r.Check, r.IdentityMappingRef})
}

// retireReviewStream retires every decision-time assignment of a stream whose
// trust root changed, and forgets its sources.
func retireReviewStream(ctx context.Context, q *custodydb.Queries, root string, record *audit.AuthorityRecord) error {
	rows, err := q.ListPermissionReviewSources(ctx, id(root))
	if err != nil {
		return err
	}
	for _, row := range rows {
		retired, err := q.RetirePermissionReviewSource(ctx, custodydb.RetirePermissionReviewSourceParams{StreamID: id(root), SourceUid: row.Uid, RetirementAuditID: id(record.ID)})
		if err != nil {
			return err
		}
		if retired > 0 {
			record.ReviewRetirements = append(record.ReviewRetirements, audit.ReviewRetirement{SourceUID: row.Uid, Retired: retired})
		}
	}
	// A source row without a current assignment may remain from an older
	// stream generation; retire anything left and forget the sources.
	if _, err = q.RetirePermissionReviewStream(ctx, custodydb.RetirePermissionReviewStreamParams{StreamID: id(root), RetirementAuditID: id(record.ID)}); err != nil {
		return err
	}
	return q.DeletePermissionReviewSources(ctx, id(root))
}

// AccessReviews is the hub's decision-time review store (ADR-245). It reads
// only the permission stream's own review tables and the caller's own
// recorded targets; it never reads evidence.
type AccessReviews struct {
	ledger *Ledger
	root   string
}

var _ authapp.AccessReviewStore = (*AccessReviews)(nil)

func NewAccessReviews(ctx context.Context, pool *pgxpool.Pool, root string) (*AccessReviews, error) {
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
	return &AccessReviews{ledger: l, root: root}, nil
}

// currentReviewStream is the stream under a share lock, current for reviews.
func currentReviewStream(ctx context.Context, q *custodydb.Queries, root string) (custodydb.PermissionStream, error) {
	s, err := q.SharePermissionStream(ctx, id(root))
	if err != nil {
		return s, err
	}
	n, err := q.CurrentTime(ctx)
	if err != nil {
		return s, err
	}
	if !s.InitialAuditID.Valid || s.Suspended || !n.Time.Before(s.LeaseUntil.Time) || !identity.Fresh(s.ObservedAt.Time, s.FreshUntil.Time, n.Time, authorization.PermissionObservationInterval) {
		return s, cfg.ErrUnavailable
	}
	return s, nil
}

func (r *AccessReviews) ReviewSources(ctx context.Context, cluster string) ([]cfg.ReviewSource, error) {
	var out []cfg.ReviewSource
	if r == nil || !authorization.UUID(cluster) {
		return nil, cfg.ErrInvalid
	}
	err := permissionError(r.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		s, err := currentReviewStream(ctx, q, r.root)
		if err != nil {
			return err
		}
		rows, err := q.CurrentPermissionReviewSources(ctx, custodydb.CurrentPermissionReviewSourcesParams{StreamID: s.ID, Epoch: s.Epoch, SeenSequence: s.Sequence, ClusterID: id(cluster)})
		if err != nil {
			return err
		}
		if len(rows) > cfg.MaxReviewSourcesPerCluster {
			return cfg.ErrLimit
		}
		for _, row := range rows {
			var src cfg.ReviewSource
			if !currentAuthorityAuditReceipt(uid(s.ID), uid(row.AcceptedAuditID), row.AcknowledgedAt.Valid, row.ObjectKey, row.ObjectVersion, row.ObjectEtag, row.ObjectBytes, row.ObjectSha256) {
				continue
			}
			if json.Unmarshal(row.SourceJson, &src) != nil || !src.Valid() || src.Resource.UID != row.Uid || src.ClusterID != cluster || src.Resource.Generation != row.Generation {
				return cfg.ErrUnavailable
			}
			out = append(out, src)
		}
		return nil
	}))
	if err != nil {
		return nil, err
	}
	return out, nil
}

func recordedTarget(row custodydb.PermissionReviewDecision, source string) authapp.RecordedReview {
	return authapp.RecordedReview{SourceUID: source, Target: targets.Request{ClusterID: uid(row.ClusterID), Namespace: cfg.NamespaceRef{Name: row.NamespaceName, UID: row.NamespaceUid}, Workload: cfg.WorkloadRef{Kind: row.WorkloadKind, Name: row.WorkloadName, UID: row.WorkloadUid}, PodName: row.PodName, PodUID: row.PodUid}}
}

func (r *AccessReviews) RecordedReviews(ctx context.Context, p identity.Principal, target authorization.Target) ([]authapp.RecordedReview, error) {
	var out []authapp.RecordedReview
	if r == nil || p.Kind != identity.Human || !target.Valid() {
		return nil, cfg.ErrInvalid
	}
	err := permissionError(r.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		rows, err := q.SelectRecordedReviews(ctx, custodydb.SelectRecordedReviewsParams{StreamID: id(r.root), Issuer: p.Issuer, SubjectID: p.Subject, ClusterID: id(target.ClusterID), NamespaceUid: target.NamespaceUID, WorkloadUid: target.WorkloadUID, PodUid: target.PodUID})
		for _, row := range rows {
			out = append(out, recordedTarget(custodydb.PermissionReviewDecision{AssignmentID: row.AssignmentID, PodUid: row.PodUid, ClusterID: row.ClusterID, NamespaceName: row.NamespaceName, NamespaceUid: row.NamespaceUid, WorkloadKind: row.WorkloadKind, WorkloadName: row.WorkloadName, WorkloadUid: row.WorkloadUid, PodName: row.PodName}, row.SourceUid))
		}
		return err
	}))
	return out, err
}

func (r *AccessReviews) RecordedCaptureReviews(ctx context.Context, p identity.Principal, capture string) ([]authapp.RecordedReview, error) {
	var out []authapp.RecordedReview
	if r == nil || p.Kind != identity.Human || !authorization.UUID(capture) {
		return nil, cfg.ErrInvalid
	}
	err := permissionError(r.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		rows, err := q.SelectRecordedCaptureReviews(ctx, custodydb.SelectRecordedCaptureReviewsParams{StreamID: id(r.root), ID: id(capture), Issuer: p.Issuer, SubjectID: p.Subject})
		for _, row := range rows {
			out = append(out, recordedTarget(custodydb.PermissionReviewDecision{AssignmentID: row.AssignmentID, PodUid: row.PodUid, ClusterID: row.ClusterID, NamespaceName: row.NamespaceName, NamespaceUid: row.NamespaceUid, WorkloadKind: row.WorkloadKind, WorkloadName: row.WorkloadName, WorkloadUid: row.WorkloadUid, PodName: row.PodName}, row.SourceUid))
		}
		return err
	}))
	return out, err
}

func (r *AccessReviews) RecordedPreviewReviews(ctx context.Context, p identity.Principal, preview string) ([]authapp.RecordedReview, error) {
	var out []authapp.RecordedReview
	if r == nil || p.Kind != identity.Human || !authorization.UUID(preview) {
		return nil, cfg.ErrInvalid
	}
	err := permissionError(r.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		rows, err := q.SelectRecordedPreviewReviews(ctx, custodydb.SelectRecordedPreviewReviewsParams{StreamID: id(r.root), ID: id(preview), ActorKey: previewActorKey(p), Issuer: p.Issuer, SubjectID: p.Subject})
		for _, row := range rows {
			out = append(out, recordedTarget(custodydb.PermissionReviewDecision{AssignmentID: row.AssignmentID, PodUid: row.PodUid, ClusterID: row.ClusterID, NamespaceName: row.NamespaceName, NamespaceUid: row.NamespaceUid, WorkloadKind: row.WorkloadKind, WorkloadName: row.WorkloadName, WorkloadUid: row.WorkloadUid, PodName: row.PodName}, row.SourceUid))
		}
		return err
	}))
	return out, err
}

// RecordReview records one outcome under the stream's share lock and the
// source's row lock, so a concurrent acceptance that retires the source
// either precedes it (nothing is recorded) or follows it (the new decision is
// retired with the assignment). An allowed review mints the principal's
// assignment once and records the Pod; a refusal only ends an existing
// decision of that Pod.
func (r *AccessReviews) RecordReview(ctx context.Context, d authapp.ReviewDecision) error {
	p, t, src := d.Principal, d.Target, d.Source
	if r == nil || p.Kind != identity.Human || !identity.Text(p.Issuer, 2048) || !identity.Text(p.Subject, 256) || !t.Valid() || !src.Valid() || src.ClusterID != t.ClusterID || d.DecidedAt.IsZero() {
		return cfg.ErrInvalid
	}
	return permissionError(r.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		s, err := currentReviewStream(ctx, q, r.root)
		if err != nil {
			return err
		}
		row, err := q.LockPermissionReviewSource(ctx, custodydb.LockPermissionReviewSourceParams{StreamID: s.ID, Uid: src.Resource.UID})
		if err != nil {
			return err
		}
		if row.Epoch != s.Epoch || row.SeenSequence != s.Sequence || row.Generation != src.Resource.Generation || string(row.SpecDigest) != string(src.Resource.SpecDigest[:]) {
			return cfg.ErrChanged
		}
		n, err := q.CurrentTime(ctx)
		if err != nil {
			return err
		}
		decided := d.DecidedAt.UTC().Truncate(time.Microsecond)
		if decided.After(n.Time) {
			decided = n.Time.UTC().Truncate(time.Microsecond)
		}
		if n.Time.Sub(decided) > 5*time.Second {
			return cfg.ErrChanged
		}
		key := custodydb.CurrentPermissionReviewAssignmentParams{StreamID: s.ID, SourceUid: src.Resource.UID, Issuer: p.Issuer, SubjectID: p.Subject}
		a, err := q.CurrentPermissionReviewAssignment(ctx, key)
		if !d.Allowed {
			if errors.Is(err, pgx.ErrNoRows) {
				return nil
			}
			if err != nil {
				return err
			}
			prior, err := q.GetPermissionReviewDecision(ctx, custodydb.GetPermissionReviewDecisionParams{AssignmentID: a.ID, PodUid: t.PodUID})
			if errors.Is(err, pgx.ErrNoRows) {
				return nil
			}
			if err != nil {
				return err
			}
			if err = q.EndPermissionReviewDecision(ctx, custodydb.EndPermissionReviewDecisionParams{AssignmentID: a.ID, PodUid: t.PodUID, DecidedAt: ts(decided)}); err != nil {
				return err
			}
			if !prior.FreshUntil.Time.After(prior.DecidedAt.Time) {
				return nil // already refused: no change
			}
			ended := decided
			if prior.DecidedAt.Time.After(ended) {
				ended = prior.DecidedAt.Time
			}
			return recordReviewChange(ctx, q, s, n.Time, audit.ReviewRevoked, reviewOutcome(d), src, p, uid(a.ID), t, ended, ended)
		}
		until := src.ReviewDecisionUntil(decided)
		if !n.Time.Before(until) {
			return cfg.ErrChanged
		}
		if errors.Is(err, pgx.ErrNoRows) {
			var count int64
			if count, err = q.CountPermissionReviewAssignments(ctx, custodydb.CountPermissionReviewAssignmentsParams{StreamID: s.ID, SourceUid: src.Resource.UID}); err != nil {
				return err
			}
			if count >= maxReviewAssignments {
				return cfg.ErrLimit
			}
			if err = q.InsertPermissionReviewAssignment(ctx, custodydb.InsertPermissionReviewAssignmentParams{StreamID: s.ID, SourceUid: src.Resource.UID, Issuer: p.Issuer, SubjectID: p.Subject, Role: src.Role, BasisDigest: src.Resource.SpecDigest[:]}); err != nil {
				return err
			}
			a, err = q.CurrentPermissionReviewAssignment(ctx, key)
		}
		if err != nil {
			return err
		}
		if a.Role != src.Role {
			return cfg.ErrChanged
		}
		change := audit.ReviewGranted
		prior, err := q.GetPermissionReviewDecision(ctx, custodydb.GetPermissionReviewDecisionParams{AssignmentID: a.ID, PodUid: t.PodUID})
		switch {
		case errors.Is(err, pgx.ErrNoRows):
		case err != nil:
			return err
		case prior.FreshUntil.Time.After(prior.DecidedAt.Time):
			change = "" // confirms the current allow: SQL only
		default:
			change = audit.ReviewRestored
		}
		if err = q.UpsertPermissionReviewDecision(ctx, custodydb.UpsertPermissionReviewDecisionParams{AssignmentID: a.ID, PodUid: t.PodUID, ClusterID: id(t.ClusterID), NamespaceName: t.Namespace.Name, NamespaceUid: t.Namespace.UID, WorkloadKind: t.Workload.Kind, WorkloadName: t.Workload.Name, WorkloadUid: t.Workload.UID, PodName: t.PodName, DecidedAt: ts(decided), FreshUntil: ts(until)}); err != nil {
			return err
		}
		if err = q.PrunePermissionReviewDecisions(ctx, a.ID); err != nil {
			return err
		}
		if change == "" {
			return nil
		}
		return recordReviewChange(ctx, q, s, n.Time, change, reviewOutcome(d), src, p, uid(a.ID), t, decided, until)
	}))
}

func reviewOutcome(d authapp.ReviewDecision) string {
	if d.Allowed {
		return "Allowed"
	}
	if identity.Text(d.Outcome, 32) {
		return d.Outcome
	}
	return "Unavailable"
}

// recordReviewChange appends one immutable decision-change event to the
// stream's authority audit outbox (REQ-PER-006, ADR-245). The hub-worker's
// authority publisher encrypts and acknowledges it like every other event.
// A review that confirms the current state writes no event.
func recordReviewChange(ctx context.Context, q *custodydb.Queries, s custodydb.PermissionStream, now time.Time, change, outcome string, src cfg.ReviewSource, p identity.Principal, assignment string, t targets.Request, decided, until time.Time) error {
	c := audit.ReviewDecisionChange{Change: change, Outcome: outcome, SourceUID: src.Resource.UID, SourceGeneration: src.Resource.Generation, SourceDigest: src.Resource.SpecDigest, IdentityMapping: src.IdentityMappingRef,
		Issuer: p.Issuer, Subject: p.Subject, AssignmentID: assignment, ClusterID: t.ClusterID, NamespaceUID: t.Namespace.UID, WorkloadUID: t.Workload.UID, PodUID: t.PodUID, DecidedAt: decided.UTC(), FreshUntil: until.UTC()}
	var input artifact.Digest
	copy(input[:], digest(c))
	return insertAuthority(ctx, q, audit.AuthorityRecord{ID: uuid.NewString(), RootID: uid(s.ID), Epoch: uid(s.Epoch), Sequence: s.Sequence, Kind: "permission-review", InputDigest: input, CreatedAt: now.UTC(), Review: &c})
}
