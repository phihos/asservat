package postgres

import (
	"bytes"
	"context"
	"errors"
	"time"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	auditapp "asservat.local/asservat/internal/application/audit"
	app "asservat.local/asservat/internal/application/capture"
	"asservat.local/asservat/internal/application/planning"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/identity"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

// A parent is control provenance only. No parent artifact, attempt or execution
// is fabricated; all custody and writer effects remain real child operations.
func recordingGroupAccepted(ctx context.Context, q *custodydb.Queries, row custodydb.RecordingSaveGroup) (value.Accepted, error) {
	var out value.Accepted
	var scope artifact.Digest
	copy(scope[:], row.ScopeDigest)
	parsed, err := planning.ReadContextScopeIdentity(row.ScopeJson, scope)
	if err != nil || parsed.CaptureID != uid(row.ID) || parsed.Requester == nil || len(parsed.Targets) != len(row.ChildIds) || len(row.ChildIds) < 2 || len(row.ChildIds) > 16 {
		return out, value.ErrUnavailable
	}
	rows, err := q.ReadRecordingSaveGroupChildren(ctx, custodydb.ReadRecordingSaveGroupChildrenParams{RootID: row.RootID, GroupID: row.ID})
	if err != nil || len(rows) != len(row.ChildIds) {
		return out, value.ErrUnavailable
	}
	return recordingGroupAcceptedRows(row, rows)
}

func recordingGroupAcceptedRows(row custodydb.RecordingSaveGroup, rows []custodydb.ContextCapture) (value.Accepted, error) {
	var out value.Accepted
	var scope artifact.Digest
	copy(scope[:], row.ScopeDigest)
	parsed, err := planning.ReadContextScopeIdentity(row.ScopeJson, scope)
	if err != nil || parsed.CaptureID != uid(row.ID) || parsed.Requester == nil || len(rows) != len(row.ChildIds) || len(parsed.Targets) != len(rows) || len(rows) < 2 || len(rows) > 16 {
		return out, value.ErrUnavailable
	}
	group := &value.RecordingSaveGroupAccepted{Children: make([]value.Accepted, 0, len(rows))}
	state := value.IntentAudited
	for n, child := range rows {
		accepted, err := admittedRecord(child)
		if err != nil || child.ID != row.ChildIds[n] || child.GroupID != row.ID || !child.GroupOrdinal.Valid || int(child.GroupOrdinal.Int16) != n || !bytes.Equal(child.ScopeDigest, row.ScopeDigest) || !bytes.Equal(child.ScopeJson, row.ScopeJson) || !child.CreatedAt.Time.Equal(row.AcceptedAt.Time) || child.Deadline.Time.After(row.Deadline.Time) || accepted.Expectation.Snapshot == nil || !accepted.Expectation.Snapshot.T0.Equal(row.AcceptedAt.Time) {
			return value.Accepted{}, value.ErrUnavailable
		}
		intent, err := captureIntent(child)
		if err != nil || intent.Group == nil || intent.Group.ChildIndex != n || intent.Target != parsed.Targets[n] || intent.Requester() != *parsed.Requester {
			return value.Accepted{}, value.ErrUnavailable
		}
		if n == 0 {
			group.CaseID = accepted.Expectation.CaseID
		} else if group.CaseID != accepted.Expectation.CaseID {
			return value.Accepted{}, value.ErrUnavailable
		}
		if accepted.State != value.IntentAudited {
			state = value.PendingAudit
		}
		group.Children = append(group.Children, accepted)
	}
	out = value.Accepted{Group: group, CaptureID: uid(row.ID), State: state, ScopeDigest: scope, CreatedAt: row.AcceptedAt.Time.UTC(), Deadline: row.Deadline.Time.UTC()}
	copy(out.SubmissionDigest[:], row.SubmissionDigest)
	return out, nil
}

func findRecordingGroupRequest(ctx context.Context, q *custodydb.Queries, in value.ReplayQuery) (custodydb.RecordingSaveGroup, bool, error) {
	row, err := q.FindRecordingSaveGroup(ctx, custodydb.FindRecordingSaveGroupParams{RootID: id(in.RootID), RequestKey: contextRequestKey(in.Identity.Principal, in.IdempotencyKey)})
	if err == nil {
		return row, true, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return row, false, err
	}
	row, err = q.FindRecordingSaveGroupByPreview(ctx, custodydb.FindRecordingSaveGroupByPreviewParams{RootID: id(in.RootID), PreviewID: id(in.PreviewID)})
	if errors.Is(err, pgx.ErrNoRows) {
		return row, false, nil
	}
	if err != nil {
		return row, false, err
	}
	var digest artifact.Digest
	copy(digest[:], row.ScopeDigest)
	scope, err := planning.ReadContextScopeIdentity(row.ScopeJson, digest)
	if err != nil || scope.Requester == nil {
		return row, false, value.ErrUnavailable
	}
	return row, *scope.Requester == in.Identity.Principal, nil
}

// AdmitRecordingSaveGroup composes existing child admission under one original
// root transaction. A later child's refusal rolls back the entire selection.
func (s *ContextAdmissions) AdmitRecordingSaveGroup(ctx context.Context, in value.RecordingSaveGroupAdmission) (value.Accepted, error) {
	began := time.Now()
	defer auditapp.MarkStep(ctx, "ga-total", began)
	var out value.Accepted
	p := in.Preview.Clone()
	if s == nil || s.ledger == nil || ctx == nil || in.RootID != s.root || p.RootID != s.root || p.Group == nil || !app.ValidContextPreview(p) || !identity.Text(in.IdempotencyKey, 128) || in.SubmissionDigest != app.ContextRequestDigest(p.ID) || len(in.Children) != len(p.Group.Children) {
		return out, value.ErrInvalid
	}
	children := append([]value.Admission(nil), in.Children...)
	for _, child := range children {
		if !validAdmission(child) || !app.ReviewedRecordingSaveGroupChild(p, child) || child.Storage.AllocationID != p.Storage.AllocationID || child.CaseID != p.CaseID || child.RecordingSave == nil {
			return out, value.ErrInvalid
		}
	}
	topology, err := s.retention.observe(ctx, children[0].Plan.Input.Target.Target().ClusterID)
	if err != nil {
		return out, captureError(err)
	}
	err = s.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		recovery, err := s.recovery.lock(ctx, q, s.root, in.Recovery)
		if err != nil {
			return err
		}
		stream, err := q.LockPermissionStream(ctx, id(s.root))
		if err != nil {
			return err
		}
		human := children[0].RecordingSave.Initiator.VerifiedIdentity
		query := value.ReplayQuery{RootID: s.root, PreviewID: p.ID, IdempotencyKey: in.IdempotencyKey, SubmissionDigest: in.SubmissionDigest, Identity: human, Recovery: in.Recovery}
		if old, found, err := findRecordingGroupRequest(ctx, q, query); err != nil {
			return err
		} else if found {
			if !bytes.Equal(old.SubmissionDigest, in.SubmissionDigest[:]) || !bytes.Equal(old.ScopeDigest, p.ScopeDigest[:]) {
				return value.ErrConflict
			}
			out, err = recordingGroupAccepted(ctx, q, old)
			if err != nil {
				return err
			}
			until, err := authorizeRecordingGroupReplay(ctx, q, stream, recovery, s.root, s.recovery, query, out)
			if err != nil {
				return err
			}
			out.Replay, out.MetadataValidUntil = true, until
			return ctx.Err()
		}
		if _, found, err := findContextRequest(ctx, q, query); err != nil {
			return err
		} else if found {
			return value.ErrConflict
		}
		row, err := q.FindContextPreview(ctx, custodydb.FindContextPreviewParams{RootID: id(s.root), ID: id(p.ID), ActorKey: previewActorKey(p.Actor)})
		if err != nil || row.ClosedAt.Valid {
			return value.ErrChanged
		}
		protected, err := previewRecord(row)
		if err != nil || protected.Group == nil || !bytes.Equal(digest(protected), digest(p)) {
			return value.ErrChanged
		}
		if err := checkContextPreviewFence(ctx, q, s.root, p.ID, p.Actor); err != nil {
			return err
		}
		if err := currentPreview(ctx, q, protected); err != nil {
			return err
		}
		permissions := newRecordingGroupPermissions(q, stream)
		reservations := make([]*policyCaptureReservation, len(children))
		for n, child := range children {
			if _, err := s.currentCaptureEligibilityWithPermissions(ctx, q, stream, recovery, child, permissions); err != nil {
				return err
			}
			reservations[n], err = lockPolicyCaptureReservation(ctx, q, recovery, child, s.recovery.installationID())
			if err != nil || reservations[n] == nil || reservations[n].manual == nil {
				if err != nil {
					return err
				}
				return value.ErrDenied
			}
		}
		auditapp.MarkStep(ctx, "ga-prefix", began)
		clock, err := q.CurrentTime(ctx)
		if err != nil {
			return err
		}
		acceptedAt := clock.Time.UTC()
		if in.RequestBounds != nil && (!in.RequestBounds.Valid(acceptedAt) || in.RequestBounds.Requester != human.Principal) {
			return value.ErrDenied
		}
		var deadline time.Time
		ids := make([]pgtype.UUID, len(children))
		for n := range children {
			r := reservations[n]
			r.manual.acceptedAt = acceptedAt
			until := r.manual.authorityUntil
			if children[n].RepeatedFrom != nil {
				until = identity.Earlier(until, children[n].RepeatedFrom.ExpiresAt)
			}
			if in.RequestBounds != nil {
				children[n].Plan, children[n].Registration, err = planning.ReanchorRecordingSaveGroup(children[n].Plan, children[n].Registration, acceptedAt, until, *in.RequestBounds)
			} else {
				children[n].Plan, children[n].Registration, err = planning.ReanchorRecordingSave(children[n].Plan, children[n].Registration, acceptedAt, until)
			}
			if err != nil || children[n].Plan.Input.Deadline.After(r.processingLimit) {
				return value.ErrDenied
			}
			if children[n].Plan.Input.Deadline.After(deadline) {
				deadline = children[n].Plan.Input.Deadline
			}
			ids[n] = id(children[n].Plan.Input.CaptureID)
		}
		first := reservations[0].manual
		header, err := q.InsertRecordingSaveGroup(ctx, custodydb.InsertRecordingSaveGroupParams{ID: id(p.CaptureID), RootID: id(s.root), PreviewID: id(p.ID), RequestKey: contextRequestKey(p.Actor, in.IdempotencyKey), SubmissionDigest: in.SubmissionDigest[:], ScopeDigest: p.ScopeDigest[:], ScopeJson: p.CanonicalScope, PolicyUid: p.Group.PolicyUID, AcceptanceID: first.acceptanceID, AllocationID: id(p.Storage.AllocationID), ChildIds: ids, AcceptedAt: ts(acceptedAt), Deadline: ts(deadline)})
		if err != nil {
			return err
		}
		if err := first.spendExecutionAndWindow(ctx, q, s.root, children[0]); err != nil {
			return err
		}
		for n, child := range children {
			if err := func() error {
				defer auditapp.MarkStep(ctx, "ga-child", time.Now())
				r := reservations[n]
				// Output and applicable grant starts remain per real source. The
				// one policy incident debit above cannot authorize free children.
				spent, err := q.SpendPolicyCollectedBytes(ctx, custodydb.SpendPolicyCollectedBytesParams{RootID: id(s.root), ID: first.acceptanceID, Bytes: r.bytes})
				if err != nil {
					return err
				}
				if spent != 1 {
					return value.ErrCapacity
				}
				if r.grant.Valid {
					spent, err = q.SpendPolicyGrantCapture(ctx, custodydb.SpendPolicyGrantCaptureParams{RootID: id(s.root), ID: r.grant, Bytes: r.bytes})
					if err != nil {
						return err
					}
					if spent != 1 {
						return value.ErrCapacity
					}
				}
				if _, err := s.admitContextInTransaction(ctx, q, p.ID, child, topology, &contextAdmissionGroupOptions{Recovery: recovery, Stream: stream, Preview: protected, PolicyReservation: r, RequestBounds: in.RequestBounds, Permissions: permissions}); err != nil {
					return err
				}
				if err := r.manual.insertReservation(ctx, q, s.root, child.Plan.Input.CaptureID, child, r.grant, r.bytes); err != nil {
					return err
				}
				return nil
			}(); err != nil {
				return err
			}
		}
		defer auditapp.MarkStep(ctx, "ga-metadata", time.Now())
		out, err = recordingGroupAccepted(ctx, q, header)
		if err != nil {
			return err
		}
		out.MetadataValidUntil, err = authorizeRecordingGroupReplayWithPermissions(ctx, q, stream, recovery, s.root, s.recovery, query, out, permissions)
		return err
	})
	return out, captureError(err)
}

func authorizeRecordingGroupReplay(ctx context.Context, q *custodydb.Queries, stream custodydb.PermissionStream, recovery custodydb.FleetCurrentTrust, root string, guard *RecoveryTransactionGuard, query value.ReplayQuery, accepted value.Accepted) (time.Time, error) {
	return authorizeRecordingGroupReplayWithPermissions(ctx, q, stream, recovery, root, guard, query, accepted, nil)
}

func authorizeRecordingGroupReplayWithPermissions(ctx context.Context, q *custodydb.Queries, stream custodydb.PermissionStream, recovery custodydb.FleetCurrentTrust, root string, guard *RecoveryTransactionGuard, query value.ReplayQuery, accepted value.Accepted, permissions *recordingGroupPermissions) (time.Time, error) {
	until := contextMetadataDeadline(ctx, query.Identity.ValidUntil, query.Recovery.FreshUntil)
	if accepted.Group == nil || len(accepted.Group.Children) < 2 {
		return time.Time{}, value.ErrUnavailable
	}
	first := accepted.Group.Children[0].Expectation
	if first.SourceSnapshotManifest == nil {
		return time.Time{}, value.ErrUnavailable
	}
	scope, err := planning.ReadContextScopeIdentity(first.SourceSnapshotManifest.CanonicalScope, accepted.ScopeDigest)
	if err != nil || scope.Requester == nil || *scope.Requester != query.Identity.Principal {
		return time.Time{}, value.ErrDenied
	}
	for _, child := range accepted.Group.Children {
		e := child.Expectation
		target := authorization.Target{ClusterID: e.Registration.Location.ClusterID, NamespaceUID: e.NamespaceUID, WorkloadUID: e.WorkloadUID, PodUID: e.PodUID}
		projection, err := permissions.read(ctx, q, stream, target)
		if err != nil {
			return time.Time{}, err
		}
		now, err := q.CurrentTime(ctx)
		if err != nil {
			return time.Time{}, err
		}
		rights := authorization.ContextEligibility(query.Identity, projection, target, now.Time)
		if !rights.Eligible || !app.ValidReplayQuery(query, now.Time) {
			return time.Time{}, value.ErrDenied
		}
		until = identity.Earlier(until, rights.ValidUntil)
	}
	if err := guard.check(ctx, q, recovery, root, query.Recovery); err != nil {
		return time.Time{}, err
	}
	now, err := q.CurrentTime(ctx)
	if err != nil || !now.Time.Before(until) || !app.ValidReplayQuery(query, now.Time) {
		return time.Time{}, value.ErrDenied
	}
	return until, ctx.Err()
}
