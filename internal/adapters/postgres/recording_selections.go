package postgres

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	app "asservat.local/asservat/internal/application/capture"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/identity"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

var _ app.RecordingSelectionStore = (*ContextPreviews)(nil)
var _ app.RecordingCandidates = (*ContextPreviews)(nil)

// Byte slices keep digest metadata compact:100 maximally sized references fit
// within64KiB. No original audience, payload or live source lease is copied.
type recordingReferenceRecord struct {
	Source    string `json:"source"`
	Fence     string `json:"fence"`
	Policy    string `json:"policy"`
	Pod       string `json:"pod"`
	Action    string `json:"action"`
	Binding   []byte `json:"binding"`
	Execution []byte `json:"execution"`
}

func encodeRecordingReferences(refs []value.RecordingReference) ([]byte, error) {
	records := make([]recordingReferenceRecord, len(refs))
	for n, r := range refs {
		records[n] = recordingReferenceRecord{r.SourceID, r.Fence, r.PolicyUID, r.PodUID, r.ActionID, r.BindingDigest[:], r.ExecutionDigest[:]}
	}
	var encoded bytes.Buffer
	encoder := json.NewEncoder(&encoded)
	encoder.SetEscapeHTML(false)
	err := encoder.Encode(records)
	raw := bytes.TrimSuffix(encoded.Bytes(), []byte("\n"))
	if err != nil || len(raw) > 65536 {
		return nil, value.ErrInvalid
	}
	return raw, nil
}
func decodeRecordingReferences(raw []byte) ([]value.RecordingReference, error) {
	if len(raw) < 2 || len(raw) > 65536 {
		return nil, value.ErrInvalid
	}
	var records []recordingReferenceRecord
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&records) != nil || len(records) > value.MaxRecordingSelections {
		return nil, value.ErrInvalid
	}
	refs := make([]value.RecordingReference, len(records))
	for n, r := range records {
		if len(r.Binding) != 32 || len(r.Execution) != 32 {
			return nil, value.ErrInvalid
		}
		refs[n] = value.RecordingReference{SourceID: r.Source, Fence: r.Fence, PolicyUID: r.Policy, PodUID: r.Pod, ActionID: r.Action, BindingDigest: artifact.Digest(r.Binding), ExecutionDigest: artifact.Digest(r.Execution)}
		if !refs[n].Valid() {
			return nil, value.ErrInvalid
		}
	}
	canonical, err := encodeRecordingReferences(refs)
	if err != nil || !bytes.Equal(canonical, raw) {
		return nil, value.ErrInvalid
	}
	return refs, nil
}

func (s *ContextPreviews) CreateRecordingSelection(ctx context.Context, set value.RecordingSelectionSet) error {
	set = set.Clone()
	if s == nil || s.ledger == nil || !set.Valid() || set.RootID != s.root {
		return value.ErrInvalid
	}
	raw, err := encodeRecordingReferences(set.References)
	if err != nil {
		return err
	}
	return captureError(s.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		if _, err := q.LockPermissionStream(ctx, id(s.root)); err != nil {
			return err
		}
		now, err := q.CurrentTime(ctx)
		if err != nil {
			return err
		}
		if now.Time.Before(set.CreatedAt) || !now.Time.Before(set.ExpiresAt) {
			return value.ErrChanged
		}
		old, err := q.ReadRecordingSelection(ctx, custodydb.ReadRecordingSelectionParams{RootID: id(s.root), ID: id(set.ID), ActorKey: previewActorKey(set.Actor)})
		if err == nil {
			if !bytes.Equal(old.ReferencesJson, raw) || !old.CreatedAt.Time.Equal(set.CreatedAt) || !old.ExpiresAt.Time.Equal(set.ExpiresAt) || old.PolicyUid != set.PolicyUID || uid(old.AfterSourceID) != set.AfterSourceID || old.HasMore != set.More || uid(old.ClusterID) != set.Target.ClusterID || old.NamespaceUid != set.Target.NamespaceUID || old.WorkloadUid != set.Target.WorkloadUID {
				return value.ErrConflict
			}
			return ctx.Err()
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if _, err = q.DeleteExpiredRecordingSelections(ctx, id(s.root)); err != nil {
			return err
		}
		count, err := q.CountContextPreviews(ctx, id(s.root))
		if err != nil {
			return err
		}
		if count >= value.MaxPreviewsPerRoot {
			return value.ErrCapacity
		}
		count, err = q.CountPrincipalContextPreviews(ctx, custodydb.CountPrincipalContextPreviewsParams{RootID: id(s.root), PrincipalKey: principalKey(set.Actor)})
		if err != nil {
			return err
		}
		if count >= value.MaxPreviewsPerPrincipal {
			return value.ErrCapacity
		}
		if err = q.InsertRecordingSelection(ctx, custodydb.InsertRecordingSelectionParams{ID: id(set.ID), RootID: id(s.root), ActorKey: previewActorKey(set.Actor), PrincipalKey: principalKey(set.Actor), ClusterID: id(set.Target.ClusterID), NamespaceUid: set.Target.NamespaceUID, WorkloadUid: set.Target.WorkloadUID, ReferencesJson: raw, CreatedAt: ts(set.CreatedAt), ExpiresAt: ts(set.ExpiresAt), PolicyUid: set.PolicyUID, AfterSourceID: id(set.AfterSourceID), HasMore: set.More}); err != nil {
			return err
		}
		now, err = q.CurrentTime(ctx)
		if err != nil {
			return err
		}
		if !now.Time.Before(set.ExpiresAt) {
			return value.ErrChanged
		}
		return ctx.Err()
	}))
}

func (s *ContextPreviews) ReadRecordingSelection(ctx context.Context, actor identity.Principal, selectionID string) (value.RecordingSelectionSet, error) {
	var out value.RecordingSelectionSet
	if s == nil || s.ledger == nil || !actor.Valid() || !authorization.UUID(selectionID) {
		return out, value.ErrInvalid
	}
	err := s.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		row, err := q.ReadRecordingSelection(ctx, custodydb.ReadRecordingSelectionParams{RootID: id(s.root), ID: id(selectionID), ActorKey: previewActorKey(actor)})
		if err != nil {
			return err
		}
		refs, err := decodeRecordingReferences(row.ReferencesJson)
		if err != nil {
			return err
		}
		out = value.RecordingSelectionSet{ID: uid(row.ID), RootID: uid(row.RootID), Actor: actor, Target: authorization.WorkloadTarget{ClusterID: uid(row.ClusterID), NamespaceUID: row.NamespaceUid, WorkloadUID: row.WorkloadUid}, References: refs, PolicyUID: row.PolicyUid, AfterSourceID: uid(row.AfterSourceID), More: row.HasMore, CreatedAt: row.CreatedAt.Time, ExpiresAt: row.ExpiresAt.Time}
		now, err := q.CurrentTime(ctx)
		if err != nil {
			return err
		}
		if !out.Valid() || !bytes.Equal(row.PrincipalKey, principalKey(actor)) || now.Time.Before(out.CreatedAt) || !now.Time.Before(out.ExpiresAt) {
			return value.ErrDenied
		}
		return ctx.Err()
	})
	return out, captureError(err)
}

func (s *ContextPreviews) RecordingCandidates(ctx context.Context, target authorization.WorkloadTarget, query app.RecordingCandidateQuery) (app.RecordingCandidatePage, error) {
	var out app.RecordingCandidatePage
	if s == nil || s.ledger == nil || !target.Valid() || query.PolicyUID != "" && !identity.Text(query.PolicyUID, 64) || query.AfterSourceID != "" && !authorization.UUID(query.AfterSourceID) {
		return out, value.ErrInvalid
	}
	err := s.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		rows, err := q.ListRecordingCandidates(ctx, custodydb.ListRecordingCandidatesParams{RootID: id(s.root), ClusterID: id(target.ClusterID), NamespaceUid: target.NamespaceUID, WorkloadUid: target.WorkloadUID, PolicyFilter: query.PolicyUID, AfterID: id(query.AfterSourceID)})
		if err != nil {
			return err
		}
		out.More = len(rows) > value.MaxRecordingSelections
		if out.More {
			rows = rows[:value.MaxRecordingSelections]
		}
		for _, row := range rows {
			source, err := policySourceState(row.PolicyRecordingSource)
			if err != nil {
				return err
			}
			out.Rows = append(out.Rows, app.RecordingCandidate{PolicyName: row.PolicyName, Source: source})
			out.AfterSourceID = source.Binding.SourceID
		}
		return ctx.Err()
	})
	return out, captureError(err)
}
func (s *ContextPreviews) RecordingSources(ctx context.Context, target authorization.WorkloadTarget, ids []string) ([]app.RecordingCandidate, error) {
	if s == nil || s.ledger == nil || !target.Valid() || len(ids) < 1 || len(ids) > value.MaxRecordingSelections {
		return nil, value.ErrInvalid
	}
	values := make([]pgtype.UUID, len(ids))
	seen := map[string]bool{}
	for n, v := range ids {
		if !authorization.UUID(v) || seen[v] {
			return nil, value.ErrInvalid
		}
		seen[v] = true
		values[n] = id(v)
	}
	var out []app.RecordingCandidate
	err := s.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		rows, err := q.ReadRecordingSources(ctx, custodydb.ReadRecordingSourcesParams{RootID: id(s.root), ClusterID: id(target.ClusterID), NamespaceUid: target.NamespaceUID, WorkloadUid: target.WorkloadUID, SourceIds: values})
		if err != nil {
			return err
		}
		for _, row := range rows {
			source, err := policySourceState(row.PolicyRecordingSource)
			if err != nil {
				return err
			}
			out = append(out, app.RecordingCandidate{PolicyName: row.PolicyName, Source: source})
		}
		return ctx.Err()
	})
	return out, captureError(err)
}
