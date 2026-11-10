package postgres

import (
	"context"
	"encoding/json"
	"time"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	app "asservat.local/asservat/internal/application/privacy"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	value "asservat.local/asservat/internal/domain/privacy"
)

var _ app.ProcessingDiscoveryReader = (*ProcessingInventory)(nil)

func (s *ProcessingInventory) ReadProcessingDiscovery(ctx context.Context, a value.ProcessingAuthority, query value.ProcessingDiscoveryQuery) (value.ProcessingDiscoveryPage, error) {
	var out value.ProcessingDiscoveryPage
	if s == nil || s.decisions == nil || !query.Valid() {
		return out, value.ErrUnavailable
	}
	err := s.decisions.transaction(ctx, a, func(call context.Context, q *custodydb.Queries, p custodydb.ProcessingRoot, now time.Time) error {
		if !p.InitializedAt.Valid || !p.InitializationID.Valid {
			return value.ErrUnavailable
		}
		afterID, afterAt := query.After.ArtifactID, query.After.AnchorAt
		if afterID == "" {
			afterID, afterAt = "00000000-0000-0000-0000-000000000000", query.AcquiredFrom
		}
		rows, err := q.ScanProcessingDiscovery(call, custodydb.ScanProcessingDiscoveryParams{
			RootID: p.RootID, CaseID: id(query.CaseID), ClusterID: id(query.ClusterID), NamespaceUid: query.NamespaceUID, WorkloadUid: query.WorkloadUID,
			AfterArtifactID: id(afterID), AfterAnchorAt: ts(afterAt), AcquiredUntil: ts(query.AcquiredUntil), ObservedAt: ts(now), ScanLimit: int32(query.Limit + 1),
		})
		if err != nil || len(rows) > query.Limit+1 {
			return value.ErrUnavailable
		}
		out = value.ProcessingDiscoveryPage{RootID: uid(p.RootID), Epoch: uid(p.Epoch), Sequence: p.Sequence, ObservedAt: a.ObservedAt,
			ValidUntil: identity.Earlier(a.ValidUntil, p.ValidUntil.Time).UTC(), Candidates: []value.ProcessingDiscoveryCandidate{}}
		if len(rows) > query.Limit {
			rows = rows[:query.Limit]
			last := rows[len(rows)-1]
			out.Next.ArtifactID = uid(last.ArtifactID)
			if query.CaseID == "" {
				out.Next.AnchorAt = last.AnchorAt.Time.UTC()
			}
			out.ValidUntil = identity.Earlier(out.ValidUntil, last.RetireBy.Time).UTC()
		}
		for _, row := range rows {
			candidate, err := processingDiscoveryCandidate(row)
			if err != nil {
				return err
			}
			if query.PurposeRef == "" || query.PurposeRef == candidate.PurposeRef {
				out.Candidates = append(out.Candidates, candidate)
				out.ValidUntil = identity.Earlier(out.ValidUntil, row.RetireBy.Time).UTC()
			}
		}
		if out.RootID != s.decisions.root || !out.Valid(query, now) {
			return value.ErrUnavailable
		}
		return nil
	})
	if err != nil || !time.Now().Before(out.ValidUntil) {
		return value.ProcessingDiscoveryPage{}, value.ErrUnavailable
	}
	return out, nil
}

func processingDiscoveryCandidate(r custodydb.ScanProcessingDiscoveryRow) (value.ProcessingDiscoveryCandidate, error) {
	var out value.ProcessingDiscoveryCandidate
	if !r.Verified {
		return out, value.ErrUnavailable
	}
	node := value.ProcessingNode{
		CaptureID: uid(r.CaptureID), Location: artifact.Location{ClusterID: uid(r.ClusterID), ArtifactID: uid(r.ArtifactID), AttemptID: uid(r.AttemptID)},
		Target:   authorization.Target{ClusterID: uid(r.ClusterID), NamespaceUID: r.NamespaceUid, WorkloadUID: r.WorkloadUid, PodUID: r.PodUid},
		AnchorAt: r.AnchorAt.Time.UTC(), DeleteBy: r.DeleteBy.Time.UTC(), RetireBy: r.RetireBy.Time.UTC(), Origin: r.Origin,
	}
	if json.Unmarshal(r.Parents, &node.Parents) != nil || !node.Valid() || r.EffectiveDeleteBy.Time.After(node.DeleteBy) {
		return out, value.ErrUnavailable
	}
	native := r.NativeType
	if native == artifact.PodStatusArtifact {
		if r.ActionID != "pod-status" || r.DataClass != "metadata" {
			return out, value.ErrUnavailable
		}
		native = "podStatus"
	}
	out = value.ProcessingDiscoveryCandidate{
		ArtifactID: node.Location.ArtifactID, CaptureID: node.CaptureID, CaseID: uid(r.CaseID), ClusterID: node.Target.ClusterID,
		NamespaceUID: node.Target.NamespaceUID, WorkloadUID: node.Target.WorkloadUID, PurposeRef: r.PurposeRef, NativeType: native, DataClass: r.DataClass,
		Origin: node.Origin, AnchorAt: node.AnchorAt, ExpiresAt: r.EffectiveExpiresAt.Time.UTC(), DeleteBy: r.EffectiveDeleteBy.Time.UTC(), CustodyState: r.State,
		Parents: make([]string, 0, len(node.Parents)),
	}
	for _, parent := range node.Parents {
		out.Parents = append(out.Parents, parent.ArtifactID)
	}
	if !out.Valid() {
		return value.ProcessingDiscoveryCandidate{}, value.ErrUnavailable
	}
	return out, nil
}
