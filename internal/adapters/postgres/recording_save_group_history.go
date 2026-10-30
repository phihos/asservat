package postgres

import (
	"bytes"
	"context"
	"time"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/capture"
	executionvalue "asservat.local/asservat/internal/domain/execution"
	"asservat.local/asservat/internal/domain/identity"
	"github.com/jackc/pgx/v5/pgtype"
)

// Candidate routing and metadata fetches are batched before per-member checks.
// At most HistoryScan routing candidates and HistoryScan complete parent/child
// records are examined. A public parent is never a synthetic capture.
func mergedHistoryEntries(ctx context.Context, tx *custodydb.Queries, root string, query value.HistoryQuery, params custodydb.ListCaptureHistoryCandidatesParams, projection authorization.Projection, now time.Time) ([]value.HistoryEntry, *value.HistoryCursor, time.Time, error) {
	candidates, err := tx.ListCaptureHistoryCandidates(ctx, params)
	if err != nil {
		return nil, nil, time.Time{}, err
	}
	moreCandidates := len(candidates) == value.HistoryScan
	candidates, boundedMore, err := boundedRecordingHistoryCandidates(candidates)
	if err != nil {
		return nil, nil, time.Time{}, err
	}
	moreCandidates = moreCandidates || boundedMore
	until := query.Identity.ValidUntil
	if len(candidates) == 0 {
		return []value.HistoryEntry{}, nil, until, nil
	}
	var singles, groups []pgtype.UUID
	for _, candidate := range candidates {
		if candidate.Grouped {
			groups = append(groups, candidate.ID)
		} else {
			singles = append(singles, candidate.ID)
		}
	}
	var singleRows []custodydb.ContextCapture
	var headers []custodydb.RecordingSaveGroup
	var members []custodydb.ContextCapture
	if len(singles) > 0 {
		singleRows, err = tx.ReadHistoryCaptureRows(ctx, custodydb.ReadHistoryCaptureRowsParams{RootID: id(root), Ids: singles})
		if err != nil {
			return nil, nil, time.Time{}, err
		}
	}
	if len(groups) > 0 {
		headers, err = tx.ReadHistoryGroupHeaders(ctx, custodydb.ReadHistoryGroupHeadersParams{RootID: id(root), Ids: groups})
		if err != nil {
			return nil, nil, time.Time{}, err
		}
		members, err = tx.ReadHistoryGroupMembers(ctx, custodydb.ReadHistoryGroupMembersParams{RootID: id(root), Ids: groups})
		if err != nil {
			return nil, nil, time.Time{}, err
		}
	}
	singleByID := map[pgtype.UUID]custodydb.ContextCapture{}
	for _, c := range singleRows {
		singleByID[c.ID] = c
	}
	groupByID := map[pgtype.UUID]custodydb.RecordingSaveGroup{}
	for _, g := range headers {
		groupByID[g.ID] = g
	}
	membersByID := map[pgtype.UUID][]custodydb.ContextCapture{}
	for _, c := range members {
		membersByID[c.GroupID] = append(membersByID[c.GroupID], c)
	}
	actors := map[pgtype.UUID]identity.Principal{}
	var visibleSingles []custodydb.ContextCapture
	var visibleGroups []custodydb.RecordingSaveGroup
	scanned, visible := 0, 0
	for _, candidate := range candidates {
		scanned++
		var rows []custodydb.ContextCapture
		if candidate.Grouped {
			g, ok := groupByID[candidate.ID]
			if !ok {
				return nil, nil, time.Time{}, value.ErrUnavailable
			}
			rows = membersByID[g.ID]
			if _, e := recordingGroupAcceptedRows(g, rows); e != nil {
				return nil, nil, time.Time{}, e
			}
		} else {
			c, ok := singleByID[candidate.ID]
			if !ok {
				return nil, nil, time.Time{}, value.ErrUnavailable
			}
			rows = []custodydb.ContextCapture{c}
		}
		allowed := true
		for _, c := range rows {
			a, e := admittedRecord(c)
			if e != nil {
				return nil, nil, time.Time{}, e
			}
			intent, e := captureIntent(c)
			if e != nil {
				return nil, nil, time.Time{}, e
			}
			t := intent.Target
			if t.ClusterID != query.Target.ClusterID || t.NamespaceUID != query.Target.NamespaceUID || t.WorkloadUID != query.Target.WorkloadUID {
				return nil, nil, time.Time{}, value.ErrUnavailable
			}
			p := projection
			p.Target = t
			eligibility := authorization.CaptureHistoryEligibility(query.Identity, p, t, intent.Requester(), a.Expectation.Audience, now)
			if !eligibility.Eligible {
				allowed = false
				break
			}
			until = identity.Earlier(until, eligibility.ValidUntil)
			if old, ok := actors[candidate.ID]; ok && old != intent.Requester() {
				return nil, nil, time.Time{}, value.ErrUnavailable
			}
			actors[candidate.ID] = intent.Requester()
		}
		if !allowed {
			continue
		}
		if candidate.Grouped {
			visibleGroups = append(visibleGroups, groupByID[candidate.ID])
		} else {
			visibleSingles = append(visibleSingles, singleByID[candidate.ID])
		}
		visible++
		if visible == query.Limit {
			break
		}
	}
	var next *value.HistoryCursor
	if scanned > 0 && (scanned < len(candidates) || moreCandidates) {
		last := candidates[scanned-1]
		next = &value.HistoryCursor{AcceptedAt: last.CreatedAt.Time.UTC(), CaptureID: uid(last.ID)}
	}
	entries, err := historyEntries(ctx, tx, root, visibleSingles, actors, now)
	if err != nil {
		return nil, nil, time.Time{}, err
	}
	grouped, err := recordingGroupHistoryEntries(ctx, tx, root, visibleGroups, membersByID, actors, now)
	if err != nil {
		return nil, nil, time.Time{}, err
	}
	byID := map[string]value.HistoryEntry{}
	for _, e := range append(entries, grouped...) {
		byID[e.CaptureID] = e
	}
	out := make([]value.HistoryEntry, 0, len(byID))
	for _, candidate := range candidates[:scanned] {
		if e, ok := byID[uid(candidate.ID)]; ok {
			out = append(out, e)
		}
	}
	return out, next, until, nil
}

func recordingGroupHistoryEntries(ctx context.Context, tx *custodydb.Queries, root string, groups []custodydb.RecordingSaveGroup, members map[pgtype.UUID][]custodydb.ContextCapture, actors map[pgtype.UUID]identity.Principal, now time.Time) ([]value.HistoryEntry, error) {
	out := make([]value.HistoryEntry, 0, len(groups))
	if len(groups) == 0 {
		return out, nil
	}
	groupIDs := make([]pgtype.UUID, 0, len(groups))
	var childIDs []pgtype.UUID
	for _, g := range groups {
		groupIDs = append(groupIDs, g.ID)
		for _, c := range members[g.ID] {
			childIDs = append(childIDs, c.ID)
		}
	}
	parameters, err := tx.ReadHistoryGroupParameters(ctx, custodydb.ReadHistoryGroupParametersParams{RootID: id(root), Ids: groupIDs})
	if err != nil {
		return nil, err
	}
	facts, err := tx.ReadCaptureHistoryFacts(ctx, custodydb.ReadCaptureHistoryFactsParams{RootID: id(root), Ids: childIDs})
	if err != nil {
		return nil, err
	}
	executions, err := tx.ReadAPIExecutions(ctx, custodydb.ReadAPIExecutionsParams{RootID: id(root), Ids: childIDs})
	if err != nil {
		return nil, err
	}
	parameterByID := map[pgtype.UUID]custodydb.ReadHistoryGroupParametersRow{}
	for _, p := range parameters {
		parameterByID[p.CaptureID] = p
	}
	factsByID := map[pgtype.UUID]custodydb.ReadCaptureHistoryFactsRow{}
	for _, f := range facts {
		factsByID[f.ContextCapture.ID] = f
	}
	executionsByID := map[pgtype.UUID][]executionvalue.APIExecution{}
	for _, row := range executions {
		x, e := apiExecution(row)
		if e != nil {
			return nil, e
		}
		executionsByID[row.CaptureID] = append(executionsByID[row.CaptureID], x)
	}
	for _, g := range groups {
		parameter, ok := parameterByID[g.ID]
		if !ok || !parameter.Visible || !now.Before(parameter.SummaryExpiresAt.Time) {
			continue
		}
		var actions []value.ContextActionProgress
		evidenceAvailable, evidenceExpired, active := false, false, false
		for _, c := range members[g.ID] {
			f, ok := factsByID[c.ID]
			if !ok || !bytes.Equal(c.ExpectationJson, f.ContextCapture.ExpectationJson) || !bytes.Equal(c.ScopeDigest, f.ContextCapture.ScopeDigest) {
				return nil, value.ErrUnavailable
			}
			p, e := progressFacts(custodydb.ReadContextProgressFactsRow(f), executionsByID[c.ID]...)
			if e != nil {
				return nil, e
			}
			actions = append(actions, value.ContextActionProgress{InstanceID: uid(c.ID), Phase: p.ActionPhase, ReasonCode: p.ReasonCode})
			switch value.HistoryEvidenceState(p.Phase, f.EffectiveExpiresAt.Time, now) {
			case "available":
				evidenceAvailable = true
			case "expired":
				evidenceExpired = true
			case "pending":
				if p.Phase != "Cancelled" {
					active = true
				}
			}
		}
		phase, _ := recordingGroupPhase(actions)
		evidence := "unavailable"
		if evidenceAvailable {
			evidence = "available"
		} else if active {
			evidence = "pending"
		} else if evidenceExpired {
			evidence = "expired"
		}
		entry := value.HistoryEntry{Operation: "recordingSave", Requester: actors[g.ID], CaptureID: uid(g.ID), Origin: value.HistoryManual, AcceptedAt: g.AcceptedAt.Time.UTC(), ExpiresAt: parameter.SummaryExpiresAt.Time, SettingsExpiresAt: identity.Earlier(parameter.SummaryExpiresAt.Time, parameter.EffectiveExpiresAt.Time), Phase: phase, EvidenceState: evidence, ActionKinds: []string{"packetCapture"}, RepeatState: "requiresSelection"}
		if !now.Before(entry.SettingsExpiresAt) {
			entry.RepeatState = "parametersExpired"
		} else if parameter.State != "available" || parameter.CustodyState != artifact.StoredUnpublished {
			entry.RepeatState = "parametersUnavailable"
		}
		rows := members[g.ID]
		if len(rows) > 0 && rows[0].RepeatedFromCaptureID.Valid && now.Before(rows[0].RepeatedFromExpiresAt.Time) {
			entry.RepeatedFrom = uid(rows[0].RepeatedFromCaptureID)
		}
		out = append(out, entry)
	}
	return out, nil
}

// HistoryScan bounds real record work, not just public parent count. A full
// sixteen-member group costs its parent plus sixteen children. Continuation
// stays at the last examined candidate, never the next unexamined group.
func boundedRecordingHistoryCandidates(in []custodydb.ListCaptureHistoryCandidatesRow) ([]custodydb.ListCaptureHistoryCandidatesRow, bool, error) {
	used := 0
	for n, candidate := range in {
		members := int(candidate.MemberCount)
		if candidate.Grouped && (members < 2 || members > value.MaxRecordingSaveGroupChildren) || !candidate.Grouped && members != 1 {
			return nil, false, value.ErrUnavailable
		}
		cost := members
		if candidate.Grouped {
			cost++
		}
		if used+cost > value.HistoryScan {
			return in[:n], true, nil
		}
		used += cost
	}
	return in, false, nil
}
