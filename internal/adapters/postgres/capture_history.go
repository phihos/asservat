package postgres

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"slices"
	"time"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/capture"
	executionvalue "asservat.local/asservat/internal/domain/execution"
	"asservat.local/asservat/internal/domain/identity"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

// ListCaptureHistory returns one page of a workload's accepted captures that
// the caller may see (ADR-236): newest first, at most seven days old, keyed by
// the typed target identity that migration 00089 records at acceptance. The
// caller needs current ordinary read rights on the workload; each row is then
// visible to its original requester or to a current member of its retained
// audience. It reads no evidence, live workload or storage capacity.
func (s *ContextProgressReads) ListCaptureHistory(ctx context.Context, q value.HistoryQuery) (value.HistoryPage, error) {
	var out value.HistoryPage
	if s == nil || s.ledger == nil || q.RootID != s.root || !q.Valid(historyInputAt(q.Identity.VerifiedAt, q.Recovery.ObservedAt)) {
		return out, value.ErrInvalid
	}
	q.Identity.Groups = slices.Clone(q.Identity.Groups)
	q.Identity.Scopes = slices.Clone(q.Identity.Scopes)
	origins := make([]string, len(q.Origins))
	for i, o := range q.Origins {
		origins[i] = string(o)
	}
	err := s.ledger.transaction(ctx, func(tx *custodydb.Queries) error {
		out = value.HistoryPage{} // definitely-aborted transaction retry
		recovery, err := s.recovery.lock(ctx, tx, s.root, q.Recovery)
		if err != nil {
			return err
		}
		stream, err := tx.LockPermissionStream(ctx, id(s.root))
		if err != nil {
			return err
		}
		first, err := tx.CurrentTime(ctx)
		if err != nil {
			return err
		}
		if !q.Valid(first.Time) {
			return value.ErrDenied
		}
		projection, err := permissionProjection(ctx, tx, stream, q.Target)
		if err != nil {
			return value.ErrDenied
		}
		n, err := tx.CurrentTime(ctx)
		if err != nil {
			return err
		}
		// Without current read rights on the workload there is no history at
		// all, the same uniform refusal as any other unauthorized target.
		scope := authorization.ScopeEligibility(q.Identity, projection, authorization.ReadApproved, q.Target, n.Time)
		if !scope.Eligible {
			return value.ErrDenied
		}
		until := identity.Earlier(first.Time.Add(5*time.Second), identity.Earlier(scope.ValidUntil, q.Recovery.FreshUntil))
		params := custodydb.ListCaptureHistoryParams{RootID: id(s.root), ClusterID: id(q.Target.ClusterID), NamespaceUid: q.Target.NamespaceUID, WorkloadUid: q.Target.WorkloadUID, Origins: origins, NotBefore: ts(first.Time.Add(-value.HistoryLifetime)), PageLimit: value.HistoryScan}
		if q.After != nil {
			params.AfterAt, params.AfterID = ts(q.After.AcceptedAt), id(q.After.CaptureID)
		}
		rows, err := tx.ListCaptureHistory(ctx, params)
		if err != nil {
			return err
		}
		var visible []custodydb.ContextCapture
		scanned := 0
		for _, c := range rows {
			scanned++
			intent, err := captureIntent(c)
			if err != nil {
				return value.ErrUnavailable
			}
			accepted, err := admittedRecord(c)
			if err != nil {
				return value.ErrUnavailable
			}
			t := intent.Target
			if t.ClusterID != q.Target.ClusterID || t.NamespaceUID != q.Target.NamespaceUID || t.WorkloadUID != q.Target.WorkloadUID {
				return value.ErrUnavailable
			}
			// Assignments are selected by cluster, namespace and workload; only
			// the row's own Pod differs from the currently resolved one.
			p := projection
			p.Target = t
			e := authorization.CaptureHistoryEligibility(q.Identity, p, t, intent.Actor, accepted.Expectation.Audience, n.Time)
			if !e.Eligible {
				continue
			}
			until = identity.Earlier(until, e.ValidUntil)
			visible = append(visible, c)
			if len(visible) == q.Limit {
				break
			}
		}
		if scanned > 0 && (scanned < len(rows) || len(rows) == value.HistoryScan) {
			last := rows[scanned-1]
			out.Next = &value.HistoryCursor{AcceptedAt: last.CreatedAt.Time.UTC(), CaptureID: uid(last.ID)}
		}
		out.Entries, err = historyEntries(ctx, tx, s.root, visible, n.Time)
		if err != nil {
			return err
		}
		out.ObservedAt, out.ValidUntil = first.Time, until
		if err = s.recovery.check(ctx, tx, recovery, s.root, q.Recovery); err != nil {
			return err
		}
		n, err = tx.CurrentTime(ctx)
		if err != nil {
			return err
		}
		if !q.Valid(n.Time) || !n.Time.Before(until) {
			return value.ErrDenied
		}
		return ctx.Err()
	})
	if err != nil {
		return value.HistoryPage{}, captureError(err)
	}
	return out, nil
}

// historyInputAt is when both independently observed inputs exist: an
// identity verified before the recovery observation (or after it) is checked
// together with it at the later instant. After the locks both are checked
// again at database time.
func historyInputAt(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
}

// historyEntries derives each visible capture's phase exactly as get_capture
// does, from one snapshot of its custody, verification, publication and API
// execution facts.
func historyEntries(ctx context.Context, tx *custodydb.Queries, root string, visible []custodydb.ContextCapture, now time.Time) ([]value.HistoryEntry, error) {
	out := make([]value.HistoryEntry, 0, len(visible))
	if len(visible) == 0 {
		return out, nil
	}
	ids := make([]pgtype.UUID, len(visible))
	for i, c := range visible {
		ids[i] = c.ID
	}
	facts, err := tx.ReadCaptureHistoryFacts(ctx, custodydb.ReadCaptureHistoryFactsParams{RootID: id(root), Ids: ids})
	if err != nil {
		return nil, err
	}
	rows, err := tx.ReadAPIExecutions(ctx, custodydb.ReadAPIExecutionsParams{RootID: id(root), Ids: ids})
	if err != nil {
		return nil, err
	}
	byID := map[pgtype.UUID]custodydb.ReadCaptureHistoryFactsRow{}
	for _, f := range facts {
		byID[f.ContextCapture.ID] = f
	}
	executions := map[pgtype.UUID][]executionvalue.APIExecution{}
	for _, row := range rows {
		x, err := apiExecution(row)
		if err != nil {
			return nil, err
		}
		executions[row.CaptureID] = append(executions[row.CaptureID], x)
	}
	for _, c := range visible {
		f, ok := byID[c.ID]
		if !ok || !bytes.Equal(f.ContextCapture.ScopeDigest, c.ScopeDigest) || !bytes.Equal(f.ContextCapture.ExpectationJson, c.ExpectationJson) {
			return nil, value.ErrUnavailable
		}
		accepted, err := admittedRecord(c)
		if err != nil {
			return nil, err
		}
		var x []executionvalue.APIExecution
		if accepted.Expectation.ExecutionClass == artifact.ContextAPIExecution {
			x = executions[c.ID]
		}
		p, err := progressFacts(custodydb.ReadContextProgressFactsRow(f), x...)
		if err != nil {
			return nil, err
		}
		accepted.CreatedAt = accepted.CreatedAt.UTC()
		out = append(out, value.HistoryEntry{CaptureID: uid(c.ID), Origin: value.HistoryOrigin(c.HistoryOrigin.String), AcceptedAt: accepted.CreatedAt, ExpiresAt: accepted.CreatedAt.Add(value.HistoryLifetime), Phase: p.Phase, EvidenceState: value.HistoryEvidenceState(p.Phase, f.EffectiveExpiresAt.Time, now)})
	}
	return out, nil
}

// historyScope is the part of the accepted collection scope that is
// repeatable. Old pod bindings, the executor and retention policy
// revisions are deliberately not read.
type historyScope struct {
	Collection struct {
		Spec struct {
			Target    json.RawMessage `json:"target"`
			Retention string          `json:"retention"`
		} `json:"spec"`
	} `json:"collection"`
	Dependencies json.RawMessage `json:"dependencies"`
}
type historyTarget struct {
	Namespace string `json:"namespace"`
	Workload  struct {
		Kind string `json:"kind"`
		Name string `json:"name"`
		UID  string `json:"uid"`
	} `json:"workloadRef"`
}

// ReadCaptureSettings returns the repeatable settings of one history entry
// under the same visibility as ListCaptureHistory. Older, unknown and
// unauthorized captures are the same uniform refusal.
func (s *ContextProgressReads) ReadCaptureSettings(ctx context.Context, q value.SettingsQuery) (value.CaptureSettings, error) {
	var out value.CaptureSettings
	if s == nil || s.ledger == nil || q.RootID != s.root || !q.Valid(historyInputAt(q.Identity.VerifiedAt, q.Recovery.ObservedAt)) {
		return out, value.ErrInvalid
	}
	q.Identity.Groups = slices.Clone(q.Identity.Groups)
	q.Identity.Scopes = slices.Clone(q.Identity.Scopes)
	err := s.ledger.transaction(ctx, func(tx *custodydb.Queries) error {
		out = value.CaptureSettings{}
		recovery, err := s.recovery.lock(ctx, tx, s.root, q.Recovery)
		if err != nil {
			return err
		}
		stream, err := tx.LockPermissionStream(ctx, id(s.root))
		if err != nil {
			return err
		}
		first, err := tx.CurrentTime(ctx)
		if err != nil {
			return err
		}
		if !q.Valid(first.Time) {
			return value.ErrDenied
		}
		c, err := tx.ReadHistoryCapture(ctx, custodydb.ReadHistoryCaptureParams{RootID: id(s.root), ID: id(q.CaptureID)})
		if errors.Is(err, pgx.ErrNoRows) {
			return value.ErrDenied
		}
		if err != nil {
			return err
		}
		accepted, err := admittedRecord(c)
		if err != nil {
			return value.ErrDenied
		}
		expires := accepted.CreatedAt.UTC().Add(value.HistoryLifetime)
		if !first.Time.Before(expires) {
			return value.ErrDenied
		}
		intent, err := captureIntent(c)
		if err != nil {
			return value.ErrDenied
		}
		projection, err := permissionProjection(ctx, tx, stream, intent.Target)
		if err != nil {
			return value.ErrDenied
		}
		n, err := tx.CurrentTime(ctx)
		if err != nil {
			return err
		}
		e := authorization.CaptureHistoryEligibility(q.Identity, projection, intent.Target, intent.Actor, accepted.Expectation.Audience, n.Time)
		if !e.Eligible {
			return value.ErrDenied
		}
		var scope historyScope
		var target historyTarget
		if json.Unmarshal(c.ScopeJson, &scope) != nil || json.Unmarshal(scope.Collection.Spec.Target, &target) != nil || len(scope.Dependencies) == 0 ||
			target.Workload.UID != intent.Target.WorkloadUID || target.Namespace != accepted.Expectation.Namespace || target.Workload.Kind == "" || target.Workload.Name == "" {
			return value.ErrUnavailable
		}
		out = value.CaptureSettings{CaptureID: accepted.CaptureID, Origin: value.HistoryOrigin(c.HistoryOrigin.String), ClusterID: intent.Target.ClusterID, NamespaceUID: intent.Target.NamespaceUID, WorkloadUID: intent.Target.WorkloadUID,
			AcceptedAt: accepted.CreatedAt.UTC(), ExpiresAt: expires, TargetJSON: bytes.Clone(scope.Collection.Spec.Target), DependencyJSON: bytes.Clone(scope.Dependencies),
			Namespace: target.Namespace, WorkloadKind: target.Workload.Kind, WorkloadName: target.Workload.Name, RequestedSeconds: accepted.Expectation.RequestedAgeSeconds, ExecutionDigest: accepted.ScopeDigest,
			ObservedAt: first.Time, ValidUntil: identity.Earlier(first.Time.Add(5*time.Second), identity.Earlier(identity.Earlier(e.ValidUntil, q.Recovery.FreshUntil), expires))}
		if err = s.recovery.check(ctx, tx, recovery, s.root, q.Recovery); err != nil {
			return err
		}
		n, err = tx.CurrentTime(ctx)
		if err != nil {
			return err
		}
		if !q.Valid(n.Time) || !n.Time.Before(out.ValidUntil) {
			return value.ErrDenied
		}
		return ctx.Err()
	})
	if err != nil {
		return value.CaptureSettings{}, captureError(err)
	}
	return out, nil
}
