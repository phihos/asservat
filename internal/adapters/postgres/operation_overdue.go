package postgres

import (
	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	app "asservat.local/asservat/internal/application/audit"
	value "asservat.local/asservat/internal/domain/audit"
	"context"
	"encoding/json"
	"time"
)

var _ app.OperationOverdueJournal = (*OperationLifecycles)(nil)
var _ app.OperationOverdueAcknowledgements = (*OperationLifecycles)(nil)

func (s *OperationLifecycles) RecordOverdueOperationPurge(ctx context.Context, l value.OperationPurgeLease) (value.OperationOverduePurge, error) {
	var out value.OperationOverduePurge
	if !l.Valid() || l.Phase != "overdueOriginal" {
		return out, app.ErrUnavailable
	}
	e := s.transaction(ctx, l.OperationID, func(q operationLifecycleQueries, _ custodydb.OperationAudit, _ custodydb.OperationAuditLifecycle, state value.OperationLifecycleSnapshot, now, _ time.Time) (time.Time, error) {
		if state.OverdueSelectedAt.IsZero() || state.Lease == nil || !sameAuditJSON(*state.Lease, l) || !now.Before(l.Until) {
			return time.Time{}, app.ErrUnavailable
		}
		if state.OverduePurge != nil {
			out = *state.OverduePurge
			return l.Until, nil
		}
		out = value.OperationOverduePurge{RootID: l.RootID, OperationID: l.OperationID, Mode: value.OperationOverdueTerminal, BindingDigest: app.OperationLifecycleDigest(*state.Intent.Lifecycle), ObjectsDigest: l.ObjectsDigest, WritersDigest: l.WritersDigest, Fence: l.Fence, SelectedAt: state.OverdueSelectedAt, PurgedAt: now, LeaseUntil: l.Until}
		if !out.Valid() {
			return time.Time{}, app.ErrUnavailable
		}
		b, _ := json.Marshal(out)
		n, e := q.SaveOverdueOperationPurge(ctx, custodydb.SaveOverdueOperationPurgeParams{RootID: id(l.RootID), OperationID: id(l.OperationID), OverduePurge: b})
		if e != nil || n != 1 {
			return time.Time{}, app.ErrUnavailable
		}
		return l.Until, nil
	})
	if e != nil {
		return value.OperationOverduePurge{}, e
	}
	return out, nil
}
func (s *OperationLifecycles) AcknowledgeOverdueOperationPurge(ctx context.Context, l value.OperationPurgeLease, p value.OperationOverduePurge) error {
	if !l.Valid() || l.Phase != "overdueOriginal" || !p.Valid() || p.Fence != l.Fence {
		return app.ErrUnavailable
	}
	return s.transaction(ctx, l.OperationID, func(q operationLifecycleQueries, _ custodydb.OperationAudit, _ custodydb.OperationAuditLifecycle, state value.OperationLifecycleSnapshot, now, _ time.Time) (time.Time, error) {
		if state.OverdueSelectedAt.IsZero() || state.Lease == nil || !sameAuditJSON(*state.Lease, l) || state.OverduePurge == nil || !sameAuditJSON(*state.OverduePurge, p) || !now.Before(l.Until) {
			return time.Time{}, app.ErrUnavailable
		}
		if state.TerminalAcknowledged {
			return l.Until, nil
		}
		n, e := q.AckTerminalOperationPurge(ctx, custodydb.AckTerminalOperationPurgeParams{RootID: id(l.RootID), OperationID: id(l.OperationID)})
		if e != nil || n != 1 {
			return time.Time{}, app.ErrUnavailable
		}
		return l.Until, nil
	})
}
