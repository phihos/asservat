package postgres

import (
	"context"
	"encoding/json"
	"time"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	app "asservat.local/asservat/internal/application/audit"
	value "asservat.local/asservat/internal/domain/audit"
	"asservat.local/asservat/internal/domain/identity"
)

// CaptureAuditBacking is an accepted installation configuration input, never a
// capture request. The distinct source credential and its independently pinned
// root must exist before this facet can reserve a workload's account.
type CaptureAuditBacking struct {
	Pool             app.OperationAuditPool
	Account          value.CaptureAuditAccount
	ExpectedRevision int64
	Paused           bool
	ValidUntil       time.Time
}

func (l *Ledger) ConfigureCaptureAuditBacking(ctx context.Context, in CaptureAuditBacking, mac *app.OperationMAC) error {
	p := in.Pool
	a := in.Account
	if l == nil || ctx == nil || ctx.Err() != nil || mac == nil || !a.Valid() || p.RootID != a.RootID || p.Lane != "capture" || p.AccountVersion != a.AccountVersion || mac.AccountVersion() != a.AccountVersion || in.ExpectedRevision < 0 || in.ExpectedRevision >= 1<<60 || a.Revision != in.ExpectedRevision+1 || p.ExpectedRevision < 0 || p.ExpectedRevision >= 1<<60 || a.Policy.BackingRevision != p.ExpectedRevision+1 || p.Accounts < 1 || p.Accounts > 1000000 || p.RecordsPerAccount < a.Records || p.RecordsPerAccount > 1000000 || a.Policy.MetadataSlots < p.Accounts*p.RecordsPerAccount || p.RetainedSeconds != a.RetainedSeconds || !identity.Fresh(p.ObservedAt, p.FreshUntil, p.ObservedAt, 5*time.Second) || !p.ValidUntil.After(p.ObservedAt) || !in.ValidUntil.After(p.ObservedAt) {
		return app.ErrUnavailable
	}
	expected, e := mac.CaptureAccount(a.Policy.InstallationID, a.RootID, a.AllocationID)
	if e != nil || expected != a.AccountDigest {
		return app.ErrUnavailable
	}
	until := minCaptureAuditTime(p.FreshUntil, minCaptureAuditTime(p.ValidUntil, minCaptureAuditTime(in.ValidUntil, a.Policy.ValidUntil)))
	live, end := context.WithDeadline(ctx, until)
	defer end()
	pool, e := json.Marshal(p)
	if e != nil {
		return app.ErrUnavailable
	}
	account, e := json.Marshal(struct {
		Account          value.CaptureAuditAccount
		ExpectedRevision int64
		Paused           bool
		ValidUntil       time.Time
	}{a, in.ExpectedRevision, in.Paused, in.ValidUntil})
	if e != nil {
		return app.ErrUnavailable
	}
	e = l.transaction(live, func(q *custodydb.Queries) error {
		granted, err := q.ConfigureCaptureAuditBacking(live, custodydb.ConfigureCaptureAuditBackingParams{RootID: id(a.RootID), PoolValue: pool, AccountValue: account, ObservedAt: ts(p.ObservedAt), FreshUntil: ts(p.FreshUntil)})
		if err != nil {
			return err
		}
		if !granted.Valid {
			return app.ErrUnavailable
		}
		until = minCaptureAuditTime(until, granted.Time)
		return nil
	})
	if e != nil || live.Err() != nil || !time.Now().Before(until) {
		return app.ErrUnavailable
	}
	return nil
}
