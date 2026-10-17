package postgres

import (
	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	app "asservat.local/asservat/internal/application/audit"
	value "asservat.local/asservat/internal/domain/audit"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	"context"
	"encoding/json"
	"github.com/jackc/pgx/v5/pgxpool"
	"time"
)

// Construct separate instances with producer, cleanup, independent verifier and
// finalizer credentials. No facet provisions policy, capacity or recovery.
type OperationLifecycles struct {
	journal      *OperationJournal
	connector    bool
	capture      bool
	captureScope captureLifecycleScope
}

func NewOperationLifecycles(ctx context.Context, pool *pgxpool.Pool, root, lane string, recovery *RecoveryTransactionGuard) (*OperationLifecycles, error) {
	j, e := NewOperationJournal(ctx, pool, root, lane, recovery)
	if e != nil {
		return nil, e
	}
	return &OperationLifecycles{journal: j}, nil
}

var _ app.OperationCompletions = (*OperationLifecycles)(nil)
var _ app.OperationLifecycleJournal = (*OperationLifecycles)(nil)
var _ app.OperationLifecycleAcknowledgements = (*OperationLifecycles)(nil)
var _ app.OperationRetirementFinalizer = (*OperationLifecycles)(nil)

func lifecycleState(a custodydb.OperationAudit, d custodydb.OperationAuditLifecycle) (value.OperationLifecycleSnapshot, error) {
	var s value.OperationLifecycleSnapshot
	if json.Unmarshal(a.Intent, &s.Intent) != nil || !s.Intent.Valid() || s.Intent.Lifecycle == nil {
		return s, app.ErrUnavailable
	}
	in := s.Intent
	b := in.Lifecycle
	snap, e := auditRow(a, in)
	if e != nil {
		return s, e
	}
	if uid(d.OperationID) != in.ID || uid(d.RootID) != in.RootID || d.Lane != value.OperationLane(in.Name) || uid(d.InstallationID) != b.Policy.InstallationID || uid(d.IssuerEpoch) != uid(a.IssuerEpoch) || !d.OriginalPurgeAt.Time.Equal(b.OriginalPurgeAt) || !d.CertificatePurgeAt.Time.Equal(b.CertificatePurgeAt) || !d.LiveRetireBy.Time.Equal(b.LiveRetireBy) {
		return s, app.ErrUnavailable
	}
	var binding value.OperationLifecycleBinding
	if json.Unmarshal(d.Binding, &binding) != nil || !sameAuditJSON(binding, *b) {
		return s, app.ErrUnavailable
	}
	decode := func(raw []byte, v any) bool { return len(raw) == 0 || json.Unmarshal(raw, v) == nil }
	if !decode(d.IntentCompletion, &s.IntentWriter) || !decode(d.OutcomeCompletion, &s.OutcomeWriter) || !decode(d.Lease, &s.Lease) || !decode(d.Retirement, &s.Retirement) || !decode(d.CertificateCompletion, &s.CertificateWriter) || !decode(d.CertificateReceipt, &s.CertificateReceipt) || !decode(d.TerminalPurge, &s.Terminal) {
		return s, app.ErrUnavailable
	}
	s.OverdueSelectedAt = d.OverdueSelectedAt.Time
	if !decode(d.OverduePurge, &s.OverduePurge) {
		return s, app.ErrUnavailable
	}
	s.CertificateVerifyAttempts = int64(d.CertificateVerifyAttempts)
	if s.CertificateVerifyAttempts < 0 || s.CertificateVerifyAttempts > 2 || !b.Policy.CertificateVerificationBacked() && s.CertificateVerifyAttempts != 2 {
		return s, app.ErrUnavailable
	}
	s.CertificateStarted = d.CertificateStarted
	s.TerminalAcknowledged = d.TerminalAcknowledgedAt.Valid
	for _, phase := range []string{"intent", "outcome"} {
		c := s.IntentWriter
		var record any = in
		receipt := snap.IntentReceipt
		if phase == "outcome" {
			c = s.OutcomeWriter
			record = snap.Outcome
			receipt = snap.OutcomeReceipt
		}
		if c != nil && (!c.Valid(in.RootID, in.ID, b.Policy.StoreID, phase, in.CreatedAt, in.WriteUntil) || c.RecordDigest != app.OperationLifecycleDigest(record) || receipt != nil && !sameAuditJSON(c.Receipt, *receipt)) {
			return s, app.ErrUnavailable
		}
		if receipt != nil && c == nil {
			return s, app.ErrUnavailable
		}
	}
	if s.Lease != nil {
		l := s.Lease
		if !l.Valid() || l.Phase == "overdueOriginal" && s.OverdueSelectedAt.IsZero() || l.RootID != in.RootID || l.OperationID != in.ID || l.StoreID != b.Policy.StoreID || l.InstallationID != b.Policy.InstallationID || l.IssuerEpoch != uid(d.IssuerEpoch) || !l.PostmasterAt.Equal(d.PostmasterAt.Time) || l.DatabaseOID != d.DatabaseOid.Uint32 || l.Fence != d.LeaseFence {
			return s, app.ErrUnavailable
		}
		if s.IntentWriter == nil || s.OutcomeWriter == nil || snap.IntentReceipt == nil || snap.OutcomeReceipt == nil || l.WritersDigest != app.OperationLifecycleDigest([]value.OperationWriteCompletion{*s.IntentWriter, *s.OutcomeWriter}) {
			return s, app.ErrUnavailable
		}
		objects := []value.Receipt{*snap.IntentReceipt, *snap.OutcomeReceipt}
		if l.Phase == "terminal" {
			if s.CertificateReceipt == nil {
				return s, app.ErrUnavailable
			}
			objects = append(objects, *s.CertificateReceipt)
		}
		if l.ObjectsDigest != app.OperationLifecycleDigest(objects) {
			return s, app.ErrUnavailable
		}
	}
	if s.Retirement != nil {
		r := s.Retirement
		if !r.Valid() || r.RootID != in.RootID || r.OperationID != in.ID || r.StoreID != b.Policy.StoreID || r.InstallationID != b.Policy.InstallationID || r.IssuerEpoch != uid(d.IssuerEpoch) || !r.PostmasterAt.Equal(d.PostmasterAt.Time) || r.DatabaseOID != d.DatabaseOid.Uint32 || !r.CertificatePurgeAt.Equal(b.CertificatePurgeAt) || !r.LiveRetireBy.Equal(b.LiveRetireBy) || snap.IntentReceipt == nil || snap.OutcomeReceipt == nil || s.IntentWriter == nil || s.OutcomeWriter == nil || r.ObjectsDigest != app.OperationLifecycleDigest([]value.Receipt{*snap.IntentReceipt, *snap.OutcomeReceipt}) || r.WritersDigest != app.OperationLifecycleDigest([]value.OperationWriteCompletion{*s.IntentWriter, *s.OutcomeWriter}) {
			return s, app.ErrUnavailable
		}
	}
	if s.CertificateWriter != nil {
		if s.Retirement == nil || !s.CertificateStarted {
			return s, app.ErrUnavailable
		}
		r := s.Retirement
		c := s.CertificateWriter
		if !c.Valid(in.RootID, in.ID, b.Policy.StoreID, "deletion-certificate", r.PurgedAt, r.CertificateWriteUntil) || c.RecordDigest != app.OperationLifecycleDigest(*r) {
			return s, app.ErrUnavailable
		}
	}
	if s.CertificateReceipt != nil && (s.CertificateWriter == nil || !d.CertificateAcknowledgedAt.Valid || !sameAuditJSON(*s.CertificateReceipt, s.CertificateWriter.Receipt)) {
		return s, app.ErrUnavailable
	}
	if s.Terminal != nil {
		p := s.Terminal
		if !p.Valid() || s.Lease == nil || s.Lease.Phase != "terminal" || s.Retirement == nil || s.CertificateReceipt == nil || p.RootID != in.RootID || p.OperationID != in.ID || p.Fence != s.Lease.Fence || !p.LeaseUntil.Equal(s.Lease.Until) || p.PurgedAt.Before(s.Lease.StartedAt) || p.RetirementDigest != app.OperationLifecycleDigest(*s.Retirement) || p.CertificateDigest != app.OperationLifecycleDigest(*s.CertificateReceipt) {
			return s, app.ErrUnavailable
		}
	}
	if !s.OverdueSelectedAt.IsZero() {
		if b.Policy.OverdueTerminal != value.OperationOverdueTerminal || s.CertificateStarted || s.CertificateWriter != nil || s.CertificateReceipt != nil || s.Terminal != nil || s.OverdueSelectedAt.Before(b.CertificatePurgeAt.Add(-time.Duration(b.Policy.ProofWindowSeconds)*time.Second)) {
			return s, app.ErrUnavailable
		}
	} else if s.OverduePurge != nil {
		return s, app.ErrUnavailable
	}
	if s.OverduePurge != nil {
		p := s.OverduePurge
		if !p.Valid() || s.Lease == nil || s.Lease.Phase != "overdueOriginal" || p.RootID != in.RootID || p.OperationID != in.ID || p.BindingDigest != app.OperationLifecycleDigest(*b) || p.ObjectsDigest != s.Lease.ObjectsDigest || p.WritersDigest != s.Lease.WritersDigest || p.Fence != s.Lease.Fence || !p.SelectedAt.Equal(s.OverdueSelectedAt) || !p.LeaseUntil.Equal(s.Lease.Until) || p.PurgedAt.Before(s.Lease.StartedAt) {
			return s, app.ErrUnavailable
		}
	}
	if s.TerminalAcknowledged && s.Terminal == nil && s.OverduePurge == nil {
		return s, app.ErrUnavailable
	}
	return s, nil
}

type operationLifecycleFn func(operationLifecycleQueries, custodydb.OperationAudit, custodydb.OperationAuditLifecycle, value.OperationLifecycleSnapshot, time.Time, time.Time) (time.Time, error)

func (s *OperationLifecycles) transaction(ctx context.Context, operation string, fn operationLifecycleFn) error {
	if s == nil || s.journal == nil || ctx == nil || ctx.Err() != nil || !authorization.UUID(operation) {
		return app.ErrUnavailable
	}
	j := s.journal
	e := j.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		trust, start, e := j.trust(ctx, q)
		if e != nil {
			return e
		}
		scoped := s.queries(q)
		// Immutable projection only; no locks or authority are obtained from this read.
		initial, e := scoped.ReadOperationForLifecycle(ctx, custodydb.ReadOperationForLifecycleParams{RootID: id(j.root), ID: id(operation)})
		if e != nil || initial.Lane != j.lane {
			return app.ErrUnavailable
		}
		if _, e = scoped.LockOperationAuditPool(ctx, custodydb.LockOperationAuditPoolParams{RootID: id(j.root), Lane: j.lane}); e != nil {
			return e
		}
		if _, e = scoped.LockOperationLifecycleAccount(ctx, custodydb.LockOperationLifecycleAccountParams{RootID: id(j.root), Lane: j.lane, PrincipalDigest: initial.PrincipalDigest}); e != nil {
			return e
		}
		a, e := scoped.LockOperationAudit(ctx, custodydb.LockOperationAuditParams{ID: id(operation), RootID: id(j.root)})
		if e != nil {
			return e
		}
		d, e := scoped.LockOperationLifecycle(ctx, custodydb.LockOperationLifecycleParams{RootID: id(j.root), OperationID: id(operation)})
		if e != nil {
			return e
		}
		state, e := lifecycleState(a, d)
		if e != nil {
			return e
		}
		if s.capture && !s.captureScope.matches(state.Intent) {
			return app.ErrUnavailable
		}
		if s.connector && !sameAuditJSON(state.Intent.Lifecycle.Policy, *j.lifecycle) {
			return app.ErrUnavailable
		}
		incarnation, e := q.ReadContextDatabaseIncarnation(ctx, id(j.recovery.installation))
		if e != nil {
			return e
		}
		if !operationLifecycleIncarnation(d, trust, incarnation, j.recovery.installation) {
			return app.ErrUnavailable
		}
		until := identity.Earlier(start.Add(5*time.Second), trust.FreshUntil.Time)
		if e = auditCurrent(ctx, q, trust, start, until); e != nil {
			return e
		}
		now, e := q.CurrentTime(ctx)
		if e != nil {
			return e
		}
		extra, e := fn(scoped, a, d, state, now.Time, until)
		if e != nil {
			return e
		}
		if !extra.IsZero() {
			until = identity.Earlier(until, extra)
		}
		return auditCurrent(ctx, q, trust, start, until)
	})
	if e != nil || ctx.Err() != nil {
		return app.ErrUnavailable
	}
	return nil
}
func (s *OperationLifecycles) ReadOperationLifecycle(ctx context.Context, id string) (value.OperationLifecycleSnapshot, error) {
	var out value.OperationLifecycleSnapshot
	e := s.transaction(ctx, id, func(_ operationLifecycleQueries, _ custodydb.OperationAudit, _ custodydb.OperationAuditLifecycle, state value.OperationLifecycleSnapshot, _, until time.Time) (time.Time, error) {
		out = state
		return until, nil
	})
	if e != nil {
		return value.OperationLifecycleSnapshot{}, e
	}
	return out, nil
}
func (s *OperationLifecycles) RecordOperationCompletion(ctx context.Context, in value.OperationIntent, phase string, c value.OperationWriteCompletion) error {
	if !in.Valid() || in.Lifecycle == nil || (phase != "intent" && phase != "outcome") || !c.Valid(in.RootID, in.ID, in.Lifecycle.Policy.StoreID, phase, in.CreatedAt, in.WriteUntil) {
		return app.ErrUnavailable
	}
	return s.transaction(ctx, in.ID, func(q operationLifecycleQueries, a custodydb.OperationAudit, _ custodydb.OperationAuditLifecycle, state value.OperationLifecycleSnapshot, now, _ time.Time) (time.Time, error) {
		if !sameAuditJSON(state.Intent, in) || !now.Before(in.WriteUntil) {
			return time.Time{}, app.ErrUnavailable
		}
		existing := state.IntentWriter
		var record any = in
		started := a.IntentStarted
		if phase == "outcome" {
			existing = state.OutcomeWriter
			started = a.OutcomeStarted
			var out value.OperationOutcome
			if json.Unmarshal(a.Outcome, &out) != nil {
				return time.Time{}, app.ErrUnavailable
			}
			record = out
		}
		if !started || c.RecordDigest != app.OperationLifecycleDigest(record) {
			return time.Time{}, app.ErrUnavailable
		}
		if existing != nil {
			if !sameAuditJSON(*existing, c) {
				return time.Time{}, app.ErrUnavailable
			}
			return in.WriteUntil, nil
		}
		b, _ := json.Marshal(c)
		var n int64
		var e error
		if phase == "intent" {
			n, e = q.CompleteOperationIntent(ctx, custodydb.CompleteOperationIntentParams{RootID: id(in.RootID), OperationID: id(in.ID), IntentCompletion: b})
		} else {
			n, e = q.CompleteOperationOutcome(ctx, custodydb.CompleteOperationOutcomeParams{RootID: id(in.RootID), OperationID: id(in.ID), OutcomeCompletion: b})
		}
		if e != nil || n != 1 {
			return time.Time{}, app.ErrUnavailable
		}
		return in.WriteUntil, nil
	})
}
func (s *OperationLifecycles) ReadOperationCompletion(ctx context.Context, in value.OperationIntent, phase string) (value.OperationWriteCompletion, error) {
	var out value.OperationWriteCompletion
	e := s.transaction(ctx, in.ID, func(_ operationLifecycleQueries, _ custodydb.OperationAudit, _ custodydb.OperationAuditLifecycle, state value.OperationLifecycleSnapshot, now, _ time.Time) (time.Time, error) {
		if !sameAuditJSON(state.Intent, in) || !now.Before(in.WriteUntil) {
			return time.Time{}, app.ErrUnavailable
		}
		c := state.IntentWriter
		if phase == "outcome" {
			c = state.OutcomeWriter
		} else if phase != "intent" {
			return time.Time{}, app.ErrUnavailable
		}
		if c == nil {
			return time.Time{}, app.ErrUnavailable
		}
		out = *c
		return in.WriteUntil, nil
	})
	if e != nil {
		return value.OperationWriteCompletion{}, e
	}
	return out, nil
}
func (s *OperationLifecycles) BeginOperationPurge(ctx context.Context, operation, phase string) (value.OperationPurgeLease, error) {
	var out value.OperationPurgeLease
	e := s.transaction(ctx, operation, func(q operationLifecycleQueries, a custodydb.OperationAudit, d custodydb.OperationAuditLifecycle, state value.OperationLifecycleSnapshot, now, until time.Time) (time.Time, error) {
		if phase != "original" && phase != "terminal" && phase != "overdueOriginal" || state.IntentWriter == nil || state.OutcomeWriter == nil || len(a.IntentReceipt) == 0 || len(a.OutcomeReceipt) == 0 || now.Before(a.WriteUntil.Time) {
			return time.Time{}, app.ErrUnavailable
		}
		if state.Lease != nil && now.Before(state.Lease.Until) {
			if state.Lease.Phase != phase {
				return time.Time{}, app.ErrUnavailable
			}
			out = *state.Lease
			return out.Until, nil
		}
		b := state.Intent.Lifecycle
		if phase == "original" && (!state.OverdueSelectedAt.IsZero() || state.Retirement != nil || now.Before(b.OriginalPurgeAt) || !now.Before(b.CertificatePurgeAt.Add(-time.Duration(b.Policy.ProofWindowSeconds)*time.Second))) || phase == "overdueOriginal" && (b.Policy.OverdueTerminal != value.OperationOverdueTerminal || state.CertificateStarted || state.CertificateWriter != nil || state.CertificateReceipt != nil || now.Before(b.CertificatePurgeAt.Add(-time.Duration(b.Policy.ProofWindowSeconds)*time.Second))) || phase == "terminal" && (!state.OverdueSelectedAt.IsZero() || state.CertificateReceipt == nil || state.CertificateWriter == nil || now.Before(b.CertificatePurgeAt)) || d.LeaseFence >= b.Policy.MaxPurgeLeases {
			return time.Time{}, app.ErrUnavailable
		}
		if phase == "original" {
			until = identity.Earlier(until, b.CertificatePurgeAt.Add(-time.Duration(b.Policy.ProofWindowSeconds)*time.Second))
		}
		objects := []value.Receipt{state.IntentWriter.Receipt, state.OutcomeWriter.Receipt}
		if phase == "terminal" {
			objects = append(objects, *state.CertificateReceipt)
		}
		out = value.OperationPurgeLease{RootID: state.Intent.RootID, OperationID: operation, StoreID: b.Policy.StoreID, InstallationID: b.Policy.InstallationID, IssuerEpoch: uid(d.IssuerEpoch), Phase: phase, PostmasterAt: d.PostmasterAt.Time, DatabaseOID: d.DatabaseOid.Uint32, ObjectsDigest: app.OperationLifecycleDigest(objects), WritersDigest: app.OperationLifecycleDigest([]value.OperationWriteCompletion{*state.IntentWriter, *state.OutcomeWriter}), Fence: d.LeaseFence + 1, StartedAt: now, Until: until}
		if !out.Valid() {
			return time.Time{}, app.ErrUnavailable
		}
		encoded, _ := json.Marshal(out)
		var n int64
		var e error
		if phase == "overdueOriginal" {
			n, e = q.LeaseOverdueOperationPurge(ctx, custodydb.LeaseOverdueOperationPurgeParams{RootID: id(out.RootID), OperationID: id(operation), OverdueSelectedAt: ts(now), Lease: encoded, LeaseFence: out.Fence})
		} else {
			n, e = q.LeaseOperationPurge(ctx, custodydb.LeaseOperationPurgeParams{RootID: id(out.RootID), OperationID: id(operation), Lease: encoded, LeaseFence: out.Fence})
		}
		if e != nil || n != 1 {
			return time.Time{}, app.ErrUnavailable
		}
		return until, nil
	})
	if e != nil {
		return value.OperationPurgeLease{}, e
	}
	return out, nil
}
func (s *OperationLifecycles) RecordOriginalOperationPurge(ctx context.Context, l value.OperationPurgeLease) (value.OperationRetirement, error) {
	var out value.OperationRetirement
	if !l.Valid() || l.Phase != "original" {
		return out, app.ErrUnavailable
	}
	e := s.transaction(ctx, l.OperationID, func(q operationLifecycleQueries, _ custodydb.OperationAudit, _ custodydb.OperationAuditLifecycle, state value.OperationLifecycleSnapshot, now, _ time.Time) (time.Time, error) {
		if state.Lease == nil || !sameAuditJSON(*state.Lease, l) || !now.Before(l.Until) {
			return time.Time{}, app.ErrUnavailable
		}
		if state.Retirement != nil {
			out = *state.Retirement
			return l.Until, nil
		}
		b := state.Intent.Lifecycle
		out = value.OperationRetirement{RootID: l.RootID, OperationID: l.OperationID, StoreID: l.StoreID, InstallationID: l.InstallationID, IssuerEpoch: l.IssuerEpoch, PostmasterAt: l.PostmasterAt, DatabaseOID: l.DatabaseOID, ObjectsDigest: l.ObjectsDigest, WritersDigest: l.WritersDigest, PurgeFence: l.Fence, PurgedAt: now, CertificateWriteUntil: identity.Earlier(now.Add(30*time.Second), b.CertificatePurgeAt.Add(-time.Duration(b.Policy.ProofWindowSeconds)*time.Second)), CertificatePurgeAt: b.CertificatePurgeAt, LiveRetireBy: b.LiveRetireBy}
		if !out.Valid() {
			return time.Time{}, app.ErrUnavailable
		}
		encoded, _ := json.Marshal(out)
		n, e := q.SaveOriginalOperationPurge(ctx, custodydb.SaveOriginalOperationPurgeParams{RootID: id(l.RootID), OperationID: id(l.OperationID), Retirement: encoded})
		if e != nil || n != 1 {
			return time.Time{}, app.ErrUnavailable
		}
		return l.Until, nil
	})
	if e != nil {
		return value.OperationRetirement{}, e
	}
	return out, nil
}
func (s *OperationLifecycles) ClaimOperationCertificate(ctx context.Context, r value.OperationRetirement) (bool, error) {
	fresh := false
	if !r.Valid() {
		return false, app.ErrUnavailable
	}
	e := s.transaction(ctx, r.OperationID, func(q operationLifecycleQueries, _ custodydb.OperationAudit, _ custodydb.OperationAuditLifecycle, state value.OperationLifecycleSnapshot, now, _ time.Time) (time.Time, error) {
		fresh = false
		if !state.OverdueSelectedAt.IsZero() || state.Retirement == nil || !sameAuditJSON(*state.Retirement, r) || !now.Before(r.CertificateWriteUntil) {
			return time.Time{}, app.ErrUnavailable
		}
		if state.CertificateStarted {
			return r.CertificateWriteUntil, nil
		}
		n, e := q.ClaimOperationCertificate(ctx, custodydb.ClaimOperationCertificateParams{RootID: id(r.RootID), OperationID: id(r.OperationID)})
		if e != nil || n != 1 {
			return time.Time{}, app.ErrUnavailable
		}
		fresh = true
		return r.CertificateWriteUntil, nil
	})
	if e != nil {
		return false, e
	}
	return fresh, nil
}
func (s *OperationLifecycles) RecordCertificateCompletion(ctx context.Context, r value.OperationRetirement, c value.OperationWriteCompletion) error {
	if !r.Valid() || !c.Valid(r.RootID, r.OperationID, r.StoreID, "deletion-certificate", r.PurgedAt, r.CertificateWriteUntil) || c.RecordDigest != app.OperationLifecycleDigest(r) {
		return app.ErrUnavailable
	}
	return s.transaction(ctx, r.OperationID, func(q operationLifecycleQueries, _ custodydb.OperationAudit, _ custodydb.OperationAuditLifecycle, state value.OperationLifecycleSnapshot, now, _ time.Time) (time.Time, error) {
		if state.Retirement == nil || !sameAuditJSON(*state.Retirement, r) || !state.CertificateStarted || !now.Before(r.CertificateWriteUntil) {
			return time.Time{}, app.ErrUnavailable
		}
		if state.CertificateWriter != nil {
			if !sameAuditJSON(*state.CertificateWriter, c) {
				return time.Time{}, app.ErrUnavailable
			}
			return r.CertificateWriteUntil, nil
		}
		b, _ := json.Marshal(c)
		n, e := q.CompleteOperationCertificate(ctx, custodydb.CompleteOperationCertificateParams{RootID: id(r.RootID), OperationID: id(r.OperationID), CertificateCompletion: b})
		if e != nil || n != 1 {
			return time.Time{}, app.ErrUnavailable
		}
		return r.CertificateWriteUntil, nil
	})
}

// ClaimOperationCertificateVerification spends before provider I/O. The current
// recovery observation, original caller interval and immutable certificate end
// all survive blocking locks. Unknown transaction replies never return a permit.
func (s *OperationLifecycles) ClaimOperationCertificateVerification(ctx context.Context, r value.OperationRetirement, receipt value.Receipt) (time.Time, error) {
	if ctx == nil || ctx.Err() != nil || !r.Valid() || !receipt.ValidOperationRetirement(r.RootID, r.OperationID) {
		return time.Time{}, app.ErrUnavailable
	}
	until := identity.Earlier(time.Now().UTC().Truncate(time.Microsecond).Add(5*time.Second), r.CertificateWriteUntil)
	ctx, cancel := context.WithDeadline(ctx, until)
	defer cancel()
	if end, ok := ctx.Deadline(); ok {
		until = identity.Earlier(until, end)
	}
	e := s.transaction(ctx, r.OperationID, func(q operationLifecycleQueries, _ custodydb.OperationAudit, _ custodydb.OperationAuditLifecycle, state value.OperationLifecycleSnapshot, now, current time.Time) (time.Time, error) {
		if !state.Intent.Lifecycle.Policy.CertificateVerificationBacked() || state.Retirement == nil || !sameAuditJSON(*state.Retirement, r) || state.CertificateWriter == nil || !sameAuditJSON(state.CertificateWriter.Receipt, receipt) || state.CertificateReceipt != nil || state.CertificateVerifyAttempts >= 2 || !state.OverdueSelectedAt.IsZero() {
			return time.Time{}, app.ErrUnavailable
		}
		until = identity.Earlier(until, current)
		if !now.Before(until) {
			return time.Time{}, app.ErrUnavailable
		}
		n, e := q.ClaimOperationCertificateVerification(ctx, custodydb.ClaimOperationCertificateVerificationParams{RootID: id(r.RootID), OperationID: id(r.OperationID)})
		if e != nil || n != 1 {
			return time.Time{}, app.ErrUnavailable
		}
		return until, nil
	})
	if e != nil || ctx.Err() != nil || !time.Now().Before(until) {
		return time.Time{}, app.ErrUnavailable
	}
	return until, nil
}
func (s *OperationLifecycles) AcknowledgeOperationCertificate(ctx context.Context, r value.OperationRetirement, receipt value.Receipt) error {
	if !r.Valid() || !receipt.ValidOperationRetirement(r.RootID, r.OperationID) {
		return app.ErrUnavailable
	}
	return s.transaction(ctx, r.OperationID, func(q operationLifecycleQueries, _ custodydb.OperationAudit, _ custodydb.OperationAuditLifecycle, state value.OperationLifecycleSnapshot, now, _ time.Time) (time.Time, error) {
		if state.Retirement == nil || !sameAuditJSON(*state.Retirement, r) || state.CertificateWriter == nil || !sameAuditJSON(state.CertificateWriter.Receipt, receipt) || !now.Before(r.CertificateWriteUntil) {
			return time.Time{}, app.ErrUnavailable
		}
		if state.CertificateReceipt != nil {
			if !sameAuditJSON(*state.CertificateReceipt, receipt) {
				return time.Time{}, app.ErrUnavailable
			}
			return r.CertificateWriteUntil, nil
		}
		if !state.Intent.Lifecycle.Policy.CertificateVerificationBacked() || state.CertificateVerifyAttempts < 1 {
			return time.Time{}, app.ErrUnavailable
		}
		b, _ := json.Marshal(receipt)
		n, e := q.AckOperationCertificate(ctx, custodydb.AckOperationCertificateParams{RootID: id(r.RootID), OperationID: id(r.OperationID), CertificateReceipt: b})
		if e != nil || n != 1 {
			return time.Time{}, app.ErrUnavailable
		}
		return r.CertificateWriteUntil, nil
	})
}
func (s *OperationLifecycles) RecordTerminalOperationPurge(ctx context.Context, l value.OperationPurgeLease) (value.OperationTerminalPurge, error) {
	var out value.OperationTerminalPurge
	if !l.Valid() || l.Phase != "terminal" {
		return out, app.ErrUnavailable
	}
	e := s.transaction(ctx, l.OperationID, func(q operationLifecycleQueries, _ custodydb.OperationAudit, _ custodydb.OperationAuditLifecycle, state value.OperationLifecycleSnapshot, now, _ time.Time) (time.Time, error) {
		if state.Lease == nil || !sameAuditJSON(*state.Lease, l) || !now.Before(l.Until) || state.Retirement == nil || state.CertificateReceipt == nil {
			return time.Time{}, app.ErrUnavailable
		}
		if state.Terminal != nil {
			out = *state.Terminal
			return l.Until, nil
		}
		out = value.OperationTerminalPurge{RootID: l.RootID, OperationID: l.OperationID, RetirementDigest: app.OperationLifecycleDigest(*state.Retirement), CertificateDigest: app.OperationLifecycleDigest(*state.CertificateReceipt), Fence: l.Fence, PurgedAt: now, LeaseUntil: l.Until}
		if !out.Valid() {
			return time.Time{}, app.ErrUnavailable
		}
		b, _ := json.Marshal(out)
		n, e := q.SaveTerminalOperationPurge(ctx, custodydb.SaveTerminalOperationPurgeParams{RootID: id(l.RootID), OperationID: id(l.OperationID), TerminalPurge: b})
		if e != nil || n != 1 {
			return time.Time{}, app.ErrUnavailable
		}
		return l.Until, nil
	})
	if e != nil {
		return value.OperationTerminalPurge{}, e
	}
	return out, nil
}
func (s *OperationLifecycles) AcknowledgeTerminalOperationPurge(ctx context.Context, l value.OperationPurgeLease, p value.OperationTerminalPurge) error {
	if !l.Valid() || !p.Valid() || l.Phase != "terminal" || l.Fence != p.Fence {
		return app.ErrUnavailable
	}
	return s.transaction(ctx, l.OperationID, func(q operationLifecycleQueries, _ custodydb.OperationAudit, _ custodydb.OperationAuditLifecycle, state value.OperationLifecycleSnapshot, now, _ time.Time) (time.Time, error) {
		if state.Lease == nil || !sameAuditJSON(*state.Lease, l) || state.Terminal == nil || !sameAuditJSON(*state.Terminal, p) || !now.Before(l.Until) {
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
func (s *OperationLifecycles) RetireOperationAudit(ctx context.Context, operation string) error {
	return s.transaction(ctx, operation, func(q operationLifecycleQueries, _ custodydb.OperationAudit, _ custodydb.OperationAuditLifecycle, state value.OperationLifecycleSnapshot, now, _ time.Time) (time.Time, error) {
		if !state.TerminalAcknowledged || state.Terminal == nil && state.OverduePurge == nil || state.Lease == nil || !now.Before(state.Lease.Until) {
			return time.Time{}, app.ErrUnavailable
		}
		ok, e := q.FinishOperationRetirement(ctx, custodydb.FinishOperationRetirementParams{R: id(s.journal.root), I: id(operation), Installation: id(s.journal.recovery.installation)})
		if e != nil || !ok {
			return time.Time{}, app.ErrUnavailable
		}
		return state.Lease.Until, nil
	})
}

var _ app.OperationHistoryJournal = (*OperationLifecycles)(nil)
var _ app.OperationHistoryFinalizer = (*OperationLifecycles)(nil)

func (s *OperationLifecycles) DueOperationHistory(ctx context.Context) ([]value.OperationHistoryKey, error) {
	if s == nil || s.journal == nil || ctx == nil || ctx.Err() != nil {
		return nil, app.ErrUnavailable
	}
	j := s.journal
	var out []value.OperationHistoryKey
	err := j.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		trust, start, e := j.trust(ctx, q)
		if e != nil {
			return e
		}
		rows, e := s.queries(q).DueOperationAuditHistory(ctx, custodydb.DueOperationAuditHistoryParams{RootID: id(j.root), Lane: j.lane})
		if e != nil {
			return e
		}
		for _, r := range rows {
			var k value.OperationHistoryKey
			k.RootID, k.Lane, k.ReleaseAt, k.DeleteBy = uid(r.RootID), r.Lane, r.ReleaseAt.Time, r.DeleteBy.Time
			if len(r.PrincipalDigest) != len(k.PrincipalDigest) {
				return app.ErrUnavailable
			}
			copy(k.PrincipalDigest[:], r.PrincipalDigest)
			if !k.Valid() || k.RootID != j.root || k.Lane != j.lane {
				return app.ErrUnavailable
			}
			out = append(out, k)
		}
		return auditCurrent(ctx, q, trust, start, identity.Earlier(start.Add(5*time.Second), trust.FreshUntil.Time))
	})
	if err != nil || ctx.Err() != nil {
		return nil, app.ErrUnavailable
	}
	return out, nil
}
func (s *OperationLifecycles) ReleaseOperationHistory(ctx context.Context, k value.OperationHistoryKey) (value.OperationHistoryRelease, error) {
	var out value.OperationHistoryRelease
	if s == nil || s.journal == nil || ctx == nil || ctx.Err() != nil || !k.Valid() || k.RootID != s.journal.root || k.Lane != s.journal.lane {
		return out, app.ErrUnavailable
	}
	j := s.journal
	err := j.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		trust, start, e := j.trust(ctx, q)
		if e != nil {
			return e
		}
		// The fixed function uses the same recovery->pool->account->history order,
		// verifies the original admission incarnation, and drains exactly once.
		r, e := s.queries(q).FinishOperationHistory(ctx, custodydb.FinishOperationHistoryParams{R: id(k.RootID), L: k.Lane, P: k.PrincipalDigest[:], Releases: ts(k.ReleaseAt), Deletes: ts(k.DeleteBy), Installation: id(j.recovery.installation)})
		if e != nil {
			return e
		}
		if r.Records < 0 {
			return app.ErrUnavailable
		}
		out = value.OperationHistoryRelease{Records: r.Records, Overdue: r.Overdue}
		return auditCurrent(ctx, q, trust, start, identity.Earlier(start.Add(5*time.Second), trust.FreshUntil.Time))
	})
	if err != nil || ctx.Err() != nil {
		return value.OperationHistoryRelease{}, app.ErrUnavailable
	}
	return out, nil
}

func operationLifecycleIncarnation(d custodydb.OperationAuditLifecycle, t custodydb.FleetCurrentTrust, current custodydb.ReadContextDatabaseIncarnationRow, installation string) bool {
	return uid(d.InstallationID) == installation && d.IssuerEpoch == t.IssuerEpoch && d.PostmasterAt.Valid && current.PostmasterAt.Valid && d.PostmasterAt.Time.Equal(current.PostmasterAt.Time) && d.DatabaseOid.Valid && d.DatabaseOid == current.DatabaseOid
}
