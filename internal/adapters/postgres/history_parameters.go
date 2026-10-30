package postgres

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"time"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	custodyprivacy "asservat.local/asservat/internal/application/privacy"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/identity"
	privacy "asservat.local/asservat/internal/domain/privacy"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

// HistoryParametersLedger shares ordinary custody accounting but has separate
// current-history authority and physical-prefix retirement. A generic evidence
// cleanup result can never settle one of these obligations.
type HistoryParametersLedger struct {
	ledger    *Ledger
	root      string
	recovery  *RecoveryTransactionGuard
	retention *RetentionTransactionGuard
}

func NewHistoryParameters(ctx context.Context, pool *pgxpool.Pool, root string, guards EffectTransactionGuards) (*HistoryParametersLedger, error) {
	l, e := New(ctx, pool)
	if e != nil {
		return nil, e
	}
	g, e := effectGuardsFor(root, []EffectTransactionGuards{guards})
	if e != nil {
		return nil, e
	}
	return &HistoryParametersLedger{ledger: l, root: root, recovery: g.Recovery, retention: g.Retention}, nil
}

func decodeHistoryExpectation(h custodydb.CaptureHistoryParameter) (value.HistoryExpectation, error) {
	var e value.HistoryExpectation
	if len(h.ExpectationJson) > 8192 || json.Unmarshal(h.ExpectationJson, &e) != nil || !e.Valid() || id(e.RootID) != h.RootID || id(e.CaptureID) != h.CaptureID || id(e.Registration.Location.AttemptID) != h.AttemptID || !bytes.Equal(e.SelectorKey[:], h.SelectorKey) || !bytes.Equal(e.SettingsKey[:], h.SettingsKey) || e.MACVersion != h.MacVersion {
		return e, value.ErrUnavailable
	}
	return e, nil
}
func historyStorage(ctx context.Context, q *custodydb.Queries, h custodydb.CaptureHistoryParameter) (value.HistoryStorage, error) {
	var out value.HistoryStorage
	e, err := decodeHistoryExpectation(h)
	if err != nil {
		return out, err
	}
	a, err := q.ReadAttempt(ctx, h.AttemptID)
	if err != nil {
		return out, err
	}
	r, err := record(ctx, q, a, e.Registration.StoreID)
	if err != nil || !r.Registration.Equal(e.Registration) {
		return out, value.ErrUnavailable
	}
	// An old restored header cannot override the generic deletion tombstone
	// or an incomplete writer. Both persisted records must agree on storage.
	if h.State == "available" && r.State != artifact.StoredUnpublished {
		return out, value.ErrSettingsUnavailable
	}
	var retention value.HistoryRetention
	if json.Unmarshal(h.RetentionJson, &retention) != nil || !retention.Valid() {
		return out, value.ErrUnavailable
	}
	out = value.HistoryStorage{Expectation: e, Copies: r.Copies, State: h.State, SummaryExpiresAt: h.SummaryExpiresAt.Time, Target: retention.Input.Target, Retention: retention, Effective: r.Effective}
	return out, nil
}
func (s *HistoryParametersLedger) transaction(ctx context.Context, r artifact.RecoveryProof, f func(*custodydb.Queries, custodydb.FleetCurrentTrust, custodydb.PermissionStream) error) error {
	if s == nil || ctx == nil {
		return value.ErrUnavailable
	}
	return s.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		trust, e := s.recovery.lock(ctx, q, s.root, r)
		if e != nil {
			return e
		}
		stream, e := q.LockPermissionStream(ctx, id(s.root))
		if e != nil {
			return e
		}
		if e = f(q, trust, stream); e != nil {
			return e
		}
		return s.recovery.check(ctx, q, trust, s.root, r)
	})
}

func (s *HistoryParametersLedger) ReserveHistoryParameters(ctx context.Context, in value.HistoryReservation) (value.HistoryStorage, error) {
	var out value.HistoryStorage
	e := in.Expectation
	if s == nil || !e.Valid() || e.RootID != s.root || !in.Limits.Valid() || !in.Retention.Target.Valid() || !in.Retention.Proof.Valid(in.Retention.Proof.ObservedAt) {
		return out, value.ErrInvalid
	}
	topology, err := s.retention.observe(ctx, e.Registration.Location.ClusterID)
	if err != nil {
		return out, err
	}
	err = s.transaction(ctx, in.Recovery, func(q *custodydb.Queries, trust custodydb.FleetCurrentTrust, stream custodydb.PermissionStream) error {
		c, until, err := historyAuthorizedCapture(ctx, q, s.root, s.recovery.installationID(), e.CaptureID, in.Identity, stream, trust, true)
		if err != nil {
			return err
		}
		original := c.Backing
		if e.OriginalExecutionDigest != c.ScopeDigest || e.Registration.Location.ClusterID != original.ClusterID || e.Registration.AllocationID != original.AllocationID || !e.Registration.AnchorAt.Equal(c.CreatedAt.Time) || in.SummaryExpiresAt.After(in.Retention.ExpiresAt) || e.Registration.ExpiresAt.After(in.SummaryExpiresAt) || !e.Registration.WriteUntil.After(c.CreatedAt.Time) {
			return value.ErrInvalid
		}
		if in.Retention.Target != c.Target {
			return value.ErrDenied
		}
		if err = s.retention.check(ctx, q, topology, in.Retention.Proof, c.Target); err != nil {
			return err
		}
		if existing, err := q.LockHistoryParameter(ctx, custodydb.LockHistoryParameterParams{RootID: id(s.root), CaptureID: id(e.CaptureID)}); err == nil {
			old, err := decodeHistoryExpectation(existing)
			if err != nil || value.HistoryExpectationDigest(old) != value.HistoryExpectationDigest(e) {
				return value.ErrConflict
			}
			out, err = historyStorage(ctx, q, existing)
			return err
		} else if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		// Validate source authority before quota eviction can hide that same
		// source. Permission/recovery locks serialize this complete transaction.
		if c.RepeatedFromCaptureID.Valid && (in.Source == nil || in.Source.CaptureID != uid(c.RepeatedFromCaptureID) || in.Source.ExpiresAt.After(c.RepeatedFromExpiresAt.Time)) {
			return value.ErrDenied
		}
		retention := value.HistoryRetention{Input: privacy.Input{ControlKind: "case-metadata", Target: c.Target, PrivacyClass: in.Retention.PrivacyClass, EvidenceType: "other", RequestedSeconds: in.Retention.RequestedSeconds, AnchorAt: e.Registration.AnchorAt}, Origins: in.Retention.Policies}
		if in.Source != nil {
			if !in.Source.Valid(in.Identity.VerifiedAt) || !c.RepeatedFromCaptureID.Valid || uid(c.RepeatedFromCaptureID) != in.Source.CaptureID || e.Registration.ExpiresAt.After(in.Source.ExpiresAt) {
				return value.ErrDenied
			}
			source, _, err := historyAuthorizedCapture(ctx, q, s.root, s.recovery.installationID(), in.Source.CaptureID, in.Identity, stream, trust, false)
			if err != nil {
				return err
			}
			if source.HistoryParametersRequired {
				h, err := q.ReadHistoryParameter(ctx, custodydb.ReadHistoryParameterParams{RootID: id(s.root), CaptureID: source.ID})
				if err != nil || !h.Visible || h.State != "available" {
					return value.ErrSettingsUnavailable
				}
				sourceStorage, err := historyStorage(ctx, q, h)
				if err != nil {
					return err
				}
				if in.Source.ExpiresAt.After(sourceStorage.Effective.ExpiresAt) || in.Source.ExpiresAt.After(h.SummaryExpiresAt.Time) {
					return value.ErrChanged
				}
				retention.Origins, err = privacy.MergePolicyOrigins(retention.Origins, sourceStorage.Retention.Origins)
				if err != nil {
					return err
				}
			} else if in.Source.ExpiresAt.After(source.CreatedAt.Time.Add(value.HistoryLifetime)) {
				return value.ErrChanged
			}
			retention.SourceCutoff = in.Source.ExpiresAt
			until = identity.Earlier(until, in.Source.ExpiresAt)
		}
		pool, allocation, err := lockAllocation(ctx, q, e.Registration.AllocationID)
		if err != nil {
			return err
		}
		if _, err = registerLocked(ctx, q, pool, allocation, normalized(e.Registration)); err != nil {
			return err
		}
		// Root then selector counters serialize ceilings. Evict only projections
		// charged to this same originating allocation; live evidence is untouched.
		zero := make([]byte, 32)
		for _, key := range [][]byte{zero, e.SelectorKey[:]} {
			if err = q.EnsureHistoryQuota(ctx, custodydb.EnsureHistoryQuotaParams{RootID: id(s.root), SelectorKey: key}); err != nil {
				return err
			}
		}
		rootCount, err := q.LockHistoryQuota(ctx, custodydb.LockHistoryQuotaParams{RootID: id(s.root), SelectorKey: zero})
		if err != nil {
			return err
		}
		selectorCount, err := q.LockHistoryQuota(ctx, custodydb.LockHistoryQuotaParams{RootID: id(s.root), SelectorKey: e.SelectorKey[:]})
		if err != nil {
			return err
		}
		if int(rootCount) >= in.Limits.PerInstallation || int(selectorCount) >= in.Limits.PerSelector {
			var key []byte
			if int(selectorCount) >= in.Limits.PerSelector {
				key = e.SelectorKey[:]
			}
			candidates, err := q.ListHistoryEvictionCandidates(ctx, custodydb.ListHistoryEvictionCandidatesParams{RootID: id(s.root), AllocationID: id(e.Registration.AllocationID), Selector: key})
			if err != nil {
				return err
			}
			for _, old := range candidates {
				changed, err := q.HideHistoryParameter(ctx, custodydb.HideHistoryParameterParams{RootID: id(s.root), CaptureID: old.CaptureID})
				if err != nil {
					return err
				}
				if changed != 1 {
					return custodyprivacy.ErrFence
				}
				changed, err = q.ChangeHistoryQuota(ctx, custodydb.ChangeHistoryQuotaParams{RootID: id(s.root), SelectorKey: zero, Amount: -1, Maximum: value.MaxHistoryPerInstallation})
				if err != nil {
					return err
				}
				if changed != 1 {
					return custodyprivacy.ErrFence
				}
				changed, err = q.ChangeHistoryQuota(ctx, custodydb.ChangeHistoryQuotaParams{RootID: id(s.root), SelectorKey: old.SelectorKey, Amount: -1, Maximum: value.MaxHistoryPerSelector})
				if err != nil {
					return err
				}
				if changed != 1 {
					return custodyprivacy.ErrFence
				}
				rootCount--
				if bytes.Equal(old.SelectorKey, e.SelectorKey[:]) {
					selectorCount--
				}
				if int(rootCount) < in.Limits.PerInstallation && int(selectorCount) < in.Limits.PerSelector {
					break
				}
			}
		}
		if int(rootCount) >= in.Limits.PerInstallation || int(selectorCount) >= in.Limits.PerSelector {
			return value.ErrCapacity
		}
		for _, entry := range []struct {
			key []byte
			max int
		}{{zero, in.Limits.PerInstallation}, {e.SelectorKey[:], in.Limits.PerSelector}} {
			n, err := q.ChangeHistoryQuota(ctx, custodydb.ChangeHistoryQuotaParams{RootID: id(s.root), SelectorKey: entry.key, Amount: 1, Maximum: int32(entry.max)})
			if err != nil {
				return err
			}
			if n != 1 {
				return value.ErrCapacity
			}
		}

		encoded, _ := json.Marshal(e)
		retained, _ := json.Marshal(retention)
		if err = q.InsertHistoryParameter(ctx, custodydb.InsertHistoryParameterParams{RootID: id(s.root), CaptureID: id(e.CaptureID), AttemptID: id(e.Registration.Location.AttemptID), SelectorKey: e.SelectorKey[:], SettingsKey: e.SettingsKey[:], MacVersion: e.MACVersion, ExpectationJson: encoded, RetentionJson: retained, SummaryExpiresAt: ts(in.SummaryExpiresAt), CreatedAt: c.CreatedAt}); err != nil {
			return err
		}
		now, err := q.CurrentTime(ctx)
		if err != nil {
			return err
		}
		if !now.Time.Before(until) || !in.Identity.Valid(now.Time) {
			return value.ErrDenied
		}
		out = value.HistoryStorage{Expectation: e, State: "reserved", SummaryExpiresAt: in.SummaryExpiresAt, ObservedAt: now.Time, ValidUntil: identity.Earlier(until, in.Recovery.FreshUntil), Target: c.Target, Retention: retention, Effective: privacy.Deadlines{AnchorAt: e.Registration.AnchorAt, ExpiresAt: e.Registration.ExpiresAt, DeleteBy: e.Registration.DeleteBy}}
		return s.retention.check(ctx, q, topology, in.Retention.Proof, c.Target)
	})
	if err != nil {
		return value.HistoryStorage{}, err
	}
	return out, nil
}

func (s *HistoryParametersLedger) ClaimHistoryWrite(ctx context.Context, in value.HistoryWriteRequest) (value.HistoryOperationAuthority, error) {
	var out value.HistoryOperationAuthority
	e := in.Storage.Expectation
	if !e.Valid() || e.RootID != s.root || !authorization.UUID(in.RequestID) || !authorization.UUID(in.ExecutorEpoch) || in.BundleDigest == (artifact.Digest{}) {
		return out, value.ErrInvalid
	}
	err := s.transaction(ctx, in.Recovery, func(q *custodydb.Queries, trust custodydb.FleetCurrentTrust, stream custodydb.PermissionStream) error {
		_, until, err := historyAuthorizedCapture(ctx, q, s.root, s.recovery.installationID(), e.CaptureID, in.Identity, stream, trust, true)
		if err != nil {
			return err
		}
		h, err := q.LockHistoryParameter(ctx, custodydb.LockHistoryParameterParams{RootID: id(s.root), CaptureID: id(e.CaptureID)})
		if err != nil {
			return err
		}
		original, err := decodeHistoryExpectation(h)
		if err != nil || value.HistoryExpectationDigest(original) != value.HistoryExpectationDigest(e) {
			return value.ErrConflict
		}
		now, err := q.CurrentTime(ctx)
		if err != nil {
			return err
		}
		until = identity.Earlier(until, identity.Earlier(in.Recovery.FreshUntil, e.Registration.WriteUntil))
		if d, ok := ctx.Deadline(); ok {
			until = identity.Earlier(until, d)
		}
		until = until.UTC().Truncate(time.Microsecond)
		out = value.HistoryOperationAuthority{Expectation: e, Operation: "write", RequestID: in.RequestID, ExecutorEpoch: in.ExecutorEpoch, StartedAt: now.Time, NotAfter: until, BundleDigest: in.BundleDigest}
		if !out.Valid(now.Time) {
			return value.ErrUnavailable
		}
		n, err := q.ClaimHistoryParameterWrite(ctx, custodydb.ClaimHistoryParameterWriteParams{RootID: id(s.root), CaptureID: id(e.CaptureID), WriteID: id(in.RequestID), WriteDigest: in.BundleDigest[:], WriteStartedAt: ts(out.StartedAt), WriteUntil: ts(until), WriteExecutorEpoch: id(in.ExecutorEpoch)})
		if err != nil {
			return err
		}
		if n != 1 {
			return value.ErrConflict
		}
		return nil
	})
	return out, err
}

func (s *HistoryParametersLedger) CompleteHistoryWrite(ctx context.Context, in value.HistoryWriteResult) error {
	a, e := in.Authority, in.Authority.Expectation
	if s == nil || a.Operation != "write" || e.RootID != s.root || !in.Completion.Valid(e) || in.Completion.OperationID != a.RequestID || in.Completion.ProcessEpoch != a.ExecutorEpoch || in.Completion.CopiesDigest != value.HistoryCopiesDigest(in.Copies) || !in.Completion.NotAfter.Equal(a.NotAfter) || in.Completion.CompletedAt.Before(a.StartedAt) || in.Copies.Validate(e.Registration) != nil {
		return value.ErrInvalid
	}
	return s.transaction(ctx, in.Recovery, func(q *custodydb.Queries, _ custodydb.FleetCurrentTrust, _ custodydb.PermissionStream) error {
		h, err := q.LockHistoryParameter(ctx, custodydb.LockHistoryParameterParams{RootID: id(s.root), CaptureID: id(e.CaptureID)})
		if err != nil {
			return err
		}
		if uid(h.WriteID) != a.RequestID || uid(h.WriteExecutorEpoch) != a.ExecutorEpoch || !h.WriteUntil.Time.Equal(a.NotAfter) || !h.WriteStartedAt.Time.Equal(a.StartedAt) || !bytes.Equal(h.WriteDigest, a.BundleDigest[:]) {
			return value.ErrConflict
		}
		if _, _, err = lockAllocation(ctx, q, e.Registration.AllocationID); err != nil {
			return err
		}
		attempt, err := q.LockAttempt(ctx, id(e.Registration.Location.AttemptID))
		if err != nil {
			return err
		}
		if !bytes.Equal(attempt.RequestDigest, digest(normalized(e.Registration))) {
			return value.ErrConflict
		}
		cd := value.HistoryCopiesDigest(in.Copies)
		if h.State == "available" {
			if !bytes.Equal(h.CopiesDigest, cd[:]) {
				return value.ErrConflict
			}
			return nil
		}
		if h.State != "write_claimed" || attempt.State != artifact.Reserved {
			return value.ErrConflict
		}
		for i, c := range in.Copies {
			if err = q.StoreCopy(ctx, custodydb.StoreCopyParams{AttemptID: attempt.ID, Role: int16(i), CiphertextBytes: pgtype.Int8{Int64: c.Bytes, Valid: true}, CiphertextSha256: c.SHA256[:], Etag: pgtype.Text{String: c.ETag, Valid: true}, VersionID: pgtype.Text{String: c.VersionID, Valid: c.VersionID != ""}}); err != nil {
				return err
			}
		}
		if err = q.MarkStored(ctx, custodydb.MarkStoredParams{ID: attempt.ID, CopiesDigest: digest(in.Copies)}); err != nil {
			return err
		}
		completion, _ := json.Marshal(in.Completion)
		n, err := q.CompleteHistoryParameterWrite(ctx, custodydb.CompleteHistoryParameterWriteParams{RootID: id(s.root), CaptureID: id(e.CaptureID), WriteID: id(a.RequestID), WriterCompletionJson: completion, CopiesDigest: cd[:]})
		if err != nil {
			return err
		}
		if n != 1 {
			return value.ErrConflict
		}
		return q.InsertEvent(ctx, custodydb.InsertEventParams{AttemptID: attempt.ID, Phase: "stored"})
	})
}

func (s *HistoryParametersLedger) AuthorizeHistoryRead(ctx context.Context, in value.HistoryReadRequest) (value.HistoryReadPermission, error) {
	var out value.HistoryReadPermission
	if s == nil || in.Query.RootID != s.root || !authorization.UUID(in.RequestID) || !authorization.UUID(in.ExecutorEpoch) {
		return out, value.ErrInvalid
	}
	if !in.Retention.Target.Valid() || !in.Retention.Proof.Valid(in.Retention.Proof.ObservedAt) {
		return out, value.ErrInvalid
	}
	topology, err := s.retention.observe(ctx, in.Retention.Target.ClusterID)
	if err != nil {
		return out, err
	}
	err = s.transaction(ctx, in.Query.Recovery, func(q *custodydb.Queries, trust custodydb.FleetCurrentTrust, stream custodydb.PermissionStream) error {
		c, until, err := historyAuthorizedCapture(ctx, q, s.root, s.recovery.installationID(), in.Query.CaptureID, in.Query.Identity, stream, trust, false)
		if err != nil {
			return err
		}
		h, err := q.ReadHistoryParameter(ctx, custodydb.ReadHistoryParameterParams{RootID: id(s.root), CaptureID: id(in.Query.CaptureID)})
		if err != nil {
			return value.ErrUnavailable
		}
		if h.State != "available" || !h.Visible {
			return value.ErrUnavailable
		}
		storage, err := historyStorage(ctx, q, h)
		if err != nil {
			return err
		}
		if in.Retention.Target != storage.Target {
			return value.ErrDenied
		}
		if err = s.retention.check(ctx, q, topology, in.Retention.Proof, storage.Target); err != nil {
			return err
		}
		if storage.Copies.Validate(storage.Expectation.Registration) != nil {
			return value.ErrUnavailable
		}
		now, err := q.CurrentTime(ctx)
		if err != nil {
			return err
		}
		until = identity.Earlier(until, identity.Earlier(in.Retention.ExpiresAt, in.Retention.ValidUntil))
		until = identity.Earlier(until, identity.Earlier(h.SummaryExpiresAt.Time, identity.Earlier(storage.Effective.ExpiresAt, in.Query.Recovery.FreshUntil)))
		if d, ok := ctx.Deadline(); ok {
			until = identity.Earlier(until, d)
		}
		storage.Origin = value.HistoryOrigin(c.HistoryOrigin.String)
		storage.ObservedAt, storage.ValidUntil = now.Time, until
		a := value.HistoryOperationAuthority{Expectation: storage.Expectation, Operation: "read", RequestID: in.RequestID, ExecutorEpoch: in.ExecutorEpoch, StartedAt: now.Time, NotAfter: until, CopiesDigest: value.HistoryCopiesDigest(storage.Copies)}
		if !a.Valid(now.Time) || !in.Query.Identity.Valid(now.Time) {
			return value.ErrDenied
		}
		out = value.HistoryReadPermission{Storage: storage, Authority: a}
		return s.retention.check(ctx, q, topology, in.Retention.Proof, storage.Target)
	})
	if err != nil {
		return value.HistoryReadPermission{}, err
	}
	return out, nil
}

// ClaimHistoryDeletion issues only history-prefix work. A claim with an
// uncertain writer cannot become deletion authority merely by waiting.
func (s *HistoryParametersLedger) ClaimHistoryDeletion(ctx context.Context, in value.HistoryDeleteRequest) (value.HistoryDeletePermission, error) {
	var out value.HistoryDeletePermission
	if !authorization.UUID(in.CaptureID) || !authorization.UUID(in.RequestID) || !authorization.UUID(in.ExecutorEpoch) {
		return out, value.ErrInvalid
	}
	err := s.transaction(ctx, in.Recovery, func(q *custodydb.Queries, _ custodydb.FleetCurrentTrust, _ custodydb.PermissionStream) error {
		h, err := q.LockHistoryParameter(ctx, custodydb.LockHistoryParameterParams{RootID: id(s.root), CaptureID: id(in.CaptureID)})
		if err != nil {
			return err
		}
		storage, err := historyStorage(ctx, q, h)
		if err != nil {
			return err
		}
		_, _, err = lockAllocation(ctx, q, storage.Expectation.Registration.AllocationID)
		if err != nil {
			return err
		}
		row, err := q.LockAttempt(ctx, h.AttemptID)
		if err != nil {
			return err
		}
		now, err := q.CurrentTime(ctx)
		if err != nil {
			return err
		}
		if h.State == "deleted" || h.State == "write_claimed" || (h.Visible && now.Time.Before(storage.Effective.ExpiresAt) && !(h.State == "reserved" && !now.Time.Before(row.WriteUntil.Time))) {
			return custodyprivacy.ErrNotDue
		}
		if h.WriteID.Valid {
			if json.Unmarshal(h.WriterCompletionJson, &out.Writer) != nil || !out.Writer.Valid(storage.Expectation) || !bytes.Equal(h.CopiesDigest, out.Writer.CopiesDigest[:]) {
				return custodyprivacy.ErrFence
			}
		} else if now.Time.Before(row.WriteUntil.Time) {
			return custodyprivacy.ErrNotDue
		}
		if row.LeaseUntil.Valid && now.Time.Before(row.LeaseUntil.Time) {
			return custodyprivacy.ErrFence
		}
		until := identity.Earlier(now.Time.Add(30*time.Second), in.Recovery.FreshUntil)
		if d, ok := ctx.Deadline(); ok {
			until = identity.Earlier(until, d)
		}
		until = until.UTC().Truncate(time.Microsecond)
		fence := row.DeletionFence + 1
		a := value.HistoryOperationAuthority{Expectation: storage.Expectation, Operation: "purge", RequestID: in.RequestID, ExecutorEpoch: in.ExecutorEpoch, StartedAt: now.Time, NotAfter: until, CopiesDigest: value.HistoryCopiesDigest(storage.Copies), DeletionFence: fence}
		if !a.Valid(now.Time) {
			return custodyprivacy.ErrFence
		}
		n, err := q.BindHistoryDelete(ctx, custodydb.BindHistoryDeleteParams{RootID: h.RootID, CaptureID: h.CaptureID, DeleteID: id(in.RequestID), DeleteExecutorEpoch: id(in.ExecutorEpoch), DeleteStartedAt: now, DeleteUntil: ts(until), DeleteFence: pgtype.Int8{Int64: fence, Valid: true}})
		if err != nil {
			return err
		}
		if n != 1 {
			return custodyprivacy.ErrConflict
		}
		claimed, err := q.ClaimDeletion(ctx, custodydb.ClaimDeletionParams{ID: h.AttemptID, LeaseUntil: ts(until)})
		if err != nil {
			return err
		}
		if claimed != fence {
			return custodyprivacy.ErrFence
		}
		out.Storage, out.Authority = storage, a
		return nil
	})
	if err != nil {
		return value.HistoryDeletePermission{}, err
	}
	return out, nil
}

// FinishHistoryDeletion consumes a positive authenticated inventory completion
// for the exact current operation/fence. Empty ordinary evidence prefixes are
// never sufficient to refund this registration.
func (s *HistoryParametersLedger) FinishHistoryDeletion(ctx context.Context, a value.HistoryOperationAuthority, c value.HistoryDeleteCompletion, recovery artifact.RecoveryProof) error {
	if a.Expectation.RootID != s.root || !c.Valid(a) {
		return value.ErrInvalid
	}
	return s.transaction(ctx, recovery, func(q *custodydb.Queries, _ custodydb.FleetCurrentTrust, _ custodydb.PermissionStream) error {
		h, err := q.LockHistoryParameter(ctx, custodydb.LockHistoryParameterParams{RootID: id(s.root), CaptureID: id(a.Expectation.CaptureID)})
		if err != nil {
			return err
		}
		e, err := decodeHistoryExpectation(h)
		if err != nil || value.HistoryExpectationDigest(e) != value.HistoryExpectationDigest(a.Expectation) {
			return custodyprivacy.ErrFence
		}
		_, allocation, err := lockAllocation(ctx, q, e.Registration.AllocationID)
		if err != nil {
			return err
		}
		row, err := q.LockAttempt(ctx, h.AttemptID)
		if err != nil {
			return err
		}
		if h.State == "deleted" && row.State == artifact.Deleted {
			var prior value.HistoryDeleteCompletion
			if json.Unmarshal(h.PurgeCompletionJson, &prior) == nil && prior == c {
				return nil
			}
			return custodyprivacy.ErrFence
		}
		now, err := q.CurrentTime(ctx)
		if err != nil {
			return err
		}
		if h.State != "deleting" || row.State != artifact.Deleting || uid(h.DeleteID) != a.RequestID || uid(h.DeleteExecutorEpoch) != a.ExecutorEpoch || !h.DeleteStartedAt.Time.Equal(a.StartedAt) || !h.DeleteUntil.Time.Equal(a.NotAfter) || h.DeleteFence.Int64 != a.DeletionFence || row.DeletionFence != a.DeletionFence || !row.LeaseUntil.Time.Equal(a.NotAfter) || !now.Time.Before(a.NotAfter) {
			return custodyprivacy.ErrFence
		}
		rec, err := record(ctx, q, row, e.Registration.StoreID)
		if err != nil || value.HistoryCopiesDigest(rec.Copies) != a.CopiesDigest {
			return custodyprivacy.ErrFence
		}
		encoded, err := json.Marshal(c)
		if err != nil {
			return err
		}
		changed, err := q.AcknowledgeHistoryPurge(ctx, custodydb.AcknowledgeHistoryPurgeParams{RootID: h.RootID, CaptureID: h.CaptureID, PurgeCompletionJson: encoded})
		if err != nil {
			return err
		}
		if changed != 1 {
			return custodyprivacy.ErrFence
		}
		changed, err = q.ReleaseCharge(ctx, custodydb.ReleaseChargeParams{ID: allocation.ID, ChargedBytes: row.ReservedBytes})
		if err != nil {
			return err
		}
		if changed != 1 {
			return custodyprivacy.ErrUnavailable
		}
		if err = q.ClearReceipts(ctx, row.ID); err != nil {
			return err
		}
		if err = q.MarkDeleted(ctx, custodydb.MarkDeletedParams{ID: row.ID, DeletedAt: now}); err != nil {
			return err
		}
		changed, err = q.MarkHistoryParameterDeleted(ctx, custodydb.MarkHistoryParameterDeletedParams{RootID: h.RootID, CaptureID: h.CaptureID})
		if err != nil {
			return err
		}
		if changed != 1 {
			return custodyprivacy.ErrConflict
		}
		return q.InsertEvent(ctx, custodydb.InsertEventParams{AttemptID: row.ID, Phase: "deleted"})
	})
}

// ReadHistoryStorage authorizes the minimized routing lookup. A returned row
// cannot authorize a regional effect; the selected live session must still be
// bound by AuthorizeHistoryRead under the original request deadline.
func (s *HistoryParametersLedger) ReadHistoryStorage(ctx context.Context, in value.SettingsQuery) (value.HistoryStorage, bool, error) {
	var out value.HistoryStorage
	required := false
	err := s.transaction(ctx, in.Recovery, func(q *custodydb.Queries, trust custodydb.FleetCurrentTrust, stream custodydb.PermissionStream) error {
		c, until, err := historyAuthorizedCapture(ctx, q, s.root, s.recovery.installationID(), in.CaptureID, in.Identity, stream, trust, false)
		if err != nil {
			return err
		}
		if !c.HistoryParametersRequired {
			return nil
		}
		required = true
		h, err := q.ReadHistoryParameter(ctx, custodydb.ReadHistoryParameterParams{RootID: id(s.root), CaptureID: id(in.CaptureID)})
		if err != nil {
			return value.ErrSettingsUnavailable
		}
		if !h.Visible || h.State != "available" {
			return value.ErrSettingsUnavailable
		}
		out, err = historyStorage(ctx, q, h)
		if err != nil {
			return err
		}
		now, err := q.CurrentTime(ctx)
		if err != nil {
			return err
		}
		out.Origin = value.HistoryOrigin(c.HistoryOrigin.String)
		out.ObservedAt = now.Time
		out.ValidUntil = identity.Earlier(until, identity.Earlier(h.SummaryExpiresAt.Time, out.Effective.ExpiresAt))
		if !now.Time.Before(out.ValidUntil) {
			return value.ErrSettingsUnavailable
		}
		return nil
	})
	if err != nil {
		return value.HistoryStorage{}, required, err
	}
	return out, required, nil
}

type historyRetirementHintDB struct{ custodydb.DBTX }

func (db historyRetirementHintDB) Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error) {
	// Cache only parameter/result descriptions for this date-sensitive hint.
	// A named generic plan reproduced 100k idle probes after five executions.
	// CacheDescribe keeps one steady round trip and plans the original bounds.
	return db.DBTX.Query(ctx, sql, append([]any{pgx.QueryExecModeCacheDescribe}, args...)...)
}

// ReadHistoryRetirementHints exposes only the generated routing query so the
// real-SQL cost regression exercises the production execution mode as well as
// its SQL. Returned IDs never grant read, write or deletion authority.
func ReadHistoryRetirementHints(ctx context.Context, db custodydb.DBTX, args custodydb.ListHistoryRetirementCandidatesParams) ([]custodydb.ListHistoryRetirementCandidatesRow, error) {
	return custodydb.New(historyRetirementHintDB{db}).ListHistoryRetirementCandidates(ctx, args)
}

// HistoryRetirementCandidates is a minimized bounded maintenance hint. It
// grants no deletion authority and includes no payload, key or object locator.
func (s *HistoryParametersLedger) HistoryRetirementCandidates(ctx context.Context, through time.Time, after string) ([]value.HistoryRetirementCandidate, error) {
	if s == nil || ctx == nil {
		return nil, value.ErrUnavailable
	}
	call, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	rows, err := ReadHistoryRetirementHints(call, s.ledger.pool, custodydb.ListHistoryRetirementCandidatesParams{RootID: id(s.root), Through: ts(through), AfterID: id(after)})
	if err != nil {
		return nil, value.ErrUnavailable
	}
	out := make([]value.HistoryRetirementCandidate, 0, len(rows))
	for _, r := range rows {
		out = append(out, value.HistoryRetirementCandidate{CaptureID: uid(r.CaptureID), ClusterID: uid(r.ClusterID), State: r.State})
	}
	return out, nil
}
func (s *HistoryParametersLedger) ExpireHistorySummaries(ctx context.Context, recovery artifact.RecoveryProof) error {
	return s.transaction(ctx, recovery, func(q *custodydb.Queries, _ custodydb.FleetCurrentTrust, _ custodydb.PermissionStream) error {
		now, err := q.CurrentTime(ctx)
		if err != nil {
			return err
		}
		rows, err := q.ListExpiredHistorySummaries(ctx, custodydb.ListExpiredHistorySummariesParams{RootID: id(s.root), Through: now})
		if err != nil {
			return err
		}
		zero := make([]byte, 32)
		for _, h := range rows {
			for _, key := range [][]byte{zero, h.SelectorKey} {
				_, err = q.LockHistoryQuota(ctx, custodydb.LockHistoryQuotaParams{RootID: h.RootID, SelectorKey: key})
				if err != nil {
					return err
				}
				changed, err := q.ChangeHistoryQuota(ctx, custodydb.ChangeHistoryQuotaParams{RootID: h.RootID, SelectorKey: key, Amount: -1, Maximum: value.MaxHistoryPerInstallation})
				if err != nil {
					return err
				}
				if changed != 1 {
					return custodyprivacy.ErrFence
				}
			}
			changed, err := q.HideHistoryParameter(ctx, custodydb.HideHistoryParameterParams{RootID: h.RootID, CaptureID: h.CaptureID})
			if err != nil {
				return err
			}
			if changed != 1 {
				return custodyprivacy.ErrFence
			}
		}
		if _, err = q.DeleteSettledHistoryParameters(ctx, custodydb.DeleteSettledHistoryParametersParams{RootID: id(s.root), Through: now}); err != nil {
			return err
		}
		if _, err = q.DeleteUnusedHistoryCounters(ctx, id(s.root)); err != nil {
			return err
		}
		return nil
	})
}
