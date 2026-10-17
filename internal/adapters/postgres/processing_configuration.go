package postgres

import (
	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	value "asservat.local/asservat/internal/domain/privacy"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ProcessingConfiguration holds independently accepted installation backing.
// Privacy operators cannot supply a bigger reservation through Change. This
// facet uses a distinct protected configuration credential and cannot mark the
// root complete or remove restrictions. An observed source alone never approves
// the row/index/WAL/backup measurements represented by accepted.
type ProcessingConfiguration struct {
	ledger           *Ledger
	recovery         *RecoveryTransactionGuard
	accepted         value.ProcessingBacking
	release          audit.OperationLifecyclePolicy
	epoch, sourceUID string
	guard            artifact.Digest
}

func NewProcessingConfiguration(ctx context.Context, pool *pgxpool.Pool, accepted value.ProcessingBacking, release audit.OperationLifecyclePolicy, epoch, sourceUID string, guard artifact.Digest, recovery *RecoveryTransactionGuard) (*ProcessingConfiguration, error) {
	if !accepted.Valid() || !release.CertificateVerificationBacked() || release.Lane != "processing" || release.History.Layout != audit.ProcessingReleaseHistoryLayout || release.RootID != accepted.RootID || release.InstallationID != accepted.InstallationID || release.MetadataSlots < accepted.MaxRules*16 || release.ValidUntil.Before(accepted.ValidUntil) || !authorization.UUID(epoch) || !authorization.UUID(sourceUID) || guard == (artifact.Digest{}) || recovery == nil || recovery.root != accepted.RootID || recovery.installation != accepted.InstallationID {
		return nil, value.ErrUnavailable
	}
	l, e := New(ctx, pool)
	if e != nil {
		return nil, value.ErrUnavailable
	}
	return &ProcessingConfiguration{l, recovery, accepted, release, epoch, sourceUID, guard}, nil
}
func (s *ProcessingConfiguration) AcceptCurrent(ctx context.Context, source value.DownloadPolicy, recovery artifact.RecoveryProof, expectedRevision int64) error {
	if s == nil || ctx == nil || ctx.Err() != nil || expectedRevision < 0 || source.RootID != s.accepted.RootID || source.InstallationID != s.accepted.InstallationID || source.Revision.UID != s.sourceUID || source.ProtectionDigest != s.guard || source.RecoveryEpoch != recovery.IssuerEpoch {
		return value.ErrUnavailable
	}
	until := identity.Earlier(source.FreshUntil, recovery.FreshUntil)
	call, stop := context.WithDeadline(ctx, until)
	defer stop()
	encoded, e := json.Marshal(s.accepted)
	if e != nil {
		return value.ErrUnavailable
	}
	releaseJSON, e := json.Marshal(s.release)
	if e != nil {
		return value.ErrUnavailable
	}
	e = s.ledger.transaction(call, func(q *custodydb.Queries) error {
		trust, e := s.recovery.lock(call, q, s.accepted.RootID, recovery)
		if e != nil {
			return e
		}
		if _, e = q.LockPermissionStream(call, id(s.accepted.RootID)); e != nil {
			return e
		}
		old, read := q.LockProcessingRoot(call, id(s.accepted.RootID))
		if read != nil && !errors.Is(read, pgx.ErrNoRows) {
			return read
		}
		now, e := q.CurrentTime(call)
		if e != nil || !source.Valid(now.Time) || source.Suspended || !recovery.Valid(now.Time) || !now.Time.Before(s.accepted.ValidUntil) {
			return value.ErrUnavailable
		}
		if errors.Is(read, pgx.ErrNoRows) {
			if expectedRevision != 0 {
				return value.ErrConflict
			}
			e = q.InsertProcessingRoot(call, custodydb.InsertProcessingRootParams{RootID: id(s.accepted.RootID), InstallationID: id(s.accepted.InstallationID), IssuerEpoch: id(recovery.IssuerEpoch), Epoch: id(s.epoch), SourceUid: id(s.sourceUID), ProtectionDigest: s.guard[:], Backing: encoded, ReleasePolicy: releaseJSON, ValidUntil: ts(s.accepted.ValidUntil), RetireBy: ts(s.accepted.RetireBy), MaxCaptures: s.accepted.MaxCaptures, MaxRules: s.accepted.MaxRules, MaxRootTransitions: s.accepted.MaxRootTransitions})
		} else {
			if uid(old.InstallationID) != s.accepted.InstallationID || uid(old.IssuerEpoch) != recovery.IssuerEpoch || uid(old.Epoch) != s.epoch || uid(old.SourceUid) != s.sourceUID || !bytes.Equal(old.ProtectionDigest, s.guard[:]) {
				return value.ErrConflict
			}
			var retained value.ProcessingBacking
			if json.Unmarshal(old.Backing, &retained) != nil {
				return value.ErrUnavailable
			}
			var priorRelease audit.OperationLifecyclePolicy
			if json.Unmarshal(old.ReleasePolicy, &priorRelease) != nil {
				return value.ErrUnavailable
			}
			if !sameAuditJSON(retained, s.accepted) || !sameAuditJSON(priorRelease, s.release) {
				if old.BackingRevision != expectedRevision {
					return value.ErrConflict
				}
				changed, e := q.UpdateProcessingBacking(call, custodydb.UpdateProcessingBackingParams{RootID: id(s.accepted.RootID), BackingRevision: expectedRevision, Backing: encoded, ReleasePolicy: releaseJSON, ValidUntil: ts(s.accepted.ValidUntil), RetireBy: ts(s.accepted.RetireBy), MaxCaptures: s.accepted.MaxCaptures, MaxRules: s.accepted.MaxRules, MaxRootTransitions: s.accepted.MaxRootTransitions})
				if e != nil {
					return e
				}
				if changed != 1 {
					return value.ErrConflict
				}
			}
		}
		if e != nil {
			return e
		}
		if e = s.recovery.check(call, q, trust, s.accepted.RootID, recovery); e != nil {
			return e
		}
		final, e := q.CurrentTime(call)
		if e != nil || !source.Valid(final.Time) || !recovery.Valid(final.Time) || !final.Time.Before(s.accepted.ValidUntil) || call.Err() != nil {
			return value.ErrUnavailable
		}
		return nil
	})
	if e != nil {
		return value.ErrUnavailable
	}
	return nil
}
