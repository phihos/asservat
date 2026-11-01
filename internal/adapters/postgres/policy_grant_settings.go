package postgres

import (
	"bytes"
	"context"
	"errors"
	"time"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	app "asservat.local/asservat/internal/application/authorization"
	"asservat.local/asservat/internal/application/configuration"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	"github.com/jackc/pgx/v5"
)

var _ configuration.PolicyGrantSettingsProjection = (*Policies)(nil)

func policyGrantSettingsObservation(row custodydb.PolicyGrantSetting) identity.PolicyGrantSettingsObservation {
	o := identity.PolicyGrantSettingsObservation{Issuer: row.Issuer,
		Revision:   identity.Revision{UID: row.SourceUid, Generation: row.SourceGeneration},
		ObservedAt: row.ObservedAt.Time, FreshUntil: row.FreshUntil.Time,
		Values: identity.PolicyGrantApproval{DefaultAge: time.Duration(row.DefaultAgeSeconds) * time.Second,
			MaxAge: time.Duration(row.MaxAgeSeconds) * time.Second, RenewalNotice: time.Duration(row.RenewalNoticeSeconds) * time.Second}}
	copy(o.Revision.Digest[:], row.SourceDigest)
	return o
}

// The existing permission root serializes the projection and grant issuance.
// A failed clamp or expired original observation rolls the entire change back.
func (s *Policies) AcceptPolicyGrantSettings(ctx context.Context, in identity.PolicyGrantSettingsObservation) error {
	if s == nil || ctx == nil || ctx.Err() != nil || !in.Valid(in.ObservedAt) {
		return identity.ErrInvalid
	}
	// PostgreSQL stores microseconds. Round down both original endpoints;
	// persistence must never manufacture a later freshness deadline.
	in.ObservedAt = in.ObservedAt.UTC().Truncate(time.Microsecond)
	in.FreshUntil = in.FreshUntil.UTC().Truncate(time.Microsecond)
	err := s.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		if _, err := q.LockPermissionStream(ctx, id(s.root)); err != nil {
			return err
		}
		now, err := q.CurrentTime(ctx)
		if err != nil {
			return err
		}
		if !in.Valid(now.Time) {
			return identity.ErrDenied
		}
		old, err := q.ReadPolicyGrantSettings(ctx, id(s.root))
		first := errors.Is(err, pgx.ErrNoRows)
		if err == nil {
			previous := policyGrantSettingsObservation(old)
			if uid(old.InstallationID) != s.installation || old.Issuer != in.Issuer || old.SourceUid != in.Revision.UID ||
				in.Revision.Generation < old.SourceGeneration || in.Revision.Generation == old.SourceGeneration && !bytes.Equal(old.SourceDigest, in.Revision.Digest[:]) ||
				in.ObservedAt.Before(previous.ObservedAt) || in.ObservedAt.Equal(previous.ObservedAt) && (in.Revision != previous.Revision || in.Values != previous.Values || !in.FreshUntil.Equal(previous.FreshUntil)) {
				return identity.ErrDenied
			}
			if in.Revision == previous.Revision && in.Values != previous.Values {
				return identity.ErrDenied
			}
		} else if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if err = q.WritePolicyGrantSettings(ctx, custodydb.WritePolicyGrantSettingsParams{RootID: id(s.root), InstallationID: id(s.installation), Issuer: in.Issuer,
			SourceUid: in.Revision.UID, SourceGeneration: in.Revision.Generation, SourceDigest: in.Revision.Digest[:], ObservedAt: ts(in.ObservedAt), FreshUntil: ts(in.FreshUntil),
			DefaultAgeSeconds: int32(in.Values.DefaultAge / time.Second), MaxAgeSeconds: int32(in.Values.MaxAge / time.Second), RenewalNoticeSeconds: int32(in.Values.RenewalNotice / time.Second)}); err != nil {
			return err
		}
		// First acceptance also clamps existing rows: an installation upgraded
		// from an earlier accepted setting cannot gain a fresh policy lifetime.
		if first || old.RootID.Valid && int64(in.Values.MaxAge/time.Second) < int64(old.MaxAgeSeconds) {
			if err = q.ClampPolicyGrantDeadlines(ctx, custodydb.ClampPolicyGrantDeadlinesParams{RootID: id(s.root), MaxAgeSeconds: int32(in.Values.MaxAge / time.Second)}); err != nil {
				return err
			}
		}
		now, err = q.CurrentTime(ctx)
		if err != nil {
			return err
		}
		if !in.Valid(now.Time) {
			return identity.ErrDenied
		}
		return ctx.Err()
	})
	if err != nil {
		return identity.ErrUnavailable
	}
	return nil
}

func (s *AccessGrants) PolicyApprovalSettings(ctx context.Context) (app.AcceptedPolicyApprovalSettings, error) {
	var out app.AcceptedPolicyApprovalSettings
	if s == nil || ctx == nil || ctx.Err() != nil {
		return out, app.ErrGrantUnavailable
	}
	err := s.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		row, err := q.ReadPolicyGrantSettings(ctx, id(s.root))
		if err != nil {
			return err
		}
		now, err := q.CurrentTime(ctx)
		if err != nil {
			return err
		}
		o := policyGrantSettingsObservation(row)
		if uid(row.InstallationID) != s.recovery.installation || !o.Valid(now.Time) {
			return identity.ErrDenied
		}
		out = app.AcceptedPolicyApprovalSettings{Values: authorization.PolicyApprovalSettings(o.Values), Revision: o.Revision, ObservedAt: o.ObservedAt, FreshUntil: o.FreshUntil}
		return ctx.Err()
	})
	if err != nil {
		return app.AcceptedPolicyApprovalSettings{}, app.ErrGrantUnavailable
	}
	return out, nil
}
