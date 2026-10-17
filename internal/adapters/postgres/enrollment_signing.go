package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"time"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	port "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	"github.com/jackc/pgx/v5/pgxpool"
)

type EnrollmentSigning struct {
	claims *EnrollmentClaims
	newID  func() string
}

var _ port.SigningLedger = (*EnrollmentSigning)(nil)

func NewEnrollmentSigning(ctx context.Context, pool *pgxpool.Pool, installation string, newID func() string) (*EnrollmentSigning, error) {
	if newID == nil {
		return nil, value.ErrInvalid
	}
	c, err := NewEnrollmentClaims(ctx, pool, installation)
	if err != nil {
		return nil, err
	}
	return &EnrollmentSigning{c, newID}, nil
}

func trustRevision(root custodydb.FleetCurrentTrust) identity.Revision {
	r := identity.Revision{UID: root.SourceUid, Generation: root.SourceGeneration}
	copy(r.Digest[:], root.SourceDigest)
	return r
}
func checkClaimedEnrollment(root custodydb.FleetCurrentTrust, slot custodydb.FleetBootstrap, c value.EnrollmentClaim, now time.Time) error {
	if !currentIssuedBootstrapAudit(slot) || !c.Valid() || slot.InstallationID != id(c.InstallationID) || slot.ID != id(c.BootstrapID) || root.InstallationID != slot.InstallationID || root.Suspended || root.RecoveryBlocked || !trustRevision(root).Valid() || !identity.Fresh(root.ObservedAt.Time, root.FreshUntil.Time, now, 30*time.Second) || slot.IssuerEpoch != root.IssuerEpoch || slot.Revoked || !slot.ClaimedAt.Valid || now.Before(slot.ClaimedAt.Time) || !now.Before(slot.NotAfter.Time) || subtle.ConstantTimeCompare(slot.SecretSha256, c.SecretDigest[:]) != 1 || subtle.ConstantTimeCompare(slot.PublicKeySha256, c.PublicKeyDigest[:]) != 1 {
		return value.ErrDenied
	}
	frozen, err := enrollmentClaimAudit(slot)
	if err != nil || !slot.ClaimAcknowledgedAt.Valid || !slot.ClaimObjectVersion.Valid || slot.ClaimObjectVersion.String == "null" || !identity.Text(slot.ClaimObjectVersion.String, 1024) || !bytes.Equal(slot.ClaimAuditDigest, digest(frozen)) {
		return value.ErrDenied
	}
	return nil
}
func signingAttempt(row custodydb.FleetCertificateIssue, slot custodydb.FleetBootstrap) (value.SigningAttempt, error) {
	var out value.SigningAttempt
	frozen, err := enrollmentClaimAudit(slot)
	if err != nil || row.InstallationID != slot.InstallationID || row.BootstrapID != slot.ID || !slot.ClaimAcknowledgedAt.Valid || !bytes.Equal(slot.ClaimAuditDigest, digest(frozen)) {
		return out, value.ErrDenied
	}
	out = value.SigningAttempt{ID: uid(row.ID), Ordinal: row.Ordinal, Permit: value.CertificateIssuePermit{Enrollment: value.Enrollment{BootstrapID: frozen.BootstrapID, Binding: frozen.Binding, PublicKeyDigest: frozen.PublicKeyDigest, ClaimedAt: frozen.ClaimedAt, NotAfter: frozen.NotAfter}, TrustRevision: identity.Revision{UID: row.TrustUid, Generation: row.TrustGeneration}, CheckedAt: row.StartedAt.Time.UTC(), ValidUntil: row.SignBefore.Time.UTC()}}
	copy(out.Permit.ClaimAuditDigest[:], slot.ClaimAuditDigest)
	copy(out.Permit.TrustRevision.Digest[:], row.TrustDigest)
	if !out.Valid(out.Permit.CheckedAt) {
		return value.SigningAttempt{}, value.ErrUnavailable
	}
	return out, nil
}
func issuedCertificate(row custodydb.FleetCertificateIssue, a value.SigningAttempt) (value.IssuedCertificate, error) {
	var c value.IssuedCertificate
	if !row.SignedAt.Valid || len(row.CertificateJson) == 0 || len(row.CertificateJson) > 48<<10 || json.Unmarshal(row.CertificateJson, &c) != nil || !a.MatchesIssued(c) || artifact.Digest(sha256.Sum256(c.DER)) != c.Certificate.Digest || !bytes.Equal(c.Certificate.Digest[:], row.CertificateSha256) || !c.Certificate.NotBefore.Equal(row.CertificateNotBefore.Time) || !c.Certificate.NotAfter.Equal(row.CertificateNotAfter.Time) {
		return value.IssuedCertificate{}, value.ErrUnavailable
	}
	return c, nil
}
func (s *EnrollmentSigning) PrepareConnector(ctx context.Context, c value.EnrollmentClaim) (value.EnrollmentProgress, error) {
	var out value.EnrollmentProgress
	if !c.Valid() || c.InstallationID != s.claims.installation {
		return out, value.ErrInvalid
	}
	err := s.claims.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		out = value.EnrollmentProgress{}
		root, err := q.LockFleetTrust(ctx, id(c.InstallationID))
		if err != nil {
			return err
		}
		slot, err := q.LockBootstrap(ctx, custodydb.LockBootstrapParams{InstallationID: id(c.InstallationID), ID: id(c.BootstrapID)})
		if err != nil {
			return err
		}
		rows, err := q.ReadCertificateIssues(ctx, custodydb.ReadCertificateIssuesParams{InstallationID: slot.InstallationID, BootstrapID: slot.ID})
		if err != nil {
			return err
		}
		now, err := q.CurrentTime(ctx)
		if err != nil {
			return err
		}
		if err = checkClaimedEnrollment(root, slot, c, now.Time); err != nil {
			return err
		}
		if len(rows) > 2 {
			return value.ErrUnavailable
		}
		if len(rows) > 0 {
			row := rows[len(rows)-1]
			out.Attempt, err = signingAttempt(row, slot)
			if err != nil {
				return err
			}
			if out.Attempt.Permit.TrustRevision != trustRevision(root) {
				return value.ErrDenied
			}
			if row.SignedAt.Valid {
				cert, err := issuedCertificate(row, out.Attempt)
				if err != nil {
					return err
				}
				out.Signed = &cert
				out.Active = row.ActivatedAt.Valid
				return nil
			}
			if now.Time.Before(row.SignBefore.Time) {
				return nil
			} // Observed retry, never MaySign.
			if len(rows) == 2 {
				return value.ErrDenied
			} // Uncertain calls remain spent.
		}
		until := now.Time.Add(5 * time.Second)
		for _, t := range []time.Time{slot.NotAfter.Time, root.FreshUntil.Time} {
			if t.Before(until) {
				until = t
			}
		}
		attemptID := s.newID()
		if !authorization.UUID(attemptID) {
			return value.ErrUnavailable
		}
		row := custodydb.FleetCertificateIssue{InstallationID: slot.InstallationID, BootstrapID: slot.ID, Ordinal: int16(len(rows) + 1), ID: id(attemptID), TrustUid: root.SourceUid, TrustGeneration: root.SourceGeneration, TrustDigest: root.SourceDigest, StartedAt: now, SignBefore: ts(until)}
		out.Attempt, err = signingAttempt(row, slot)
		if err != nil {
			return err
		}
		if err = q.InsertCertificateIssue(ctx, custodydb.InsertCertificateIssueParams{InstallationID: row.InstallationID, BootstrapID: row.BootstrapID, Ordinal: row.Ordinal, ID: row.ID, TrustUid: row.TrustUid, TrustGeneration: row.TrustGeneration, TrustDigest: row.TrustDigest, StartedAt: row.StartedAt, SignBefore: row.SignBefore}); err != nil {
			return err
		}
		after, err := q.CurrentTime(ctx)
		if err != nil {
			return err
		}
		if !out.Attempt.Valid(after.Time) {
			return value.ErrDenied
		}
		out.MaySign = true
		return nil
	})
	if err != nil {
		return value.EnrollmentProgress{}, err
	}
	return out, nil
}

func (s *EnrollmentSigning) StoreConnectorCertificate(ctx context.Context, a value.SigningAttempt, c value.IssuedCertificate) error {
	if a.Permit.Enrollment.Binding.InstallationID != s.claims.installation || !a.Valid(a.Permit.CheckedAt) || !a.MatchesIssued(c) || artifact.Digest(sha256.Sum256(c.DER)) != c.Certificate.Digest {
		return value.ErrInvalid
	}
	encoded, err := json.Marshal(c)
	if err != nil || len(encoded) > 48<<10 {
		return value.ErrInvalid
	}
	return s.claims.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		e := a.Permit.Enrollment
		root, err := q.LockFleetTrust(ctx, id(e.Binding.InstallationID))
		if err != nil {
			return err
		}
		slot, err := q.LockBootstrap(ctx, custodydb.LockBootstrapParams{InstallationID: root.InstallationID, ID: id(e.BootstrapID)})
		if err != nil {
			return err
		}
		rows, err := q.ReadCertificateIssues(ctx, custodydb.ReadCertificateIssuesParams{InstallationID: slot.InstallationID, BootstrapID: slot.ID})
		if err != nil {
			return err
		}
		if len(rows) == 0 || len(rows) > 2 {
			return value.ErrDenied
		}
		row := rows[len(rows)-1]
		frozen, err := signingAttempt(row, slot)
		if err != nil || !bytes.Equal(digest(frozen), digest(a)) {
			return value.ErrDenied
		}
		now, err := q.CurrentTime(ctx)
		if err != nil {
			return err
		}
		claim := value.EnrollmentClaim{InstallationID: e.Binding.InstallationID, BootstrapID: e.BootstrapID, PublicKeyDigest: e.PublicKeyDigest}
		copy(claim.SecretDigest[:], slot.SecretSha256)
		if err = checkClaimedEnrollment(root, slot, claim, now.Time); err != nil {
			return err
		}
		if trustRevision(root) != a.Permit.TrustRevision {
			return value.ErrDenied
		}
		if row.SignedAt.Valid {
			if !bytes.Equal(row.CertificateJson, encoded) {
				return value.ErrDenied
			}
			return nil
		}
		if !a.Valid(now.Time) || !c.Certificate.Valid(now.Time) {
			return value.ErrDenied
		}
		n, err := q.StoreConnectorCertificate(ctx, custodydb.StoreConnectorCertificateParams{InstallationID: root.InstallationID, ID: id(a.ID), CertificateJson: encoded, CertificateSha256: c.Certificate.Digest[:], CertificateNotBefore: ts(c.Certificate.NotBefore), CertificateNotAfter: ts(c.Certificate.NotAfter)})
		if err != nil {
			return err
		}
		if n != 1 {
			return value.ErrDenied
		}
		now, err = q.CurrentTime(ctx)
		if err != nil {
			return err
		}
		if !a.Valid(now.Time) {
			return value.ErrDenied
		}
		return nil
	})
}
