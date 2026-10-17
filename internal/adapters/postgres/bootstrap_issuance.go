package postgres

import (
	"bytes"
	"context"
	"encoding/json"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	auditport "asservat.local/asservat/internal/application/audit"
	fleetport "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/domain/audit"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Each instance is wired with its own purpose-specific SQL credential. Method
// sets do not grant permission to the other issuance roles.
type BootstrapIssues struct{ claims *EnrollmentClaims }

var _ fleetport.BootstrapCredentialRecorder = (*BootstrapIssues)(nil)
var _ auditport.BootstrapIssueLedger = (*BootstrapIssues)(nil)
var _ fleetport.BootstrapActivator = (*BootstrapIssues)(nil)

func NewBootstrapIssues(ctx context.Context, pool *pgxpool.Pool, installation string) (*BootstrapIssues, error) {
	c, err := NewEnrollmentClaims(ctx, pool, installation)
	if err != nil {
		return nil, err
	}
	return &BootstrapIssues{c}, nil
}
func bootstrapIssue(row custodydb.FleetBootstrapIntent) (audit.BootstrapIssue, error) {
	r := audit.BootstrapIssue{ID: uid(row.ID), Binding: value.PeerBinding{InstallationID: uid(row.InstallationID), ClusterID: uid(row.ClusterID), PeerID: uid(row.PeerID), IssuerEpoch: uid(row.IssuerEpoch), Role: value.ConnectorPeer}, IdentityRevision: identity.Revision{UID: row.IdentityUid, Generation: row.IdentityGeneration}, AdministrationRevision: identity.Revision{UID: row.TrustUid, Generation: row.TrustGeneration}, DisplayName: row.DisplayName, Region: row.Region, DeliveryProfile: row.DeliveryProfile, NotBefore: row.NotBefore.Time.UTC(), NotAfter: row.NotAfter.Time.UTC(), Credential: value.BootstrapCredential{SlotID: uid(row.ID), DeliveryProfile: row.DeliveryProfile, Version: int(row.CredentialVersion.Int16)}}
	copy(r.RequestDigest[:], row.RequestDigest)
	copy(r.IdentityRevision.Digest[:], row.IdentityDigest)
	copy(r.AdministrationRevision.Digest[:], row.TrustDigest)
	copy(r.Credential.SecretDigest[:], row.CredentialSha256)
	if !row.CredentialRecordedAt.Valid || json.Unmarshal(row.ActorJson, &r.Actor) != nil || !bytes.Equal(row.ActorDigest, digest(r.Actor)) || !r.Valid() {
		return audit.BootstrapIssue{}, value.ErrUnavailable
	}
	return r, nil
}
func slotMatchesRow(s value.BootstrapSlot, row custodydb.FleetBootstrapIntent) bool {
	return s.ID == uid(row.ID) && s.Binding.InstallationID == uid(row.InstallationID) && s.Binding.ClusterID == uid(row.ClusterID) && s.Binding.PeerID == uid(row.PeerID) && s.Binding.IssuerEpoch == uid(row.IssuerEpoch) && s.Binding.Role == value.ConnectorPeer && s.DeliveryProfile == row.DeliveryProfile && bytes.Equal(s.RequestDigest[:], row.RequestDigest) && s.NotBefore.Equal(row.NotBefore.Time) && s.NotAfter.Equal(row.NotAfter.Time)
}
func (s *BootstrapIssues) RecordBootstrapCredential(ctx context.Context, slot value.BootstrapSlot, c value.BootstrapCredential) (audit.BootstrapIssue, error) {
	var out audit.BootstrapIssue
	if slot.Binding.InstallationID != s.claims.installation || !slot.Valid(slot.CheckedAt) || !c.Matches(slot) {
		return out, value.ErrInvalid
	}
	err := s.claims.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		if _, err := q.LockFleetTrust(ctx, id(s.claims.installation)); err != nil {
			return err
		}
		row, err := q.LockBootstrapIntent(ctx, custodydb.LockBootstrapIntentParams{InstallationID: id(s.claims.installation), ID: id(slot.ID)})
		if err != nil {
			return err
		}
		if !slotMatchesRow(slot, row) {
			return value.ErrDenied
		}
		// Record an already observed credential even if authority has since expired.
		// This cannot create a claimable token or extend its original deadline.
		if row.CredentialRecordedAt.Valid {
			if !bytes.Equal(row.CredentialSha256, c.SecretDigest[:]) || row.CredentialVersion.Int16 != 1 {
				return value.ErrConflict
			}
		} else {
			row, err = q.RecordBootstrapCredential(ctx, custodydb.RecordBootstrapCredentialParams{InstallationID: row.InstallationID, ID: row.ID, CredentialSha256: c.SecretDigest[:]})
			if err != nil {
				return err
			}
		}
		out, err = bootstrapIssue(row)
		return err
	})
	if err != nil {
		return audit.BootstrapIssue{}, err
	}
	return out, nil
}
func (s *BootstrapIssues) PendingBootstrapIssues(ctx context.Context) ([]audit.BootstrapIssue, error) {
	var out []audit.BootstrapIssue
	err := s.claims.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		rows, err := q.PendingBootstrapIssues(ctx, id(s.claims.installation))
		if err != nil {
			return err
		}
		out = nil
		for _, row := range rows {
			r, err := bootstrapIssue(row)
			if err != nil {
				return err
			}
			out = append(out, r)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}
func (s *BootstrapIssues) AcknowledgeBootstrapIssue(ctx context.Context, r audit.BootstrapIssue, receipt audit.Receipt) error {
	if r.Binding.InstallationID != s.claims.installation || !r.Valid() || !receipt.ValidBootstrapIssue(s.claims.installation, r.ID) {
		return value.ErrInvalid
	}
	return s.claims.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		if _, err := q.LockFleetTrust(ctx, id(s.claims.installation)); err != nil {
			return err
		}
		row, err := q.LockBootstrapIntent(ctx, custodydb.LockBootstrapIntentParams{InstallationID: id(s.claims.installation), ID: id(r.ID)})
		if err != nil {
			return err
		}
		frozen, err := bootstrapIssue(row)
		if err != nil {
			return err
		}
		if !bytes.Equal(digest(frozen), digest(r)) {
			return value.ErrDenied
		}
		if row.AuditAcknowledgedAt.Valid {
			if !bytes.Equal(row.AuditDigest, digest(r)) || row.AuditObjectKey.String != receipt.Key || row.AuditObjectVersion.String != receipt.Version || row.AuditObjectEtag.String != receipt.ETag || row.AuditObjectBytes.Int64 != receipt.Bytes || !bytes.Equal(row.AuditObjectSha256, receipt.SHA256[:]) {
				return value.ErrConflict
			}
			return nil
		}
		n, err := q.AcknowledgeBootstrapIssue(ctx, custodydb.AcknowledgeBootstrapIssueParams{InstallationID: row.InstallationID, ID: row.ID, AuditDigest: digest(r), AuditObjectKey: pgtype.Text{String: receipt.Key, Valid: true}, AuditObjectVersion: pgtype.Text{String: receipt.Version, Valid: true}, AuditObjectEtag: pgtype.Text{String: receipt.ETag, Valid: true}, AuditObjectBytes: pgtype.Int8{Int64: receipt.Bytes, Valid: true}, AuditObjectSha256: receipt.SHA256[:]})
		if err != nil {
			return err
		}
		if n != 1 {
			return value.ErrDenied
		}
		return nil
	})
}
func (s *BootstrapIssues) ActivateBootstrap(ctx context.Context, request value.BootstrapRequest, bootstrapID string) (value.BootstrapIntent, error) {
	var out value.BootstrapIntent
	a := request.Authority
	if a.InstallationID != s.claims.installation || !request.Valid(a.CheckedAt) || !authorization.UUID(bootstrapID) {
		return out, value.ErrInvalid
	}
	err := s.claims.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		out = value.BootstrapIntent{}
		root, err := q.LockFleetTrust(ctx, id(s.claims.installation))
		if err != nil {
			return err
		}
		row, err := q.LockBootstrapIntent(ctx, custodydb.LockBootstrapIntentParams{InstallationID: root.InstallationID, ID: id(bootstrapID)})
		if err != nil {
			return err
		}
		if !bytes.Equal(row.ActorDigest, digest(a.Actor)) || !bytes.Equal(row.KeyDigest, request.KeyDigest[:]) || !bytes.Equal(row.RequestDigest, bootstrapRequestDigest(request)) {
			return value.ErrDenied
		}
		frozen, err := bootstrapIssue(row)
		if err != nil {
			return err
		}
		if !currentBootstrapIntentAudit(row) || !bytes.Equal(row.AuditDigest, digest(frozen)) {
			return value.ErrDenied
		}
		now, err := q.CurrentTime(ctx)
		if err != nil {
			return err
		}
		if err = checkEnrollmentAuthority(root, a, now.Time); err != nil {
			return err
		}
		out, err = bootstrapIntent(row, a, now.Time, identity.Earlier(a.ValidUntil, root.FreshUntil.Time))
		if err != nil {
			return err
		}
		if row.IssuedAt.Valid {
			existing, err := q.LockBootstrap(ctx, custodydb.LockBootstrapParams{InstallationID: root.InstallationID, ID: row.ID})
			if err != nil {
				return err
			}
			if existing.Revoked || existing.ClusterID != row.ClusterID || existing.PeerID != row.PeerID || existing.IssuerEpoch != row.IssuerEpoch || !bytes.Equal(existing.SecretSha256, row.CredentialSha256) || !existing.NotBefore.Time.Equal(row.NotBefore.Time) || !existing.NotAfter.Time.Equal(row.NotAfter.Time) || !bytes.Equal(existing.IssueAuthorityDigest, row.AuditDigest) || existing.IssueAuditID != row.ID || existing.IssueAuditKey != row.AuditObjectKey.String || existing.IssueAuditVersion != row.AuditObjectVersion.String || !bytes.Equal(existing.IssueAuditSha256, row.AuditObjectSha256) {
				return value.ErrDenied
			}
		} else {
			if err = q.CreateIssuedBootstrap(ctx, custodydb.CreateIssuedBootstrapParams{InstallationID: root.InstallationID, ID: row.ID, ClusterID: row.ClusterID, PeerID: row.PeerID, IssuerEpoch: row.IssuerEpoch, SecretSha256: row.CredentialSha256, NotBefore: row.NotBefore, NotAfter: row.NotAfter, IssueAuthorityDigest: row.AuditDigest, IssueAuditKey: row.AuditObjectKey.String, IssueAuditVersion: row.AuditObjectVersion.String, IssueAuditSha256: row.AuditObjectSha256}); err != nil {
				return err
			}
			n, err := q.MarkBootstrapIssued(ctx, custodydb.MarkBootstrapIssuedParams{InstallationID: root.InstallationID, ID: row.ID})
			if err != nil {
				return err
			}
			if n != 1 {
				return value.ErrDenied
			}
		}
		now, err = q.CurrentTime(ctx)
		if err != nil {
			return err
		}
		if err = checkEnrollmentAuthority(root, a, now.Time); err != nil {
			return err
		}
		if !now.Time.Before(row.NotAfter.Time) {
			return value.ErrDenied
		}
		out.Credential = &frozen.Credential
		out.Issued = true
		return nil
	})
	if err != nil {
		return value.BootstrapIntent{}, err
	}
	return out, nil
}
