package postgres

import (
	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	auditapp "asservat.local/asservat/internal/application/audit"
	app "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"time"
)

type OwnerEnrollments struct {
	configuration *OwnerConfigurations
	newID         func() string
}

var _ app.OwnerEnrollmentLedger = (*OwnerEnrollments)(nil)
var _ app.OwnerCertificateActivator = (*OwnerEnrollments)(nil)
var _ app.OwnerCertificateRegistry = (*OwnerEnrollments)(nil)
var _ app.OwnerEnrollmentCleanup = (*OwnerEnrollments)(nil)
var _ auditapp.OwnerEnrollmentAcknowledgements = (*OwnerEnrollments)(nil)

func NewOwnerEnrollments(ctx context.Context, pool *pgxpool.Pool, installation, cluster, namespace, source string, newID func() string) (*OwnerEnrollments, error) {
	if newID == nil {
		return nil, value.ErrInvalid
	}
	c, e := NewOwnerConfigurations(ctx, pool, installation, cluster, namespace, source)
	if e != nil {
		return nil, e
	}
	return &OwnerEnrollments{c, newID}, nil
}

// All changing facets serialize on the pinned pool head, after recovery. No
// network I/O is performed in these transactions. Readers only share the head.
func (s *OwnerEnrollments) current(ctx context.Context, write bool, original time.Time, f func(*custodydb.Queries, value.OwnerConfigurationObservation, value.RecoveryState, time.Time) error) error {
	if s == nil || ctx == nil {
		return value.ErrInvalid
	}
	c := s.configuration
	return c.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		start, e := q.CurrentTime(ctx)
		if e != nil {
			return e
		}
		if original.IsZero() {
			original = start.Time
		}
		trust, e := q.ShareFleetTrust(ctx, id(c.installation))
		if e != nil {
			return e
		}
		var h custodydb.HubOwnerConfiguration
		if write {
			h, e = q.LockOwnerConfiguration(ctx, custodydb.LockOwnerConfigurationParams{InstallationID: id(c.installation), ClusterID: id(c.cluster)})
		} else {
			h, e = q.ShareOwnerConfiguration(ctx, custodydb.ShareOwnerConfigurationParams{InstallationID: id(c.installation), ClusterID: id(c.cluster)})
		}
		if e != nil {
			return e
		}
		if uid(h.SourceUid) != c.source || h.Generation == 0 {
			return value.ErrUnavailable
		}
		row, e := q.ReadOwnerConfigurationRevision(ctx, custodydb.ReadOwnerConfigurationRevisionParams{InstallationID: h.InstallationID, ClusterID: h.ClusterID, SourceUid: h.SourceUid, Generation: h.Generation})
		if e != nil {
			return e
		}
		var config value.OwnerConfiguration
		var receipt audit.Receipt
		if json.Unmarshal(row.SnapshotJson, &config) != nil || !c.matches(config) || config.Revision.Generation != h.Generation || config.Suspended || json.Unmarshal(row.AuditReceiptJson, &receipt) != nil || !receipt.ValidOwnerConfiguration(config) {
			return value.ErrUnavailable
		}
		check := func() (value.OwnerConfigurationObservation, value.RecoveryState, time.Time, error) {
			n, e := q.CurrentTime(ctx)
			if e != nil {
				return value.OwnerConfigurationObservation{}, value.RecoveryState{}, time.Time{}, e
			}
			recovery, e := recoveryState(trust, original, n.Time)
			observation := value.OwnerConfigurationObservation{Configuration: config, ObservedAt: h.ObservedAt.Time, FreshUntil: identity.Earlier(h.FreshUntil.Time, recovery.FreshUntil)}
			if e != nil || !observation.Valid(n.Time) || recovery.IssuerEpoch != config.Pool.IssuerEpoch {
				return observation, recovery, n.Time, value.ErrUnavailable
			}
			return observation, recovery, n.Time, nil
		}
		observation, recovery, now, e := check()
		if e != nil {
			return e
		}
		if e = f(q, observation, recovery, now); e != nil {
			return e
		}
		_, _, _, e = check()
		return e
	})
}
func (s *OwnerEnrollments) withProof(ctx context.Context, p value.OwnerEnrollmentProof, f func(*custodydb.Queries, value.RecoveryState, time.Time) error) error {
	if ctx == nil || !p.WellFormed() {
		return value.ErrInvalid
	}
	p = p.Clone()
	ctx, end := context.WithDeadline(ctx, p.FreshUntil)
	defer end()
	return s.current(ctx, true, p.ObservedAt, func(q *custodydb.Queries, c value.OwnerConfigurationObservation, r value.RecoveryState, n time.Time) error {
		if !p.Valid(n) || !p.Configuration.Configuration.Equal(c.Configuration) || p.FreshUntil.After(c.FreshUntil) {
			return value.ErrUnavailable
		}
		if e := f(q, r, n); e != nil {
			return e
		}
		now, e := q.CurrentTime(ctx)
		if e != nil {
			return e
		}
		if !p.Valid(now.Time) {
			return value.ErrUnavailable
		}
		return nil
	})
}
func (s *OwnerEnrollments) readEnrollment(ctx context.Context, q *custodydb.Queries, b value.OwnerBinding, usage string) (custodydb.HubOwnerEnrollment, error) {
	return q.ReadOwnerEnrollment(ctx, custodydb.ReadOwnerEnrollmentParams{InstallationID: id(b.InstallationID), ClusterID: id(b.ClusterID), IssuerEpoch: id(b.IssuerEpoch), PodUid: id(b.PodUID), ProcessEpoch: id(b.ProcessEpoch), Usage: usage})
}
func decodeOwnerEnrollment(r custodydb.HubOwnerEnrollment) (value.OwnerEnrollment, error) {
	var e value.OwnerEnrollment
	if json.Unmarshal(r.EnrollmentJson, &e) != nil || !e.Valid() || e.ID != uid(r.ID) || e.Binding.InstallationID != uid(r.InstallationID) || e.Binding.ClusterID != uid(r.ClusterID) || e.Binding.IssuerEpoch != uid(r.IssuerEpoch) || e.Binding.PodUID != uid(r.PodUid) || e.Binding.ProcessEpoch != uid(r.ProcessEpoch) || e.Usage != r.Usage || !e.ClaimedAt.Equal(r.CreatedAt.Time) || r.HoldUntil.Time.Before(e.InitialHoldUntil) {
		return e, artifact.ErrIntegrity
	}
	return e, nil
}
func ownerEnrollmentReceipt(r custodydb.HubOwnerEnrollment, e value.OwnerEnrollment) (audit.Receipt, bool, error) {
	var out audit.Receipt
	if r.AuditReceiptJson == nil {
		return out, false, nil
	}
	if json.Unmarshal(r.AuditReceiptJson, &out) != nil || !out.ValidOwnerEnrollment(e) {
		return out, false, artifact.ErrIntegrity
	}
	return out, true, nil
}
func (s *OwnerEnrollments) prune(ctx context.Context, q *custodydb.Queries) error {
	c := s.configuration
	if _, e := q.PruneOwnerCertificates(ctx, custodydb.PruneOwnerCertificatesParams{InstallationID: id(c.installation), ClusterID: id(c.cluster)}); e != nil {
		return e
	}
	_, e := q.PruneOwnerEnrollments(ctx, custodydb.PruneOwnerEnrollmentsParams{InstallationID: id(c.installation), ClusterID: id(c.cluster)})
	return e
}
func (s *OwnerEnrollments) ClaimOwnerEnrollment(ctx context.Context, p value.OwnerEnrollmentProof) (value.OwnerEnrollment, audit.Receipt, bool, error) {
	var out value.OwnerEnrollment
	var receipt audit.Receipt
	var ack bool
	err := s.withProof(ctx, p, func(q *custodydb.Queries, _ value.RecoveryState, now time.Time) error {
		out, receipt, ack = value.OwnerEnrollment{}, audit.Receipt{}, false
		if e := s.prune(ctx, q); e != nil {
			return e
		}
		row, e := s.readEnrollment(ctx, q, p.Binding, p.Usage)
		if errors.Is(e, pgx.ErrNoRows) {
			counts, e := q.CountOwnerEnrollments(ctx, custodydb.CountOwnerEnrollmentsParams{InstallationID: id(p.Binding.InstallationID), ClusterID: id(p.Binding.ClusterID), PodUid: id(p.Binding.PodUID)})
			if e != nil {
				return e
			}
			if counts.Total >= value.OwnerRegistrationsPerPool || counts.Pod >= value.OwnerRegistrationsPerPod {
				return value.ErrCapacity
			}
			_, until, e := value.OwnerCertificateWindow(now)
			if e != nil {
				return e
			}
			out = value.OwnerEnrollment{ID: s.newID(), Binding: p.Binding, Usage: p.Usage, Pool: p.Configuration.Configuration.Pool, SourceUID: p.Configuration.Configuration.Revision.UID, Pod: p.Pod, ReplicaSet: p.ReplicaSet, ReplicaSetUID: p.ReplicaSetUID, PublicKeyDigest: p.PublicKeyDigest, InitialTokenDigest: p.TokenDigest, InitialWorkloadDigest: p.WorkloadDigest, InitialProtectionDigest: p.ProtectionDigest, ClaimedAt: now.UTC(), InitialHoldUntil: until.Add(value.OwnerRegistrationGrace)}
			if !out.Matches(p) {
				return value.ErrInvalid
			}
			b, _ := json.Marshal(out)
			return q.InsertOwnerEnrollment(ctx, custodydb.InsertOwnerEnrollmentParams{ID: id(out.ID), InstallationID: id(p.Binding.InstallationID), ClusterID: id(p.Binding.ClusterID), IssuerEpoch: id(p.Binding.IssuerEpoch), PodUid: id(p.Binding.PodUID), ProcessEpoch: id(p.Binding.ProcessEpoch), Usage: p.Usage, EnrollmentJson: b, CreatedAt: ts(out.ClaimedAt), HoldUntil: ts(out.InitialHoldUntil)})
		}
		if e != nil {
			return e
		}
		out, e = decodeOwnerEnrollment(row)
		if e != nil {
			return e
		}
		if !out.Matches(p) || row.RetiredAt.Valid {
			return value.ErrConflict
		}
		receipt, ack, e = ownerEnrollmentReceipt(row, out)
		return e
	})
	if err != nil {
		return value.OwnerEnrollment{}, audit.Receipt{}, false, err
	}
	return out, receipt, ack, nil
}
func decodeOwnerAttempt(r custodydb.HubOwnerCertificate) (value.OwnerCertificateAttempt, error) {
	var a value.OwnerCertificateAttempt
	if json.Unmarshal(r.AttemptJson, &a) != nil || !a.Valid(a.Permit.CheckedAt) || a.Permit.ID != uid(r.ID) || a.Enrollment.ID != uid(r.EnrollmentID) || a.Permit.Epoch != r.Epoch || a.Permit.Ordinal != int(r.Ordinal) || !a.Permit.CertificateNotAfter.Equal(r.NotAfter.Time) {
		return a, artifact.ErrIntegrity
	}
	return a, nil
}
func decodeOwnerCertificate(r custodydb.HubOwnerCertificate, a value.OwnerCertificateAttempt) (value.IssuedOwnerCertificate, error) {
	var c value.IssuedOwnerCertificate
	if json.Unmarshal(r.CertificateJson, &c) != nil || !a.Permit.Matches(c) || artifact.Digest(sha256.Sum256(c.DER)) != c.Certificate.Digest || !bytes.Equal(r.CertificateSha256, c.Certificate.Digest[:]) {
		return c, artifact.ErrIntegrity
	}
	return c, nil
}
func (s *OwnerEnrollments) provenEnrollment(ctx context.Context, q *custodydb.Queries, p value.OwnerEnrollmentProof) (custodydb.HubOwnerEnrollment, value.OwnerEnrollment, audit.Receipt, error) {
	row, err := s.readEnrollment(ctx, q, p.Binding, p.Usage)
	if err != nil {
		return row, value.OwnerEnrollment{}, audit.Receipt{}, err
	}
	e, err := decodeOwnerEnrollment(row)
	if err != nil {
		return row, e, audit.Receipt{}, err
	}
	if !e.Matches(p) || row.RetiredAt.Valid {
		return row, e, audit.Receipt{}, value.ErrDenied
	}
	r, ok, err := ownerEnrollmentReceipt(row, e)
	if err != nil {
		return row, e, r, err
	}
	if !ok {
		return row, e, r, value.ErrUnavailable
	}
	return row, e, r, nil
}
func (s *OwnerEnrollments) PrepareOwnerCertificate(ctx context.Context, p value.OwnerEnrollmentProof) (value.OwnerCertificateProgress, error) {
	var out value.OwnerCertificateProgress
	err := s.withProof(ctx, p, func(q *custodydb.Queries, recovery value.RecoveryState, now time.Time) error {
		out = value.OwnerCertificateProgress{}
		row, enrollment, receipt, e := s.provenEnrollment(ctx, q, p)
		if e != nil {
			return e
		}
		epoch, until, e := value.OwnerCertificateWindow(now)
		if e != nil {
			return e
		}
		if epoch < row.HighestEpoch {
			return value.ErrDenied
		}
		if e = s.prune(ctx, q); e != nil {
			return e
		}
		rows, e := q.ReadOwnerCertificateEpoch(ctx, custodydb.ReadOwnerCertificateEpochParams{EnrollmentID: row.ID, Epoch: epoch})
		if e != nil {
			return e
		}
		if len(rows) > 2 {
			return artifact.ErrIntegrity
		}
		if len(rows) > 0 {
			last := rows[len(rows)-1]
			a, e := decodeOwnerAttempt(last)
			if e != nil {
				return e
			}
			if a.Enrollment != enrollment || a.Permit.EnrollmentAudit != receipt.SHA256 || a.Permit.Recovery.Revision != recovery.Revision {
				return value.ErrDenied
			}
			out.Attempt = a
			if last.CertificateJson != nil {
				c, e := decodeOwnerCertificate(last, a)
				if e != nil {
					return e
				}
				out.Signed = &c
				return nil
			}
			if now.Before(a.Permit.SignBefore) {
				return nil
			}
			if len(rows) == 2 {
				return value.ErrCapacity
			}
		}
		permit := value.OwnerCertificatePermit{ID: s.newID(), Binding: p.Binding, Usage: p.Usage, PublicKeyDigest: p.PublicKeyDigest, EnrollmentAudit: receipt.SHA256, Configuration: p.Configuration, Recovery: recovery, Epoch: epoch, Ordinal: len(rows) + 1, CheckedAt: now.UTC(), SignBefore: identity.Earlier(p.FreshUntil, identity.Earlier(recovery.FreshUntil, identity.Earlier(now.Add(5*time.Second), until))), CertificateNotAfter: until}
		a := value.OwnerCertificateAttempt{Enrollment: enrollment, Permit: permit, TokenDigest: p.TokenDigest, WorkloadDigest: p.WorkloadDigest, ProtectionDigest: p.ProtectionDigest, ProofObservedAt: p.ObservedAt, ProofFreshUntil: p.FreshUntil}
		if !a.Valid(now) {
			return value.ErrUnavailable
		}
		b, e := json.Marshal(a)
		if e != nil || len(b) > 64<<10 {
			return value.ErrInvalid
		}
		if e = q.InsertOwnerCertificateAttempt(ctx, custodydb.InsertOwnerCertificateAttemptParams{ID: id(permit.ID), EnrollmentID: row.ID, Epoch: epoch, Ordinal: int32(permit.Ordinal), NotAfter: ts(until), AttemptJson: b}); e != nil {
			return e
		}
		out = value.OwnerCertificateProgress{Attempt: a.Clone(), MaySign: true}
		return nil
	})
	if err != nil {
		return value.OwnerCertificateProgress{}, err
	}
	return out, nil
}
func (s *OwnerEnrollments) StoreOwnerCertificate(ctx context.Context, a value.OwnerCertificateAttempt, c value.IssuedOwnerCertificate) error {
	if !a.Valid(a.Permit.CheckedAt) || !a.Permit.Matches(c) || artifact.Digest(sha256.Sum256(c.DER)) != c.Certificate.Digest {
		return value.ErrInvalid
	}
	b, e := json.Marshal(c)
	if e != nil || len(b) > 64<<10 {
		return value.ErrInvalid
	}
	return s.withProof(ctx, a.Proof(), func(q *custodydb.Queries, r value.RecoveryState, now time.Time) error {
		_, enrollment, receipt, e := s.provenEnrollment(ctx, q, a.Proof())
		if e != nil {
			return e
		}
		if enrollment != a.Enrollment || receipt.SHA256 != a.Permit.EnrollmentAudit || !a.Valid(now) || !c.Certificate.Valid(now) || r.Revision != a.Permit.Recovery.Revision {
			return value.ErrUnavailable
		}
		row, e := q.ReadOwnerCertificate(ctx, custodydb.ReadOwnerCertificateParams{ID: id(a.Permit.ID), EnrollmentID: id(enrollment.ID)})
		if e != nil {
			return e
		}
		frozen, e := decodeOwnerAttempt(row)
		if e != nil || !frozen.Equal(a) {
			return artifact.ErrIntegrity
		}
		if row.CertificateJson != nil {
			if !bytes.Equal(row.CertificateJson, b) {
				return value.ErrConflict
			}
			return nil
		}
		n, e := q.StoreOwnerCertificate(ctx, custodydb.StoreOwnerCertificateParams{ID: row.ID, EnrollmentID: row.EnrollmentID, CertificateJson: b, CertificateSha256: c.Certificate.Digest[:]})
		if e != nil {
			return e
		}
		if n != 1 {
			return value.ErrConflict
		}
		checked, e := q.CurrentTime(ctx)
		if e != nil {
			return e
		}
		if !a.Valid(checked.Time) {
			return value.ErrUnavailable
		}
		return nil
	})
}
func (s *OwnerEnrollments) ActivateOwnerCertificate(ctx context.Context, p value.OwnerEnrollmentProof, a value.OwnerCertificateAttempt) (value.IssuedOwnerCertificate, error) {
	var out value.IssuedOwnerCertificate
	if !a.Valid(a.Permit.CheckedAt) || !a.Enrollment.Matches(p) {
		return out, value.ErrInvalid
	}
	err := s.withProof(ctx, p, func(q *custodydb.Queries, recovery value.RecoveryState, now time.Time) error {
		_, enrollment, receipt, e := s.provenEnrollment(ctx, q, p)
		if e != nil {
			return e
		}
		if enrollment != a.Enrollment || receipt.SHA256 != a.Permit.EnrollmentAudit || recovery.Revision != a.Permit.Recovery.Revision {
			return value.ErrDenied
		}
		row, e := q.ReadOwnerCertificate(ctx, custodydb.ReadOwnerCertificateParams{ID: id(a.Permit.ID), EnrollmentID: id(enrollment.ID)})
		if e != nil {
			return e
		}
		frozen, e := decodeOwnerAttempt(row)
		if e != nil || !frozen.Equal(a) {
			return artifact.ErrIntegrity
		}
		out, e = decodeOwnerCertificate(row, a)
		if e != nil {
			return e
		}
		var ack audit.Receipt
		if json.Unmarshal(row.AuditReceiptJson, &ack) != nil || !ack.ValidOwnerCertificate(audit.OwnerCertificate{Attempt: a, Certificate: out.Certificate}) || !out.Certificate.Valid(now) {
			return value.ErrUnavailable
		}
		if !row.ActivatedAt.Valid {
			n, e := q.ActivateOwnerCertificate(ctx, custodydb.ActivateOwnerCertificateParams{ID: row.ID, EnrollmentID: row.EnrollmentID})
			if e != nil {
				return e
			}
			if n != 1 {
				return value.ErrConflict
			}
		}
		n, e := q.CurrentTime(ctx)
		if e != nil {
			return e
		}
		if !out.Certificate.Valid(n.Time) {
			return value.ErrUnavailable
		}
		return nil
	})
	if err != nil {
		return value.IssuedOwnerCertificate{}, err
	}
	return out.Clone(), nil
}

// Audit and retirement can finish after source/recovery unavailability. They
// cannot refresh authority, alter identities or refund possible live issuance.
func (s *OwnerEnrollments) historical(ctx context.Context, f func(*custodydb.Queries) error) error {
	if s == nil || ctx == nil {
		return value.ErrInvalid
	}
	c := s.configuration
	return c.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		h, e := q.LockOwnerConfiguration(ctx, custodydb.LockOwnerConfigurationParams{InstallationID: id(c.installation), ClusterID: id(c.cluster)})
		if e != nil {
			return e
		}
		if uid(h.SourceUid) != c.source {
			return value.ErrDenied
		}
		return f(q)
	})
}
func (s *OwnerEnrollments) exactEnrollment(ctx context.Context, q *custodydb.Queries, e value.OwnerEnrollment) (custodydb.HubOwnerEnrollment, error) {
	row, err := q.ReadOwnerEnrollmentID(ctx, custodydb.ReadOwnerEnrollmentIDParams{ID: id(e.ID), InstallationID: id(s.configuration.installation), ClusterID: id(s.configuration.cluster)})
	if err != nil {
		return row, err
	}
	frozen, err := decodeOwnerEnrollment(row)
	if err != nil || frozen != e {
		return row, artifact.ErrIntegrity
	}
	return row, nil
}
func (s *OwnerEnrollments) AcknowledgeOwnerEnrollment(ctx context.Context, e value.OwnerEnrollment, r audit.Receipt) error {
	if !r.ValidOwnerEnrollment(e) {
		return value.ErrInvalid
	}
	return s.historical(ctx, func(q *custodydb.Queries) error {
		row, err := s.exactEnrollment(ctx, q, e)
		if err != nil {
			return err
		}
		b, _ := json.Marshal(r)
		if row.AuditReceiptJson != nil {
			if !bytes.Equal(b, row.AuditReceiptJson) {
				return value.ErrConflict
			}
			return nil
		}
		n, err := q.AcknowledgeOwnerEnrollment(ctx, custodydb.AcknowledgeOwnerEnrollmentParams{ID: row.ID, AuditReceiptJson: b})
		if err != nil {
			return err
		}
		if n != 1 {
			return value.ErrConflict
		}
		return nil
	})
}
func (s *OwnerEnrollments) certificateAudit(ctx context.Context, q *custodydb.Queries, c audit.OwnerCertificate) (custodydb.HubOwnerCertificate, error) {
	var zero custodydb.HubOwnerCertificate
	if _, e := s.exactEnrollment(ctx, q, c.Attempt.Enrollment); e != nil {
		return zero, e
	}
	row, e := q.ReadOwnerCertificate(ctx, custodydb.ReadOwnerCertificateParams{ID: id(c.Attempt.Permit.ID), EnrollmentID: id(c.Attempt.Enrollment.ID)})
	if e != nil {
		return row, e
	}
	a, e := decodeOwnerAttempt(row)
	if e != nil || !a.Equal(c.Attempt) {
		return row, artifact.ErrIntegrity
	}
	issued, e := decodeOwnerCertificate(row, a)
	if e != nil || issued.Certificate != c.Certificate {
		return row, artifact.ErrIntegrity
	}
	return row, nil
}
func (s *OwnerEnrollments) ReadOwnerCertificateReceipt(ctx context.Context, c audit.OwnerCertificate) (audit.Receipt, bool, error) {
	var r audit.Receipt
	var ok bool
	if !c.Valid() {
		return r, false, value.ErrInvalid
	}
	err := s.historical(ctx, func(q *custodydb.Queries) error {
		r, ok = audit.Receipt{}, false
		row, e := s.certificateAudit(ctx, q, c)
		if e != nil {
			return e
		}
		if row.AuditReceiptJson == nil {
			return nil
		}
		if json.Unmarshal(row.AuditReceiptJson, &r) != nil || !r.ValidOwnerCertificate(c) {
			return artifact.ErrIntegrity
		}
		ok = true
		return nil
	})
	if err != nil {
		return audit.Receipt{}, false, err
	}
	return r, ok, nil
}
func (s *OwnerEnrollments) AcknowledgeOwnerCertificate(ctx context.Context, c audit.OwnerCertificate, r audit.Receipt) error {
	if !r.ValidOwnerCertificate(c) {
		return value.ErrInvalid
	}
	return s.historical(ctx, func(q *custodydb.Queries) error {
		row, e := s.certificateAudit(ctx, q, c)
		if e != nil {
			return e
		}
		b, _ := json.Marshal(r)
		if row.AuditReceiptJson != nil {
			if !bytes.Equal(b, row.AuditReceiptJson) {
				return value.ErrConflict
			}
			return nil
		}
		n, e := q.AcknowledgeOwnerCertificate(ctx, custodydb.AcknowledgeOwnerCertificateParams{ID: row.ID, EnrollmentID: row.EnrollmentID, AuditReceiptJson: b})
		if e != nil {
			return e
		}
		if n != 1 {
			return value.ErrConflict
		}
		return nil
	})
}
func (s *OwnerEnrollments) ReadOwnerRegistration(ctx context.Context, certificate value.OwnerCertificate) (value.OwnerRegistrationObservation, error) {
	var out value.OwnerRegistrationObservation
	if !certificate.Valid(certificate.NotBefore) {
		return out, value.ErrInvalid
	}
	err := s.current(ctx, false, time.Time{}, func(q *custodydb.Queries, c value.OwnerConfigurationObservation, recovery value.RecoveryState, now time.Time) error {
		row, e := s.readEnrollment(ctx, q, certificate.Binding, certificate.Usage)
		if e != nil {
			return e
		}
		enrollment, e := decodeOwnerEnrollment(row)
		if e != nil {
			return e
		}
		r, ok, e := ownerEnrollmentReceipt(row, enrollment)
		if e != nil || !ok || row.RetiredAt.Valid || enrollment.Pool != c.Configuration.Pool || !certificate.Valid(now) {
			return value.ErrUnavailable
		}
		leaf, e := q.ReadActiveOwnerCertificate(ctx, custodydb.ReadActiveOwnerCertificateParams{EnrollmentID: row.ID, CertificateSha256: certificate.Digest[:]})
		if e != nil {
			return e
		}
		a, e := decodeOwnerAttempt(leaf)
		if e != nil || a.Enrollment != enrollment || a.Permit.EnrollmentAudit != r.SHA256 || a.Permit.Recovery.Revision != recovery.Revision {
			return value.ErrDenied
		}
		cert, e := decodeOwnerCertificate(leaf, a)
		if e != nil || cert.Certificate != certificate {
			return value.ErrDenied
		}
		var ack audit.Receipt
		if json.Unmarshal(leaf.AuditReceiptJson, &ack) != nil || !ack.ValidOwnerCertificate(audit.OwnerCertificate{Attempt: a, Certificate: certificate}) {
			return value.ErrDenied
		}
		out = value.OwnerRegistrationObservation{Enrollment: enrollment, Certificate: certificate, Configuration: c, ObservedAt: recovery.ObservedAt, FreshUntil: identity.Earlier(c.FreshUntil, identity.Earlier(recovery.FreshUntil, certificate.NotAfter))}
		n, e := q.CurrentTime(ctx)
		if e != nil {
			return e
		}
		if !out.Valid(n.Time) {
			return value.ErrUnavailable
		}
		return nil
	})
	if err != nil {
		return value.OwnerRegistrationObservation{}, err
	}
	return out, nil
}
func (s *OwnerEnrollments) RetireOwnerEnrollment(ctx context.Context, e value.OwnerEnrollment) error {
	if !e.Valid() {
		return value.ErrInvalid
	}
	return s.historical(ctx, func(q *custodydb.Queries) error {
		row, err := s.exactEnrollment(ctx, q, e)
		if err != nil {
			return err
		}
		if row.RetiredAt.Valid {
			return nil
		}
		n, err := q.RetireOwnerEnrollment(ctx, custodydb.RetireOwnerEnrollmentParams{ID: row.ID, InstallationID: row.InstallationID, ClusterID: row.ClusterID})
		if err != nil {
			return err
		}
		if n != 1 {
			return value.ErrConflict
		}
		return nil
	})
}
func (s *OwnerEnrollments) PruneOwnerEnrollments(ctx context.Context) error {
	return s.historical(ctx, func(q *custodydb.Queries) error { return s.prune(ctx, q) })
}
