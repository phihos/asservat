package postgres

import (
	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	"asservat.local/asservat/internal/application/evidence"
	query "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	value "asservat.local/asservat/internal/domain/authorization"
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

// Enrollment establishes only the identity of an already admitted query
// worker. Query/native/key effects retain their own current typed authority.
type ProjectionEnrollments struct {
	identity *admittedWorkerIdentity
	newID    func() string
}

var _ evidence.ProjectionEnrollmentEffects = (*ProjectionEnrollments)(nil)
var _ evidence.AcquisitionEnrollmentBindings = (*ProjectionEnrollments)(nil)

func NewProjectionEnrollments(ctx context.Context, pool *pgxpool.Pool, root string, profile value.DownloadWorkerProfile, newID func() string) (*ProjectionEnrollments, error) {
	if newID == nil {
		return nil, artifact.ErrInvalid
	}
	guard, err := newAdmittedWorkerIdentity(ctx, pool, root, profile)
	if err != nil {
		return nil, err
	}
	return &ProjectionEnrollments{identity: guard, newID: newID}, nil
}
func (s *ProjectionEnrollments) withProof(ctx context.Context, p value.AcquisitionWorkerProof, f func(context.Context, *custodydb.Queries, admittedWorkerCheck, time.Time) error) error {
	if s == nil || ctx == nil || !p.Valid(p.ObservedAt) || p.Worker.Intent.Parent.Purpose != value.AcquisitionProjection || p.Worker.Intent.Profile != s.identity.profile {
		return query.ErrUnavailable
	}
	ctx, cancel := context.WithDeadline(ctx, p.FreshUntil)
	defer cancel()
	return s.identity.withCurrent(ctx, p.Worker.Intent.Parent, p.Worker.Intent.ID, func(ctx context.Context, tx *custodydb.Queries, checked admittedWorkerCheck, now time.Time) error {
		if checked.worker != p.Worker || !p.Valid(now) {
			return query.ErrUnavailable
		}
		if e := f(ctx, tx, checked, now); e != nil {
			return e
		}
		n, e := tx.CurrentTime(ctx)
		if e != nil || ctx.Err() != nil || !p.Valid(n.Time) {
			return query.ErrUnavailable
		}
		return nil
	})
}
func (s *ProjectionEnrollments) ReadAcquisitionEnrollment(ctx context.Context, parent value.AcquisitionParent, worker string) (value.AcquisitionWorkerIdentity, error) {
	if s == nil || parent.Purpose != value.AcquisitionProjection {
		return value.AcquisitionWorkerIdentity{}, query.ErrUnavailable
	}
	reader := &WorkerRouting{ledger: s.identity.ledger, root: s.identity.root, installation: s.identity.profile.InstallationID}
	out, err := reader.ReadAcquisitionEnrollment(ctx, parent, worker)
	if err != nil || out.Worker.Intent.Profile != s.identity.profile {
		return value.AcquisitionWorkerIdentity{}, query.ErrUnavailable
	}
	return out, nil
}
func currentAuditedAcquisitionEnrollment(ctx context.Context, tx *custodydb.Queries, w value.AcquisitionWorker) (value.AcquisitionEnrollment, error) {
	r, e := tx.ReadWorkerEnrollment(ctx, id(w.Intent.ID))
	if e != nil {
		return value.AcquisitionEnrollment{}, e
	}
	out, e := decodeAcquisitionEnrollment(r, w)
	if e != nil {
		return out, e
	}
	_, ok, e := acquisitionEnrollmentReceipt(r, out)
	if e != nil || !ok {
		return value.AcquisitionEnrollment{}, query.ErrUnavailable
	}
	return out, nil
}
func decodeAcquisitionEnrollment(r custodydb.DownloadWorkerEnrollment, w value.AcquisitionWorker) (value.AcquisitionEnrollment, error) {
	var e value.AcquisitionEnrollment
	if json.Unmarshal(r.EnrollmentJson, &e) != nil || !e.Valid() || e.Worker != w || uid(r.WorkerID) != w.Intent.ID {
		return e, artifact.ErrIntegrity
	}
	return e, nil
}
func acquisitionEnrollmentReceipt(r custodydb.DownloadWorkerEnrollment, e value.AcquisitionEnrollment) (audit.Receipt, bool, error) {
	var receipt audit.Receipt
	if r.AuditReceiptJson == nil {
		return receipt, false, nil
	}
	if json.Unmarshal(r.AuditReceiptJson, &receipt) != nil || !receipt.ValidAcquisitionEnrollment(e) {
		return receipt, false, artifact.ErrIntegrity
	}
	return receipt, true, nil
}
func (s *ProjectionEnrollments) ClaimAcquisitionEnrollment(ctx context.Context, p value.AcquisitionWorkerProof) (value.AcquisitionEnrollment, audit.Receipt, bool, error) {
	var out value.AcquisitionEnrollment
	var receipt audit.Receipt
	var ack bool
	err := s.withProof(ctx, p, func(ctx context.Context, q *custodydb.Queries, checked admittedWorkerCheck, now time.Time) error {
		r, e := q.ReadWorkerEnrollment(ctx, id(p.Worker.Intent.ID))
		if errors.Is(e, pgx.ErrNoRows) {
			out = value.AcquisitionEnrollment{Worker: p.Worker, PublicKeyDigest: p.PublicKeyDigest, ClaimedAt: now.UTC()}
			if !out.Valid() {
				return artifact.ErrInvalid
			}
			b, _ := json.Marshal(out)
			return q.InsertWorkerEnrollment(ctx, custodydb.InsertWorkerEnrollmentParams{WorkerID: id(p.Worker.Intent.ID), EnrollmentJson: b})
		}
		if e != nil {
			return e
		}
		out, e = decodeAcquisitionEnrollment(r, p.Worker)
		if e != nil {
			return e
		}
		if out.PublicKeyDigest != p.PublicKeyDigest {
			return artifact.ErrDownloadConflict
		}
		receipt, ack, e = acquisitionEnrollmentReceipt(r, out)
		return e
	})
	if err != nil {
		return value.AcquisitionEnrollment{}, audit.Receipt{}, false, err
	}
	return out, receipt, ack, nil
}
func decodeAcquisitionCertificateAttempt(r custodydb.DownloadWorkerCertificate) (value.AcquisitionCertificateAttempt, error) {
	var a value.AcquisitionCertificateAttempt
	if json.Unmarshal(r.AttemptJson, &a) != nil || !a.Valid(a.CheckedAt) || a.ID != uid(r.ID) || a.Enrollment.Worker.Intent.ID != uid(r.WorkerID) || int(r.Epoch) != a.Epoch || int(r.Ordinal) != a.Ordinal {
		return a, artifact.ErrIntegrity
	}
	return a, nil
}
func decodeAcquisitionCertificate(r custodydb.DownloadWorkerCertificate, a value.AcquisitionCertificateAttempt) (value.WorkerCertificate, error) {
	var c value.WorkerCertificate
	if json.Unmarshal(r.CertificateJson, &c) != nil || !a.Matches(c) || artifact.Digest(sha256.Sum256(c.DER)) != c.Peer.Certificate || !bytes.Equal(r.CertificateSha256, c.Peer.Certificate[:]) {
		return c, artifact.ErrIntegrity
	}
	return c, nil
}
func (s *ProjectionEnrollments) PrepareAcquisitionCertificate(ctx context.Context, p value.AcquisitionWorkerProof) (value.AcquisitionCertificateProgress, error) {
	var out value.AcquisitionCertificateProgress
	err := s.withProof(ctx, p, func(ctx context.Context, q *custodydb.Queries, checked admittedWorkerCheck, now time.Time) error {
		out = value.AcquisitionCertificateProgress{}
		r, e := q.ReadWorkerEnrollment(ctx, id(p.Worker.Intent.ID))
		if e != nil {
			return e
		}
		enrollment, e := decodeAcquisitionEnrollment(r, p.Worker)
		if e != nil || enrollment.PublicKeyDigest != p.PublicKeyDigest {
			return artifact.ErrIntegrity
		}
		receipt, ok, e := acquisitionEnrollmentReceipt(r, enrollment)
		if e != nil || !ok {
			return artifact.ErrDownloadUnavailable
		}
		epoch, until, e := p.Worker.CertificateEpoch(now)
		if e != nil {
			return e
		}
		rows, e := q.ReadWorkerCertificateEpoch(ctx, custodydb.ReadWorkerCertificateEpochParams{WorkerID: r.WorkerID, Epoch: int32(epoch)})
		if e != nil {
			return e
		}
		if len(rows) > 2 {
			return artifact.ErrIntegrity
		}
		if len(rows) > 0 {
			row := rows[len(rows)-1]
			a, e := decodeAcquisitionCertificateAttempt(row)
			if e != nil {
				return e
			}
			if a.Enrollment != enrollment || a.RecoveryEpoch != checked.recoveryEpoch || a.EnrollmentAudit != receipt.SHA256 {
				return artifact.ErrIntegrity
			}
			out.Attempt = a
			if row.CertificateJson != nil {
				c, e := decodeAcquisitionCertificate(row, a)
				if e != nil {
					return e
				}
				out.Signed = &c
				return nil
			}
			if now.Before(a.SignBefore) {
				return nil
			}
			if len(rows) == 2 {
				return artifact.ErrDownloadCapacity
			}
		}
		end := identity.Earlier(p.FreshUntil, identity.Earlier(checked.freshUntil, identity.Earlier(now.Add(5*time.Second), until)))
		attempt := value.AcquisitionCertificateAttempt{ID: s.newID(), Epoch: epoch, Ordinal: len(rows) + 1, Enrollment: enrollment, Proof: p, RecoveryEpoch: checked.recoveryEpoch, EnrollmentAudit: receipt.SHA256, CheckedAt: now.UTC(), SignBefore: end, CertificateNotAfter: until}
		if !attempt.Valid(now) {
			return artifact.ErrDownloadExpired
		}
		b, e := json.Marshal(attempt)
		if e != nil || len(b) > 65536 {
			return artifact.ErrInvalid
		}
		if e = q.InsertWorkerCertificateAttempt(ctx, custodydb.InsertWorkerCertificateAttemptParams{ID: id(attempt.ID), WorkerID: r.WorkerID, Epoch: int32(epoch), Ordinal: int32(attempt.Ordinal), AttemptJson: b}); e != nil {
			return e
		}
		out = value.AcquisitionCertificateProgress{Attempt: attempt, MaySign: true}
		n, e := q.CurrentTime(ctx)
		if e != nil {
			return e
		}
		if !attempt.Valid(n.Time) {
			return artifact.ErrDownloadExpired
		}
		return nil
	})
	if err != nil {
		return value.AcquisitionCertificateProgress{}, err
	}
	return out, nil
}
func (s *ProjectionEnrollments) StoreAcquisitionCertificate(ctx context.Context, a value.AcquisitionCertificateAttempt, c value.WorkerCertificate) error {
	if !a.Matches(c) || artifact.Digest(sha256.Sum256(c.DER)) != c.Peer.Certificate {
		return artifact.ErrInvalid
	}
	b, e := json.Marshal(c)
	if e != nil || len(b) > 48<<10 {
		return artifact.ErrInvalid
	}
	return s.withProof(ctx, a.Proof, func(ctx context.Context, q *custodydb.Queries, checked admittedWorkerCheck, now time.Time) error {
		if a.RecoveryEpoch != checked.recoveryEpoch {
			return artifact.ErrDownloadExpired
		}
		if !a.Valid(now) || !c.Peer.Valid(now) {
			return artifact.ErrDownloadExpired
		}
		r, e := q.ReadWorkerCertificate(ctx, custodydb.ReadWorkerCertificateParams{ID: id(a.ID), WorkerID: id(a.Enrollment.Worker.Intent.ID)})
		if e != nil {
			return e
		}
		_, e = decodeAcquisitionCertificateAttempt(r)
		if e != nil || !storedAttempt(r.AttemptJson, a) {
			return artifact.ErrIntegrity
		}
		if r.CertificateJson != nil {
			if !bytes.Equal(r.CertificateJson, b) {
				return artifact.ErrIntegrity
			}
			return nil
		}
		n, e := q.StoreWorkerCertificate(ctx, custodydb.StoreWorkerCertificateParams{ID: r.ID, WorkerID: r.WorkerID, CertificateJson: b, CertificateSha256: c.Peer.Certificate[:]})
		if e != nil {
			return e
		}
		if n != 1 {
			return artifact.ErrDownloadConflict
		}
		final, e := q.CurrentTime(ctx)
		if e != nil {
			return e
		}
		if !a.Valid(final.Time) || !c.Peer.Valid(final.Time) {
			return artifact.ErrDownloadExpired
		}
		return nil
	})
}
func (s *ProjectionEnrollments) ActivateAcquisitionCertificate(ctx context.Context, p value.AcquisitionWorkerProof, a value.AcquisitionCertificateAttempt) (value.WorkerCertificate, error) {
	var out value.WorkerCertificate
	if a.Enrollment.Worker != p.Worker || a.Enrollment.PublicKeyDigest != p.PublicKeyDigest {
		return out, artifact.ErrInvalid
	}
	err := s.withProof(ctx, p, func(ctx context.Context, q *custodydb.Queries, checked admittedWorkerCheck, now time.Time) error {
		if a.RecoveryEpoch != checked.recoveryEpoch {
			return artifact.ErrDownloadExpired
		}
		enrollment, e := currentAuditedAcquisitionEnrollment(ctx, q, p.Worker)
		if e != nil || enrollment != a.Enrollment {
			return artifact.ErrDownloadUnavailable
		}

		r, e := q.ReadWorkerCertificate(ctx, custodydb.ReadWorkerCertificateParams{ID: id(a.ID), WorkerID: id(p.Worker.Intent.ID)})
		if e != nil {
			return e
		}
		_, e = decodeAcquisitionCertificateAttempt(r)
		if e != nil || !storedAttempt(r.AttemptJson, a) {
			return artifact.ErrIntegrity
		}
		out, e = decodeAcquisitionCertificate(r, a)
		if e != nil {
			return e
		}
		var receipt audit.Receipt
		if json.Unmarshal(r.AuditReceiptJson, &receipt) != nil || !receipt.ValidAcquisitionCertificate(audit.AcquisitionCertificate{Attempt: a, Peer: out.Peer}) || !out.Peer.Valid(now) {
			return artifact.ErrDownloadExpired
		}
		if r.ActivatedAt.Valid {
			return nil
		}
		n, e := q.ActivateWorkerCertificate(ctx, custodydb.ActivateWorkerCertificateParams{ID: r.ID, WorkerID: r.WorkerID})
		if e != nil {
			return e
		}
		if n != 1 {
			return artifact.ErrDownloadConflict
		}
		final, e := q.CurrentTime(ctx)
		if e != nil {
			return e
		}
		if !out.Peer.Valid(final.Time) {
			return artifact.ErrDownloadExpired
		}
		return nil
	})
	if err != nil {
		return value.WorkerCertificate{}, err
	}
	return out, nil
}

// Historical acknowledgement cannot create a signing permit or activate a
// certificate. Preserve the immutable original worker without renewing it.
func (s *ProjectionEnrollments) auditTransaction(ctx context.Context, w value.AcquisitionWorker, f func(context.Context, *custodydb.Queries) error) error {
	if s == nil || ctx == nil || !w.Valid() || w.Intent.Parent.Purpose != value.AcquisitionProjection || w.Intent.Profile != s.identity.profile {
		return artifact.ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return s.identity.ledger.transaction(ctx, func(tx *custodydb.Queries) error {
		row, e := tx.LockDownloadWorker(ctx, custodydb.LockDownloadWorkerParams{ID: id(w.Intent.ID), RootID: id(s.identity.root)})
		if e != nil {
			return e
		}
		var original query.ContextProjectionWorkerIntent
		if queryDecode(row.IntentJson, 65536, &original) != nil || !original.Valid() {
			return artifact.ErrIntegrity
		}
		stored, e := projectionWorkerState(row, original.Query)
		if e != nil || stored.Worker != w {
			return artifact.ErrIntegrity
		}
		return f(ctx, tx)
	})
}
func (s *ProjectionEnrollments) AcknowledgeAcquisitionEnrollment(ctx context.Context, e value.AcquisitionEnrollment, receipt audit.Receipt) error {
	if !receipt.ValidAcquisitionEnrollment(e) {
		return artifact.ErrInvalid
	}
	return s.auditTransaction(ctx, e.Worker, func(ctx context.Context, q *custodydb.Queries) error {
		r, err := q.ReadWorkerEnrollment(ctx, id(e.Worker.Intent.ID))
		if err != nil {
			return err
		}
		frozen, err := decodeAcquisitionEnrollment(r, e.Worker)
		if err != nil || frozen != e {
			return artifact.ErrIntegrity
		}
		b, _ := json.Marshal(receipt)
		if r.AuditReceiptJson != nil {
			if !bytes.Equal(b, r.AuditReceiptJson) {
				return artifact.ErrIntegrity
			}
			return nil
		}
		n, err := q.AcknowledgeWorkerEnrollment(ctx, custodydb.AcknowledgeWorkerEnrollmentParams{WorkerID: r.WorkerID, AuditReceiptJson: b})
		if err != nil {
			return err
		}
		if n != 1 {
			return artifact.ErrDownloadConflict
		}
		return nil
	})
}
func (s *ProjectionEnrollments) certificateAuditRow(ctx context.Context, q *custodydb.Queries, c audit.AcquisitionCertificate) (custodydb.DownloadWorkerCertificate, error) {
	r, e := q.ReadWorkerCertificate(ctx, custodydb.ReadWorkerCertificateParams{ID: id(c.Attempt.ID), WorkerID: id(c.Attempt.Enrollment.Worker.Intent.ID)})
	if e != nil {
		return r, e
	}
	a, e := decodeAcquisitionCertificateAttempt(r)
	if e != nil || !storedAttempt(r.AttemptJson, c.Attempt) {
		return r, artifact.ErrIntegrity
	}
	issued, e := decodeAcquisitionCertificate(r, a)
	if e != nil || issued.Peer != c.Peer {
		return r, artifact.ErrIntegrity
	}
	return r, nil
}
func (s *ProjectionEnrollments) ReadAcquisitionCertificateReceipt(ctx context.Context, c audit.AcquisitionCertificate) (audit.Receipt, bool, error) {
	var out audit.Receipt
	var ok bool
	if !c.Valid() {
		return out, false, artifact.ErrInvalid
	}
	err := s.auditTransaction(ctx, c.Attempt.Enrollment.Worker, func(ctx context.Context, q *custodydb.Queries) error {
		r, e := s.certificateAuditRow(ctx, q, c)
		if e != nil {
			return e
		}
		if r.AuditReceiptJson == nil {
			return nil
		}
		if json.Unmarshal(r.AuditReceiptJson, &out) != nil || !out.ValidAcquisitionCertificate(c) {
			return artifact.ErrIntegrity
		}
		ok = true
		return nil
	})
	if err != nil {
		return audit.Receipt{}, false, err
	}
	return out, ok, nil
}
func (s *ProjectionEnrollments) AcknowledgeAcquisitionCertificate(ctx context.Context, c audit.AcquisitionCertificate, receipt audit.Receipt) error {
	if !receipt.ValidAcquisitionCertificate(c) {
		return artifact.ErrInvalid
	}
	return s.auditTransaction(ctx, c.Attempt.Enrollment.Worker, func(ctx context.Context, q *custodydb.Queries) error {
		r, e := s.certificateAuditRow(ctx, q, c)
		if e != nil {
			return e
		}
		b, _ := json.Marshal(receipt)
		if r.AuditReceiptJson != nil {
			if !bytes.Equal(b, r.AuditReceiptJson) {
				return artifact.ErrIntegrity
			}
			return nil
		}
		n, e := q.AcknowledgeWorkerCertificate(ctx, custodydb.AcknowledgeWorkerCertificateParams{ID: r.ID, WorkerID: r.WorkerID, AuditReceiptJson: b})
		if e != nil {
			return e
		}
		if n != 1 {
			return artifact.ErrDownloadConflict
		}
		return nil
	})
}

func activeAcquisitionCertificate(ctx context.Context, q *custodydb.Queries, w value.AcquisitionWorker, peer value.KeyPeer) error {
	enrollment, err := currentAuditedAcquisitionEnrollment(ctx, q, w)
	if err != nil {
		return err
	}

	r, e := q.ReadActiveWorkerCertificate(ctx, custodydb.ReadActiveWorkerCertificateParams{WorkerID: id(w.Intent.ID), CertificateSha256: peer.Certificate[:]})
	if e != nil {
		return artifact.ErrDownloadUnavailable
	}
	a, e := decodeAcquisitionCertificateAttempt(r)
	if e != nil || a.Enrollment != enrollment {
		return artifact.ErrIntegrity
	}
	c, e := decodeAcquisitionCertificate(r, a)
	if e != nil || c.Peer != peer {
		return artifact.ErrIntegrity
	}
	var receipt audit.Receipt
	if json.Unmarshal(r.AuditReceiptJson, &receipt) != nil || !receipt.ValidAcquisitionCertificate(audit.AcquisitionCertificate{Attempt: a, Peer: peer}) {
		return artifact.ErrIntegrity
	}
	return nil
}
