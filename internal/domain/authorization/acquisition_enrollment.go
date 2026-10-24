package authorization

import (
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/identity"
)

// These values carry only the admitted worker's identity and spent signing
// attempt. Their producer must separately check the exact parent's authority.
// They share one certificate algorithm without carrying human grants to a Pod.
type AcquisitionWorkerProof struct {
	Worker                       AcquisitionWorker
	PublicKeyDigest, TokenDigest artifact.Digest
	ObservedAt, FreshUntil       time.Time
}

func (p AcquisitionWorkerProof) Valid(now time.Time) bool {
	return p.Worker.Valid() && p.PublicKeyDigest != (artifact.Digest{}) && p.TokenDigest != (artifact.Digest{}) &&
		identity.Fresh(p.ObservedAt, p.FreshUntil, now, 5*time.Second) && !p.FreshUntil.After(p.Worker.Intent.RunUntil)
}

type AcquisitionEnrollment struct {
	Worker          AcquisitionWorker
	PublicKeyDigest artifact.Digest
	ClaimedAt       time.Time
}

func (e AcquisitionEnrollment) Valid() bool {
	return e.Worker.Valid() && e.PublicKeyDigest != (artifact.Digest{}) &&
		!e.ClaimedAt.Before(e.Worker.Intent.CreatedAt) && e.ClaimedAt.Before(e.Worker.Intent.RunUntil)
}

type AcquisitionCertificateAttempt struct {
	ID                                         string
	Epoch, Ordinal                             int
	Enrollment                                 AcquisitionEnrollment
	Proof                                      AcquisitionWorkerProof
	RecoveryEpoch                              string
	EnrollmentAudit                            artifact.Digest
	CheckedAt, SignBefore, CertificateNotAfter time.Time
}

func (a AcquisitionCertificateAttempt) Valid(now time.Time) bool {
	epoch, until, err := a.Enrollment.Worker.CertificateEpoch(a.CheckedAt)
	return err == nil && UUID(a.ID) && a.Epoch == epoch && a.Ordinal >= 1 && a.Ordinal <= 2 &&
		a.Enrollment.Valid() && a.Proof.Worker == a.Enrollment.Worker && a.Proof.PublicKeyDigest == a.Enrollment.PublicKeyDigest &&
		a.Proof.Valid(now) && UUID(a.RecoveryEpoch) && a.EnrollmentAudit != (artifact.Digest{}) &&
		identity.Fresh(a.CheckedAt, a.SignBefore, now, 5*time.Second) && !a.SignBefore.After(a.Proof.FreshUntil) &&
		a.CertificateNotAfter.Equal(until) && !a.SignBefore.After(until)
}

func (a AcquisitionCertificateAttempt) Matches(c WorkerCertificate) bool {
	b := a.Enrollment.Worker.Binding
	if !a.Valid(a.CheckedAt) || !c.Peer.Valid(a.CheckedAt) || c.Peer.Role != "acquisition" ||
		c.Peer.InstallationID != b.InstallationID || c.Peer.PeerID != b.PodUID || !c.Peer.NotAfter.Equal(a.CertificateNotAfter) ||
		c.Peer.NotBefore.Before(a.CheckedAt.Add(-time.Minute)) || len(c.DER) < 1 || len(c.DER) > 16<<10 || len(c.ChainDER) > 3 {
		return false
	}
	size := len(c.DER)
	for _, der := range c.ChainDER {
		if len(der) < 1 || len(der) > 16<<10 {
			return false
		}
		size += len(der)
	}
	return size <= 32<<10
}

func (p WorkerEnrollmentProof) Acquisition() AcquisitionWorkerProof {
	return AcquisitionWorkerProof{Worker: p.Worker.Acquisition(), PublicKeyDigest: p.PublicKeyDigest, TokenDigest: p.TokenDigest,
		ObservedAt: p.ObservedAt, FreshUntil: p.FreshUntil}
}

func (e WorkerEnrollment) Acquisition() AcquisitionEnrollment {
	return AcquisitionEnrollment{Worker: e.Worker.Acquisition(), PublicKeyDigest: e.PublicKeyDigest, ClaimedAt: e.ClaimedAt}
}

// Existing download records retain their serialized form and audit identity.
// Only checked immutable identity is passed to the common certificate code.
func (a WorkerCertificateAttempt) Acquisition() AcquisitionCertificateAttempt {
	return AcquisitionCertificateAttempt{ID: a.ID, Epoch: a.Epoch, Ordinal: a.Ordinal,
		Enrollment: a.Enrollment.Acquisition(), Proof: a.Proof.Acquisition(), RecoveryEpoch: a.RecoveryEpoch,
		EnrollmentAudit: a.EnrollmentAudit, CheckedAt: a.CheckedAt, SignBefore: a.SignBefore,
		CertificateNotAfter: a.CertificateNotAfter}
}

// A replay observes the original finite attempt; only the inserting call may
// sign it. A missing/unknown provider response never resets MaySign.
type AcquisitionCertificateProgress struct {
	Attempt AcquisitionCertificateAttempt
	Signed  *WorkerCertificate
	MaySign bool
}
