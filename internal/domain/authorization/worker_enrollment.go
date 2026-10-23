package authorization

import (
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/identity"
	"time"
)

// WorkerEnrollmentProof proves the admitted Pod token and CSR key before a
// client certificate exists. It is neither a signing permit nor evidence access.
type WorkerEnrollmentProof struct {
	Worker                       DownloadWorker
	PublicKeyDigest, TokenDigest artifact.Digest
	ObservedAt, FreshUntil       time.Time
}

func (p WorkerEnrollmentProof) Valid(now time.Time) bool {
	return p.Worker.Valid() && p.PublicKeyDigest != (artifact.Digest{}) && p.TokenDigest != (artifact.Digest{}) && identity.Fresh(p.ObservedAt, p.FreshUntil, now, 5*time.Second) && !p.FreshUntil.After(p.Worker.Intent.RunUntil)
}

// One immutable key enrollment per admitted worker. Token refresh and retry do
// not replace the process key or extend the worker's original deadline.
type WorkerEnrollment struct {
	Worker          DownloadWorker
	PublicKeyDigest artifact.Digest
	ClaimedAt       time.Time
}

func (e WorkerEnrollment) Valid() bool {
	return e.Worker.Valid() && e.PublicKeyDigest != (artifact.Digest{}) && !e.ClaimedAt.Before(e.Worker.Intent.CreatedAt) && e.ClaimedAt.Before(e.Worker.Intent.RunUntil)
}

const WorkerCertificatePeriod = 20 * time.Minute
const WorkerCertificateRenewBefore = time.Minute

// Epochs derive from the original worker start, never from a retry. There are
// at most 24 epochs for the eight-hour worker ceiling. A next epoch may be
// prepared one minute early, avoiding a forced TLS outage at renewal.
func WorkerCertificateEpoch(w DownloadWorker, now time.Time) (int, time.Time, error) {
	if !w.Valid() {
		return 0, time.Time{}, artifact.ErrInvalid
	}
	return workerCertificatePeriod(w.Intent.CreatedAt, w.Intent.RunUntil, now)
}

// WorkerCredentialTarget is public bootstrap identity, not execution authority.
// Its exact values come from the admitted Job and pinned installation config.
// A certificate and this value never replace current SQL/token authorization.
type WorkerCredentialTarget struct {
	InstallationID, SessionID, WorkerID, PodUID string
	QueryID                                     string `json:",omitempty"`
	CreatedAt, RunUntil                         time.Time
}

func (t WorkerCredentialTarget) Valid() bool {
	return UUID(t.InstallationID) && t.Parent().Valid() && UUID(t.WorkerID) && UUID(t.PodUID) && !t.CreatedAt.IsZero() && t.RunUntil.Sub(t.CreatedAt) >= time.Second && t.RunUntil.Sub(t.CreatedAt) <= 8*time.Hour
}

func (t WorkerCredentialTarget) Parent() AcquisitionParent {
	return AcquisitionParentFor(t.SessionID, t.QueryID)
}

func (t WorkerCredentialTarget) CertificateEpoch(now time.Time) (int, time.Time, error) {
	if !t.Valid() {
		return 0, time.Time{}, artifact.ErrInvalid
	}
	return workerCertificatePeriod(t.CreatedAt, t.RunUntil, now)
}

func workerCertificatePeriod(created, end, now time.Time) (int, time.Time, error) {
	if now.Before(created) || !now.Before(end) {
		return 0, time.Time{}, artifact.ErrInvalid
	}
	last := int((end.Sub(created) - time.Nanosecond) / WorkerCertificatePeriod)
	epoch := min(int((now.Sub(created)+WorkerCertificateRenewBefore)/WorkerCertificatePeriod), last)
	if epoch < 0 || epoch > 23 {
		return 0, time.Time{}, artifact.ErrInvalid
	}
	until := identity.Earlier(end, created.Add(time.Duration(epoch+1)*WorkerCertificatePeriod)).UTC().Truncate(time.Second)
	if !now.Before(until) {
		return 0, time.Time{}, artifact.ErrDownloadExpired
	}
	return epoch, until, nil
}

type WorkerCertificateAttempt struct {
	ID                                         string
	Epoch, Ordinal                             int
	Enrollment                                 WorkerEnrollment
	Proof                                      WorkerEnrollmentProof
	RecoveryEpoch                              string
	EnrollmentAudit                            artifact.Digest
	CheckedAt, SignBefore, CertificateNotAfter time.Time
}

func (a WorkerCertificateAttempt) Valid(now time.Time) bool {
	epoch, until, err := WorkerCertificateEpoch(a.Enrollment.Worker, a.CheckedAt)
	return err == nil && UUID(a.ID) && a.Epoch == epoch && a.Ordinal >= 1 && a.Ordinal <= 2 && a.Enrollment.Valid() && a.Proof.Worker == a.Enrollment.Worker && a.Proof.PublicKeyDigest == a.Enrollment.PublicKeyDigest && a.Proof.Valid(now) && UUID(a.RecoveryEpoch) && a.EnrollmentAudit != (artifact.Digest{}) && identity.Fresh(a.CheckedAt, a.SignBefore, now, 5*time.Second) && !a.SignBefore.After(a.Proof.FreshUntil) && a.CertificateNotAfter.Equal(until) && !a.SignBefore.After(until)
}

type WorkerCertificate struct {
	Peer     KeyPeer
	DER      []byte
	ChainDER [][]byte
}

// Matches checks bounded consistency only. X.509 trust, CSR key and proof of
// possession must be checked independently by the configured issuer/verifier.
func (a WorkerCertificateAttempt) Matches(c WorkerCertificate) bool {
	return a.Valid(a.CheckedAt) && a.Acquisition().Matches(c)
}

type WorkerCertificateProgress struct {
	Attempt WorkerCertificateAttempt
	MaySign bool
	Signed  *WorkerCertificate
}
