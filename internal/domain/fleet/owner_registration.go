package fleet

import (
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
)

// Registrations include uncertain/retired attempts until every possible leaf
// and request locator has expired. These are internal capacity ceilings.
const OwnerRegistrationsPerPool = 1024
const OwnerRegistrationsPerPod = 32
const OwnerRegistrationGrace = time.Minute

type OwnerEnrollment struct {
	ID                                                                                  string
	Binding                                                                             OwnerBinding
	Usage                                                                               string
	Pool                                                                                OwnerPool
	SourceUID, Pod, ReplicaSet, ReplicaSetUID                                           string
	PublicKeyDigest, InitialTokenDigest, InitialWorkloadDigest, InitialProtectionDigest artifact.Digest
	ClaimedAt, InitialHoldUntil                                                         time.Time
}

func (e OwnerEnrollment) Valid() bool {
	_, until, err := OwnerCertificateWindow(e.ClaimedAt)
	return err == nil && authorization.UUID(e.ID) && e.Binding.Valid() && e.Pool.Valid() && e.Binding.InstallationID == e.Pool.InstallationID && e.Binding.ClusterID == e.Pool.ClusterID && e.Binding.IssuerEpoch == e.Pool.IssuerEpoch && (e.Usage == "server" || e.Usage == "client") && authorization.UUID(e.SourceUID) && identity.Text(e.Pod, 253) && identity.Text(e.ReplicaSet, 253) && authorization.UUID(e.ReplicaSetUID) && e.PublicKeyDigest != (artifact.Digest{}) && e.InitialTokenDigest != (artifact.Digest{}) && e.InitialWorkloadDigest != (artifact.Digest{}) && e.InitialProtectionDigest != (artifact.Digest{}) && e.InitialHoldUntil.Equal(until.Add(OwnerRegistrationGrace))
}

func (e OwnerEnrollment) Matches(p OwnerEnrollmentProof) bool {
	return e.Valid() && p.WellFormed() && e.Binding == p.Binding && e.Usage == p.Usage && e.Pool == p.Configuration.Configuration.Pool && e.SourceUID == p.Configuration.Configuration.Revision.UID && e.PublicKeyDigest == p.PublicKeyDigest && e.Pod == p.Pod && e.ReplicaSet == p.ReplicaSet && e.ReplicaSetUID == p.ReplicaSetUID
}

// Keep the configuration once, in Permit. The remaining fields preserve the
// original workload proof; a retry cannot turn its deadline into a fresh one.
type OwnerCertificateAttempt struct {
	Enrollment                                    OwnerEnrollment
	Permit                                        OwnerCertificatePermit
	TokenDigest, WorkloadDigest, ProtectionDigest artifact.Digest
	ProofObservedAt, ProofFreshUntil              time.Time
}

func (a OwnerCertificateAttempt) Proof() OwnerEnrollmentProof {
	return OwnerEnrollmentProof{Binding: a.Enrollment.Binding, Usage: a.Enrollment.Usage, Configuration: a.Permit.Configuration, Pod: a.Enrollment.Pod, ReplicaSet: a.Enrollment.ReplicaSet, ReplicaSetUID: a.Enrollment.ReplicaSetUID, PublicKeyDigest: a.Enrollment.PublicKeyDigest, TokenDigest: a.TokenDigest, WorkloadDigest: a.WorkloadDigest, ProtectionDigest: a.ProtectionDigest, ObservedAt: a.ProofObservedAt, FreshUntil: a.ProofFreshUntil}
}
func (a OwnerCertificateAttempt) Valid(now time.Time) bool {
	p := a.Proof()
	return a.Enrollment.Matches(p) && p.Valid(now) && a.Permit.Valid(now) && a.Permit.Binding == a.Enrollment.Binding && a.Permit.Usage == a.Enrollment.Usage && a.Permit.PublicKeyDigest == a.Enrollment.PublicKeyDigest && !a.Permit.SignBefore.After(p.FreshUntil) && !a.Permit.CheckedAt.Before(a.Enrollment.ClaimedAt)
}
func (a OwnerCertificateAttempt) Equal(b OwnerCertificateAttempt) bool {
	x, y := a.Permit, b.Permit
	return a.Enrollment == b.Enrollment && a.TokenDigest == b.TokenDigest && a.WorkloadDigest == b.WorkloadDigest && a.ProtectionDigest == b.ProtectionDigest && a.ProofObservedAt.Equal(b.ProofObservedAt) && a.ProofFreshUntil.Equal(b.ProofFreshUntil) && x.ID == y.ID && x.Binding == y.Binding && x.Usage == y.Usage && x.PublicKeyDigest == y.PublicKeyDigest && x.EnrollmentAudit == y.EnrollmentAudit && x.Configuration.Configuration.Equal(y.Configuration.Configuration) && x.Configuration.ObservedAt.Equal(y.Configuration.ObservedAt) && x.Configuration.FreshUntil.Equal(y.Configuration.FreshUntil) && x.Recovery.InstallationID == y.Recovery.InstallationID && x.Recovery.IssuerEpoch == y.Recovery.IssuerEpoch && x.Recovery.Revision == y.Recovery.Revision && x.Recovery.ObservedAt.Equal(y.Recovery.ObservedAt) && x.Recovery.FreshUntil.Equal(y.Recovery.FreshUntil) && x.Epoch == y.Epoch && x.Ordinal == y.Ordinal && x.CheckedAt.Equal(y.CheckedAt) && x.SignBefore.Equal(y.SignBefore) && x.CertificateNotAfter.Equal(y.CertificateNotAfter)
}
func (a OwnerCertificateAttempt) Clone() OwnerCertificateAttempt {
	a.Permit.Configuration.Configuration = a.Permit.Configuration.Configuration.Clone()
	return a
}

type OwnerCertificateProgress struct {
	Attempt OwnerCertificateAttempt
	MaySign bool
	Signed  *IssuedOwnerCertificate
}

type OwnerRegistrationObservation struct {
	Enrollment             OwnerEnrollment
	Certificate            OwnerCertificate
	Configuration          OwnerConfigurationObservation
	ObservedAt, FreshUntil time.Time
}

func (o OwnerRegistrationObservation) Valid(now time.Time) bool {
	return o.Enrollment.Valid() && o.Certificate.Valid(now) && o.Certificate.Binding == o.Enrollment.Binding && o.Certificate.Usage == o.Enrollment.Usage && o.Configuration.Valid(now) && !o.Configuration.Configuration.Suspended && o.Configuration.Configuration.Pool == o.Enrollment.Pool && o.Configuration.Configuration.Revision.UID == o.Enrollment.SourceUID && identity.Fresh(o.ObservedAt, o.FreshUntil, now, 5*time.Second) && !o.FreshUntil.After(o.Configuration.FreshUntil) && !o.FreshUntil.After(o.Certificate.NotAfter)
}
