package audit

import (
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	"time"
)

func OwnerEnrollmentKey(e value.OwnerEnrollment) string {
	return "hub-owner-enrollment/v1/" + e.Binding.InstallationID + "/" + e.ID
}
func (r Receipt) ValidOwnerEnrollment(e value.OwnerEnrollment) bool {
	return e.Valid() && r.Version != "null" && identity.Text(r.Version, 1024) && r.workerReceipt(OwnerEnrollmentKey(e))
}

type OwnerCertificate struct {
	Attempt     value.OwnerCertificateAttempt
	Certificate value.OwnerCertificate
}

func (r OwnerCertificate) Valid() bool {
	a, c := r.Attempt, r.Certificate
	p := a.Permit
	return a.Valid(p.CheckedAt) && c.Valid(p.CheckedAt) && c.Binding == p.Binding && c.Usage == p.Usage && c.NotAfter.Equal(p.CertificateNotAfter) && !c.NotBefore.Before(p.CheckedAt.Add(-time.Minute))
}
func OwnerCertificateKey(c OwnerCertificate) string {
	return "hub-owner-certificate/v1/" + c.Certificate.Binding.InstallationID + "/" + c.Attempt.Permit.ID
}
func (r Receipt) ValidOwnerCertificate(c OwnerCertificate) bool {
	return c.Valid() && r.Version != "null" && identity.Text(r.Version, 1024) && r.workerReceipt(OwnerCertificateKey(c))
}
