package fleet

import (
	"time"

	"asservat.local/asservat/internal/domain/authorization"
)

// SigningAttempt identifies one durably spent provider attempt. A value does
// not authorize calling a provider: only a successful Prepare result with
// MaySign does, and only within its original five-second interval.
type SigningAttempt struct {
	ID      string
	Ordinal int16
	Permit  CertificateIssuePermit
}

func (s SigningAttempt) Valid(now time.Time) bool {
	return authorization.UUID(s.ID) && s.Ordinal >= 1 && s.Ordinal <= 2 && s.Permit.Valid(now)
}

type EnrollmentProgress struct {
	Attempt SigningAttempt
	MaySign bool
	Signed  *IssuedCertificate
	Active  bool
}

// MatchesIssued checks bounded data consistency, not X.509 trust. The C-21
// issuer/verifier must independently validate the actual chain and CSR key.
func (s SigningAttempt) MatchesIssued(c IssuedCertificate) bool {
	if !c.Certificate.Valid(s.Permit.CheckedAt) || c.Certificate.Binding != s.Permit.Enrollment.Binding || !c.Certificate.NotAfter.Equal(s.Permit.CertificateNotAfter()) || c.Certificate.NotBefore.Before(s.Permit.Enrollment.ClaimedAt.Add(-time.Minute)) || len(c.DER) == 0 || len(c.DER) > 16<<10 || len(c.ChainDER) > 3 {
		return false
	}
	total := len(c.DER)
	for _, b := range c.ChainDER {
		if len(b) == 0 || len(b) > 16<<10 {
			return false
		}
		total += len(b)
	}
	return total <= 32<<10
}
