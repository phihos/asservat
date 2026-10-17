package fleet

import (
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	"bytes"
	"time"
)

const OwnerCertificatePeriod = 20 * time.Minute
const OwnerCertificateRenewBefore = time.Minute

// Periods are anchored to UTC, not a retry or process restart. Preparing the
// next period one minute early avoids an obligatory connection outage. A
// long-lived owner can renew; every period still needs fresh proof/activation.
func OwnerCertificateWindow(now time.Time) (int64, time.Time, error) {
	if now.IsZero() || now.Unix() < 0 || now.Year() > 9999 {
		return 0, time.Time{}, ErrInvalid
	}
	epoch := (now.Unix() + int64(OwnerCertificateRenewBefore/time.Second)) / int64(OwnerCertificatePeriod/time.Second)
	return epoch, time.Unix((epoch+1)*int64(OwnerCertificatePeriod/time.Second), 0).UTC(), nil
}

// This is the exact already-spent signing attempt supplied by the coordinator,
// not an ingress grant. Proof of Pod/process ownership, durable attempt spend,
// encrypted enrollment audit and later activation remain separate boundaries.
type OwnerCertificatePermit struct {
	ID                                         string
	Binding                                    OwnerBinding
	Usage                                      string
	PublicKeyDigest, EnrollmentAudit           artifact.Digest
	Configuration                              OwnerConfigurationObservation
	Recovery                                   RecoveryState
	Epoch                                      int64
	Ordinal                                    int
	CheckedAt, SignBefore, CertificateNotAfter time.Time
}

func (p OwnerCertificatePermit) Valid(now time.Time) bool {
	epoch, until, err := OwnerCertificateWindow(p.CheckedAt)
	b, c := p.Binding, p.Configuration.Configuration
	return err == nil && authorization.UUID(p.ID) && b.Valid() && (p.Usage == "server" || p.Usage == "client") && p.PublicKeyDigest != (artifact.Digest{}) && p.EnrollmentAudit != (artifact.Digest{}) && p.Configuration.Valid(now) && !c.Suspended && b.InstallationID == c.Pool.InstallationID && b.ClusterID == c.Pool.ClusterID && b.IssuerEpoch == c.Pool.IssuerEpoch && p.Recovery.Valid(now) && p.Recovery.InstallationID == b.InstallationID && p.Recovery.IssuerEpoch == b.IssuerEpoch && p.Epoch == epoch && p.Ordinal >= 1 && p.Ordinal <= 2 && p.CertificateNotAfter.Equal(until) && identity.Fresh(p.CheckedAt, p.SignBefore, now, 5*time.Second) && !p.SignBefore.After(p.Configuration.FreshUntil) && !p.SignBefore.After(p.Recovery.FreshUntil) && !p.SignBefore.After(until)
}

type IssuedOwnerCertificate struct {
	Certificate OwnerCertificate
	DER         []byte
	ChainDER    [][]byte
}

func (c IssuedOwnerCertificate) Clone() IssuedOwnerCertificate {
	c.DER = bytes.Clone(c.DER)
	c.ChainDER = append([][]byte(nil), c.ChainDER...)
	for i, r := range c.ChainDER {
		c.ChainDER[i] = bytes.Clone(r)
	}
	return c
}

// Structural consistency only. The adapter must additionally verify X.509,
// exact CSR key and actual certificate digest before storing or activating.
func (p OwnerCertificatePermit) Matches(c IssuedOwnerCertificate) bool {
	if !p.Valid(p.CheckedAt) || !c.Certificate.Valid(p.CheckedAt) || c.Certificate.Binding != p.Binding || c.Certificate.Usage != p.Usage || !c.Certificate.NotAfter.Equal(p.CertificateNotAfter) || c.Certificate.NotBefore.Before(p.CheckedAt.Add(-time.Minute)) || len(c.DER) < 1 || len(c.DER) > 16<<10 || len(c.ChainDER) > 3 {
		return false
	}
	n := len(c.DER)
	for _, b := range c.ChainDER {
		if len(b) < 1 || len(b) > 16<<10 {
			return false
		}
		n += len(b)
	}
	return n <= 32<<10
}
