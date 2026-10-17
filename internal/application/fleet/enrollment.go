package fleet

import (
	"context"

	"asservat.local/asservat/internal/domain/audit"
	value "asservat.local/asservat/internal/domain/fleet"
)

// EnrollmentLedger only claims an existing reviewed/audited bootstrap slot.
// Claiming cannot issue a certificate or activate peer authority. Lost replies
// retry this same identity/key within its unchanged expiry.
type EnrollmentLedger interface {
	ClaimConnector(context.Context, value.EnrollmentClaim) (value.Enrollment, error)
}

// CertificateIssuer cannot activate the resulting certificate. Its coordinator
// records an exact audit/registration after verifying the result. An uncertain
// remote signing outcome never becomes an automatically trusted certificate.
type CertificateIssuer interface {
	SignConnector(context.Context, value.CertificateIssuePermit, []byte) (value.IssuedCertificate, error)
}

// SigningLedger spends provider attempts before I/O. Replays observe the
// existing attempt and never acquire another allowance while it is live.
type SigningLedger interface {
	PrepareConnector(context.Context, value.EnrollmentClaim) (value.EnrollmentProgress, error)
	StoreConnectorCertificate(context.Context, value.SigningAttempt, value.IssuedCertificate) error
}
type EnrollmentActivator interface {
	ActivateConnector(context.Context, value.EnrollmentClaim, string) (value.IssuedCertificate, error)
}

// BootstrapCredentials stores a credential in a configured operator channel.
// It returns only its digest and opaque reference; no API result contains the
// secret. A separate audited SQL issuance step makes that credential usable.
type BootstrapCredentials interface {
	EnsureBootstrapCredential(context.Context, value.BootstrapSlot) (value.BootstrapCredential, error)
}

type BootstrapReservations interface {
	ReserveBootstrap(context.Context, value.BootstrapRequest) (value.BootstrapIntent, error)
}

type BootstrapCredentialRecorder interface {
	RecordBootstrapCredential(context.Context, value.BootstrapSlot, value.BootstrapCredential) (audit.BootstrapIssue, error)
}
type BootstrapActivator interface {
	ActivateBootstrap(context.Context, value.BootstrapRequest, string) (value.BootstrapIntent, error)
}
