package fleet

import (
	"context"
	"time"

	auditport "asservat.local/asservat/internal/application/audit"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	value "asservat.local/asservat/internal/domain/fleet"
)

type EnrollmentAuthorityResolver interface {
	AuthorizeEnrollment(context.Context, string, string) (value.EnrollmentAuthority, error)
}

// BootstrapInput contains request intent only. The caller cannot supply actor,
// trust, quota or authority fields; these come from the protected authorizer.
type BootstrapInput struct {
	KeyDigest                            artifact.Digest
	DisplayName, Region, DeliveryProfile string
}

type BootstrapIssuer struct {
	Authority    EnrollmentAuthorityResolver
	Reservations BootstrapReservations
	Credentials  BootstrapCredentials
	Records      BootstrapCredentialRecorder
	Audits       auditport.BootstrapIssueLedger
	Objects      auditport.BootstrapIssueWriter
	Activation   BootstrapActivator
	Now          func() time.Time
}

func (s BootstrapIssuer) Issue(ctx context.Context, token string, in BootstrapInput) (value.BootstrapIntent, error) {
	var empty value.BootstrapIntent
	if s.Authority == nil || s.Reservations == nil || s.Credentials == nil || s.Records == nil || s.Audits == nil || s.Objects == nil || s.Activation == nil || s.Now == nil {
		return empty, value.ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	a, err := s.Authority.AuthorizeEnrollment(ctx, token, in.DeliveryProfile)
	if err != nil {
		return empty, err
	}
	request := value.BootstrapRequest{KeyDigest: in.KeyDigest, DisplayName: in.DisplayName, Region: in.Region, Authority: a}
	if !request.Valid(s.Now()) || a.DeliveryProfile != in.DeliveryProfile {
		return empty, value.ErrDenied
	}
	intent, err := s.Reservations.ReserveBootstrap(ctx, request)
	if err != nil {
		return empty, err
	}
	if !intent.Slot.Valid(s.Now()) || intent.Actor != a.Actor || intent.AdministrationRevision != a.AdministrationRevision || intent.Slot.Binding.InstallationID != a.InstallationID || intent.Slot.Binding.IssuerEpoch != a.IssuerEpoch || intent.Slot.DeliveryProfile != in.DeliveryProfile || intent.DisplayName != in.DisplayName || intent.Region != in.Region {
		return empty, value.ErrDenied
	}
	if intent.Credential == nil {
		c, err := s.Credentials.EnsureBootstrapCredential(ctx, intent.Slot)
		if err != nil {
			return empty, err
		}
		if !c.Matches(intent.Slot) {
			return empty, value.ErrDenied
		}
		intent.Credential = &c
	}
	if !intent.Credential.Matches(intent.Slot) {
		return empty, value.ErrDenied
	}
	r, err := s.Records.RecordBootstrapCredential(ctx, intent.Slot, *intent.Credential)
	if err != nil {
		return empty, err
	}
	want := audit.BootstrapIssue{ID: intent.Slot.ID, Binding: intent.Slot.Binding, RequestDigest: intent.Slot.RequestDigest, Actor: intent.Actor, IdentityRevision: intent.IdentityRevision, AdministrationRevision: intent.AdministrationRevision, DisplayName: intent.DisplayName, Region: intent.Region, DeliveryProfile: intent.Slot.DeliveryProfile, NotBefore: intent.Slot.NotBefore, NotAfter: intent.Slot.NotAfter, Credential: *intent.Credential}
	if !r.Valid() || r != want {
		return empty, value.ErrDenied
	}
	receipt, err := s.Objects.WriteBootstrapIssue(ctx, r)
	if err != nil {
		return empty, err
	}
	if !receipt.ValidBootstrapIssue(a.InstallationID, intent.Slot.ID) {
		return empty, value.ErrDenied
	}
	if err = s.Audits.AcknowledgeBootstrapIssue(ctx, r, receipt); err != nil {
		return empty, err
	}
	// Provider and audit I/O can outlast the original five-second authority.
	// Revalidate the authenticated actor and protected policy without renewing
	// the reserved IDs, original request, credential or five-minute deadline.
	current, err := s.Authority.AuthorizeEnrollment(ctx, token, in.DeliveryProfile)
	if err != nil {
		return empty, err
	}
	if !current.Valid(s.Now()) || current.Actor != a.Actor || current.InstallationID != a.InstallationID || current.IssuerEpoch != a.IssuerEpoch || current.AdministrationRevision != a.AdministrationRevision || current.DeliveryProfile != a.DeliveryProfile || ctx.Err() != nil {
		return empty, value.ErrDenied
	}
	request.Authority = current
	out, err := s.Activation.ActivateBootstrap(ctx, request, intent.Slot.ID)
	if err != nil {
		return empty, err
	}
	if !out.Issued || out.Credential == nil || *out.Credential != *intent.Credential || out.Actor != intent.Actor || out.Slot.ID != intent.Slot.ID || out.Slot.Binding != intent.Slot.Binding || out.Slot.RequestDigest != intent.Slot.RequestDigest || !out.Slot.NotBefore.Equal(intent.Slot.NotBefore) || !out.Slot.NotAfter.Equal(intent.Slot.NotAfter) {
		return empty, value.ErrDenied
	}
	return out, nil
}
