package fleet

import (
	"context"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
)

type bootstrapFixture struct {
	now                                                                                            time.Time
	a                                                                                              value.EnrollmentAuthority
	intent                                                                                         value.BootstrapIntent
	authorizations, credentials, activations                                                       int
	failAuthority, changeActor, changeEpoch, changeSettings, changeCredential, failObject, failACK bool
	delay                                                                                          time.Duration
}

func (f *bootstrapFixture) AuthorizeEnrollment(context.Context, string, string) (value.EnrollmentAuthority, error) {
	f.authorizations++
	a := f.a
	a.CheckedAt = f.now
	a.ValidUntil = f.now.Add(5 * time.Second)
	if f.authorizations > 1 {
		if f.failAuthority {
			return value.EnrollmentAuthority{}, value.ErrDenied
		}
		if f.changeActor {
			a.Actor.Subject = "another"
		}
		if f.changeEpoch {
			a.IssuerEpoch = "00000000-0000-4000-8000-000000000009"
		}
		if f.changeSettings {
			a.AdministrationRevision.Generation++
		}
	}
	return a, nil
}
func (f *bootstrapFixture) ReserveBootstrap(context.Context, value.BootstrapRequest) (value.BootstrapIntent, error) {
	return f.intent, nil
}
func (f *bootstrapFixture) EnsureBootstrapCredential(_ context.Context, s value.BootstrapSlot) (value.BootstrapCredential, error) {
	f.credentials++
	f.now = f.now.Add(f.delay)
	return value.BootstrapCredential{SlotID: s.ID, DeliveryProfile: s.DeliveryProfile, SecretDigest: artifact.Digest{3}, Version: 1}, nil
}
func (f *bootstrapFixture) RecordBootstrapCredential(_ context.Context, s value.BootstrapSlot, c value.BootstrapCredential) (audit.BootstrapIssue, error) {
	f.intent.Credential = &c
	r := audit.BootstrapIssue{ID: s.ID, Binding: s.Binding, RequestDigest: s.RequestDigest, Actor: f.intent.Actor, IdentityRevision: f.intent.IdentityRevision, AdministrationRevision: f.intent.AdministrationRevision, DisplayName: f.intent.DisplayName, Region: f.intent.Region, DeliveryProfile: s.DeliveryProfile, NotBefore: s.NotBefore, NotAfter: s.NotAfter, Credential: c}
	if f.changeCredential {
		r.Credential.SecretDigest[0]++
	}
	return r, nil
}
func (f *bootstrapFixture) PendingBootstrapIssues(context.Context) ([]audit.BootstrapIssue, error) {
	return nil, nil
}
func (f *bootstrapFixture) WriteBootstrapIssue(_ context.Context, r audit.BootstrapIssue) (audit.Receipt, error) {
	if f.failObject {
		return audit.Receipt{}, value.ErrUnavailable
	}
	return audit.Receipt{Key: audit.BootstrapIssueKey(r.Binding.InstallationID, r.ID), Version: "synthetic-version", ETag: "synthetic", Bytes: 100, SHA256: artifact.Digest{5}}, nil
}
func (f *bootstrapFixture) AcknowledgeBootstrapIssue(context.Context, audit.BootstrapIssue, audit.Receipt) error {
	if f.failACK {
		return value.ErrUnavailable
	}
	return nil
}
func (f *bootstrapFixture) ActivateBootstrap(_ context.Context, r value.BootstrapRequest, id string) (value.BootstrapIntent, error) {
	f.activations++
	if !r.Authority.Valid(f.now) || id != f.intent.Slot.ID {
		return value.BootstrapIntent{}, value.ErrDenied
	}
	out := f.intent
	out.Issued = true
	return out, nil
}
func newBootstrapFixture() (*bootstrapFixture, BootstrapIssuer, BootstrapInput) {
	now := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	a := value.EnrollmentAuthority{InstallationID: "00000000-0000-4000-8000-000000000001", IssuerEpoch: "00000000-0000-4000-8000-000000000002", DeliveryProfile: "operator-channel", Actor: identity.Principal{Issuer: "https://identity.example.test", Subject: "operator", ClientID: "console", Kind: identity.Human}, IdentityRevision: identity.Revision{UID: "identity", Generation: 1, Digest: artifact.Digest{1}}, AdministrationRevision: identity.Revision{UID: "fleet", Generation: 1, Digest: artifact.Digest{2}}, CheckedAt: now, ValidUntil: now.Add(5 * time.Second), MaxActiveBootstraps: 8, MaxBootstrapHistory: 16, MaxClusters: 16}
	intent := value.BootstrapIntent{Slot: value.BootstrapSlot{ID: "00000000-0000-4000-8000-000000000003", Binding: value.PeerBinding{InstallationID: a.InstallationID, ClusterID: "00000000-0000-4000-8000-000000000004", PeerID: "00000000-0000-4000-8000-000000000005", IssuerEpoch: a.IssuerEpoch, Role: value.ConnectorPeer}, RequestDigest: artifact.Digest{1}, DeliveryProfile: a.DeliveryProfile, NotBefore: now, NotAfter: now.Add(5 * time.Minute), CheckedAt: now, ValidUntil: now.Add(5 * time.Second)}, Actor: a.Actor, IdentityRevision: a.IdentityRevision, AdministrationRevision: a.AdministrationRevision, DisplayName: "synthetic", Region: "eu-test"}
	f := &bootstrapFixture{now: now, a: a, intent: intent}
	service := BootstrapIssuer{Authority: f, Reservations: f, Credentials: f, Records: f, Audits: f, Objects: f, Activation: f, Now: func() time.Time { return f.now }}
	input := BootstrapInput{KeyDigest: artifact.Digest{1}, DisplayName: intent.DisplayName, Region: intent.Region, DeliveryProfile: a.DeliveryProfile}
	return f, service, input
}
func TestBootstrapIssuanceRechecksCurrentAuthorityAfterIO(t *testing.T) {
	f, s, in := newBootstrapFixture()
	f.delay = 6 * time.Second
	out, err := s.Issue(context.Background(), "synthetic", in)
	if err != nil || !out.Issued || f.authorizations != 2 || f.activations != 1 || !out.Slot.NotAfter.Equal(f.intent.Slot.NotAfter) {
		t.Fatal("fresh reauthorization failed", err)
	}
}
func TestBootstrapIssuanceRejectsBoundaryFailuresBeforeActivation(t *testing.T) {
	for _, mode := range []string{"revoked", "actor", "epoch", "settings", "credential", "object", "ack"} {
		t.Run(mode, func(t *testing.T) {
			f, s, in := newBootstrapFixture()
			switch mode {
			case "revoked":
				f.failAuthority = true
			case "actor":
				f.changeActor = true
			case "epoch":
				f.changeEpoch = true
			case "settings":
				f.changeSettings = true
			case "credential":
				f.changeCredential = true
			case "object":
				f.failObject = true
			case "ack":
				f.failACK = true
			}
			if _, err := s.Issue(context.Background(), "synthetic", in); err == nil || f.activations != 0 {
				t.Fatal("failed boundary activated credential", err)
			}
		})
	}
}
func TestBootstrapIssuanceRecoversAuditFailureWithoutNewCredential(t *testing.T) {
	f, s, in := newBootstrapFixture()
	f.failACK = true
	if _, err := s.Issue(context.Background(), "synthetic", in); err == nil {
		t.Fatal("missing ACK accepted")
	}
	f.failACK = false
	if _, err := s.Issue(context.Background(), "synthetic", in); err != nil || f.credentials != 1 || f.activations != 1 {
		t.Fatal("recovery created another credential", err)
	}
}
