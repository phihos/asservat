package framed

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	"asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
)

func TestBootstrapIssueAuditAuthenticatesActorCredentialAndPurpose(t *testing.T) {
	ctx, k := context.Background(), keys(t)
	now := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	r := audit.BootstrapIssue{ID: testBinding.ArtifactID, Binding: fleet.PeerBinding{InstallationID: testBinding.ClusterID, ClusterID: testBinding.ClusterID, PeerID: testBinding.AttemptID, IssuerEpoch: testBinding.ArtifactID, Role: fleet.ConnectorPeer}, RequestDigest: artifact.Digest{1}, Actor: identity.Principal{Issuer: "https://identity.example.test", Subject: "operator", ClientID: "console", Kind: identity.Human}, IdentityRevision: identity.Revision{UID: "identity", Generation: 1, Digest: artifact.Digest{2}}, AdministrationRevision: identity.Revision{UID: "fleet", Generation: 1, Digest: artifact.Digest{3}}, DisplayName: "synthetic cluster", Region: "eu-test", DeliveryProfile: "channel", NotBefore: now, NotAfter: now.Add(5 * time.Minute), Credential: fleet.BootstrapCredential{SlotID: testBinding.ArtifactID, DeliveryProfile: "channel", SecretDigest: artifact.Digest{4}, Version: 1}}
	b, err := SealBootstrapIssue(ctx, k, r)
	if err != nil {
		t.Fatal(err)
	}
	if err = VerifyBootstrapIssue(ctx, k, r, b); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*audit.BootstrapIssue){func(r *audit.BootstrapIssue) { r.Actor.Subject = "another" }, func(r *audit.BootstrapIssue) { r.Credential.SecretDigest[0]++ }, func(r *audit.BootstrapIssue) { r.NotAfter = r.NotAfter.Add(-time.Second) }, func(r *audit.BootstrapIssue) { r.AdministrationRevision.Generation++ }, func(r *audit.BootstrapIssue) { r.Binding.PeerID = r.ID }} {
		other := r
		change(&other)
		if VerifyBootstrapIssue(ctx, k, other, b) == nil {
			t.Fatal("substituted issuance authenticated")
		}
	}
	var envelope authorityEnvelope
	if json.Unmarshal(b, &envelope) != nil {
		t.Fatal("bad fixture")
	}
	envelope.Format = enrollmentClaimFormat
	other, _ := json.Marshal(envelope)
	if verifyControlAudit(ctx, k, enrollmentClaimFormat, r.Binding.InstallationID, r.ID, r, other, 64<<10) == nil {
		t.Fatal("cross-purpose audit accepted")
	}
	envelope.Format = bootstrapIssueFormat
	envelope.Ciphertext[len(envelope.Ciphertext)-1] ^= 1
	other, _ = json.Marshal(envelope)
	if VerifyBootstrapIssue(ctx, k, r, other) == nil {
		t.Fatal("corrupt audit accepted")
	}
	k.fail = true
	if _, err = SealBootstrapIssue(ctx, k, r); err == nil {
		t.Fatal("failed encryption accepted")
	}
}
