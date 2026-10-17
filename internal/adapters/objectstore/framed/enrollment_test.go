package framed

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	"asservat.local/asservat/internal/domain/fleet"
)

func TestEnrollmentClaimAuditAuthenticatesIdentityAndPurpose(t *testing.T) {
	ctx, k := context.Background(), keys(t)
	now := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	r := audit.EnrollmentClaim{BootstrapID: testBinding.ArtifactID, Binding: fleet.PeerBinding{InstallationID: testBinding.ClusterID, ClusterID: testBinding.ClusterID, PeerID: testBinding.AttemptID, IssuerEpoch: testBinding.ArtifactID, Role: fleet.ConnectorPeer}, PublicKeyDigest: artifact.Digest{1}, IssueAuthorityDigest: artifact.Digest{2}, IssueAuditDigest: artifact.Digest{3}, IssueAuditID: testBinding.AttemptID, IssuedAt: now, ClaimedAt: now.Add(time.Second), NotAfter: now.Add(5 * time.Minute)}
	b, err := SealEnrollmentClaim(ctx, k, r)
	if err != nil {
		t.Fatal(err)
	}
	if err = VerifyEnrollmentClaim(ctx, k, r, b); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*audit.EnrollmentClaim){func(r *audit.EnrollmentClaim) { r.PublicKeyDigest[0]++ }, func(r *audit.EnrollmentClaim) { r.Binding.PeerID = r.BootstrapID }, func(r *audit.EnrollmentClaim) { r.IssueAuditDigest[0]++ }, func(r *audit.EnrollmentClaim) { r.NotAfter = r.NotAfter.Add(-time.Second) }} {
		other := r
		change(&other)
		if VerifyEnrollmentClaim(ctx, k, other, b) == nil {
			t.Fatal("changed claim authenticated")
		}
	}
	var envelope authorityEnvelope
	if json.Unmarshal(b, &envelope) != nil {
		t.Fatal("bad fixture")
	}
	envelope.Format = captureIntentFormat
	other, _ := json.Marshal(envelope)
	if verifyControlAudit(ctx, k, captureIntentFormat, r.Binding.InstallationID, r.BootstrapID, r, other, 64<<10) == nil {
		t.Fatal("cross-purpose audit authenticated")
	}
	envelope.Format = enrollmentClaimFormat
	envelope.Ciphertext[len(envelope.Ciphertext)-1] ^= 1
	other, _ = json.Marshal(envelope)
	if VerifyEnrollmentClaim(ctx, k, r, other) == nil {
		t.Fatal("corruption authenticated")
	}
	k.fail = true
	if _, err = SealEnrollmentClaim(ctx, k, r); err == nil {
		t.Fatal("key failure ignored")
	}
}
