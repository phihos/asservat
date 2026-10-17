package framed

import (
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	"asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	"context"
	"encoding/json"
	"testing"
	"time"
)

func TestInitialInstallationAuditRejectsScopeClaimAndPurposeSubstitution(t *testing.T) {
	ctx, k := context.Background(), keys(t)
	id := testBinding.ArtifactID
	n := time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)
	r := audit.InitialInstallation{Scope: fleet.InstallationWitnessScope{InstallationID: id, IssuerEpoch: id, ClusterID: id, Namespace: "control", NamespaceUID: id, Name: "witness", UID: id, WriterAccount: "installer", WriterAccountUID: id}, Claim: fleet.InitialActivationClaim{ID: id, Database: fleet.DatabaseIncarnation{StartedAt: n.Add(-time.Minute), DatabaseOID: 10, SchemaVersion: 32}, FleetSource: identity.Revision{UID: "fleet", Generation: 1, Digest: artifact.Digest{1}}, PlanDigest: artifact.Digest{2}, NotBefore: n, NotAfter: n.Add(time.Minute)}}
	encoded, err := SealInitialInstallation(ctx, k, r)
	if err != nil {
		t.Fatal(err)
	}
	if err = VerifyInitialInstallation(ctx, k, r, encoded); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*audit.InitialInstallation){func(r *audit.InitialInstallation) { r.Scope.Name = "replacement" }, func(r *audit.InitialInstallation) { r.Claim.Database.DatabaseOID++ }, func(r *audit.InitialInstallation) { r.Claim.NotAfter = r.Claim.NotAfter.Add(time.Second) }, func(r *audit.InitialInstallation) { r.Claim.PlanDigest[0]++ }, func(r *audit.InitialInstallation) { r.Claim.FleetSource.Generation++ }} {
		other := r
		change(&other)
		if VerifyInitialInstallation(ctx, k, other, encoded) == nil {
			t.Fatal("substituted activation attempt authenticated")
		}
	}
	var envelope authorityEnvelope
	if json.Unmarshal(encoded, &envelope) != nil {
		t.Fatal("bad envelope")
	}
	envelope.Format = bootstrapIssueFormat
	wrong, _ := json.Marshal(envelope)
	if verifyControlAudit(ctx, k, bootstrapIssueFormat, r.Scope.InstallationID, r.Claim.ID, r, wrong, 8<<10) == nil {
		t.Fatal("cross-purpose record authenticated")
	}
	encoded[len(encoded)/2] ^= 1
	if VerifyInitialInstallation(ctx, k, r, encoded) == nil {
		t.Fatal("corrupt record authenticated")
	}
	k.fail = true
	if _, err = SealInitialInstallation(ctx, k, r); err == nil {
		t.Fatal("failed encryption accepted")
	}
}
