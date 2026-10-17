package postgres

import (
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	"testing"
	"time"
)

func TestInitialSchemaExpectationRejectsIncompatibleCompiledProvenance(t *testing.T) {
	b, e := EmbeddedInitialSchema()
	if e != nil {
		t.Fatal(e)
	}
	original := contracts.InitialSchemaExpectation{BundleDigest: b.Digest, Head: b.Head, DatabaseOID: 123, PostmasterAt: time.Now().UTC().Add(-time.Hour).Truncate(time.Microsecond)}
	d, e := InitialSchemaIncarnation(original)
	if e != nil || d.DatabaseOID != original.DatabaseOID || !d.StartedAt.Equal(original.PostmasterAt) {
		t.Fatal("valid compiled provenance rejected", e)
	}
	for _, mode := range []string{"head", "bundle", "database", "precision"} {
		t.Run(mode, func(t *testing.T) {
			v := original
			switch mode {
			case "head":
				v.Head++
			case "bundle":
				v.BundleDigest = "00"
			case "database":
				v.DatabaseOID = 0
			case "precision":
				v.PostmasterAt = v.PostmasterAt.Add(time.Nanosecond)
			}
			if _, e := InitialSchemaIncarnation(v); e == nil {
				t.Fatal("invalid compiled provenance accepted")
			}
		})
	}
}

func TestInitialSchemaBindingAlsoRejectsHistoricalRecordFromOtherIncarnation(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	id := "11111111-1111-4111-8111-111111111111"
	scope := value.InstallationWitnessScope{InstallationID: id, IssuerEpoch: id, ClusterID: id, Namespace: "control", NamespaceUID: id, Name: "witness", UID: id, WriterAccount: "installer", WriterAccountUID: id}
	db := value.DatabaseIncarnation{DatabaseOID: 123, StartedAt: now.Add(-time.Hour), SchemaVersion: currentSchemaVersion}
	r := audit.InitialInstallation{Scope: scope, Claim: value.InitialActivationClaim{ID: id, Database: db, FleetSource: identity.Revision{UID: "source", Generation: 1, Digest: artifact.Digest{1}}, PlanDigest: artifact.Digest{2}, NotBefore: now, NotAfter: now.Add(5 * time.Minute)}}
	s := &InitialInstallations{scope: scope, plan: r.Claim.PlanDigest, expectedDatabase: &db}
	if !s.record(r) {
		t.Fatal("valid original record rejected")
	}
	for _, mode := range []string{"database", "postmaster", "head"} {
		t.Run(mode, func(t *testing.T) {
			v := r
			switch mode {
			case "database":
				v.Claim.Database.DatabaseOID++
			case "postmaster":
				v.Claim.Database.StartedAt = v.Claim.Database.StartedAt.Add(-time.Second)
			case "head":
				v.Claim.Database.SchemaVersion++
			}
			if s.record(v) {
				t.Fatal("another database record accepted by audit/activation facet")
			}
		})
	}
}
