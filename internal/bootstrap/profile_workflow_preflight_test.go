package bootstrap

import (
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
	query "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/domain/privacy"
)

// Cross-boundary regression: use installer output as input to the actual
// consumer, instead of asserting that each side accepts its own fixture.
// The installation identity is synthetic; this does not qualify a deployment.
func TestInstalledProfileWorkflowConfiguration(t *testing.T) {
	now := time.Now().UTC()
	rev := identity.Revision{UID: runtimeID, Generation: 1, Digest: artifact.Digest{1}}
	template := buildDownloadPathTemplate(runtimeID, "local", runtimeID, rev, rev)
	paths, err := downloadEnvironmentPaths(runtimeID, runtimeID, []contracts.DownloadEnvironmentPath{}, &template, []string{runtimeID})
	if err != nil || len(paths) != 1 {
		t.Fatal("installer path", err)
	}
	clients := downloadClients(contracts.InstallerPublicSettings{Issuer: "https://id.synthetic.invalid", Clients: []contracts.IdentityClient{{ID: "console", Kind: "human", ClassQualified: true}}, RetentionBaseline: &contracts.InstallerRetentionBaseline{PurposeRef: "diagnostics"}})
	if len(clients) != 1 {
		t.Fatal("installer client", clients)
	}
	c := clients[0]
	actor := identity.Principal{Issuer: c.Issuer, ClientID: c.ID, Subject: "developer", Kind: identity.Human}
	p := privacy.DownloadPolicy{RootID: runtimeID, InstallationID: runtimeID, RecoveryEpoch: runtimeID, Revision: rev, ProtectionDigest: artifact.Digest{2}, PermittedRegions: []string{"local"}, Paths: paths, Clients: []privacy.DownloadClient{{Issuer: c.Issuer, ID: c.ID, Kind: identity.Kind(c.Kind), DataClasses: c.DataClasses, PrivacyClasses: c.PrivacyClasses, EvidenceTypes: c.EvidenceTypes, Purposes: c.Purposes, PathIDs: []string{paths[0].ID}}}, Operators: []privacy.ProcessingOperator{{Issuer: c.Issuer, ClientID: c.ID, Kind: "Group", ID: "privacy"}}, ObservedAt: now, FreshUntil: now.Add(5 * time.Second)}
	for _, class := range []string{"raw", "extract"} {
		if _, ok := p.SelectDownload(actor, runtimeID, runtimeID, "diagnostics", class, "potentialPersonalData", "profile", now); !ok {
			t.Fatalf("installer policy refuses profile %s", class)
		}
	}
	p.Clients[0].EvidenceTypes = []string{"context", "packetCapture", "syscallTrace"}
	if _, ok := p.SelectDownload(actor, runtimeID, runtimeID, "diagnostics", "raw", "potentialPersonalData", "profile", now); ok {
		t.Fatal("legacy policy acquired profile permission")
	}
}

func TestInstalledProfileSummaryCapacity(t *testing.T) {
	settings := capacityProfileFixture()
	settings.Records = query.ProfileSummaryQueryUnits
	qualification, err := installedQueryBudget(settings, sequentialIDs())
	if err != nil {
		t.Fatal(err)
	}
	worker := qualification.Profile.Worker
	if worker.MemoryBytes != downloadWorkerMemoryBytes || worker.MemoryBytes < query.ProfileSummaryWorkerBytes || worker.WorkerTransientBytes < query.ProfileSummaryWorkerBytes || qualification.PrincipalQueries < query.ProfileSummaryQueryUnits || qualification.WorkloadQueries < query.ProfileSummaryQueryUnits {
		t.Fatal("installed summary resource mismatch", qualification)
	}
	if _, err = qualification.Required(); err != nil {
		t.Fatal("unfunded installed summary", err)
	}
}
