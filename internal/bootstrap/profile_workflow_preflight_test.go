package bootstrap

import (
	"testing"

	query "asservat.local/asservat/internal/domain/analysis"
)

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

func TestInstalledProfileComparisonCapacity(t *testing.T) {
	settings := capacityProfileFixture()
	settings.Records = query.ProfileComparisonQueryUnits
	qualification, err := installedQueryBudget(settings, sequentialIDs())
	if err != nil {
		t.Fatal(err)
	}
	if qualification.Profile.Source.Digest == profileDigest("shared-query/v2", settings) {
		t.Fatal("new shared resource declaration reused the previous identity")
	}
	worker := qualification.Profile.Worker
	if worker.MemoryBytes != query.ProfileComparisonWorkerBytes || worker.WorkerTransientBytes != query.ProfileComparisonWorkerBytes || qualification.PrincipalQueries < query.ProfileComparisonQueryUnits || qualification.WorkloadQueries < query.ProfileComparisonQueryUnits {
		t.Fatal("comparison producer/consumer capacity mismatch", qualification)
	}
	if _, err = qualification.Required(); err != nil {
		t.Fatal("unfunded installed comparison", err)
	}
}
