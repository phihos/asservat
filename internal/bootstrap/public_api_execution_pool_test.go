package bootstrap

import (
	"context"
	"slices"
	"testing"

	"asservat.local/asservat/internal/adapters/postgres"
	"asservat.local/asservat/internal/contracts"
)

func TestPublicAPIExecutionPoolIsColdAndRetiredFacetsCannotOpen(t *testing.T) {
	if slices.Contains(hubAPIHotPurposes, "api-execution") {
		t.Fatal("shared execution pool became persistent")
	}
	in, dir, c := ownerInputFixture(t)
	governor, err := postgres.NewSQLConnectionGovernor(contracts.SQLConnectionsPerHubReplica, len(hubAPIHotPurposes))
	if err != nil {
		t.Fatal(err)
	}
	pools := &publicPools{in: in.providerInputs, manifest: publicManifestFixture(c), governor: governor}
	defer pools.Close()
	name, _ := postgres.PublicRuntimeRoleName(c.InstallationID, "api-execution")
	for _, old := range []string{"api-execution-read", "api-execution-prepare", "api-execution-record"} {
		writeOwnerJSON(t, dir, "sql-public-"+old+".json", contracts.OwnerSQLCredential{Username: name, Password: "synthetic"})
		if _, err := pools.open(context.Background(), old); err == nil || len(pools.pools) != 0 {
			t.Fatal("retired facet was opened or adopted", old, err)
		}
	}
}
