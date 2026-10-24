package bootstrap

import (
	"context"
	"testing"

	"asservat.local/asservat/internal/adapters/postgres"
	"asservat.local/asservat/internal/contracts"
)

func TestSharedPublicPoolKeepsResolutionReservationsAndRefusesRetiredFacets(t *testing.T) {
	for _, duty := range []string{"api-execution", "hub-metadata-read", "download-session", "capture-preview"} {
		role, key, limit, hot, ok := publicPoolPlan(duty)
		if !ok || role != "hub-runtime" || key != "hub-runtime" || limit != 18 || !hot {
			t.Fatal("ordinary duty did not share its governed pool", duty)
		}
	}
	for _, duty := range []string{"audit-resolution-journal", "audit-resolution-ack"} {
		role, key, limit, hot, ok := publicPoolPlan(duty)
		if !ok || role != "hub-runtime" || key != duty || limit != 1 || !hot {
			t.Fatal("resolution duty lost its reserved connection", duty)
		}
	}
	in, dir, c := ownerInputFixture(t)
	governor, err := postgres.NewSQLConnectionGovernor(contracts.SQLConnectionsPerHubReplica, hubAPIHotConnections)
	if err != nil {
		t.Fatal(err)
	}
	pools := &publicPools{in: in.providerInputs, manifest: publicManifestFixture(c), governor: governor}
	defer pools.Close()
	name, _ := postgres.PublicRuntimeRoleName(c.InstallationID, "hub-runtime")
	for _, old := range []string{"api-execution-read", "api-execution-prepare", "api-execution-record"} {
		writeOwnerJSON(t, dir, "sql-public-"+old+".json", contracts.OwnerSQLCredential{Username: name, Password: "synthetic"})
		if _, err := pools.open(context.Background(), old); err == nil || len(pools.pools) != 0 {
			t.Fatal("retired facet was opened or adopted", old, err)
		}
	}
}
