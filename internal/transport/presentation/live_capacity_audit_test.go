package presentation

import (
	"testing"

	"asservat.local/asservat/internal/contracts"
)

func TestLiveCapacityAuditNormalizationRetainsCluster(t *testing.T) {
	wire, err := contracts.NewInvestigationContracts()
	if err != nil {
		t.Fatal(err)
	}
	operations := &AuditedOperations{contracts: wire}
	const input = `{"cluster_id":"22222222-3333-4444-8555-666666666666"}`
	normalized, err := operations.normalize("get_live_capacity", []byte(input))
	if err != nil || string(normalized) != input {
		t.Fatal("audit normalization changed live capacity input", string(normalized), err)
	}
}
