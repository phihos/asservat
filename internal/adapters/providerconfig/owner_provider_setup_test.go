package providerconfig

import (
	"encoding/json"
	"net/http"
	"sync/atomic"
	"testing"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/fleet"
)

type setupFixture struct {
	in        contracts.OwnerDeployment
	profile   contracts.OwnerProviderAuthentication
	pool      fleet.OwnerPool
	reader    *SetupReader
	roots     [][]byte
	responses map[string]map[string]json.RawMessage
	requests  atomic.Int32
	intercept func(http.ResponseWriter, *http.Request) bool
}

func setupMap(t *testing.T, v any) map[string]json.RawMessage {
	t.Helper()
	raw, e := json.Marshal(v)
	if e != nil {
		t.Fatal(e)
	}
	var out map[string]json.RawMessage
	if e = json.Unmarshal(raw, &out); e != nil {
		t.Fatal(e)
	}
	return out
}
