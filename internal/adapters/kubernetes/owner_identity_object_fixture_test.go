package kubernetes

import (
	"encoding/json"
	"net/http"
	"testing"

	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
	apps "k8s.io/api/apps/v1"
	core "k8s.io/api/core/v1"
	"k8s.io/client-go/rest"
)

// Actual loopback TLS exercises only the native object readers. Its objects and
// receipts are synthetic; this fixture confers no current guard/SQL authority.
type ownerIdentityObjectFixture struct {
	extra      func(http.ResponseWriter, *http.Request) bool
	apiConfig  *rest.Config
	plan       cfg.OwnerWorkloadAdministration
	reader     *InstalledOwnerIdentityReader
	state      contracts.InitialRuntimeResourceState
	manifest   contracts.OwnerIdentityCredentialManifest
	mounted    map[string][]byte
	journal    *core.Secret
	providers  *core.Secret
	config     *core.ConfigMap
	deployment *apps.Deployment
	account    *core.ServiceAccount
}

func (x *ownerIdentityObjectFixture) writeJournal(t *testing.T) {
	t.Helper()
	raw, e := json.Marshal(x.state)
	if e != nil {
		t.Fatal(e)
	}
	x.journal.Data["state.json"] = raw
}
