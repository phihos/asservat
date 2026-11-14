package kubernetes

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"sync"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

func pendingBootstrapProvider(t *testing.T, d contracts.InitialBootstrap, state contracts.InitialBootstrapState) contracts.InitialBootstrapState {
	t.Helper()
	s := cloneBootstrapState(t, state)
	s.Manager = nil
	s.Creates = []contracts.InitialBootstrapCreate{}
	s.Projection = nil
	s.PassiveHistory = nil
	now := time.Now().UTC().Truncate(time.Microsecond)
	s.Material.IssuerToken = ""
	s.Material.SetupToken = "original-private-setup-token"
	s.Material.BundledIdentity = &contracts.BundledInitialProviderIdentity{Format: contracts.BundledInitialProviderIdentityFormat, BackendName: d.Name, Namespace: s.Prelude.Namespace, SetupAccount: contracts.WorkerObjectReference{Name: d.Name + "-setup", UID: ownerID(81)}, EntityID: ownerID(82), SetupParent: contracts.InitialProviderParent{Accessor: "original-setup-accessor", IssuedAt: now, ExpiresAt: now.Add(300 * time.Second)}}
	if !bootstrapStateValid(d, s) {
		t.Fatal("pending original provider state invalid")
	}
	return s
}
func TestBootstrapProviderPendingCannotReachSQLOrProjection(t *testing.T) {
	d, state := bootstrapStateFixture(t)
	d.KeyService.Endpoint = "https://" + d.Name + "-openbao." + d.BootstrapNamespace + ".svc:8200"
	state.DesiredDigest = bootstrapDigest(d)
	pending := pendingBootstrapProvider(t, d, state)
	if _, err := bootstrapProjectionValue(d, pending); err == nil {
		t.Fatal("pending setup credential projected")
	}
	if _, err := bootstrapPrivateObject(d, pending, 2); err == nil {
		t.Fatal("pending setup credential copied into activation material")
	}
	next := cloneBootstrapState(t, pending)
	next.Manager = state.Manager
	if bootstrapStateValid(d, next) || bootstrapStateTransition(d, pending, next) {
		t.Fatal("SQL manager allowed before mint completion")
	}
	changed := cloneBootstrapState(t, pending)
	changed.Material.IssuerToken = "pretend-result"
	changed.Material.SetupToken = ""
	if bootstrapStateTransition(d, pending, changed) {
		t.Fatal("result installed without original mint claim")
	}
}

type bootstrapProviderCASFixture struct {
	mu       sync.Mutex
	producer *InitialBootstrap
	state    contracts.InitialBootstrapState
	rv       int
	puts     int
	loseNext bool
}

func newBootstrapProviderCASFixture(t *testing.T) *bootstrapProviderCASFixture {
	t.Helper()
	ctx := context.Background()
	f := newBootstrapObserverFixtureVersion(t, ctx, contracts.InitialBootstrapFormat, func(d *contracts.InitialBootstrap) {
		d.KeyService.Endpoint = "https://" + d.Name + "-openbao." + d.BootstrapNamespace + ".svc:8200"
	})
	c := &bootstrapProviderCASFixture{rv: 1, state: pendingBootstrapProvider(t, f.desired, f.state)}
	path := "/api/v1/namespaces/" + f.desired.BootstrapNamespace + "/secrets/" + bootstrapNames(f.desired).seed
	f.extra = func(w http.ResponseWriter, r *http.Request) bool {
		if r.URL.Path != path {
			return false
		}
		c.mu.Lock()
		defer c.mu.Unlock()
		if r.Method == http.MethodPut {
			var incoming core.Secret
			if json.NewDecoder(r.Body).Decode(&incoming) != nil || incoming.ResourceVersion != strconv.Itoa(c.rv) || string(incoming.UID) != c.state.SeedUID {
				http.Error(w, "conflict", 409)
				return true
			}
			next, err := contracts.DecodeInitialBootstrapState(bytes.NewReader(incoming.Data["state.json"]))
			if err != nil || !bootstrapStateTransition(f.desired, c.state, next) {
				t.Error("invalid actual CAS transition")
				http.Error(w, "invalid", 400)
				return true
			}
			c.state = next
			c.rv++
			c.puts++
			if c.loseNext {
				c.loseNext = false
				http.Error(w, "bounded unknown reply", 503)
				return true
			}
		}
		body, _ := json.Marshal(c.state)
		permissionReply(w, core.Secret{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "Secret"}, ObjectMeta: meta.ObjectMeta{Name: bootstrapNames(f.desired).seed, Namespace: f.desired.BootstrapNamespace, UID: types.UID(c.state.SeedUID), ResourceVersion: strconv.Itoa(c.rv), Annotations: bootstrapSeedAnnotations(f.desired, c.state)}, Type: core.SecretTypeOpaque, Data: map[string][]byte{"state.json": body}})
		return true
	}
	var err error
	c.producer, err = NewInitialBootstrap(ctx, f.apiConfig, f.desired)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.producer.Close)
	c.producer.seedUID = c.state.SeedUID
	bounded, end := context.WithTimeout(ctx, 5*time.Second)
	defer end()
	if err = c.producer.qualify(bounded, c.state.Prelude, c.state.ClusterID); err != nil {
		t.Fatal("actual native guard fixture", err)
	}
	return c
}
