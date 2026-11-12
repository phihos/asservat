package kubernetes

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
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
	s.Material.BundledIdentity = &contracts.BundledInitialProviderIdentity{Format: contracts.BundledInitialProviderIdentityFormat, BackendName: d.Name, Namespace: s.Prelude.Namespace, SetupAccount: contracts.WorkerObjectReference{Name: d.Name + "-bootstrap-runner", UID: ownerID(81)}, EntityID: ownerID(82), SetupParent: contracts.InitialProviderParent{Accessor: "original-setup-accessor", IssuedAt: now, ExpiresAt: now.Add(300 * time.Second)}}
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
func TestBootstrapProviderClaimUnknownReplyNeverGrantsFresh(t *testing.T) {
	f := newBootstrapProviderCASFixture(t)
	f.loseNext = true
	if got, err := f.producer.ClaimBundledProvider(context.Background()); err == nil || got.Fresh {
		t.Fatal("unknown claim granted POST authority")
	}
	got, err := f.producer.ClaimBundledProvider(context.Background())
	if err != nil || got.Fresh || got.State.ProviderMint == nil || f.puts != 1 {
		t.Fatal("retained pending claim was replaced or reissued", err)
	}
	if err = f.producer.CompleteBundledProvider(context.Background(), got, "invented-result", contracts.InitialProviderParent{}); err == nil {
		t.Fatal("unknown POST claim fabricated result")
	}
}
func TestBootstrapProviderResultCASReopensExactCompletionOnly(t *testing.T) {
	f := newBootstrapProviderCASFixture(t)
	claim, err := f.producer.ClaimBundledProvider(context.Background())
	if err != nil || !claim.Fresh {
		t.Fatal("original acknowledged CAS not fresh", err)
	}
	mint := claim.State.ProviderMint
	parent := contracts.InitialProviderParent{Accessor: "positive-original-issuer", IssuedAt: time.Now().UTC(), ExpiresAt: mint.ExpiresBefore.Add(-time.Second)}
	f.loseNext = true
	if err = f.producer.CompleteBundledProvider(context.Background(), claim, "original-private-issuer", parent); err != nil {
		t.Fatal("same-UID exact positive completion unavailable", err)
	}
	if f.state.Material.SetupToken != "" || f.state.Material.IssuerToken != "original-private-issuer" || f.puts != 2 {
		t.Fatal("completion did not atomically replace private setup credential")
	}
	if err = f.producer.CompleteBundledProvider(context.Background(), claim, "original-private-issuer", parent); err != nil || f.puts != 2 {
		t.Fatal("completion replay mutated or refused", err)
	}
	if err = f.producer.CompleteBundledProvider(context.Background(), claim, "replacement-issuer", parent); err == nil {
		t.Fatal("replacement result accepted")
	}
	if text := fmt.Sprint(claim); text == "" || strings.Contains(text, "original-private-") {
		t.Fatal("private claim diagnostics exposed token")
	}
}

func TestBootstrapProviderOriginalSetupExpiryCannotStartNewClaim(t *testing.T) {
	f := newBootstrapProviderCASFixture(t)
	original := f.state.Material.BundledIdentity.SetupParent
	f.state.Material.BundledIdentity.SetupParent.IssuedAt = original.IssuedAt.Add(-301 * time.Second)
	f.state.Material.BundledIdentity.SetupParent.ExpiresAt = original.ExpiresAt.Add(-301 * time.Second)
	if got, err := f.producer.ClaimBundledProvider(context.Background()); err == nil || got.Fresh || f.puts != 0 {
		t.Fatal("expired original setup interval renewed by claim", err)
	}
}

func TestBootstrapProviderClaimAndResultAreMonotonic(t *testing.T) {
	f := newBootstrapProviderCASFixture(t)
	claim, err := f.producer.ClaimBundledProvider(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, edit := range []func(*contracts.InitialBootstrapState){
		func(s *contracts.InitialBootstrapState) { s.ProviderMint.OperationID = ownerID(99) },
		func(s *contracts.InitialBootstrapState) {
			s.ProviderMint.StartedAt = s.ProviderMint.StartedAt.Add(time.Second)
			s.ProviderMint.Until = s.ProviderMint.Until.Add(time.Second)
		},
		func(s *contracts.InitialBootstrapState) { s.ProviderMint = nil },
		func(s *contracts.InitialBootstrapState) { s.Material.SetupToken = "replacement-setup" },
	} {
		next := cloneBootstrapState(t, claim.State)
		edit(&next)
		if bootstrapStateTransition(f.producer.desired, claim.State, next) {
			t.Fatal("retained mint claim replaced or renewed")
		}
	}
	parent := contracts.InitialProviderParent{Accessor: "original-positive-parent", IssuedAt: time.Now().UTC(), ExpiresAt: claim.State.ProviderMint.ExpiresBefore.Add(-time.Second)}
	if err = f.producer.CompleteBundledProvider(context.Background(), claim, "original-private-issuer", parent); err != nil {
		t.Fatal(err)
	}
	before := cloneBootstrapState(t, f.state)
	reset := cloneBootstrapState(t, before)
	reset.ProviderMint = nil
	if bootstrapStateTransition(f.producer.desired, before, reset) {
		t.Fatal("completed mint history discarded")
	}
	if !bootstrapProviderReady(before) {
		t.Fatal("verified original result did not enable next phase")
	}
}

func TestBootstrapProviderClaimRetainsOriginalCallerDeadline(t *testing.T) {
	f := newBootstrapProviderCASFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	original, _ := ctx.Deadline()
	claim, err := f.producer.ClaimBundledProvider(ctx)
	if err != nil || !claim.Fresh || claim.State.ProviderMint == nil || f.puts != 1 {
		t.Fatal("original bounded claim refused", err)
	}
	mint := claim.State.ProviderMint
	if mint.Until.After(original) || mint.Until.After(original.UTC().Truncate(time.Microsecond)) || claim.ValidUntil.After(original) {
		t.Fatal("mint claim extended original caller deadline")
	}
	if !mint.Until.After(mint.StartedAt) || mint.Until.Sub(mint.StartedAt) > time.Second || mint.StartedAt != mint.StartedAt.UTC().Truncate(time.Microsecond) || mint.Until != mint.Until.UTC().Truncate(time.Microsecond) {
		t.Fatal("persisted mint interval lost original finite precision")
	}
	if !f.state.ProviderMint.Until.Equal(mint.Until) || !bootstrapStateValid(f.producer.desired, f.state) {
		t.Fatal("returned claim was not the persisted original interval")
	}
}

func TestBootstrapProviderMintStateAcceptsOnlyPositiveBoundedIntervals(t *testing.T) {
	f := newBootstrapProviderCASFixture(t)
	claim, err := f.producer.ClaimBundledProvider(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, duration := range []time.Duration{-time.Microsecond, 0, time.Microsecond, time.Second, 5 * time.Second, 5*time.Second + time.Microsecond} {
		t.Run(duration.String(), func(t *testing.T) {
			state := cloneBootstrapState(t, claim.State)
			state.ProviderMint.Until = state.ProviderMint.StartedAt.Add(duration)
			if bootstrapStateValid(f.producer.desired, state) != (duration > 0 && duration <= 5*time.Second) {
				t.Fatal("mint state accepted wrong interval")
			}
		})
	}
	expired, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	before := f.puts
	if c, err := f.producer.ClaimBundledProvider(expired); err == nil || c.Fresh || f.puts != before {
		t.Fatal("expired caller obtained renewed claim or mutation")
	}
}
