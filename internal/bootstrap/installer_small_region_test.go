package bootstrap

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
	"k8s.io/utils/ptr"
)

type smallRegionalSourceFixture struct {
	provider *continuationBaoFixture
	original contracts.InitialPreparer
	current  core.ConfigMap
	native   *rest.Config
	reads    int
}

func newSmallRegionalSourceFixture(t *testing.T) *smallRegionalSourceFixture {
	t.Helper()
	f := &smallRegionalSourceFixture{provider: newContinuationBaoFixture(t, "")}
	pair, ca := smallServicesHookTLS(t)
	api := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/namespaces/bootstrap/configmaps/trial-preparer" {
			f.reads++
			if r.Method != http.MethodGet || r.Header.Get("Authorization") != "Bearer synthetic-native-read" {
				t.Error("source reader lost original native identity or mutated state")
				w.WriteHeader(400)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(f.current)
			return
		}
		f.provider.base.native(w, r)
	}))
	api.TLS = &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS13}
	api.StartTLS()
	t.Cleanup(api.Close)
	block, _ := pem.Decode([]byte(ca))
	f.provider.base.plan.Kubernetes = contracts.OwnerProviderEndpoint{Endpoint: api.URL, Roots: [][]byte{block.Bytes}}
	*f.provider.base.config = rest.Config{Host: api.URL, TLSClientConfig: rest.TLSClientConfig{CAData: []byte(ca)}, BearerToken: "synthetic-native-read"}
	f.native = rest.CopyConfig(f.provider.base.config)
	f.original = f.provider.original(t)
	f.original.Format = contracts.InitialPreparerFormat
	f.original.Plan.InstallationID = "20000000-0000-4000-8000-000000000001"
	f.original.Plan.ClusterID = "20000000-0000-4000-8000-000000000002"
	f.original.Plan.RequestID = "20000000-0000-4000-8000-000000000003"
	f.original.Plan.Workload.Namespace = "runtime"
	f.original.Plan.Workload.Image = "registry.example/asservat@sha256:" + strings.Repeat("a", 64)
	f.original.Services.Fleet.IssuerEpoch = "20000000-0000-4000-8000-000000000004"
	f.original.Services.AuditStore = contracts.OwnerAuditStore{Endpoint: "https://trial-objectstore.bootstrap.svc:8333", Region: "us-east-1", Bucket: "trial-audit", Roots: f.original.Kubernetes.Roots}
	f.current = core.ConfigMap{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "ConfigMap"}, ObjectMeta: meta.ObjectMeta{Name: "trial-preparer", Namespace: "bootstrap", ResourceVersion: "1"}, Immutable: ptr.To(true)}
	f.persist(t)
	return f
}
func (f *smallRegionalSourceFixture) persist(t *testing.T) {
	t.Helper()
	raw, err := json.Marshal(f.original)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(f.provider.base.files.Name(), smallRegionalPreparerFile), raw, 0600); err != nil {
		t.Fatal(err)
	}
	f.current.Data = map[string]string{"deployment.json": string(raw)}
	plan, err := json.Marshal(f.provider.base.plan)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(f.provider.base.files.Name(), contracts.InitialBootstrapKeyServicePlanFile), plan, 0600); err != nil {
		t.Fatal(err)
	}
}
func TestSmallRegionalSourcesReachActualSetupIdentityWithoutRenewingContext(t *testing.T) {
	f := newSmallRegionalSourceFixture(t)
	// A certificate-covered alternate API address need not equal the original
	// address; the actual selected request must still use the original endpoint.
	f.native.Host = "https://independent-in-cluster-address.invalid"
	ctx, end := context.WithTimeout(t.Context(), time.Minute)
	defer end()
	until, _ := ctx.Deadline()
	original, config, plan, err := loadSmallRegionalSources(ctx, f.provider.base.files, f.native, "trial")
	if err != nil || !reflect.DeepEqual(original, f.original) || !reflect.DeepEqual(plan, f.provider.base.plan) || config.Host != original.Kubernetes.Endpoint || config.BearerToken != f.native.BearerToken || f.reads != 1 {
		t.Fatal("exact original preparer did not reach selected source", err)
	}
	source, err := readInitialOpenBaoProviderSource(ctx, f.provider.base.files, plan, config)
	if err != nil {
		t.Fatal(err)
	}
	setup, err := openInitialOpenBaoProviderSource(ctx, f.provider.base.files, source, config, f.provider.base.http)
	if err != nil {
		t.Fatal("matched sources rejected by actual setup identity consumer", err)
	}
	defer setup.Close()
	after, _ := ctx.Deadline()
	if !after.Equal(until) || setup.Identity.Namespace != original.Plan.BootstrapNamespace || setup.Identity.SetupParent.ExpiresAt.Sub(setup.Identity.SetupParent.IssuedAt) != 5*time.Minute {
		t.Fatal("source observation changed original identity/deadline")
	}
	f.provider.base.mu.Lock()
	defer f.provider.base.mu.Unlock()
	if f.provider.base.requests["POST /v1/auth/asservat-setup/login"] != 1 {
		t.Fatal("setup login missing/repeated")
	}
}
func TestSmallRegionalSourcesRefuseMismatchBeforeProviderLogin(t *testing.T) {
	for _, mode := range []string{"name", "key-endpoint", "key-roots", "api-roots", "insecure-api", "namespace", "current-changed", "current-mutable", "current-extra", "canceled"} {
		t.Run(mode, func(t *testing.T) {
			f := newSmallRegionalSourceFixture(t)
			name := "trial"
			switch mode {
			case "name":
				name = "other"
			case "key-endpoint":
				f.original.Services.KeyService.Endpoint = "https://other.invalid"
			case "key-roots":
				f.original.Services.KeyService.Roots = f.original.Kubernetes.Roots
			case "api-roots":
				_, other := smallServicesHookTLS(t)
				f.native.CAData = []byte(other)
			case "insecure-api":
				f.native.Insecure = true
			case "namespace":
				f.original.Plan.BootstrapNamespace.Name = "other"
			}
			f.persist(t)
			switch mode {
			case "current-changed":
				changed := f.original
				changed.Plan.RequestID = "20000000-0000-4000-8000-000000000009"
				raw, _ := json.Marshal(changed)
				f.current.Data["deployment.json"] = string(raw)
			case "current-mutable":
				f.current.Immutable = ptr.To(false)
			case "current-extra":
				f.current.Data["unexpected"] = "public"
			}
			ctx, end := context.WithTimeout(t.Context(), time.Minute)
			defer end()
			if mode == "canceled" {
				end()
			}
			if _, _, _, err := loadSmallRegionalSources(ctx, f.provider.base.files, f.native, name); err == nil {
				t.Fatal("mismatched original source accepted")
			}
			f.provider.base.mu.Lock()
			defer f.provider.base.mu.Unlock()
			if len(f.provider.base.requests) != 0 || f.provider.base.patches != 0 {
				t.Fatal("source mismatch performed provider login/readiness effect")
			}
		})
	}
}
func TestSmallRegionalOfferScopeMatchesOriginalOwnerAndStore(t *testing.T) {
	f := newSmallRegionalSourceFixture(t)
	owner := contracts.OwnerDeployment{InstallationID: f.original.Plan.InstallationID, ClusterID: f.original.Plan.ClusterID, Namespace: contracts.WorkerObjectReference{Name: "runtime"}, PermissionRootID: "20000000-0000-4000-8000-000000000005", Public: &contracts.OwnerPublicDeployment{}}
	owner.KeyService.Endpoint, owner.KeyService.Roots = f.provider.base.plan.Endpoint(), f.original.Services.KeyService.Roots
	a := f.original.Services.AuditStore
	offer := contracts.RegionalOffer{Format: contracts.RegionalOfferFormat, InstallationID: owner.InstallationID, HubClusterID: owner.ClusterID, IssuerEpoch: f.original.Services.Fleet.IssuerEpoch, PermissionRootID: owner.PermissionRootID, Image: f.original.Plan.Workload.Image, Owners: &contracts.RegionalContextOwners{}, KeyService: &contracts.RegionalWrapService{}, WorkKey: &contracts.APIContextWorkPublicKey{}, EvidenceStore: &contracts.RegionalEvidenceStore{Endpoint: a.Endpoint, Bucket: a.Bucket, Region: a.Region, Roots: a.Roots}}
	if !smallRegionalOfferMatches(f.original, f.provider.base.plan, owner, offer) {
		t.Fatal("matching actual owner/offer refused")
	}
	for _, mode := range []string{"installation", "hub-cluster", "root", "epoch", "image", "partial", "bucket", "region", "endpoint", "roots", "owner-namespace", "owner-provider"} {
		t.Run(mode, func(t *testing.T) {
			raw, _ := json.Marshal(offer)
			var changed contracts.RegionalOffer
			_ = json.Unmarshal(raw, &changed)
			other := owner
			switch mode {
			case "installation":
				changed.InstallationID = "20000000-0000-4000-8000-000000000009"
			case "hub-cluster":
				changed.HubClusterID = "20000000-0000-4000-8000-000000000009"
			case "root":
				changed.PermissionRootID = "20000000-0000-4000-8000-000000000009"
			case "epoch":
				changed.IssuerEpoch = "20000000-0000-4000-8000-000000000009"
			case "image":
				changed.Image = "registry.example/other@sha256:" + strings.Repeat("b", 64)
			case "partial":
				changed.WorkKey = nil
			case "bucket":
				changed.EvidenceStore.Bucket = "other"
			case "region":
				changed.EvidenceStore.Region = "other"
			case "endpoint":
				changed.EvidenceStore.Endpoint = "https://other.invalid"
			case "roots":
				changed.EvidenceStore.Roots = nil
			case "owner-namespace":
				other.Namespace.Name = "other"
			case "owner-provider":
				other.KeyService.Endpoint = "https://other.invalid"
			}
			if smallRegionalOfferMatches(f.original, f.provider.base.plan, other, changed) {
				t.Fatal("foreign offer scope accepted")
			}
		})
	}
}
func TestSmallRegionalFlagsRefuseExternalSourceAmbiguity(t *testing.T) {
	base := []string{"--in-cluster", "--bundled-hub=trial", "--bootstrap-id=20000000-0000-4000-8000-000000000001"}
	for _, flag := range []string{"--kubeconfig=external", "--context=external", "--offer=external", "--bootstrap=external", "--evidence-credential=external", "--history-credential=external"} {
		t.Run(flag, func(t *testing.T) {
			var out bytes.Buffer
			args := append(append([]string{}, base...), flag)
			err := RunInstallerCluster(t.Context(), args, &out)
			var stage *fixedStepError
			if err == nil || errors.As(err, &stage) || out.Len() != 0 {
				t.Fatal("ambiguous flags reached source IO or output", err)
			}
		})
	}
	for _, args := range [][]string{{"--bundled-hub=trial", "--bootstrap-id=20000000-0000-4000-8000-000000000001"}, {"--in-cluster", "--bundled-hub=trial"}, {"--in-cluster", "--bootstrap-id=20000000-0000-4000-8000-000000000001"}, {"--join-hub"}} {
		var out bytes.Buffer
		err := RunInstallerCluster(t.Context(), args, &out)
		var stage *fixedStepError
		if err == nil || errors.As(err, &stage) || out.Len() != 0 {
			t.Fatal("incomplete selected mode reached source IO", err)
		}
	}
}
