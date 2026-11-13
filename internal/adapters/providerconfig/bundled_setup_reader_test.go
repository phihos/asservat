package providerconfig

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
)

// Test-only endpoint mapping keeps the selected production URL/profile intact
// while using the existing real-TLS synthetic readback fixture.
type bundledSetupFixtureTransport struct {
	upstream http.RoundTripper
	target   *url.URL
}

func (t bundledSetupFixtureTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	request := r.Clone(r.Context())
	u := *r.URL
	u.Scheme = t.target.Scheme
	u.Host = t.target.Host
	request.URL = &u
	request.Host = t.target.Host
	return t.upstream.RoundTrip(request)
}
func (t bundledSetupFixtureTransport) CloseIdleConnections() {
	if c, ok := t.upstream.(interface{ CloseIdleConnections() }); ok {
		c.CloseIdleConnections()
	}
}
func selectBundledSetupFixture(t *testing.T, f *setupFixture, kubernetes contracts.OwnerProviderEndpoint) contracts.SmallOpenBaoPlan {
	t.Helper()
	plan := contracts.SmallOpenBaoPlan{Format: contracts.SmallOpenBaoFormat, Namespace: "hub", Name: "trial", Image: contracts.SmallOpenBaoImage, Kubernetes: kubernetes, SetupAccount: "trial-setup"}
	plan.Kubernetes.Roots = cloneSetupRoots(kubernetes.Roots)
	original, err := url.Parse(f.in.KeyService.Endpoint)
	if err != nil {
		t.Fatal(err)
	}
	selected, err := NewBundledSetupReader(contracts.OwnerProviderEndpoint{Endpoint: plan.Endpoint(), Roots: f.roots}, []byte("synthetic-inspection-only"), plan)
	if err != nil {
		t.Fatal(err)
	}
	selected.http.Transport = bundledSetupFixtureTransport{upstream: f.reader.http.Transport, target: original}
	f.reader = selected
	return plan
}

func TestBundledSetupReaderSelectsOnlyExactProtectedPlan(t *testing.T) {
	f := newSetupFixture(t)
	plan := selectBundledSetupFixture(t, f, f.in.Kubernetes)
	data := f.responses["auth/owner-auth/config"]
	data["disable_local_ca_jwt"] = json.RawMessage("false")
	data["token_reviewer_jwt_set"] = json.RawMessage("false")
	if err := verifyKubernetesAuthConfig(data, f.in.Kubernetes); err == nil {
		t.Fatal("default external validator accepted local reviewer")
	}
	if err := f.reader.verifyKubernetesAuthConfig(data, f.in.Kubernetes); err != nil {
		t.Fatal("selected same-API reviewer refused", err)
	}
	// Constructor copies the protected API pin, rather than retaining caller slices.
	plan.Kubernetes.Roots[0] = nil
	if err := f.reader.verifyKubernetesAuthConfig(data, f.in.Kubernetes); err != nil {
		t.Fatal("caller changed copied selected plan")
	}
	for _, mode := range []string{"operation-api", "operation-ca", "provider-api", "provider-ca", "explicit-reviewer", "mixed-reviewer", "pem-key", "annotation-alias"} {
		t.Run(mode, func(t *testing.T) {
			original := newSetupFixture(t)
			selectBundledSetupFixture(t, original, original.in.Kubernetes)
			d := original.responses["auth/owner-auth/config"]
			d["disable_local_ca_jwt"] = json.RawMessage("false")
			d["token_reviewer_jwt_set"] = json.RawMessage("false")
			endpoint := original.in.Kubernetes
			switch mode {
			case "operation-api":
				endpoint.Endpoint = "https://foreign.invalid"
			case "operation-ca":
				endpoint.Roots = f.roots
			case "provider-api":
				d["kubernetes_host"] = json.RawMessage(`"https://foreign.invalid"`)
			case "provider-ca":
				d["kubernetes_ca_cert"] = json.RawMessage(`"invalid certificate"`)
			case "explicit-reviewer":
				d["disable_local_ca_jwt"] = json.RawMessage("true")
				d["token_reviewer_jwt_set"] = json.RawMessage("true")
			case "mixed-reviewer":
				d["token_reviewer_jwt_set"] = json.RawMessage("true")
			case "pem-key":
				d["pem_keys"] = json.RawMessage(`["foreign"]`)
			case "annotation-alias":
				d["use_annotations_as_alias_metadata"] = json.RawMessage("true")
			}
			if err := original.reader.verifyKubernetesAuthConfig(d, endpoint); err == nil {
				t.Fatal("selected reader accepted mismatched profile")
			}
			if original.requests.Load() != 0 {
				t.Fatal("configuration shape check performed I/O")
			}
		})
	}
}

func TestBundledSetupReaderRejectsInvalidPlanOrProviderURL(t *testing.T) {
	f := newSetupFixture(t)
	plan := contracts.SmallOpenBaoPlan{Format: contracts.SmallOpenBaoFormat, Namespace: "hub", Name: "trial", Image: contracts.SmallOpenBaoImage, Kubernetes: f.in.Kubernetes, SetupAccount: "trial-setup"}
	endpoint := contracts.OwnerProviderEndpoint{Endpoint: plan.Endpoint(), Roots: f.roots}
	foreign := endpoint
	foreign.Endpoint = "https://foreign.invalid"
	if r, err := NewBundledSetupReader(foreign, []byte("synthetic-inspection-only"), plan); err == nil || r != nil {
		t.Fatal("inferred bundled selection from foreign endpoint")
	}
	plan.SetupAccount = "foreign"
	if r, err := NewBundledSetupReader(endpoint, []byte("synthetic-inspection-only"), plan); err == nil || r != nil {
		t.Fatal("invalid protected plan accepted")
	}
	if f.requests.Load() != 0 {
		t.Fatal("constructor performed provider I/O")
	}
}

func TestBundledSetupReaderOwnerReadbackUsesLocalReviewerOnly(t *testing.T) {
	f := newSetupFixture(t)
	plan := selectBundledSetupFixture(t, f, f.in.Kubernetes)
	f.in.KeyService.Endpoint = plan.Endpoint()
	recipe, err := OwnerProviderRecipeFor(f.in, f.profile.AuthMount, f.profile.AuthMountAccessor, f.profile.ServiceAccount, f.profile.AuditCredentials, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	f.profile = recipe.Profile
	for _, role := range recipe.Roles {
		f.responses["auth/"+f.profile.AuthMount+"/role/"+role.Name] = setupMap(t, role.Role)
		f.responses["sys/policies/acl/"+role.Name] = setupMap(t, map[string]any{"name": role.Name, "policy": string(role.Policy)})
	}
	d := f.responses["auth/owner-auth/config"]
	d["disable_local_ca_jwt"] = json.RawMessage("false")
	d["token_reviewer_jwt_set"] = json.RawMessage("false")
	check, err := f.reader.VerifyOwner(context.Background(), f.in, f.profile, f.pool, f.roots)
	if err != nil || !check.Matches(f.in, f.profile, f.pool, f.roots, time.Now()) || f.requests.Load() != 16 {
		t.Fatal("selected owner readback refused", err, f.requests.Load())
	}
}

func TestBundledSetupReaderConfigurationReadbackUsesLocalReviewerOnly(t *testing.T) {
	f, in, oldRecipe := configurationSetupFixture(t)
	plan := selectBundledSetupFixture(t, f, in.Kubernetes)
	in.KeyService.Endpoint = plan.Endpoint()
	recipe, err := ConfigurationProviderRecipeFor(in, configurationProviderSelectionOf(oldRecipe.Profile), oldRecipe.Profile.ServiceAccount, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	for _, role := range recipe.Roles {
		f.responses["auth/"+recipe.Profile.AuthMount+"/role/"+role.Name] = setupMap(t, role.Role)
		f.responses["sys/policies/acl/"+role.Name] = setupMap(t, map[string]any{"name": role.Name, "policy": string(role.Policy)})
	}
	d := f.responses["auth/"+recipe.Profile.AuthMount+"/config"]
	d["disable_local_ca_jwt"] = json.RawMessage("false")
	d["token_reviewer_jwt_set"] = json.RawMessage("false")
	check, err := f.reader.VerifyConfiguration(context.Background(), in, recipe.Profile)
	if err != nil || !check.Matches(in, recipe.Profile, time.Now()) || f.requests.Load() != 8 {
		t.Fatal("selected configuration readback refused", err, f.requests.Load())
	}
}
