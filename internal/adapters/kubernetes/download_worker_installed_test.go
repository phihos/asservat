package kubernetes

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
	core "k8s.io/api/core/v1"
	rbac "k8s.io/api/rbac/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
)

// downloadWorkerAPI is a synthetic API server that stores created objects by
// path and applies updates; it enforces no admission or RBAC.
type downloadWorkerAPI struct {
	mu      sync.Mutex
	objects map[string]map[string]any
	uid     int
}

func newDownloadWorkerAPI(t *testing.T) (*downloadWorkerAPI, *rest.Config) {
	t.Helper()
	a := &downloadWorkerAPI{objects: map[string]map[string]any{}}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a.mu.Lock()
		defer a.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		status := func(code int, reason meta.StatusReason) {
			w.WriteHeader(code)
			_ = json.NewEncoder(w).Encode(meta.Status{TypeMeta: meta.TypeMeta{Kind: "Status", APIVersion: "v1"}, Status: meta.StatusFailure, Reason: reason, Code: int32(code)})
		}
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		key := r.URL.Path
		switch r.Method {
		case http.MethodPost:
			key += "/" + body["metadata"].(map[string]any)["name"].(string)
			if a.objects[key] != nil {
				status(409, meta.StatusReasonAlreadyExists)
				return
			}
			a.uid++
			m := body["metadata"].(map[string]any)
			m["uid"] = strings.Replace("20000000-0000-4000-8000-0000000000xx", "xx", string(rune('a'+a.uid/10))+string(rune('0'+a.uid%10)), 1)
			m["resourceVersion"], m["generation"] = "1", 1
			a.objects[key] = body
		case http.MethodPut:
			old := a.objects[key]
			if old == nil {
				status(404, meta.StatusReasonNotFound)
				return
			}
			if immutable, _ := old["immutable"].(bool); immutable {
				status(422, meta.StatusReasonInvalid)
				return
			}
			body["metadata"].(map[string]any)["uid"] = old["metadata"].(map[string]any)["uid"]
			a.objects[key] = body
		}
		if a.objects[key] == nil {
			status(404, meta.StatusReasonNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(a.objects[key])
	}))
	t.Cleanup(server.Close)
	return a, &rest.Config{Host: server.URL, BearerToken: "synthetic-only", TLSClientConfig: rest.TLSClientConfig{CAData: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})}}
}

func (a *downloadWorkerAPI) object(path string) map[string]any {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.objects[path]
}

// ADR-204 decision 1: the two hub accounts get exactly the named reads their
// worker namespace readers perform; only Jobs (named per dispatch) and Pods
// are unnamed, and no account may write anything but the probed source.
func TestDownloadWorkerRBACIsNamedAndMinimal(t *testing.T) {
	installation := ownerID(1)
	got, err := BuildDownloadWorkerRBAC(installation, "hub", "owner", "worker")
	if err != nil {
		t.Fatal(err)
	}
	ns := contracts.DownloadWorkerNamespaceName(installation)
	source, control, store := contracts.DownloadWorkerProfileName(installation), contracts.DownloadWorkerControlName(installation), contracts.DownloadWorkerStoreName(installation)
	guard := contracts.DownloadWorkerProfileGuardName(installation)
	rule := func(group, resource string, names []string, verbs ...string) rbac.PolicyRule {
		return rbac.PolicyRule{APIGroups: []string{group}, Resources: []string{resource}, ResourceNames: names, Verbs: verbs}
	}
	guards := rbac.PolicyRule{APIGroups: []string{"admissionregistration.k8s.io"}, Resources: []string{"validatingadmissionpolicies", "validatingadmissionpolicybindings"}, ResourceNames: []string{guard}, Verbs: []string{"get"}}
	want := [][]rbac.PolicyRule{
		{rule("", "configmaps", []string{source, control}, "get"), rule("", "configmaps", []string{source}, "update"), rule("", "secrets", []string{store}, "get"),
			rule("", "serviceaccounts", []string{contracts.DownloadWorkerAccountName(installation)}, "get"), rule("batch", "jobs", nil, "create", "get", "delete"), rule("", "pods", nil, "get", "list")},
		{rule("", "configmaps", []string{source}, "get", "update"), rule("", "secrets", []string{store}, "get")},
	}
	wantCluster := [][]rbac.PolicyRule{
		{rule("", "namespaces", []string{ns}, "get"), guards, rule("scheduling.k8s.io", "priorityclasses", []string{contracts.DownloadWorkerPriorityClassName(installation)}, "get"), rule("authentication.k8s.io", "tokenreviews", nil, "create")},
		{rule("", "namespaces", []string{ns}, "get"), guards},
	}
	if len(got.Roles) != 2 || len(got.Bindings) != 2 || len(got.ClusterRoles) != 2 || len(got.ClusterBindings) != 2 {
		t.Fatal("unexpected RBAC object set")
	}
	for i, account := range []string{"owner", "worker"} {
		if got.Roles[i].Namespace != ns || !reflect.DeepEqual(got.Roles[i].Rules, want[i]) || !reflect.DeepEqual(got.ClusterRoles[i].Rules, wantCluster[i]) {
			t.Fatal("rules", account, got.Roles[i].Rules, got.ClusterRoles[i].Rules)
		}
		subjects := []rbac.Subject{{Kind: "ServiceAccount", Name: account, Namespace: "hub"}}
		b, c := got.Bindings[i], got.ClusterBindings[i]
		if b.Namespace != ns || !reflect.DeepEqual(b.Subjects, subjects) || b.RoleRef != (rbac.RoleRef{APIGroup: rbac.GroupName, Kind: "Role", Name: got.Roles[i].Name}) ||
			!reflect.DeepEqual(c.Subjects, subjects) || c.RoleRef != (rbac.RoleRef{APIGroup: rbac.GroupName, Kind: "ClusterRole", Name: got.ClusterRoles[i].Name}) {
			t.Fatal("binding", account)
		}
	}
	for _, r := range append(append([]rbac.PolicyRule{}, got.Roles[0].Rules...), got.Roles[1].Rules...) {
		for _, v := range r.Verbs {
			if (v == "update" && !reflect.DeepEqual(r.ResourceNames, []string{source})) || v == "*" || v == "patch" || v == "deletecollection" || v == "watch" {
				t.Fatal("write or wildcard beyond the probed source", r)
			}
		}
		if slices.Contains(r.Resources, "secrets") && len(r.ResourceNames) != 1 {
			t.Fatal("unnamed Secret access", r)
		}
	}
	for name, args := range map[string][4]string{"installation": {"x", "hub", "owner", "worker"}, "same-account": {installation, "hub", "owner", "owner"}, "worker-namespace": {installation, ns, "owner", "worker"}, "account": {installation, "hub", "Owner", "worker"}} {
		if _, err = BuildDownloadWorkerRBAC(args[0], args[1], args[2], args[3]); err == nil {
			t.Fatal("accepted", name)
		}
	}
	n, pc := BuildDownloadWorkerNamespace(installation), BuildDownloadWorkerPriorityClass(installation)
	if n.Name != ns || !reflect.DeepEqual(n.Labels, map[string]string{"pod-security.kubernetes.io/enforce": "restricted"}) || pc.Value != 0 || pc.GlobalDefault || pc.PreemptionPolicy == nil || *pc.PreemptionPolicy != core.PreemptNever {
		t.Fatal("namespace or priority class", n, pc)
	}
}

// The worker objects are created once and reopened exactly; the store
// Secret and the control ConfigMap become immutable with one exact content,
// and the profile source changes only from the unconfigured marker.
func TestDownloadWorkerSourcesCreateFillAndConfigure(t *testing.T) {
	api, config := newDownloadWorkerAPI(t)
	ctx, installation := context.Background(), ownerID(1)
	hub := cfg.NamespaceRef{Name: "hub", UID: ownerID(2)}
	admins := []cfg.KubernetesActor{{Kind: "User", Name: "system:serviceaccount:install:runner"}}
	owner, worker := contracts.WorkerObjectReference{Name: "owner", UID: ownerID(3)}, contracts.WorkerObjectReference{Name: "worker", UID: ownerID(4)}
	out, err := EnsureDownloadWorkerSources(ctx, config, installation, hub, admins, owner, worker)
	if err != nil {
		t.Fatal(err)
	}
	ns := contracts.DownloadWorkerNamespaceName(installation)
	if out.Namespace.Name != ns || out.ServiceAccount.Name != contracts.DownloadWorkerAccountName(installation) || out.PriorityClass.Name != contracts.DownloadWorkerPriorityClassName(installation) ||
		out.StoreCredentials.Name != contracts.DownloadWorkerStoreName(installation) || out.Profile.Source.Name != contracts.DownloadWorkerProfileName(installation) ||
		out.Profile.Guard.Name != contracts.DownloadWorkerProfileGuardName(installation) || out.Profile.Guard.PolicyUID == "" || out.Profile.Guard.BindingUID == "" || len(out.Profile.Guard.Administrators) != 1 {
		t.Fatal("worker sources", out)
	}
	labels := api.object("/api/v1/namespaces/" + ns)["metadata"].(map[string]any)["labels"].(map[string]any)
	if labels["pod-security.kubernetes.io/enforce"] != "restricted" {
		t.Fatal("namespace not restricted")
	}
	source := api.object("/api/v1/namespaces/" + ns + "/configmaps/" + out.Profile.Source.Name)
	if source["data"].(map[string]any)["worker-profile.json"] != contracts.UnconfiguredWorkerConfiguration(installation) {
		t.Fatal("source not unconfigured")
	}
	for _, path := range []string{"/apis/rbac.authorization.k8s.io/v1/namespaces/" + ns + "/roles/" + ns + "-owner", "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings/asservat." + ns + "-hub-worker"} {
		if api.object(path) == nil {
			t.Fatal("missing access object", path)
		}
	}
	again, err := EnsureDownloadWorkerSources(ctx, config, installation, hub, admins, owner, worker)
	if err != nil || !reflect.DeepEqual(again, out) {
		t.Fatal("rerun did not reopen the exact objects", err)
	}

	credentials := []byte(`{"accessKeyID":"synthetic","secretAccessKey":"synthetic-secret"}`)
	for _, bad := range [][]byte{nil, []byte(`{"accessKeyID":"a"}`), []byte(`{"accessKeyID":"a","secretAccessKey":"b","sessionToken":"c"}`), []byte(`{"accessKeyID":"a","secretAccessKey":"b","extra":1}`)} {
		if FillDownloadWorkerStore(ctx, config, out, bad) == nil {
			t.Fatal("accepted store credential", string(bad))
		}
	}
	if err = FillDownloadWorkerStore(ctx, config, out, credentials); err != nil {
		t.Fatal(err)
	}
	secret := api.object("/api/v1/namespaces/" + ns + "/secrets/" + out.StoreCredentials.Name)
	if secret["immutable"] != true || len(secret["data"].(map[string]any)) != 1 || secret["data"].(map[string]any)["credentials.json"] == nil {
		t.Fatal("store Secret not filled immutably", secret)
	}
	if err = FillDownloadWorkerStore(ctx, config, out, credentials); err != nil {
		t.Fatal("same credential refused on rerun", err)
	}
	if err = FillDownloadWorkerStore(ctx, config, out, []byte(`{"accessKeyID":"other","secretAccessKey":"synthetic-secret"}`)); !errors.Is(err, cfg.ErrChanged) {
		t.Fatal("replaced the filled credential", err)
	}
	if _, err = EnsureDownloadWorkerSources(ctx, config, installation, hub, admins, owner, worker); err != nil {
		t.Fatal("filled store Secret not reopened", err)
	}

	raw := []byte(`{"synthetic":"not a control"}`)
	if _, err = EnsureDownloadWorkerControl(ctx, config, installation, out.Namespace, raw); err == nil {
		t.Fatal("unparseable control accepted")
	}
	raw = syntheticWorkerControl(t, installation)
	ref, err := EnsureDownloadWorkerControl(ctx, config, installation, out.Namespace, raw)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(map[string]string{"worker.json": string(raw)})
	digest := sha256.Sum256(b)
	cm := api.object("/api/v1/namespaces/" + ns + "/configmaps/" + contracts.DownloadWorkerControlName(installation))
	if ref.Name != contracts.DownloadWorkerControlName(installation) || ref.SHA256 != hex.EncodeToString(digest[:]) || cm["immutable"] != true {
		t.Fatal("control reference", ref)
	}
	if again, err := EnsureDownloadWorkerControl(ctx, config, installation, out.Namespace, raw); err != nil || again != ref {
		t.Fatal("control not reopened", err)
	}
	var changed contracts.WorkerControl
	_ = json.Unmarshal(raw, &changed)
	changed.Address = "other.hub.svc:9443"
	other, _ := json.Marshal(changed)
	if _, err = EnsureDownloadWorkerControl(ctx, config, installation, out.Namespace, other); !errors.Is(err, cfg.ErrChanged) {
		t.Fatal("different control adopted", err)
	}

	profile := []byte(`{"format":"asservat-worker-configuration/v2"}`)
	if err = ConfigureDownloadWorkerProfile(ctx, config, installation, out, profile); err != nil {
		t.Fatal(err)
	}
	if api.object("/api/v1/namespaces/" + ns + "/configmaps/" + out.Profile.Source.Name)["data"].(map[string]any)["worker-profile.json"] != string(profile) {
		t.Fatal("profile not configured")
	}
	if err = ConfigureDownloadWorkerProfile(ctx, config, installation, out, profile); err != nil {
		t.Fatal("same profile refused on rerun", err)
	}
	if err = ConfigureDownloadWorkerProfile(ctx, config, installation, out, []byte(`{"format":"other"}`)); !errors.Is(err, cfg.ErrChanged) {
		t.Fatal("administrator content overwritten", err)
	}
	moved := out
	moved.Profile.Source.UID = ownerID(9)
	if ConfigureDownloadWorkerProfile(ctx, config, installation, moved, profile) == nil {
		t.Fatal("replaced source accepted")
	}
}

// ADR-204 decision 5: the phase-3 inbox carries the download workers' own
// evidence read credential under its fixed key, apart from the publisher's.
func TestInstallerInboxCarriesDownloadEvidenceCredential(t *testing.T) {
	api, config := newDownloadWorkerAPI(t)
	ctx, installation := context.Background(), ownerID(1)
	downloads := []byte(`{"accessKeyID":"synthetic","secretAccessKey":"synthetic-secret","sessionToken":""}`)
	if err := WriteInstallerInbox(ctx, config, "release", installation, 3, []byte("inspection"), []byte("audit"), nil, nil, nil, downloads); err != nil {
		t.Fatal(err)
	}
	stored := api.object("/api/v1/namespaces/release/secrets/" + contracts.InstallerInboxName(installation))["data"].(map[string]any)
	if _, ok := stored[contracts.InstallerInboxDownloadEvidenceCredential]; !ok || stored[contracts.InstallerInboxEvidenceReadCredential] != nil {
		t.Fatal("inbox keys", stored)
	}
	inbox, err := ReadInstallerInbox(ctx, config, "release", installation, 3)
	if err != nil || string(inbox.DownloadEvidenceCredential) != string(downloads) || inbox.EvidenceReadCredential != nil {
		t.Fatal("inbox read", err)
	}
	if err = WriteInstallerInbox(ctx, config, "release", installation, 3, []byte("inspection"), []byte("audit"), nil, nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	if inbox, err = ReadInstallerInbox(ctx, config, "release", installation, 3); err != nil || inbox.DownloadEvidenceCredential != nil {
		t.Fatal("replaced inbox kept the download credential", err)
	}
}

// An existing namespace without restricted Pod Security is never adopted.
func TestDownloadWorkerSourcesRefuseUnrestrictedNamespace(t *testing.T) {
	api, config := newDownloadWorkerAPI(t)
	installation := ownerID(1)
	ns := contracts.DownloadWorkerNamespaceName(installation)
	api.objects["/api/v1/namespaces/"+ns] = map[string]any{"apiVersion": "v1", "kind": "Namespace", "metadata": map[string]any{"name": ns, "uid": ownerID(8), "labels": map[string]any{"pod-security.kubernetes.io/enforce": "baseline"}}}
	_, err := EnsureDownloadWorkerSources(context.Background(), config, installation, cfg.NamespaceRef{Name: "hub", UID: ownerID(2)}, []cfg.KubernetesActor{{Kind: "User", Name: "runner"}},
		contracts.WorkerObjectReference{Name: "owner", UID: ownerID(3)}, contracts.WorkerObjectReference{Name: "worker", UID: ownerID(4)})
	if !errors.Is(err, cfg.ErrChanged) {
		t.Fatal("adopted an unrestricted namespace", err)
	}
}

// ADR-204: the provider-installed owner projects the hub worker API's client
// and probe tokens into its backend root under names fixed before the worker
// namespace exists; both are the owner's own default-audience tokens.
func TestProviderOwnerProjectsDownloadWorkerTokens(t *testing.T) {
	p, cluster := installedOwnerPlan(), ownerID(2)
	w, err := BuildProviderOwnerWorkload(p, cluster, ownerProviderInstalledSelection())
	if err != nil {
		t.Fatal(err)
	}
	pod := w.Deployment.Spec.Template.Spec
	var observation *core.Volume
	for i := range pod.Volumes {
		if pod.Volumes[i].Name == "observation" {
			observation = &pod.Volumes[i]
		}
	}
	if observation == nil || observation.Projected == nil || observation.Secret != nil || len(observation.Projected.Sources) != 3 || *observation.Projected.DefaultMode != 0440 {
		t.Fatal("observation root is not the projected backend root")
	}
	s := observation.Projected.Sources
	if s[0].Secret == nil || s[0].Secret.Name != contracts.OwnerObservationProjectionName(p.InstallationID) || s[0].Secret.Optional == nil || !*s[0].Secret.Optional || len(s[0].Secret.Items) != 0 {
		t.Fatal("worker control catalog projection changed")
	}
	ns := contracts.DownloadWorkerNamespaceName(p.InstallationID)
	for i, path := range []string{contracts.NativeKubernetesTokenFile(cluster, ns), contracts.NativeKubernetesProbeTokenFile(cluster, ns)} {
		token := s[1+i].ServiceAccountToken
		if token == nil || token.Path != path || token.Audience != "" || token.ExpirationSeconds == nil || *token.ExpirationSeconds != 600 {
			t.Fatal("worker API token", path, token)
		}
	}
	if path := contracts.NativeKubernetesTokenFile(cluster, ns); path != "native-kube-"+cluster+"-"+ns+".token" || contracts.NativeKubernetesProbeTokenFile(cluster, ns) == path {
		t.Fatal("token file names", path)
	}
	mounted := false
	for _, m := range pod.Containers[0].VolumeMounts {
		mounted = mounted || m.Name == "observation" && m.MountPath == contracts.OwnerObservationProjectionRoot && m.ReadOnly
	}
	if !mounted {
		t.Fatal("observation root moved")
	}
}

// ADR-204 decision 8: the key service reads the guarded catalog with its own
// dry-run probe, so the hub guard admits its one catalog pair, like the
// publisher's, within the pair bound; the bridge proves neither.
func TestOwnerPublicSourceProbesAdmitKeyServiceCatalog(t *testing.T) {
	installation := ownerID(1)
	pairs := ownerPublicSourceProbes(installation, "owner")
	catalog := contracts.OwnerClusterCatalogName(installation)
	for _, account := range []string{contracts.PublisherName(installation), contracts.KeyServiceName(installation)} {
		if !slices.Contains(pairs, cfg.OwnerConfigurationProbe{ConfigMap: catalog, ServiceAccount: account}) || !slices.Contains(ownerRuntimeProbeAccounts(installation), account) {
			t.Fatal("missing runtime catalog pair", account)
		}
	}
	if len(ownerRuntimeProbeAccounts(installation)) != 2 || 3+len(pairs) > cfg.MaxOwnerConfigurationProbes {
		t.Fatal("pair bound exceeded", len(pairs))
	}
}

func workerControlTestRoot(t *testing.T) []byte {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	now := time.Now()
	ca := &x509.Certificate{SerialNumber: big.NewInt(204), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, ca, ca, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// syntheticWorkerControl is a v2 control document the worker parser accepts,
// with synthetic roots.
func syntheticWorkerControl(t *testing.T, installation string) []byte {
	t.Helper()
	root := workerControlTestRoot(t)
	c := contracts.WorkerControl{Format: contracts.WorkerNativeControlFormat, InstallationID: installation, ClusterID: ownerID(5), Endpoint: "https://owner.synthetic.invalid:9443", Address: "owner.hub.svc:9443",
		ServerRoots: [][]byte{root}, IssuerRoots: [][]byte{root},
		Native: &contracts.WorkerNativeControl{Format: contracts.WorkerNativeStartupFormat, ExchangeEndpoint: "https://owner.synthetic.invalid:9443" + contracts.NativeWorkerPath, ExchangeAddress: "owner.hub.svc:9443", ExchangeServerRoots: [][]byte{root},
			ObjectStore: contracts.WorkerNativeStore{ID: ownerID(6), Endpoint: "https://store.synthetic.invalid", Region: "synthetic", Bucket: "evidence", ServerRoots: [][]byte{root}, CredentialSecretName: "store", CredentialSecretUID: ownerID(7)},
			KeyService:  contracts.WorkerNativeKeyService{Endpoint: "https://keys.synthetic.invalid:9447", ServerRoots: [][]byte{root}, Scope: contracts.KeyScope{InstallationID: installation, Purpose: "artifact", KeyID: "artifact-key"}}}}
	raw, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
