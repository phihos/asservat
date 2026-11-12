package integration

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/http"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/kms"
	"asservat.local/asservat/internal/adapters/objectstore/framed"
	"asservat.local/asservat/internal/adapters/providerconfig"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/audit"
	"asservat.local/asservat/internal/domain/authorization"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/jackc/pgx/v5/pgxpool"
	auth "k8s.io/api/authentication/v1"
	core "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/utils/ptr"
)

type helmOriginalProviderChildren struct {
	installation, request  string
	privateUID             types.UID
	wrap, unwrap           string
	parent                 string
	wrapUntil, unwrapUntil time.Time
	err                    error
}
type helmBundledKeyService struct {
	plan                contracts.SmallOpenBaoPlan
	children            chan helmOriginalProviderChildren
	state, pvc          contracts.WorkerObjectReference
	stateVersion, ready string
	providerHTTP        *http.Client
}

// Only a new owned node directory/PV is fixture infrastructure. The actual
// chart creates all Bao material, reviewer identity, server and PVC itself.
func newHelmBundledKeyService(t *testing.T, ctx context.Context, api kubernetes.Interface, d contracts.InitialBootstrap, x helmBootstrapFixture) *helmBundledKeyService {
	t.Helper()
	p := contracts.SmallOpenBaoPlan{Format: contracts.SmallOpenBaoFormat, Namespace: d.BootstrapNamespace, Name: d.Name, Image: x.KeyServiceImage, Kubernetes: d.Kubernetes, SetupAccount: d.Name + "-bootstrap-runner"}
	if !p.Valid() {
		t.Fatal("actual bundled key-service plan/image unavailable")
	}
	node, err := api.CoreV1().Nodes().Get(ctx, x.NodeA, meta.GetOptions{})
	if err != nil || string(node.UID) != x.NodeAUID || node.Labels[core.LabelHostname] == "" {
		t.Fatal("owned Bao PV node changed", err)
	}
	directory := "/var/local/asservat-bundled-bao/" + p.Namespace + "/" + p.Name
	if _, err = exec.CommandContext(ctx, "docker", "exec", x.NodeA, "install", "-d", "-m", "0700", "-o", "65532", "-g", "65532", directory).CombinedOutput(); err != nil {
		t.Fatal("owned Bao node directory", err)
	}
	pvName := p.Namespace + "-keyservice"
	pv, err := api.CoreV1().PersistentVolumes().Create(ctx, &core.PersistentVolume{ObjectMeta: meta.ObjectMeta{Name: pvName, Labels: map[string]string{"asservat.test.owner": p.Namespace}}, Spec: core.PersistentVolumeSpec{Capacity: core.ResourceList{core.ResourceStorage: resource.MustParse("8Gi")}, AccessModes: []core.PersistentVolumeAccessMode{core.ReadWriteOnce}, PersistentVolumeReclaimPolicy: core.PersistentVolumeReclaimRetain, StorageClassName: "asservat-owned-local", ClaimRef: &core.ObjectReference{Namespace: p.Namespace, Name: p.DataPVCName()}, PersistentVolumeSource: core.PersistentVolumeSource{Local: &core.LocalVolumeSource{Path: directory}}, NodeAffinity: &core.VolumeNodeAffinity{Required: &core.NodeSelector{NodeSelectorTerms: []core.NodeSelectorTerm{{MatchExpressions: []core.NodeSelectorRequirement{{Key: core.LabelHostname, Operator: core.NodeSelectorOpIn, Values: []string{node.Labels[core.LabelHostname]}}}}}}}}}, meta.CreateOptions{})
	if err != nil {
		t.Fatal("owned Bao static PV", err)
	}
	t.Cleanup(func() {
		if keepFailedFixture(t) {
			return
		}
		clean, end := context.WithTimeout(context.Background(), 60*time.Second)
		defer end()
		got, e := api.CoreV1().PersistentVolumes().Get(clean, pvName, meta.GetOptions{})
		if apierrors.IsNotFound(e) {
			return
		}
		if e != nil || got.UID != pv.UID || got.Labels["asservat.test.owner"] != p.Namespace {
			t.Error("owned Bao PV cleanup identity", e)
			return
		}
		if e = api.CoreV1().PersistentVolumes().Delete(clean, pvName, meta.DeleteOptions{Preconditions: &meta.Preconditions{UID: &pv.UID}}); e != nil && !apierrors.IsNotFound(e) {
			t.Error("owned Bao PV cleanup", e)
		}
	})
	b := &helmBundledKeyService{plan: p, children: make(chan helmOriginalProviderChildren, 1)}
	observer, cancel := context.WithCancel(ctx)
	// Accessors are private progress, absent from the retained public root. An
	// original LIST watermark + exact watch observes them before product removal;
	// no token is retained, used, printed or substituted by this observer.
	list, err := api.CoreV1().Secrets(p.Namespace).List(observer, meta.ListOptions{FieldSelector: "metadata.name=" + p.Name + "-private-progress", Limit: 2})
	if err != nil || len(list.Items) != 0 || list.ResourceVersion == "" {
		cancel()
		t.Fatal("fresh original child-progress absence", err)
	}
	stream, err := api.CoreV1().Secrets(p.Namespace).Watch(observer, meta.ListOptions{FieldSelector: "metadata.name=" + p.Name + "-private-progress", ResourceVersion: list.ResourceVersion})
	if err != nil {
		cancel()
		t.Fatal("original child accessor watch", err)
	}
	joined := make(chan struct{})
	go func() {
		defer close(joined)
		defer stream.Stop()
		for events := 0; events < 128; events++ {
			select {
			case <-observer.Done():
				return
			case event, ok := <-stream.ResultChan():
				if !ok || event.Type == watch.Error || event.Type == watch.Deleted {
					b.children <- helmOriginalProviderChildren{err: errors.New("original child-progress event unavailable")}
					return
				}
				secret, ok := event.Object.(*core.Secret)
				if !ok {
					continue
				}
				state, e := contracts.DecodeInitialPreparationPrivateState(bytes.NewReader(secret.Data["state.json"]))
				for _, raw := range secret.Data {
					clear(raw)
				}
				if e != nil {
					b.children <- helmOriginalProviderChildren{err: errors.New("original child-progress invalid")}
					return
				}
				if state.Providers == nil || state.Providers.Wrap == nil || state.Providers.Unwrap == nil || state.Providers.Wrap.Response == nil || state.Providers.Unwrap.Response == nil {
					continue
				}
				b.children <- helmOriginalProviderChildren{installation: state.InstallationID, request: state.RequestID, privateUID: secret.UID, wrap: state.Providers.Wrap.Response.Accessor, unwrap: state.Providers.Unwrap.Response.Accessor, parent: state.Providers.Parent.Accessor, wrapUntil: state.Providers.Wrap.Response.ExpiresAt, unwrapUntil: state.Providers.Unwrap.Response.ExpiresAt}
				return
			}
		}
		b.children <- helmOriginalProviderChildren{err: errors.New("original child-progress event bound exhausted")}
	}()
	t.Cleanup(func() { cancel(); stream.Stop(); <-joined })
	return b
}
func (b *helmBundledKeyService) Values(values map[string]any) {
	services, ok := values["services"].(map[string]any)
	if !ok {
		services = map[string]any{}
		values["services"] = services
	}
	services["keyService"] = map[string]any{"provider": "openbao", "openbao": map[string]any{"image": b.plan.Image, "persistence": map[string]any{"storageClass": "asservat-owned-local", "size": "8Gi"}}}
}

func (b *helmBundledKeyService) metadata(t *testing.T, ctx context.Context, kc *rest.Config) *meta.PartialObjectMetadata {
	t.Helper()
	api, err := kubernetes.NewForConfig(kc)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := api.CoreV1().RESTClient().Get().AbsPath("/api/v1/namespaces/"+b.plan.Namespace+"/secrets/"+b.plan.StateSecretName()).SetHeader("Accept", "application/json;as=PartialObjectMetadata;g=meta.k8s.io;v=v1").MaxRetries(0).DoRaw(ctx)
	defer clear(raw)
	var state meta.PartialObjectMetadata
	if err != nil || len(raw) > 32<<10 || json.Unmarshal(raw, &state) != nil || state.Kind != "PartialObjectMetadata" || state.APIVersion != "meta.k8s.io/v1" || state.Name != b.plan.StateSecretName() || state.Namespace != b.plan.Namespace || !authorization.UUID(string(state.UID)) || state.ResourceVersion == "" || state.DeletionTimestamp != nil || len(state.OwnerReferences) != 0 || len(state.Finalizers) != 0 || state.Labels["asservat.io/private-role"] != "small-openbao" {
		t.Fatal("original public Bao metadata unavailable", err)
	}
	return &state
}

// Resolve from the actual protected preparer projection, not from fixture CA,
// provider admin state or a replacement endpoint guessed from the host.
func (b *helmBundledKeyService) Resolve(t *testing.T, ctx context.Context, api kubernetes.Interface, kc *rest.Config, input *contracts.InitialBootstrapInput, state contracts.InitialBootstrapState, node *core.Node) {
	t.Helper()
	if state.Projection == nil {
		t.Fatal("original bundled projection missing")
	}
	projection, err := api.CoreV1().ConfigMaps(b.plan.Namespace).Get(ctx, state.Projection.Name, meta.GetOptions{})
	if err != nil || string(projection.UID) != state.Projection.UID {
		t.Fatal("original public provider projection changed", err)
	}
	original, err := contracts.DecodeInitialPreparer(strings.NewReader(projection.Data["deployment.json"]))
	if err != nil || original.Services == nil || original.Services.KeyService.Endpoint != b.plan.Endpoint() || original.Services.KeyService.AuditMount != contracts.SmallOpenBaoAuditMount || original.Services.KeyService.AuditKey != "audit" || !reflectEndpoint(original.Kubernetes, b.plan.Kubernetes) {
		t.Fatal("actual generated provider source mismatch", err)
	}
	var ca bytes.Buffer
	for _, der := range original.Services.KeyService.Roots {
		_ = pem.Encode(&ca, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	}
	if _, err = providerconfig.TrustRootsPEM(ca.Bytes(), time.Now()); err != nil {
		t.Fatal("actual generated Bao CA invalid", err)
	}
	input.KeyService = contracts.InitialBootstrapKeyServiceInput{Endpoint: b.plan.Endpoint(), RootsPEM: ca.String(), AuditMount: contracts.SmallOpenBaoAuditMount, AuditKey: "audit"}
	input.Providers = contracts.SmallOpenBaoInitialProviders()
	metadata := b.metadata(t, ctx, kc)
	backend := metadata.Annotations[contracts.SmallOpenBaoBackendAnnotation]
	pvc, err := api.CoreV1().PersistentVolumeClaims(b.plan.Namespace).Get(ctx, b.plan.DataPVCName(), meta.GetOptions{})
	if err != nil || !authorization.UUID(backend) || metadata.Annotations[contracts.SmallOpenBaoReadyAnnotation] != backend+"/"+string(pvc.UID) || pvc.Status.Phase != core.ClaimBound || pvc.Spec.VolumeName != b.plan.Namespace+"-keyservice" {
		t.Fatal("original Ready Bao/PVC pin unavailable", err)
	}
	b.state = contracts.WorkerObjectReference{Name: metadata.Name, UID: string(metadata.UID)}
	b.pvc = contracts.WorkerObjectReference{Name: pvc.Name, UID: string(pvc.UID)}
	b.stateVersion = metadata.ResourceVersion
	b.ready = metadata.Annotations[contracts.SmallOpenBaoReadyAnnotation]
	service, err := api.CoreV1().Services(b.plan.Namespace).Create(ctx, &core.Service{ObjectMeta: meta.ObjectMeta{Name: b.plan.ServiceName() + "-inspection"}, Spec: core.ServiceSpec{Type: core.ServiceTypeNodePort, Selector: map[string]string{"asservat.io/key-provider": b.plan.ServiceName()}, Ports: []core.ServicePort{{Port: 8200}}}}, meta.CreateOptions{})
	if err != nil {
		t.Fatal("owned Bao verification route", err)
	}
	address := ""
	for _, entry := range node.Status.Addresses {
		if entry.Type == core.NodeInternalIP {
			address = net.JoinHostPort(entry.Address, strconv.Itoa(int(service.Spec.Ports[0].NodePort)))
		}
	}
	if address == "" {
		t.Fatal("owned Bao verification node address")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca.Bytes()) {
		t.Fatal("actual Bao roots")
	}
	transport := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13}, DisableKeepAlives: true, DialContext: func(call context.Context, network, target string) (net.Conn, error) {
		if target != b.plan.Host()+":8200" {
			return nil, errors.New("foreign Bao verification origin")
		}
		return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(call, network, address)
	}}
	b.providerHTTP = &http.Client{Transport: transport, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	t.Cleanup(transport.CloseIdleConnections)
	if state.ProviderMint == nil || state.ProviderMint.Response == nil || state.ProviderMint.Response.Accessor == "" || !state.ProviderMint.Response.ExpiresAt.Before(state.ProviderMint.ExpiresBefore) || !state.ProviderMint.Until.Before(state.ProviderMint.ExpiresBefore) {
		t.Fatal("original bounded bundled issuer mint not recorded")
	}
	t.Log("actual original bundled issuer retained its recorded finite expiry; private source closes separately; no immediate issuer revocation claim")
}
func reflectEndpoint(a, c contracts.OwnerProviderEndpoint) bool {
	if a.Endpoint != c.Endpoint || len(a.Roots) != len(c.Roots) {
		return false
	}
	for i := range a.Roots {
		if !bytes.Equal(a.Roots[i], c.Roots[i]) {
			return false
		}
	}
	return true
}

// Never logs provider errors/payloads. The only caller-supplied paths here are
// fixed fixture policy/role/token reads; no root token is ever available.
func (b *helmBundledKeyService) call(t *testing.T, ctx context.Context, token, method, path string, body any, status int) map[string]any {
	t.Helper()
	raw, err := json.Marshal(body)
	if body == nil {
		raw = nil
	}
	if err != nil {
		t.Fatal("fixture Bao body encoding")
	}
	defer clear(raw)
	request, err := http.NewRequestWithContext(ctx, method, b.plan.Endpoint()+"/v1/"+path, bytes.NewReader(raw))
	if err != nil {
		t.Fatal("fixture Bao request encoding")
	}
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		request.Header.Set("X-Vault-Token", token)
	}
	response, err := b.providerHTTP.Do(request)
	if response != nil && response.Body != nil {
		defer response.Body.Close()
	}
	if err != nil || response == nil || response.StatusCode != status {
		actual := 0
		if response != nil {
			actual = response.StatusCode
		}
		// path contains only fixed endpoints or this fixture's synthetic name;
		// tokens/accessors remain headers/bodies and never enter diagnostics.
		t.Fatalf("fixture Bao bounded request refused: path=%s method=%s expectedStatus=%d actualStatus=%d transportFailed=%t", path, method, status, actual, err != nil)
	}
	result, err := io.ReadAll(io.LimitReader(response.Body, 32769))
	defer clear(result)
	if err != nil || len(result) > 32768 {
		t.Fatal("fixture Bao response bound")
	}
	var decoded map[string]any
	if len(result) != 0 && json.Unmarshal(result, &decoded) != nil {
		t.Fatal("fixture Bao response decoding")
	}
	return decoded
}
func (b *helmBundledKeyService) VerifyAudit(t *testing.T, ctx context.Context, api kubernetes.Interface, admin *pgxpool.Pool, store *s3.Client, d contracts.InitialBootstrap, state contracts.InitialBootstrapState, root contracts.InitialPreparationRoot, configuration contracts.InitialPreparer) {
	t.Helper()
	var children helmOriginalProviderChildren
	select {
	case children = <-b.children:
	case <-ctx.Done():
		t.Fatal("original provider children unobserved")
	}
	if children.err != nil || children.installation != state.InstallationID || children.request != state.RequestID || children.wrap == "" || children.unwrap == "" || children.wrap == children.unwrap || configuration.Plan.PrivateState == nil || children.privateUID != types.UID(configuration.Plan.PrivateState.UID) || state.ProviderMint == nil || state.ProviderMint.Response == nil || children.parent != state.ProviderMint.Response.Accessor {
		t.Fatal("original child accessor provenance unavailable")
	}
	// This token is fixture-only setup authority minted by the same real API for
	// the actual chart account. Product uses its own projected JWT independently.
	jwt, err := api.CoreV1().ServiceAccounts(b.plan.Namespace).CreateToken(ctx, b.plan.SetupAccount, &auth.TokenRequest{Spec: auth.TokenRequestSpec{Audiences: []string{contracts.SmallOpenBaoSetupAudience}, ExpirationSeconds: ptr.To(int64(600))}}, meta.CreateOptions{})
	if err != nil {
		t.Fatal("fixture verifier setup JWT", err)
	}
	login := b.call(t, ctx, "", http.MethodPost, "auth/"+contracts.SmallOpenBaoSetupMount+"/login", map[string]string{"role": contracts.SmallOpenBaoSetupRole, "jwt": jwt.Status.Token}, 200)
	jwt.Status.Token = ""
	authData, ok := login["auth"].(map[string]any)
	if !ok {
		t.Fatal("fixture setup login reply")
	}
	setup, ok := authData["client_token"].(string)
	if !ok || !kms.ValidProviderToken([]byte(setup)) {
		t.Fatal("fixture setup login token")
	}
	namespace, err := api.CoreV1().Namespaces().Get(ctx, b.plan.Namespace, meta.GetOptions{})
	if err != nil {
		t.Fatal("actual verifier namespace", err)
	}
	account, err := api.CoreV1().ServiceAccounts(b.plan.Namespace).Get(ctx, b.plan.SetupAccount, meta.GetOptions{})
	if err != nil {
		t.Fatal("actual verifier setup account", err)
	}
	selected, err := kms.ObserveBundledInitialProviderIdentity(ctx, b.plan.Endpoint(), setup, b.plan, contracts.WorkerObjectReference{Name: namespace.Name, UID: string(namespace.UID)}, contracts.WorkerObjectReference{Name: account.Name, UID: string(account.UID)}, b.providerHTTP, time.Now)
	if err != nil || !selected.Valid() {
		t.Fatal("actual finite fixture setup identity did not verify")
	}
	// Ordinary audit unwrap has its own exact-key policy and finite nonrenewing
	// child. It is not the product's retired child or evidence authority.
	name := "asservat-fixture-initial-audit-" + custodyID()[:8]
	policy, _ := json.Marshal(map[string]any{"path": map[string]any{d.KeyService.AuditMount + "/decrypt/" + d.KeyService.AuditKey: map[string]any{"capabilities": []string{"update"}}, "auth/token/lookup-self": map[string]any{"capabilities": []string{"read"}}}})
	b.call(t, ctx, setup, http.MethodPut, "sys/policies/acl/"+name, map[string]string{"policy": string(policy)}, 204)
	b.call(t, ctx, setup, http.MethodPost, "auth/token/roles/"+name, map[string]any{"allowed_policies": []string{name}, "orphan": false, "renewable": false, "token_type": "service", "token_no_default_policy": true, "token_explicit_max_ttl": 60}, 204)
	end, ok := ctx.Deadline()
	seconds := min(int64(60), int64(time.Until(end)/time.Second)-1, int64(time.Until(selected.SetupParent.ExpiresAt.Add(-10*time.Second))/time.Second)-1)
	if !ok || seconds < 1 {
		t.Fatal("original verifier bound expired")
	}
	issued := b.call(t, ctx, setup, http.MethodPost, "auth/token/create/"+name, map[string]any{"policies": []string{name}, "no_default_policy": true, "renewable": false, "type": "service", "ttl": strconv.FormatInt(seconds, 10) + "s", "explicit_max_ttl": strconv.FormatInt(seconds, 10) + "s"}, 200)
	child, ok := issued["auth"].(map[string]any)
	if !ok {
		t.Fatal("fixture ordinary verifier reply")
	}
	token, ok := child["client_token"].(string)
	accessor, aok := child["accessor"].(string)
	if !ok || !aok || token == setup || accessor == "" {
		t.Fatal("fixture verifier identity")
	}
	// Positive own lookup proves setup can inspect accessors; later denial of
	// the two recorded product children cannot pass due to missing privileges.
	b.call(t, ctx, setup, http.MethodPost, "auth/token/lookup-accessor", map[string]string{"accessor": accessor}, 200)
	own := b.call(t, ctx, token, http.MethodGet, "auth/token/lookup-self", nil, 200)
	ownData, _ := own["data"].(map[string]any)
	policies, _ := ownData["policies"].([]any)
	identityPolicies, _ := ownData["identity_policies"].([]any)
	if len(policies) != 1 || policies[0] != name || len(identityPolicies) != 0 || ownData["renewable"] != false || ownData["type"] != "service" || ownData["explicit_max_ttl"] != float64(60) {
		t.Fatal("fixture verifier not ordinary finite nonrenewing service")
	}
	// Each HTTP call is bounded by five seconds. Refusal before the original
	// expiries demonstrates revocation rather than merely natural expiration.
	if !time.Now().Add(10*time.Second).Before(children.wrapUntil) || !time.Now().Add(10*time.Second).Before(children.unwrapUntil) {
		t.Fatal("original child revocation cannot be distinguished from expiry within verifier call budget")
	}
	b.call(t, ctx, setup, http.MethodPost, "auth/token/lookup-accessor", map[string]string{"accessor": children.wrap}, 400)
	b.call(t, ctx, setup, http.MethodPost, "auth/token/lookup-accessor", map[string]string{"accessor": children.unwrap}, 400)
	var recordJSON, receiptJSON []byte
	var activated, blocked bool
	if err = admin.QueryRow(ctx, "SELECT record_json,audit_receipt_json,activated_at IS NOT NULL FROM fleet_initial_activation WHERE installation_id=$1", state.InstallationID).Scan(&recordJSON, &receiptJSON, &activated); err != nil || !activated {
		t.Fatal("actual initial activation absent", err)
	}
	if err = admin.QueryRow(ctx, "SELECT recovery_blocked FROM fleet_current_trust WHERE installation_id=$1", state.InstallationID).Scan(&blocked); err != nil || blocked {
		t.Fatal("actual initial incarnation not active", err)
	}
	var record audit.InitialInstallation
	var receipt audit.Receipt
	if json.Unmarshal(recordJSON, &record) != nil || json.Unmarshal(receiptJSON, &receipt) != nil || !record.Valid() || !receipt.ValidInitialInstallation(state.InstallationID, record.Claim.ID) || receipt.Version == "" || receipt.Version == "null" || root.Activation.Handover.Cleanup.ActivatedClaimID != record.Claim.ID || record.Scope.ClusterID != state.ClusterID {
		t.Fatal("exact initial activation record/receipt mismatch")
	}
	object, err := store.GetObject(ctx, &s3.GetObjectInput{Bucket: &d.AuditStore.Bucket, Key: &receipt.Key, VersionId: &receipt.Version})
	if err != nil {
		t.Fatal("actual initial audit object", err)
	}
	ciphertext, err := io.ReadAll(io.LimitReader(object.Body, (128<<10)+1))
	object.Body.Close()
	defer clear(ciphertext)
	if err != nil || len(ciphertext) > 128<<10 || int64(len(ciphertext)) != receipt.Bytes || sha256.Sum256(ciphertext) != [32]byte(receipt.SHA256) {
		t.Fatal("exact initial audit ciphertext mismatch")
	}
	opener, err := kms.NewOpener(d.KeyService.Endpoint, token, d.KeyService.AuditMount, d.KeyService.AuditKey, b.providerHTTP)
	if err != nil {
		t.Fatal("ordinary verifier composition", err)
	}
	if err = framed.VerifyInitialInstallation(ctx, opener, record, ciphertext); err != nil {
		t.Fatal("independent actual Bao audit verification failed")
	}
	b.call(t, ctx, setup, http.MethodPost, "auth/token/revoke-accessor", map[string]string{"accessor": accessor}, 204)
	b.call(t, ctx, token, http.MethodGet, "auth/token/lookup-self", nil, 403)
	b.call(t, ctx, setup, http.MethodPost, "auth/token/revoke-self", nil, 204)
	t.Log("actual bundled initial audit independently decrypted with exact-key finite fixture verifier; original product wrap/unwrap children positively revoked; no root/seal/privateCA or fixture issuer used")
}
func (b *helmBundledKeyService) VerifyReplay(t *testing.T, ctx context.Context, api kubernetes.Interface, kc *rest.Config) {
	t.Helper()
	m := b.metadata(t, ctx, kc)
	if string(m.UID) != b.state.UID || m.ResourceVersion != b.stateVersion || m.Annotations[contracts.SmallOpenBaoReadyAnnotation] != b.ready {
		t.Fatal("passive replay changed original Bao state/Ready pin")
	}
	pvc, err := api.CoreV1().PersistentVolumeClaims(b.plan.Namespace).Get(ctx, b.pvc.Name, meta.GetOptions{})
	if err != nil || string(pvc.UID) != b.pvc.UID {
		t.Fatal("passive replay replaced original Bao PVC", err)
	}
	pod, err := api.CoreV1().Pods(b.plan.Namespace).Get(ctx, b.plan.ServiceName()+"-0", meta.GetOptions{})
	if err != nil || len(pod.Status.ContainerStatuses) != 1 || pod.Status.ContainerStatuses[0].RestartCount != 0 || pod.Spec.Containers[0].Image != b.plan.Image {
		t.Fatal("actual Bao executable/restart identity", err)
	}
}
