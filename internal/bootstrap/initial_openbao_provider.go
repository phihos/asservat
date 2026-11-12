package bootstrap

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/json/jsontext"
	"io"
	"net/http"
	"os"
	"reflect"
	"time"

	"asservat.local/asservat/internal/adapters/kms"
	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/adapters/mounts"
	"asservat.local/asservat/internal/adapters/providerconfig"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	coreclient "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/rest"
)

// This result owns only the original finite setup login. It has not minted an
// initial issuer. The caller must persist its original seed/claim before any
// issuer POST; reopening this helper is not replay of such an uncertain effect.
type initialOpenBaoProvider struct {
	Plan     contracts.SmallOpenBaoPlan
	Token    []byte
	Identity contracts.BundledInitialProviderIdentity
	HTTP     *http.Client
}

func (p *initialOpenBaoProvider) Close() {
	if p != nil {
		clear(p.Token)
		p.Token = nil
		if p.HTTP != nil {
			p.HTTP.CloseIdleConnections()
		}
	}
}

type initialOpenBaoCheck string

func (e initialOpenBaoCheck) Error() string     { return "bundled key provider " + string(e) }
func (e initialOpenBaoCheck) FixedStep() string { return string(e) }
func (e initialOpenBaoCheck) Unwrap() error     { return mounts.ErrUnavailable }
func initialOpenBaoCurrent(ctx context.Context) bool {
	if ctx == nil || ctx.Err() != nil {
		return false
	}
	end, ok := ctx.Deadline()
	return ok && time.Now().Before(end)
}

type initialOpenBaoProviderSource struct {
	plan    contracts.SmallOpenBaoPlan
	roots   [][]byte
	backend string
}

func readInitialOpenBaoProviderSource(ctx context.Context, files *os.Root, selected contracts.SmallOpenBaoPlan, config *rest.Config) (initialOpenBaoProviderSource, error) {
	var zero initialOpenBaoProviderSource
	if !initialOpenBaoCurrent(ctx) || files == nil || !selected.Valid() || config == nil {
		return zero, initialOpenBaoCheck("source")
	}
	plan, ca, backend, err := readBundledOpenBaoSource(ctx, files, selected.Namespace, selected.Name)
	if err != nil || !reflect.DeepEqual(plan, selected) || config.Host != plan.Kubernetes.Endpoint || config.Insecure || config.CAFile != "" {
		return zero, initialOpenBaoCheck("source")
	}
	roots, err := providerconfig.TrustRootsPEM(ca, time.Now())
	if err != nil {
		return zero, initialOpenBaoCheck("source")
	}
	apiRoots, err := providerconfig.TrustRootsPEM(config.CAData, time.Now())
	if err != nil || !reflect.DeepEqual(apiRoots, plan.Kubernetes.Roots) || !initialOpenBaoCurrent(ctx) {
		return zero, initialOpenBaoCheck("api-source")
	}
	return initialOpenBaoProviderSource{plan: plan, roots: roots, backend: backend}, nil
}

// openInitialOpenBaoProvider uses only projected public state and the original
// setup JWT. It never reads seal/private CA keys, mints an issuer, retries a
// login, renews a token or obtains installation/recovery/evidence authority.
func openInitialOpenBaoProvider(ctx context.Context, files *os.Root, selected contracts.SmallOpenBaoPlan, config *rest.Config) (*initialOpenBaoProvider, error) {
	source, err := readInitialOpenBaoProviderSource(ctx, files, selected, config)
	if err != nil {
		return nil, err
	}
	h, err := ownerHTTP(source.plan.Endpoint(), source.roots)
	if err != nil {
		return nil, initialOpenBaoCheck("tls")
	}
	// Fresh connections make transport replay impossible even for the finite
	// read sequence. No proxy, redirect or ambient provider token is selected.
	h.Transport.(*http.Transport).DisableKeepAlives = true
	return openInitialOpenBaoProviderSource(ctx, files, source, config, h)
}

func initialOpenBaoRead(ctx context.Context, api rest.Interface, path string, out any, metadata bool) error {
	if !initialOpenBaoCurrent(ctx) {
		return mounts.ErrUnavailable
	}
	request := api.Get().AbsPath(path).MaxRetries(0)
	if metadata {
		request.SetHeader("Accept", "application/json;as=PartialObjectMetadata;g=meta.k8s.io;v=v1")
	}
	raw, err := request.DoRaw(ctx)
	defer clear(raw)
	if err != nil || len(raw) > 32<<10 || !jsontext.Value(raw).IsValid() || json.Unmarshal(raw, out) != nil || !initialOpenBaoCurrent(ctx) {
		return mounts.ErrUnavailable
	}
	return nil
}

// The caller supplies the already constructed selected-TLS client. Production
// always obtains it from ownerHTTP; tests remap only the dial address while
// preserving the real TLS hostname and selected root verification.
func openInitialOpenBaoProviderSource(ctx context.Context, files *os.Root, source initialOpenBaoProviderSource, config *rest.Config, h *http.Client) (_ *initialOpenBaoProvider, err error) {
	p := &initialOpenBaoProvider{Plan: source.plan, HTTP: h}
	complete := false
	defer func() {
		if !complete {
			p.Close()
		}
	}()
	if !initialOpenBaoCurrent(ctx) || h == nil {
		return nil, initialOpenBaoCheck("context")
	}
	native, err := coreclient.NewForConfig(config)
	if err != nil {
		return nil, initialOpenBaoCheck("native")
	}
	api := native.RESTClient()
	var ns core.Namespace
	if initialOpenBaoRead(ctx, api, "/api/v1/namespaces/"+source.plan.Namespace, &ns, false) != nil || ns.APIVersion != "v1" || ns.Kind != "Namespace" || ns.Name != source.plan.Namespace || !authorization.UUID(string(ns.UID)) || ns.DeletionTimestamp != nil {
		return nil, initialOpenBaoCheck("namespace")
	}
	var sa core.ServiceAccount
	if initialOpenBaoRead(ctx, api, "/api/v1/namespaces/"+source.plan.Namespace+"/serviceaccounts/"+source.plan.SetupAccount, &sa, false) != nil || sa.APIVersion != "v1" || sa.Kind != "ServiceAccount" || sa.Namespace != source.plan.Namespace || sa.Name != source.plan.SetupAccount || !authorization.UUID(string(sa.UID)) || sa.DeletionTimestamp != nil {
		return nil, initialOpenBaoCheck("account")
	}
	var state meta.PartialObjectMetadata
	if initialOpenBaoRead(ctx, api, "/api/v1/namespaces/"+source.plan.Namespace+"/secrets/"+source.plan.StateSecretName(), &state, true) != nil || state.APIVersion != "meta.k8s.io/v1" || state.Kind != "PartialObjectMetadata" || state.Namespace != source.plan.Namespace || state.Name != source.plan.StateSecretName() || !authorization.UUID(string(state.UID)) || state.ResourceVersion == "" || state.DeletionTimestamp != nil || state.Annotations[contracts.SmallOpenBaoBackendAnnotation] != source.backend {
		return nil, initialOpenBaoCheck("state")
	}
	jwt, err := mounts.Read(ctx, files, contracts.InitialBootstrapKeyServiceTokenFile, contracts.WorkerEnrollmentMaxToken)
	if err != nil || !kms.ValidProviderToken(jwt) || !initialOpenBaoCurrent(ctx) {
		clear(jwt)
		return nil, initialOpenBaoCheck("jwt")
	}
	defer clear(jwt)
	body, err := json.Marshal(map[string]string{"role": contracts.SmallOpenBaoSetupRole, "jwt": string(jwt)})
	if err != nil {
		return nil, initialOpenBaoCheck("login")
	}
	defer clear(body)
	login, err := initialOpenBaoCall(ctx, h, source.plan.Endpoint(), "", http.MethodPost, "auth/"+contracts.SmallOpenBaoSetupMount+"/login", body)
	if err != nil || login.Auth == nil || !kms.ValidProviderToken([]byte(login.Auth.ClientToken)) || len(login.Auth.ClientToken) > contracts.InitialProviderTokenMaxBytes {
		return nil, initialOpenBaoCheck("login")
	}
	p.Token = []byte(login.Auth.ClientToken)
	marker, err := initialOpenBaoCall(ctx, h, source.plan.Endpoint(), string(p.Token), http.MethodGet, contracts.SmallOpenBaoBackendPolicyPath, nil)
	var policy struct {
		Name           string     `json:"name"`
		Policy         string     `json:"policy"`
		Version        int64      `json:"version"`
		CASRequired    bool       `json:"cas_required"`
		AllowWildcards bool       `json:"allow_wildcards_in_identity_templates"`
		AllowSlashes   bool       `json:"allow_slashes_in_identity_templates"`
		Modified       *time.Time `json:"modified"`
		Expiration     *time.Time `json:"expiration"`
	}
	decoder := json.NewDecoder(bytes.NewReader(marker.Data))
	decoder.DisallowUnknownFields()
	if err != nil || decoder.Decode(&policy) != nil || decoder.Decode(new(any)) != io.EOF || policy.Name != contracts.SmallOpenBaoBackendPolicyName || policy.Version < 0 || policy.AllowWildcards || policy.AllowSlashes || policy.Expiration != nil || policy.Modified != nil && policy.Modified.IsZero() {
		return nil, initialOpenBaoCheck("marker")
	}
	wanted, _ := kube.SmallOpenBaoBackendPolicy(source.backend)
	gotPolicy, wantPolicy := jsontext.Value(policy.Policy), jsontext.Value(wanted)
	if gotPolicy.Canonicalize() != nil || wantPolicy.Canonicalize() != nil || !bytes.Equal(gotPolicy, wantPolicy) || !initialOpenBaoCurrent(ctx) {
		return nil, initialOpenBaoCheck("marker")
	}
	p.Identity, err = kms.ObserveBundledInitialProviderIdentity(ctx, source.plan.Endpoint(), string(p.Token), source.plan, contracts.WorkerObjectReference{Name: ns.Name, UID: string(ns.UID)}, contracts.WorkerObjectReference{Name: sa.Name, UID: string(sa.UID)}, h, time.Now)
	if err != nil || !initialOpenBaoCurrent(ctx) {
		return nil, initialOpenBaoCheck("identity")
	}
	preparation, err := kube.NewSmallOpenBaoPreparation(config, source.plan)
	if err != nil {
		return nil, initialOpenBaoCheck("ready")
	}
	if _, err = preparation.MarkReady(ctx, contracts.WorkerObjectReference{Name: state.Name, UID: string(state.UID)}, source.backend); err != nil || !initialOpenBaoCurrent(ctx) {
		return nil, initialOpenBaoCheck("ready")
	}
	complete = true
	return p, nil
}

type initialOpenBaoReply struct {
	Auth *struct {
		ClientToken string `json:"client_token"`
	} `json:"auth"`
	Data     json.RawMessage `json:"data"`
	Warnings []string        `json:"warnings"`
	Wrap     json.RawMessage `json:"wrap_info"`
	Errors   []string        `json:"errors"`
}

func initialOpenBaoCall(ctx context.Context, h *http.Client, endpoint, token, method, path string, body []byte) (initialOpenBaoReply, error) {
	var zero initialOpenBaoReply
	if !initialOpenBaoCurrent(ctx) {
		return zero, mounts.ErrUnavailable
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint+"/v1/"+path, bytes.NewReader(body))
	if err != nil {
		return zero, mounts.ErrUnavailable
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("X-Vault-Token", token)
	}
	response, err := h.Do(req)
	if response != nil && response.Body != nil {
		defer response.Body.Close()
	}
	if err != nil || response == nil || response.StatusCode != http.StatusOK {
		return zero, mounts.ErrUnavailable
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, 32769))
	defer clear(raw)
	if err != nil || len(raw) > 32768 || !jsontext.Value(raw).IsValid() || json.Unmarshal(raw, &zero) != nil || len(zero.Warnings) != 0 || len(zero.Errors) != 0 || len(zero.Wrap) != 0 && string(zero.Wrap) != "null" || !initialOpenBaoCurrent(ctx) {
		return initialOpenBaoReply{}, mounts.ErrUnavailable
	}
	return zero, nil
}
