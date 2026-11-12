//go:build asservat_testfixture

// The bounded synthetic provider probe has no SQL, evidence, production permit,
// or cluster administration credentials. Its setup JWT belongs only to this
// owned disposable cluster's exact finite setup ServiceAccount.
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"asservat.local/asservat/internal/adapters/kms"
	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/adapters/providerconfig"
	"asservat.local/asservat/internal/contracts"
	bao "github.com/openbao/openbao/api/v2"
)

type input struct {
	Plan          contracts.SmallOpenBaoPlan `json:"plan"`
	ProviderCA    []byte                     `json:"providerCA"`
	NamespaceUID  string                     `json:"namespaceUID"`
	WorkerUID     string                     `json:"workerUID"`
	CredentialUID string                     `json:"credentialUID"`
	SetupUID      string                     `json:"setupUID"`
}

func emit(value any) { _ = json.NewEncoder(os.Stdout).Encode(value) }

func readClosed(r io.Reader, value any) error {
	d := json.NewDecoder(io.LimitReader(r, 192<<10))
	d.DisallowUnknownFields()
	if err := d.Decode(value); err != nil {
		return err
	}
	if d.Decode(new(any)) != io.EOF {
		return errors.New("trailing input")
	}
	return nil
}

func httpClient(roots [][]byte) *http.Client {
	pool := x509.NewCertPool()
	for _, der := range roots {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			panic("invalid fixture CA")
		}
		pool.AddCert(cert)
	}
	return &http.Client{Transport: &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: pool}, MaxConnsPerHost: 1, DisableKeepAlives: true}, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func client(endpoint string, h *http.Client, token string) (*bao.Client, error) {
	c, err := bao.NewClient(&bao.Config{Address: endpoint, HttpClient: h, MaxRetries: 0, DisableEnvironment: true, DisableRedirects: true})
	if err == nil {
		c.SetToken(token)
	}
	return c, err
}

func copyClient(c *bao.Client, token string) *bao.Client {
	copy, err := c.Clone()
	if err != nil {
		panic("fixture client clone")
	}
	copy.SetToken(token)
	return copy
}

func status(err error) int {
	var response *bao.ResponseError
	if errors.As(err, &response) {
		return response.StatusCode
	}
	return 0
}

func tokenLookup(ctx context.Context, c *bao.Client) (map[string]any, error) {
	r, err := c.Auth().Token().LookupSelfWithContext(ctx)
	if err != nil {
		return nil, err
	}
	if r == nil {
		return nil, errors.New("missing token")
	}
	return r.Data, nil
}

func number(data map[string]any, key string) int64 {
	switch v := data[key].(type) {
	case json.Number:
		n, _ := v.Int64()
		return n
	case float64:
		return int64(v)
	case int:
		return int64(v)
	}
	return 0
}

func expiry(data map[string]any) time.Time {
	s, _ := data["expire_time"].(string)
	t, _ := time.Parse(time.RFC3339Nano, s)
	return t
}

func safeTokenFacts(data map[string]any) map[string]any {
	entity, _ := data["entity_id"].(string)
	return map[string]any{"entityPresent": entity != "", "orphan": data["orphan"], "renewable": data["renewable"], "creationTTL": number(data, "creation_ttl"), "explicitMaxTTL": number(data, "explicit_max_ttl"), "remainingSeconds": number(data, "ttl"), "identityPolicyCount": func() int {
		if x, ok := data["identity_policies"].([]any); ok {
			return len(x)
		}
		return 0
	}()}
}

func write(ctx context.Context, c *bao.Client, path string, value any) error {
	raw, err := json.Marshal(value)
	if err != nil {
		return err
	}
	_, err = c.Logical().WriteBytesWithContext(ctx, path, raw)
	return err
}

func login(ctx context.Context, c *bao.Client, role, jwt string) (*bao.Secret, error) {
	return c.Logical().WriteWithContext(ctx, "auth/"+contracts.SmallOpenBaoSetupMount+"/login", map[string]any{"role": role, "jwt": jwt})
}

func run(in input) (result map[string]any, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), 110*time.Second)
	defer cancel()
	stage := "inputs"
	result = map[string]any{"scope": "synthetic same-API provider compatibility; no installed or SQL authority"}
	defer func() {
		if err != nil {
			result["failedStage"] = stage
			result["httpStatus"] = status(err)
			result["errorClass"] = fmt.Sprintf("%T", err)
		}
	}()
	step := func(s string) { stage = s; emit(map[string]any{"stage": s}) }
	if !in.Plan.Valid() {
		return result, errors.New("invalid plan")
	}
	b, _ := pem.Decode(in.ProviderCA)
	if b == nil {
		return result, errors.New("missing provider CA")
	}
	roots := [][]byte{b.Bytes}
	h := httpClient(roots)
	defer h.CloseIdleConnections()
	c, e := client(in.Plan.Endpoint(), h, "")
	if e != nil {
		return result, e
	}
	jwt, e := os.ReadFile("/run/probe/setup.token")
	if e != nil {
		return result, e
	}
	defer clear(jwt)
	wrong, e := os.ReadFile("/run/probe/wrong.token")
	if e != nil {
		return result, e
	}
	defer clear(wrong)
	step("wrong-audience-refusal")
	_, e = login(ctx, c, contracts.SmallOpenBaoSetupRole, string(wrong))
	result["wrongAudienceObservedHTTP"] = status(e)
	if status(e) != 403 && status(e) != 400 {
		return result, errors.New("wrong audience not refused")
	}
	result["wrongAudienceRefused"] = true
	step("actual-kubernetes-setup-login")
	auth, e := login(ctx, c, contracts.SmallOpenBaoSetupRole, string(jwt))
	if e != nil {
		return result, e
	}
	if auth == nil || auth.Auth == nil || auth.Auth.ClientToken == "" {
		return result, errors.New("missing login")
	}
	if len(auth.Auth.TokenPolicies) != 1 || auth.Auth.TokenPolicies[0] != contracts.SmallOpenBaoSetupPolicy || len(auth.Auth.IdentityPolicies) != 0 || auth.Auth.Metadata["service_account_uid"] != in.SetupUID {
		return result, errors.New("actual setup login binding mismatch")
	}
	c.SetToken(auth.Auth.ClientToken)
	parent, e := tokenLookup(ctx, c)
	if e != nil {
		return result, e
	}
	result["setupToken"] = safeTokenFacts(parent)
	step("independent-original-setup-identity")
	serviceIdentity, e := kms.ObserveBundledInitialProviderIdentity(ctx, in.Plan.Endpoint(), auth.Auth.ClientToken, in.Plan,
		contracts.WorkerObjectReference{Name: in.Plan.Namespace, UID: in.NamespaceUID},
		contracts.WorkerObjectReference{Name: in.Plan.SetupAccount, UID: in.SetupUID}, h, time.Now)
	if e != nil {
		return result, e
	}
	if !serviceIdentity.SetupParent.ExpiresAt.Equal(expiry(parent)) || serviceIdentity.EntityID != auth.Auth.EntityID {
		return result, errors.New("independent original identity mismatch")
	}
	result["setupIdentityIndependentlyVerified"] = true
	step("original-final-marker")
	marker, e := c.Logical().ReadWithContext(ctx, contracts.SmallOpenBaoBackendPolicyPath)
	if e != nil || marker == nil {
		return result, errors.New("marker read")
	}
	result["setupMarkerReadable"] = true
	step("configuration-prerequisites")
	const mount = contracts.SmallOpenBaoConfigurationAuthMount
	const audit = contracts.SmallOpenBaoAuditMount
	step("configuration-auth-mount-create")
	if e = write(ctx, c, "sys/auth/"+mount, map[string]any{"type": "kubernetes"}); e != nil {
		return result, e
	}
	var apiCA bytes.Buffer
	for _, der := range in.Plan.Kubernetes.Roots {
		_ = pem.Encode(&apiCA, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	}
	step("configuration-local-api-config")
	if e = write(ctx, c, "auth/"+mount+"/config", map[string]any{"kubernetes_host": in.Plan.Kubernetes.Endpoint, "kubernetes_ca_cert": apiCA.String(), "disable_local_ca_jwt": false, "disable_iss_validation": true}); e != nil {
		return result, e
	}
	step("configuration-auth-mount-read")
	authMount, e := c.Logical().ReadWithContext(ctx, "sys/mounts/auth/"+mount)
	if e != nil || authMount == nil {
		return result, errors.New("auth mount read")
	}
	accessor, _ := authMount.Data["accessor"].(string)
	step("configuration-transit-mount-create")
	if e = write(ctx, c, "sys/mounts/"+audit, map[string]any{"type": "transit"}); e != nil {
		return result, e
	}
	step("configuration-transit-key-create")
	if e = write(ctx, c, audit+"/keys/configuration", map[string]any{"type": "aes256-gcm96", "exportable": false, "allow_plaintext_backup": false}); e != nil {
		return result, e
	}
	const installation = "10000000-0000-4000-8000-000000000001"
	const cluster = "10000000-0000-4000-8000-000000000002"
	prefix := "asservat-" + strings.ReplaceAll(installation, "-", "")
	account := contracts.WorkerObjectReference{Name: prefix + "-worker", UID: in.WorkerUID}
	scope := contracts.HubWorkerDeployment{Format: contracts.HubWorkerDeploymentFormat, InstallationID: installation, ClusterID: cluster,
		Namespace:   contracts.WorkerObjectReference{Name: in.Plan.Namespace, UID: in.NamespaceUID},
		FleetSource: contracts.WorkerObjectReference{Name: "fleet", UID: "10000000-0000-4000-8000-000000000004"}, OwnerSource: contracts.WorkerObjectReference{Name: prefix + "-owner-source", UID: "10000000-0000-4000-8000-000000000005"},
		Kubernetes: in.Plan.Kubernetes, Postgres: contracts.OwnerPostgresEndpoint{Host: "unused-fixture.invalid", Port: 5432, Database: "fixture", MaxConnections: 1, Roots: roots}, AuditStore: contracts.OwnerAuditStore{Endpoint: "https://unused-fixture.invalid", Region: "fixture", Bucket: "fixture", Roots: roots},
		KeyService: contracts.ConfigurationKeyService{Endpoint: in.Plan.Endpoint(), Roots: roots, AuditMount: audit, AuditKey: "configuration"}}
	selection := contracts.ConfigurationProviderSelection{AuthMount: mount, AuthMountAccessor: accessor, AuditCredentials: contracts.WorkerObjectReference{Name: prefix + "-worker-providers", UID: in.CredentialUID}}
	recipe, e := providerconfig.ConfigurationProviderRecipeFor(scope, selection, account, time.Now())
	if e != nil {
		return result, e
	}
	artifact, e := providerconfig.ConfigurationProviderSetupArtifact(scope, selection, account, time.Now())
	if e != nil {
		return result, e
	}
	step("actual-bundled-inspection-issuance")
	inspection, e := providerconfig.ApplyBundledSetupArtifact(ctx, c, prefix+"-configuration-inspection", artifact, io.Discard)
	if e != nil {
		return result, e
	}
	defer clear(inspection)
	step("inspection-self-lookup-refusal")
	_, e = tokenLookup(ctx, copyClient(c, string(inspection)))
	if status(e) != http.StatusForbidden {
		return result, errors.New("inspection self lookup was not refused")
	}
	result["inspectionSelfLookupRefused"] = true
	step("actual-bundled-configuration-reader")
	reader, e := providerconfig.NewBundledSetupReader(contracts.OwnerProviderEndpoint{Endpoint: in.Plan.Endpoint(), Roots: roots}, inspection, in.Plan)
	if e != nil {
		return result, e
	}
	defer reader.Close(ctx)
	check, e := reader.VerifyConfiguration(ctx, scope, recipe.Profile)
	if e != nil {
		// Fixed bounded named reads on failure only; disclose field names/status,
		// never provider data, policy bodies, tokens or native identity values.
		diagnostic := []string{"sys/mounts/auth/" + mount, "auth/" + mount + "/config", "sys/mounts/" + audit, audit + "/keys/configuration"}
		for _, role := range recipe.Roles {
			diagnostic = append(diagnostic, "sys/policies/acl/"+role.Name, "auth/"+mount+"/role/"+role.Name)
		}
		for i, path := range diagnostic {
			response, failure := copyClient(c, string(inspection)).Logical().ReadWithContext(ctx, path)
			keys := []string{}
			if response != nil {
				for k := range response.Data {
					keys = append(keys, k)
				}
			}
			sort.Strings(keys)
			emit(map[string]any{"diagnosticRead": i, "status": status(failure), "present": response != nil, "fields": keys})
		}
		return result, e
	}
	if !check.Matches(scope, recipe.Profile, time.Now()) {
		return result, errors.New("reader mismatch")
	}
	result["configurationReaderVerified"] = true
	step("initial-issuer-prerequisites")
	profile := contracts.InitialProviderProfile{Format: contracts.InitialProviderProfileFormat, Material: contracts.WorkerObjectReference{Name: "fixture-material", UID: "10000000-0000-4000-8000-000000000007"}, IssuerPolicy: "asservat-initial-issuer", WrapRole: "asservat-initial-wrap", WrapPolicy: "asservat-initial-encrypt", UnwrapRole: "asservat-initial-unwrap", UnwrapPolicy: "asservat-initial-decrypt"}
	policies, e := kms.InitialProviderPolicies(profile, audit, "initial-audit")
	if e != nil {
		return result, e
	}
	for name, policy := range policies {
		if e = write(ctx, c, "sys/policies/acl/"+name, map[string]any{"policy": policy}); e != nil {
			return result, e
		}
	}
	role := func(policy string) map[string]any {
		return map[string]any{"allowed_policies": []string{policy}, "orphan": false, "renewable": false, "token_no_default_policy": true, "token_type": "service", "token_explicit_max_ttl": 900, "token_num_uses": 0}
	}
	for name, policy := range map[string]string{profile.WrapRole: profile.WrapPolicy, profile.UnwrapRole: profile.UnwrapPolicy, "asservat-initial-issuer-issue": profile.IssuerPolicy} {
		if e = write(ctx, c, "auth/token/roles/"+name, role(policy)); e != nil {
			return result, e
		}
	}
	if e = write(ctx, c, audit+"/keys/initial-audit", map[string]any{"type": "aes256-gcm96"}); e != nil {
		return result, e
	}
	create := func(owner *bao.Client, name, policy string) (*bao.Secret, error) {
		no := false
		return owner.Auth().Token().CreateWithRoleWithContext(ctx, &bao.TokenCreateRequest{Policies: []string{policy}, NoDefaultPolicy: true, Renewable: &no, TTL: "900s", ExplicitMaxTTL: "900s", Type: "service"}, name)
	}
	step("actual-bounded-initial-issuer")
	originalCutoff := serviceIdentity.SetupParent.ExpiresAt.Add(-kms.BundledInitialProviderSafetyMargin)
	issueUntil := time.Now().Add(5 * time.Second)
	seconds := int64(originalCutoff.Sub(issueUntil)/time.Second) - 1
	if seconds < 1 || seconds > 900 {
		return result, errors.New("original setup interval exhausted")
	}
	noRenewal := false
	issueCtx, issueDone := context.WithDeadline(ctx, issueUntil)
	issuerSecret, e := c.Auth().Token().CreateWithRoleWithContext(issueCtx, &bao.TokenCreateRequest{Policies: []string{profile.IssuerPolicy}, NoDefaultPolicy: true, Renewable: &noRenewal, TTL: fmt.Sprintf("%ds", seconds), ExplicitMaxTTL: fmt.Sprintf("%ds", seconds), Type: "service"}, "asservat-initial-issuer-issue")
	issueDone()
	if e != nil {
		return result, e
	}
	if issuerSecret == nil || issuerSecret.Auth == nil || !time.Now().Before(issueUntil) {
		return result, errors.New("late or missing original issuer")
	}
	issuerClient := copyClient(c, issuerSecret.Auth.ClientToken)
	issuerLookup, e := tokenLookup(ctx, issuerClient)
	if e != nil {
		return result, e
	}
	result["initialIssuerToken"] = safeTokenFacts(issuerLookup)
	result["issuerExpiryBeforeSetupMillis"] = expiry(parent).Sub(expiry(issuerLookup)).Milliseconds()
	if expiry(issuerLookup).After(originalCutoff) {
		return result, errors.New("issuer exceeded original setup cutoff")
	}
	defaultIssuer, e := kms.NewInitialProviderIssuer(in.Plan.Endpoint(), issuerSecret.Auth.ClientToken, audit, "initial-audit", installation, "10000000-0000-4000-8000-000000000009", profile, h, time.Now)
	if e != nil {
		return result, e
	}
	_, _, defaultErr := defaultIssuer.Check(ctx, originalCutoff)
	defaultIssuer.Close()
	if defaultErr == nil {
		return result, errors.New("external profile accepted inherited entity")
	}
	result["defaultInitialIssuerRefusedEntity"] = true
	issuer, e := kms.NewBundledInitialProviderIssuer(in.Plan.Endpoint(), issuerSecret.Auth.ClientToken, audit, "initial-audit", installation, "10000000-0000-4000-8000-000000000009", profile, serviceIdentity, h, time.Now)
	if e != nil {
		return result, e
	}
	defer issuer.Close()
	step("actual-adapter-check-issue-verify-revoke")
	issuerParent, _, e := issuer.Check(ctx, originalCutoff)
	if e != nil {
		result["adapterRefusalStage"] = kms.InitialProviderCheckStage(e)
		return result, e
	}
	for i, purpose := range []string{"wrap", "unwrap"} {
		at := time.Now().UTC().Truncate(time.Microsecond)
		claim := contracts.InitialProviderIssue{ID: fmt.Sprintf("10000000-0000-4000-8000-%012d", 20+i), StartedAt: at, Until: at.Add(5 * time.Second), ExpiresBefore: issuerParent.ExpiresAt}
		step("adapter-" + purpose + "-issue")
		response, e := issuer.Issue(ctx, purpose, claim, issuerParent)
		if e != nil {
			return result, e
		}
		step("adapter-" + purpose + "-verify")
		if e = issuer.Verify(ctx, purpose, claim, issuerParent, response); e != nil {
			return result, e
		}
		claim.Response = &response
		step("adapter-" + purpose + "-revoke")
		if _, e = issuer.Revoke(ctx, purpose, claim, issuerParent, response); e != nil {
			return result, e
		}
		step("adapter-" + purpose + "-revoke-replay")
		if _, e = issuer.Revoke(ctx, purpose, claim, issuerParent, response); e != nil {
			return result, e
		}
	}
	result["actualAdapterCheckIssueVerifyRevoke"] = true
	step("actual-child-and-parent-revocation")
	child, e := create(issuerClient, profile.WrapRole, profile.WrapPolicy)
	if e != nil {
		return result, e
	}
	if child == nil || child.Auth == nil {
		return result, errors.New("missing child")
	}
	childClient := copyClient(c, child.Auth.ClientToken)
	childLookup, e := tokenLookup(ctx, childClient)
	if e != nil {
		return result, e
	}
	result["wrapChildToken"] = safeTokenFacts(childLookup)
	result["wrapExpiryAfterSetupMillis"] = expiry(childLookup).Sub(expiry(parent)).Milliseconds()
	step("actual-short-parent-expiry")
	shortRole := map[string]any{"bound_service_account_names": []string{in.Plan.SetupAccount}, "bound_service_account_namespaces": []string{in.Plan.Namespace}, "alias_name_source": "serviceaccount_uid", "audience": in.Plan.SetupAudience(), "token_policies": []string{contracts.SmallOpenBaoSetupPolicy}, "token_no_default_policy": true, "token_ttl": 3, "token_max_ttl": 3, "token_explicit_max_ttl": 3, "token_type": "service"}
	if e = write(ctx, c, "auth/"+contracts.SmallOpenBaoSetupMount+"/role/asservat-short-parent", shortRole); e != nil {
		return result, e
	}
	shortLogin, e := login(ctx, c, "asservat-short-parent", string(jwt))
	if e != nil {
		return result, e
	}
	if shortLogin == nil || shortLogin.Auth == nil {
		return result, errors.New("short login absent")
	}
	shortClient := copyClient(c, shortLogin.Auth.ClientToken)
	shortLookup, e := tokenLookup(ctx, shortClient)
	if e != nil {
		return result, e
	}
	shortChild, e := create(shortClient, "asservat-initial-issuer-issue", profile.IssuerPolicy)
	if e != nil {
		return result, e
	}
	if shortChild == nil || shortChild.Auth == nil {
		return result, errors.New("short child absent")
	}
	shortChildClient := copyClient(c, shortChild.Auth.ClientToken)
	shortChildLookup, e := tokenLookup(ctx, shortChildClient)
	if e != nil {
		return result, e
	}
	result["shortParentToken"] = safeTokenFacts(shortLookup)
	result["shortChildToken"] = safeTokenFacts(shortChildLookup)
	result["shortChildExpiryAfterParentMillis"] = expiry(shortChildLookup).Sub(expiry(shortLookup)).Milliseconds()
	originalExpiry := expiry(shortLookup)
	if originalExpiry.IsZero() || originalExpiry.After(time.Now().Add(4*time.Second)) {
		return result, errors.New("short original expiry invalid")
	}
	deadline := originalExpiry.Add(8 * time.Second)
	for {
		_, e = tokenLookup(ctx, shortChildClient)
		if status(e) == 403 {
			break
		}
		if e != nil || !time.Now().Before(deadline) {
			return result, errors.New("short child survived original parent expiry")
		}
		select {
		case <-ctx.Done():
			return result, ctx.Err()
		case <-time.After(200 * time.Millisecond):
		}
	}
	result["actualParentExpiryDeniesChild"] = true
	step("original-parent-revocation")
	if e = c.Auth().Token().RevokeSelfWithContext(ctx, ""); e != nil {
		return result, e
	}
	if _, e = tokenLookup(ctx, issuerClient); status(e) != 403 {
		return result, errors.New("issuer survived parent revocation")
	}
	if _, e = tokenLookup(ctx, childClient); status(e) != 403 {
		return result, errors.New("child survived parent revocation")
	}
	result["parentRevocationDeniesIssuerAndChild"] = true
	result["measurementComplete"] = true

	return result, nil
}

func main() {
	if len(os.Args) == 2 && os.Args[1] == "command" {
		emit(contracts.SmallOpenBaoServerCommand())
		return
	}
	if len(os.Args) == 2 && os.Args[1] == "material" {
		p, e := contracts.DecodeSmallOpenBaoPlan(os.Stdin)
		if e != nil || !p.Valid() {
			os.Exit(2)
		}
		m, e := kube.BuildSmallOpenBaoMaterial(p, time.Now().UTC())
		if e != nil {
			os.Exit(2)
		}
		if json.NewEncoder(os.Stdout).Encode(m) != nil {
			os.Exit(2)
		}
		return
	}
	f, e := os.Open("/run/probe/input.json")
	if e != nil {
		emit(map[string]any{"failedStage": "input-open"})
		os.Exit(2)
	}
	var in input
	e = readClosed(f, &in)
	f.Close()
	if e != nil {
		emit(map[string]any{"failedStage": "input-decode"})
		os.Exit(2)
	}
	r, e := run(in)
	emit(r)
	if e != nil {
		os.Exit(1)
	}
	if r["compatibilityBlocked"] == true {
		os.Exit(3)
	}
}
