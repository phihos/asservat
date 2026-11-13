package providerconfig

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"asservat.local/asservat/internal/adapters/mtls"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/fleet"
	bao "github.com/openbao/openbao/api/v2"
	"k8s.io/apimachinery/pkg/util/validation"
)

// OpenBaoSetupInput is the Helm-native installation's OpenBao scope: chart
// values plus the generated IDs. Every name below derives from it.
type OpenBaoSetupInput struct {
	Name, Namespace           string            // installation.name and release namespace
	InstallationID, ClusterID string            // from the ids Secret
	IssuerEpoch               string            // from the ids Secret; binds the owner PKI roles
	Accounts                  map[string]string // component -> service account name: "hub-api", "hub-worker", "federation", "publisher"
}

// OpenBaoComponents are the hub components that authenticate to OpenBao.
var OpenBaoComponents = []string{"hub-api", "hub-worker", "federation", "publisher"}

// OpenBaoRoleName is the policy and Kubernetes auth role name of one
// component purpose: "<name>-<component>-<purpose>". It is "" when the
// result is not a valid provider name.
func OpenBaoRoleName(name, component, purpose string) string {
	out := name + "-" + component + "-" + purpose
	if name == "" || component == "" || purpose == "" || !providerName.MatchString(out) {
		return ""
	}
	return out
}

// OpenBaoNames are the fixed key and PKI role names of one installation on
// the bundled mounts (contracts.SmallOpenBao*Mount). Runtime components use
// the same names.
type OpenBaoNames struct {
	AuditKey, WorkerConfigurationAuditKey, DeletionSigningKey, FederationAuditKey, PublisherAuditKey string // on SmallOpenBaoAuditMount
	BrowserSessionKey, WorkSigningKey                                                                string // on SmallOpenBaoTransitMount
	OwnerServerRole, OwnerClientRole                                                                 string // on SmallOpenBaoOwnerPKIMount
	ConnectorClientRole, ConnectorServerRole                                                         string // on SmallOpenBaoConnectorPKIMount
	DownloadWorkerRole, VerifierRole                                                                 string // on SmallOpenBaoWorkerPKIMount
}

func OpenBaoNamesFor(installationID string) OpenBaoNames {
	p := "asservat-" + strings.ReplaceAll(installationID, "-", "")
	return OpenBaoNames{AuditKey: "audit", WorkerConfigurationAuditKey: contracts.WorkerConfigurationAuditKeyName(installationID),
		DeletionSigningKey: contracts.ContextDeletionSigningKeyName(installationID), FederationAuditKey: p + "-federation-audit",
		PublisherAuditKey: PublisherAuditKey(installationID), BrowserSessionKey: p + "-browser-sessions", WorkSigningKey: p + "-work-signing",
		OwnerServerRole: p + "-owner-server", OwnerClientRole: p + "-owner-client", ConnectorClientRole: p + "-connector-client",
		ConnectorServerRole: p + "-connector-server", DownloadWorkerRole: p + "-download-worker", VerifierRole: contracts.PublisherVerifierRole(installationID)}
}

// SetupOpenBaoLogin authenticates the setup Job with its projected service
// account token at the bundled setup auth mount.
func SetupOpenBaoLogin(ctx context.Context, endpoint string, rootsPEM, token []byte) (*bao.Client, error) {
	if ctx == nil || ctx.Err() != nil || !validEndpoint(endpoint) || len(token) < 1 || len(token) > 16<<10 {
		return nil, ErrSetupUnavailable
	}
	der, err := TrustRootsPEM(rootsPEM, time.Now())
	if err != nil {
		return nil, ErrSetupUnavailable
	}
	roots, _, err := mtls.OwnerTrustRoots(der, time.Now())
	if err != nil {
		return nil, ErrSetupUnavailable
	}
	client, err := newSetupClient(endpoint, roots)
	if err != nil {
		return nil, err
	}
	secret, err := client.Logical().WriteWithContext(ctx, "auth/"+contracts.SmallOpenBaoSetupMount+"/login", map[string]any{"role": contracts.SmallOpenBaoSetupRole, "jwt": strings.TrimSpace(string(token))})
	if err != nil || secret == nil || secret.Auth == nil || secret.Auth.ClientToken == "" {
		return nil, fmt.Errorf("%w: setup login refused", ErrSetupUnavailable)
	}
	client.SetToken(secret.Auth.ClientToken)
	return client, nil
}

func newSetupClient(endpoint string, roots *x509.CertPool) (*bao.Client, error) {
	config := bao.DefaultConfig()
	config.Address = endpoint
	config.MaxRetries = 0
	config.DisableRedirects = true
	config.Timeout = 30 * time.Second
	config.HttpClient = &http.Client{Timeout: 30 * time.Second,
		Transport: &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
			TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots}, TLSHandshakeTimeout: 5 * time.Second,
			ResponseHeaderTimeout: 30 * time.Second, MaxResponseHeaderBytes: 64 << 10, DisableCompression: true},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	client, err := bao.NewClient(config)
	if err != nil {
		return nil, ErrSetupUnavailable
	}
	client.ClearToken()
	client.SetNamespace("")
	return client, nil
}

// openBaoRole is one component purpose: its auth mount, audience and paths.
type openBaoRole struct {
	component, purpose, mount, audience string
	ttl, maxTTL                         int
	paths                               map[string][]string
}

type openBaoSetupPlan struct {
	transit, pki, kv, auth []string
	roots                  []string // PKI mounts
	keys                   []openBaoKey
	pkiRoles               []openBaoPKIRole
	roles                  []openBaoRole
}
type openBaoKey struct{ mount, name, kind string }
type openBaoPKIRole struct {
	mount, name string
	body        json.RawMessage
}

func validOpenBaoSetupInput(in OpenBaoSetupInput) bool {
	if len(validation.IsDNS1123Label(in.Name)) != 0 || len(in.Name) > 30 || len(validation.IsDNS1123Label(in.Namespace)) != 0 || !authorization.UUID(in.InstallationID) || !authorization.UUID(in.ClusterID) || !authorization.UUID(in.IssuerEpoch) {
		return false
	}
	for _, c := range OpenBaoComponents {
		if len(validation.IsDNS1123Subdomain(in.Accounts[c])) != 0 {
			return false
		}
	}
	return true
}

func openBaoSetupPlanFor(in OpenBaoSetupInput) (openBaoSetupPlan, error) {
	var p openBaoSetupPlan
	if !validOpenBaoSetupInput(in) {
		return p, ErrSetupUnavailable
	}
	n := OpenBaoNamesFor(in.InstallationID)
	audit, transit := contracts.SmallOpenBaoAuditMount, contracts.SmallOpenBaoTransitMount
	ownerPKI, connectorPKI, workerPKI := contracts.SmallOpenBaoOwnerPKIMount, contracts.SmallOpenBaoConnectorPKIMount, contracts.SmallOpenBaoWorkerPKIMount
	p.transit = []string{audit, transit}
	p.pki = []string{ownerPKI, connectorPKI, workerPKI}
	p.kv = []string{contracts.SmallOpenBaoBootstrapMount}
	p.auth = []string{contracts.SmallOpenBaoConfigurationAuthMount, contracts.SmallOpenBaoOwnerAuthMount}
	p.keys = []openBaoKey{{audit, n.AuditKey, "aes256-gcm96"}, {audit, n.WorkerConfigurationAuditKey, "aes256-gcm96"}, {audit, n.DeletionSigningKey, "ed25519"},
		{audit, n.FederationAuditKey, "aes256-gcm96"}, {audit, n.PublisherAuditKey, "aes256-gcm96"},
		{transit, n.BrowserSessionKey, "aes256-gcm96"}, {transit, n.WorkSigningKey, "ed25519"}}
	key := func(mount, name, op string) string { return mount + "/" + op + "/" + name }
	use := func(paths ...string) map[string][]string {
		out := map[string][]string{}
		for _, path := range paths {
			out[path] = []string{"update"}
		}
		return out
	}
	cfgMount, ownerMount := contracts.SmallOpenBaoConfigurationAuthMount, contracts.SmallOpenBaoOwnerAuthMount
	worker := func(purpose string, paths map[string][]string) openBaoRole {
		return openBaoRole{"hub-worker", purpose, cfgMount, contracts.ConfigurationProviderAudience(in.InstallationID, in.ClusterID), contracts.ConfigurationProviderTokenTTLSeconds, contracts.ConfigurationProviderTokenMaxTTLSeconds, paths}
	}
	owner := func(component, audience, purpose string, paths map[string][]string) openBaoRole {
		return openBaoRole{component, purpose, ownerMount, audience, contracts.OwnerProviderTokenTTLSeconds, contracts.OwnerProviderTokenMaxTTLSeconds, paths}
	}
	encrypt, decrypt, sign := key(audit, n.AuditKey, "encrypt"), key(audit, n.AuditKey, "decrypt"), key(audit, n.DeletionSigningKey, "sign")
	hub := contracts.OwnerProviderAudience(in.InstallationID, in.ClusterID)
	federation := contracts.FederationProviderAudience(in.InstallationID, in.ClusterID)
	publisher := contracts.PublisherProviderAudience(in.InstallationID, in.ClusterID)
	channel := map[string][]string{contracts.SmallOpenBaoBootstrapMount + "/data/" + contracts.OwnerFleetChannelPrefix + "/" + in.InstallationID + "/*": {"create", "read"}}
	p.roles = []openBaoRole{
		worker("audit-wrap", use(encrypt, key(audit, n.WorkerConfigurationAuditKey, "encrypt"), sign)),
		worker("audit-unwrap", use(decrypt, key(audit, n.WorkerConfigurationAuditKey, "decrypt"))),
		worker("cleanup-wrap", use(encrypt)), worker("cleanup-open", use(decrypt)), worker("cleanup-verify", use(decrypt)), worker("cleanup-sign", use(sign)),
		owner("hub-api", hub, "audit-wrap", use(encrypt)), owner("hub-api", hub, "audit-unwrap", use(decrypt)),
		owner("hub-api", hub, "server-sign", use(ownerPKI+"/sign/"+n.OwnerServerRole)), owner("hub-api", hub, "client-sign", use(ownerPKI+"/sign/"+n.OwnerClientRole)),
		owner("hub-api", hub, "browser-seal", use(key(transit, n.BrowserSessionKey, "encrypt"))), owner("hub-api", hub, "browser-open", use(key(transit, n.BrowserSessionKey, "decrypt"))),
		owner("hub-api", hub, "work-sign", use(key(transit, n.WorkSigningKey, "sign"))), owner("hub-api", hub, "worker-issue", use(workerPKI+"/sign/"+n.DownloadWorkerRole)),
		owner("hub-api", hub, OwnerFleetProviderPurpose, channel),
		owner("federation", federation, "audit-wrap", use(key(audit, n.FederationAuditKey, "encrypt"))), owner("federation", federation, "audit-unwrap", use(key(audit, n.FederationAuditKey, "decrypt"))),
		owner("federation", federation, "client-sign", use(connectorPKI+"/sign/"+n.ConnectorClientRole)), owner("federation", federation, "server-sign", use(connectorPKI+"/sign/"+n.ConnectorServerRole)),
		owner("publisher", publisher, "audit-wrap", use(key(audit, n.PublisherAuditKey, "encrypt"))), owner("publisher", publisher, "audit-unwrap", use(key(audit, n.PublisherAuditKey, "decrypt"))),
		owner("publisher", publisher, "verifier-sign", use(workerPKI+"/sign/"+n.VerifierRole)),
	}
	// PKI roles: the same bodies the runtime verifiers were written against.
	hubURI := "spiffe://asservat." + in.InstallationID + "/hub/" + in.ClusterID + "/issuer/" + in.IssuerEpoch + "/pod/*/process/*"
	hubServer := []string{"p-*.e-*.hub." + in.ClusterID + ".asservat." + in.InstallationID, "s-*.e-" + in.IssuerEpoch + ".hub-bootstrap." + in.ClusterID + ".asservat." + in.InstallationID}
	ownerTTL := int64((fleet.OwnerCertificatePeriod + fleet.OwnerCertificateRenewBefore) / time.Second)
	connectorTTL := int64((fleet.ConnectorCertificatePeriod + fleet.ConnectorCertificateRenewBefore) / time.Second)
	connectorURI := "spiffe://asservat." + in.InstallationID + "/cluster/*/epoch/*/connector/*"
	connectorServer := []string{"*." + contracts.ConnectorServerSuffix(in.InstallationID)}
	for _, r := range []struct {
		mount, name string
		server      bool
		domains     []string
		uri         string
		ttl         int64
	}{{ownerPKI, n.OwnerServerRole, true, hubServer, hubURI, ownerTTL}, {ownerPKI, n.OwnerClientRole, false, nil, hubURI, ownerTTL},
		{connectorPKI, n.ConnectorClientRole, false, nil, connectorURI, connectorTTL}, {connectorPKI, n.ConnectorServerRole, true, connectorServer, connectorURI, connectorTTL}} {
		body, err := setupPKIRole(r.server, r.domains, r.uri, r.ttl)
		if err != nil {
			return p, err
		}
		p.pkiRoles = append(p.pkiRoles, openBaoPKIRole{r.mount, r.name, body})
	}
	downloads, err := ownerWorkerPKIRole(in.InstallationID)
	if err != nil {
		return p, err
	}
	verifier, err := publisherVerifierPKIRole(in.InstallationID)
	if err != nil {
		return p, err
	}
	p.pkiRoles = append(p.pkiRoles, openBaoPKIRole{workerPKI, n.DownloadWorkerRole, downloads}, openBaoPKIRole{workerPKI, n.VerifierRole, verifier})
	return p, nil
}

func setupPKIRole(server bool, domains []string, uri string, ttl int64) (json.RawMessage, error) {
	if domains == nil {
		domains = []string{}
	}
	return ownerProviderCanonical(map[string]any{
		"issuer_ref": "default", "require_cn": false, "use_csr_common_name": false, "use_csr_sans": false,
		"allow_any_name": false, "allow_ip_sans": false, "allow_localhost": false, "allow_subdomains": false,
		"allow_glob_domains": server, "allow_bare_domains": server, "allow_wildcard_certificates": false,
		"enforce_hostnames": true, "allowed_domains": domains, "allowed_domains_template": false,
		"allowed_uri_sans": []string{uri}, "allowed_uri_sans_template": false, "allowed_other_sans": []string{},
		"allowed_user_ids": []string{}, "allowed_serial_numbers": []string{},
		"key_type": "ec", "key_bits": 256, "server_flag": server, "client_flag": !server,
		"code_signing_flag": false, "email_protection_flag": false, "key_usage": []string{"DigitalSignature"},
		"ext_key_usage": []string{}, "ext_key_usage_oids": []string{}, "policy_identifiers": []string{},
		"organization": []string{}, "ou": []string{}, "country": []string{}, "locality": []string{},
		"province": []string{}, "street_address": []string{}, "postal_code": []string{},
		"basic_constraints_valid_for_non_ca": true, "not_before_duration": 30, "ttl": ttl, "max_ttl": ttl,
		"generate_lease": false, "no_store": false, "not_after": "",
		"not_before": "", "not_before_bound": "forbid", "not_after_bound": "ttl-limited",
		"allow_globs_in_identity_templates": false, "allow_token_displayname": false, "allowed_ip_sans_cidr": []string{},
		"signature_bits": 0, "use_pss": false, "cn_validations": []string{"email", "hostname"},
	})
}

// SetupOpenBaoMounts lists the mounts, by type, that setup ensures (and that
// an external provider's operator creates).
func SetupOpenBaoMounts() map[string][]string {
	return map[string][]string{"transit": {contracts.SmallOpenBaoAuditMount, contracts.SmallOpenBaoTransitMount},
		"pki":   {contracts.SmallOpenBaoOwnerPKIMount, contracts.SmallOpenBaoConnectorPKIMount, contracts.SmallOpenBaoWorkerPKIMount},
		"kv-v2": {contracts.SmallOpenBaoBootstrapMount}, "kubernetes": {contracts.SmallOpenBaoConfigurationAuthMount, contracts.SmallOpenBaoOwnerAuthMount}}
}

// EnsureOpenBaoSetup idempotently ensures the mounts, the Kubernetes auth
// configuration, transit keys (created if missing, never replaced), PKI
// roots (generated only when a mount has no issuer), PKI roles and the
// component policies and auth roles (written on every run).
func EnsureOpenBaoSetup(ctx context.Context, client *bao.Client, in OpenBaoSetupInput, out io.Writer) error {
	if ctx == nil || client == nil || out == nil {
		return ErrSetupUnavailable
	}
	plan, err := openBaoSetupPlanFor(in)
	if err != nil {
		return err
	}
	l := client.Logical()
	report := func(state, path string) { _, _ = fmt.Fprintf(out, "%s: %s\n", state, path) }
	failed := func(path string, e error) error { return fmt.Errorf("%w: %s: %v", ErrSetupUnavailable, path, e) }
	exists := func(path string) (bool, error) {
		s, e := l.ReadWithContext(ctx, path)
		var re *bao.ResponseError
		if errors.As(e, &re) && re.StatusCode == http.StatusNotFound {
			return false, nil
		}
		if e != nil {
			return false, failed(path, e)
		}
		return s != nil, nil
	}
	ensure := func(check, write string, body map[string]any) error {
		ok, e := exists(check)
		if e != nil || ok {
			if ok {
				report("unchanged", write)
			}
			return e
		}
		if _, e = l.WriteWithContext(ctx, write, body); e != nil {
			return failed(write, e)
		}
		report("created", write)
		return nil
	}
	upsert := func(path string, body map[string]any) error {
		ok, e := exists(path)
		if e != nil {
			return e
		}
		if _, e = l.WriteWithContext(ctx, path, body); e != nil {
			return failed(path, e)
		}
		report(map[bool]string{true: "updated", false: "created"}[ok], path)
		return nil
	}
	// A missing mount is not a 404 on its own path, so compare the listings.
	mounted := func(list string) (map[string]bool, error) {
		s, e := l.ReadWithContext(ctx, list)
		if e != nil || s == nil {
			return nil, failed(list, e)
		}
		out := map[string]bool{}
		for k := range s.Data {
			out[strings.TrimSuffix(k, "/")] = true
		}
		return out, nil
	}
	mount := func(present map[string]bool, path, m string, body map[string]any) error {
		if present[m] {
			report("unchanged", path+m)
			return nil
		}
		if _, e := l.WriteWithContext(ctx, path+m, body); e != nil {
			return failed(path+m, e)
		}
		report("created", path+m)
		return nil
	}
	engines, err := mounted("sys/mounts")
	if err != nil {
		return err
	}
	for _, m := range plan.transit {
		if err = mount(engines, "sys/mounts/", m, map[string]any{"type": "transit"}); err != nil {
			return err
		}
	}
	for _, m := range plan.kv {
		if err = mount(engines, "sys/mounts/", m, map[string]any{"type": "kv", "options": map[string]any{"version": "2"}}); err != nil {
			return err
		}
	}
	methods, err := mounted("sys/auth")
	if err != nil {
		return err
	}
	for _, m := range plan.pki {
		if err = mount(engines, "sys/mounts/", m, map[string]any{"type": "pki", "config": map[string]any{"max_lease_ttl": "87600h"}}); err != nil {
			return err
		}
		issuers, e := l.ListWithContext(ctx, m+"/issuers")
		if e != nil {
			return failed(m+"/issuers", e)
		}
		if issuers == nil || len(issuers.Data) == 0 {
			if _, e = l.WriteWithContext(ctx, m+"/root/generate/internal", map[string]any{"common_name": in.Name + " " + m, "ttl": "87600h", "key_type": "ec", "key_bits": 256}); e != nil {
				return failed(m+"/root/generate/internal", e)
			}
			report("created", m+"/root/generate/internal")
		} else {
			report("unchanged", m+"/issuers")
		}
	}
	for _, m := range plan.auth {
		if err = mount(methods, "sys/auth/", m, map[string]any{"type": "kubernetes"}); err != nil {
			return err
		}
		// In-cluster OpenBao reviews tokens with its own service account and CA.
		if err = upsert("auth/"+m+"/config", map[string]any{"kubernetes_host": "https://kubernetes.default.svc", "disable_local_ca_jwt": false, "disable_iss_validation": true}); err != nil {
			return err
		}
	}
	for _, k := range plan.keys {
		if err = ensure(k.mount+"/keys/"+k.name, k.mount+"/keys/"+k.name, map[string]any{"type": k.kind, "derived": false, "exportable": false, "allow_plaintext_backup": false}); err != nil {
			return err
		}
	}
	for _, r := range plan.pkiRoles {
		var body map[string]any
		if err = json.Unmarshal(r.body, &body); err != nil {
			return ErrSetupUnavailable
		}
		if err = upsert(r.mount+"/roles/"+r.name, body); err != nil {
			return err
		}
	}
	for _, r := range plan.roles {
		name := OpenBaoRoleName(in.Name, r.component, r.purpose)
		if name == "" {
			return ErrSetupUnavailable
		}
		acl := ownerProviderACL{Path: map[string]ownerProviderACLRule{
			"auth/token/lookup-self": {Capabilities: []string{"read"}},
			"auth/token/renew-self":  {Capabilities: []string{"update"}},
			"auth/token/revoke-self": {Capabilities: []string{"update"}},
		}}
		for path, capabilities := range r.paths {
			acl.Path[path] = ownerProviderACLRule{Capabilities: capabilities}
		}
		policy, e := ownerProviderCanonical(acl)
		if e != nil {
			return e
		}
		path := "sys/policies/acl/" + name
		current, e := l.ReadWithContext(ctx, path)
		var re *bao.ResponseError
		if e != nil && !(errors.As(e, &re) && re.StatusCode == http.StatusNotFound) {
			return failed(path, e)
		}
		if current != nil && current.Data["policy"] == string(policy) {
			report("unchanged", path)
		} else {
			if _, e = l.WriteWithContext(ctx, path, map[string]any{"policy": string(policy)}); e != nil {
				return failed(path, e)
			}
			report(map[bool]string{true: "updated", false: "created"}[current != nil], path)
		}
		role := OwnerKubernetesAuthRole{Accounts: []string{in.Accounts[r.component]}, Namespaces: []string{in.Namespace}, Audience: r.audience,
			AliasSource: "serviceaccount_uid", TTL: r.ttl, MaxTTL: r.maxTTL, ExplicitMaxTTL: r.maxTTL, Policies: []string{name}, NoDefault: true, Type: "service", BoundCIDRs: []string{}}
		raw, e := json.Marshal(role)
		if e != nil {
			return ErrSetupUnavailable
		}
		var body map[string]any
		if e = json.Unmarshal(raw, &body); e != nil {
			return ErrSetupUnavailable
		}
		if err = upsert("auth/"+r.mount+"/role/"+name, body); err != nil {
			return err
		}
	}
	if ctx.Err() != nil {
		return ErrSetupUnavailable
	}
	return nil
}
