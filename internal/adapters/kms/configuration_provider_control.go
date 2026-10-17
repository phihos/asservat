package kms

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/url"
	"time"

	"asservat.local/asservat/internal/adapters/providerconfig"
	"asservat.local/asservat/internal/contracts"
)

// Reuse the fixed login/self-control wire and lease accounting, while deriving
// only a worker recipe. No fabricated owner deployment or PKI role is involved.
func newConfigurationProviderControl(in contracts.HubWorkerDeployment, profile contracts.ConfigurationProviderAuthentication, purpose string, client *http.Client, now func() time.Time) (*ownerProviderControl, error) {
	if now == nil || client == nil || client.Jar != nil || (purpose != "audit-wrap" && purpose != "audit-unwrap") ||
		contracts.ConfigurationProviderTokenTTLSeconds != contracts.OwnerProviderTokenTTLSeconds || contracts.ConfigurationProviderTokenMaxTTLSeconds != contracts.OwnerProviderTokenMaxTTLSeconds ||
		providerconfig.ValidateConfigurationProviderAuthentication(in, profile, now()) != nil {
		return nil, ErrKeyService
	}
	recipe, err := providerconfig.ConfigurationProviderRecipeFor(in, contracts.ConfigurationProviderSelection{AuthMount: profile.AuthMount, AuthMountAccessor: profile.AuthMountAccessor, AuditCredentials: profile.AuditCredentials}, profile.ServiceAccount, now())
	if err != nil {
		return nil, ErrKeyService
	}
	var name string
	for _, role := range recipe.Roles {
		if role.Purpose == purpose {
			name = role.Name
		}
	}
	u, err := url.Parse(in.KeyService.Endpoint)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Path != "" && u.Path != "/" || name == "" {
		return nil, ErrKeyService
	}
	base := client.Transport
	if base == nil {
		base = http.DefaultTransport
	}
	transport, ok := base.(*http.Transport)
	if !ok || transport.TLSClientConfig != nil && transport.TLSClientConfig.InsecureSkipVerify {
		return nil, ErrKeyService
	}
	transport = transport.Clone()
	transport.DialTLS = nil
	transport.DialTLSContext = nil
	transport.TLSNextProto = nil
	transport.Proxy = nil
	roots := x509.NewCertPool()
	for _, der := range in.KeyService.Roots {
		certificate, e := x509.ParseCertificate(der)
		if e != nil {
			return nil, ErrKeyService
		}
		roots.AddCert(certificate)
	}
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}
	u.Path = ""
	h := *client
	h.Transport = transport
	h.Timeout = 5 * time.Second
	h.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &ownerProviderControl{http: &h, endpoint: u.String(), mount: profile.AuthMount, role: name, namespace: in.Namespace.Name, account: profile.ServiceAccount.Name, accountUID: profile.ServiceAccount.UID, now: now}, nil
}
