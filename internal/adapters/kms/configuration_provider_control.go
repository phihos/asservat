package kms

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/url"
	"time"
)

// Reuse the fixed login/self-control wire and lease accounting with the
// Helm-rendered auth role. No owner deployment or PKI role is involved.
func newConfigurationProviderControl(in ConfigurationProviderInput, role string, client *http.Client, now func() time.Time) (*ownerProviderControl, error) {
	if now == nil || client == nil || client.Jar != nil || !keyName.MatchString(role) || !keyName.MatchString(in.AuthMount) || in.Namespace == "" || in.ServiceAccount == "" {
		return nil, ErrKeyService
	}
	u, err := url.Parse(in.Endpoint)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Path != "" && u.Path != "/" {
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
	for _, der := range in.Roots {
		certificate, e := x509.ParseCertificate(der)
		if e != nil {
			return nil, ErrKeyService
		}
		roots.AddCert(certificate)
	}
	if len(in.Roots) == 0 {
		return nil, ErrKeyService
	}
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}
	u.Path = ""
	h := *client
	h.Transport = transport
	h.Timeout = 5 * time.Second
	h.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	// The service account UID is not pinned (Helm-native installation): the
	// provider role binds the account by name and namespace.
	return &ownerProviderControl{http: &h, endpoint: u.String(), mount: in.AuthMount, role: role, namespace: in.Namespace, account: in.ServiceAccount, now: now}, nil
}
