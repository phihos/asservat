package kms

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/url"
	"time"

	"asservat.local/asservat/internal/contracts"
	"k8s.io/apimachinery/pkg/util/validation"
)

// ProviderLogin selects one component's OpenBao Kubernetes-auth roles by name
// (Helm-native: chart constants shared with setup). The account binds by name;
// the projected token file carries the role's audience.
type ProviderLogin struct {
	Provider       contracts.OwnerProviderEndpoint
	AuthMount      string
	Namespace      string
	ServiceAccount string
	// Roles maps each fixed purpose to its role (and policy) name.
	Roles map[string]string
}

func (l ProviderLogin) valid(purposes ...string) bool {
	if !keyName.MatchString(l.AuthMount) || l.AuthMount == "token" || len(validation.IsDNS1123Label(l.Namespace)) != 0 || len(validation.IsDNS1123Subdomain(l.ServiceAccount)) != 0 || len(l.Roles) != len(purposes) {
		return false
	}
	seen := map[string]bool{}
	for _, p := range purposes {
		name := l.Roles[p]
		if !keyName.MatchString(name) || seen[name] {
			return false
		}
		seen[name] = true
	}
	return true
}

// newKubernetesProviderControl is the fixed login/self-control transport for
// one named role: pinned provider roots only, no proxy, custom TLS hook,
// cookie jar or redirect. The account binds by name.
// ponytail: the owner and configuration controls keep their own copies of
// this transport tail; fold them in here when one of them changes.
func newKubernetesProviderControl(provider contracts.OwnerProviderEndpoint, mount, name, namespace, account string, client *http.Client, now func() time.Time) (*ownerProviderControl, error) {
	if now == nil || client == nil || client.Jar != nil {
		return nil, ErrKeyService
	}
	u, err := url.Parse(provider.Endpoint)
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
	for _, der := range provider.Roots {
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
	return &ownerProviderControl{http: &h, endpoint: u.String(), mount: mount, role: name, namespace: namespace, account: account, now: now}, nil
}
