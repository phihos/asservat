package kms

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/url"
	"os"
	"sync"
	"time"

	"asservat.local/asservat/internal/adapters/mounts"
	"asservat.local/asservat/internal/adapters/providerconfig"
	"asservat.local/asservat/internal/contracts"
	value "asservat.local/asservat/internal/domain/fleet"
	bao "github.com/openbao/openbao/api/v2"
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

// FederationProviderKeys are the federation's audit Transit key and connector
// PKI roles on the login's provider.
type FederationProviderKeys struct {
	AuditMount, AuditKey, PKIMount, ClientRole, ServerRole string
}

// InstalledFederationProviderEffects owns the federation's four provider
// lifetimes (ADR-193): Kubernetes-auth logins with the projected federation
// token for audit wrap/unwrap and connector client/server signing. Each login
// and renewal runs only under the composition's current proof; crypto effects
// borrow a token and never trigger a login.
type InstalledFederationProviderEffects struct {
	keys                         FederationProviderKeys
	files                        *os.Root
	wrap, unwrap, client, server *ownerProviderLifetime
	seal                         *Sealer
	open                         *Opener
	clientPKI, serverPKI         *bao.Client
	root                         context.Context
	cancel                       context.CancelFunc
	mu                           sync.Mutex
	started, closed              bool
	joined                       sync.WaitGroup
	closeWait                    sync.Once
	closeDone                    chan struct{}
}

// NewInstalledFederationProviderEffects composes the four lifetimes. proof is
// the federation's current recovery observation; its returned time bounds
// every login, renewal and borrowed effect.
func NewInstalledFederationProviderEffects(ctx context.Context, login ProviderLogin, k FederationProviderKeys, concurrency int, files *os.Root, proof func(context.Context) (time.Time, error)) (*InstalledFederationProviderEffects, error) {
	if ctx == nil || ctx.Err() != nil || files == nil || proof == nil || !login.valid(providerconfig.FederationProviderPurposes[:]...) || concurrency < 1 ||
		!keyName.MatchString(k.AuditMount) || !keyName.MatchString(k.AuditKey) || !keyName.MatchString(k.PKIMount) || !keyName.MatchString(k.ClientRole) || !keyName.MatchString(k.ServerRole) || k.ClientRole == k.ServerRole {
		return nil, ErrKeyService
	}
	root, cancel := context.WithCancel(ctx)
	s := &InstalledFederationProviderEffects{keys: k, files: files, root: root, cancel: cancel, closeDone: make(chan struct{})}
	complete := false
	defer func() {
		if !complete {
			_ = s.Close(context.Background())
		}
	}()
	base := &http.Client{Transport: &http.Transport{}, Timeout: 5 * time.Second}
	for _, fixed := range []struct {
		purpose string
		target  **ownerProviderLifetime
	}{{"audit-wrap", &s.wrap}, {"audit-unwrap", &s.unwrap}, {"client-sign", &s.client}, {"server-sign", &s.server}} {
		control, err := newKubernetesProviderControl(login.Provider, login.AuthMount, login.Roles[fixed.purpose], login.Namespace, login.ServiceAccount, base, time.Now)
		if err != nil {
			return nil, err
		}
		slot, err := newOwnerProviderLifetime(root, control, s.projectedJWT, ownerProviderCurrent(proof), concurrency)
		if err != nil {
			control.close()
			return nil, err
		}
		*fixed.target = slot
	}
	wrap, err := newOwnerProviderEffectClient(s.wrap, k.AuditMount+"/encrypt/"+k.AuditKey)
	if err != nil {
		return nil, err
	}
	s.seal = &Sealer{client: wrap, mount: k.AuditMount, key: k.AuditKey, reference: k.AuditMount + "/" + k.AuditKey}
	unwrap, err := newOwnerProviderEffectClient(s.unwrap, k.AuditMount+"/decrypt/"+k.AuditKey)
	if err != nil {
		return nil, err
	}
	s.open = &Opener{client: unwrap, mount: k.AuditMount, key: k.AuditKey, reference: k.AuditMount + "/" + k.AuditKey}
	if s.clientPKI, err = newOwnerProviderEffectClient(s.client, k.PKIMount+"/sign/"+k.ClientRole); err != nil {
		return nil, err
	}
	if s.serverPKI, err = newOwnerProviderEffectClient(s.server, k.PKIMount+"/sign/"+k.ServerRole); err != nil {
		return nil, err
	}
	complete = true
	return s, nil
}

func (s *InstalledFederationProviderEffects) Sealer() *Sealer { return s.seal }
func (s *InstalledFederationProviderEffects) Opener() *Opener { return s.open }

// ConnectorIssuer returns one peer's connector leaf issuer over the shared
// borrowed signing effect of its usage.
func (s *InstalledFederationProviderEffects) ConnectorIssuer(usage string, profile value.ConnectorCredentialProfile) (*ConnectorCredentialIssuer, error) {
	client, role := s.clientPKI, s.keys.ClientRole
	if usage == "server" {
		client, role = s.serverPKI, s.keys.ServerRole
	}
	if s == nil || client == nil || (usage != "client" && usage != "server") || !profile.Valid() || profile.Suspended {
		return nil, value.ErrInvalid
	}
	return newConnectorCredentialIssuerWithClient(client, s.keys.PKIMount, role, usage, profile, time.Now)
}

func (s *InstalledFederationProviderEffects) projectedJWT(ctx context.Context) ([]byte, error) {
	b, err := mounts.Read(ctx, s.files, contracts.FederationProviderTokenFile, 16<<10)
	if err != nil || !contracts.ValidWorkerToken(b) {
		clear(b)
		return nil, ErrKeyService
	}
	return b, nil
}

func (s *InstalledFederationProviderEffects) slots() []*ownerProviderLifetime {
	return []*ownerProviderLifetime{s.wrap, s.unwrap, s.client, s.server}
}

// Prime funds every purpose before serving. A failed attempt waits for the
// slot's own backoff inside the caller's bound, as the owner's Prime does.
func (s *InstalledFederationProviderEffects) Prime(ctx context.Context) error {
	if s == nil || ctx == nil || ctx.Err() != nil || s.root.Err() != nil {
		return ErrKeyService
	}
	call, end := context.WithTimeout(ctx, 30*time.Second)
	defer end()
	for _, slot := range s.slots() {
		for slot.refresh(call) != nil {
			retry, now := slot.retryAt()
			if !retry.After(now) || !waitUntil(call, retry) {
				return ErrKeyService
			}
		}
	}
	return nil
}

// Run refreshes each purpose once a second until ctx or Close ends it.
func (s *InstalledFederationProviderEffects) Run(ctx context.Context) error {
	if s == nil || ctx == nil {
		return ErrKeyService
	}
	s.mu.Lock()
	if s.started || s.closed || s.root.Err() != nil {
		s.mu.Unlock()
		return ErrKeyService
	}
	s.started = true
	s.joined.Add(1)
	s.mu.Unlock()
	defer s.joined.Done()
	call, end := context.WithCancel(ctx)
	defer end()
	stop := context.AfterFunc(s.root, end)
	defer stop()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-call.Done():
			return ErrKeyService
		case <-ticker.C:
		}
		for _, slot := range s.slots() {
			if call.Err() != nil {
				return ErrKeyService
			}
			_ = slot.refresh(call)
		}
	}
}

// Close cancels every purpose, revokes within ten seconds and keeps ownership
// on failure; CloseAndJoin then joins without another provider request.
func (s *InstalledFederationProviderEffects) Close(ctx context.Context) error {
	if s == nil || ctx == nil {
		return ErrKeyService
	}
	s.mu.Lock()
	s.closed = true
	s.cancel()
	s.mu.Unlock()
	call, end := context.WithTimeout(ctx, 10*time.Second)
	defer end()
	s.closeWait.Do(func() { go func() { s.joined.Wait(); close(s.closeDone) }() })
	var result error
	for _, slot := range s.slots() {
		if slot != nil {
			if err := slot.close(call); err != nil {
				result = ErrKeyService
			}
		}
	}
	if result != nil {
		return result
	}
	if s.seal != nil {
		s.seal.Close()
	}
	if s.open != nil {
		s.open.Close()
	}
	select {
	case <-s.closeDone:
		return nil
	case <-call.Done():
		return ErrKeyService
	}
}

func (s *InstalledFederationProviderEffects) CloseAndJoin(ctx context.Context) error {
	if s == nil || ctx == nil {
		return ErrKeyService
	}
	result := s.Close(ctx)
	<-s.closeDone
	for _, slot := range s.slots() {
		if slot != nil {
			slot.joinClosed()
		}
	}
	return result
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
