package kms

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
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
)

// InstalledFederationProviderEffects owns the federation's four provider
// lifetimes (ADR-193): Kubernetes-auth logins with the projected federation
// token for audit wrap/unwrap and connector client/server signing. Each login
// and renewal runs only under the composition's current proof; crypto effects
// borrow a token and never trigger a login.
type InstalledFederationProviderEffects struct {
	input                        contracts.FederationDeployment
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
// the federation's current native proof (hub workload guard and recovery);
// its returned time bounds every login, renewal and borrowed effect.
func NewInstalledFederationProviderEffects(ctx context.Context, input contracts.FederationDeployment, files *os.Root, proof func(context.Context) (time.Time, error)) (*InstalledFederationProviderEffects, error) {
	if ctx == nil || ctx.Err() != nil || files == nil || proof == nil || input.ProviderAuthentication == nil ||
		providerconfig.ValidateFederationProviderAuthentication(input, *input.ProviderAuthentication, time.Now()) != nil {
		return nil, ErrKeyService
	}
	raw, err := json.Marshal(input)
	var cloned contracts.FederationDeployment
	if err != nil || json.Unmarshal(raw, &cloned) != nil {
		return nil, ErrKeyService
	}
	root, cancel := context.WithCancel(ctx)
	s := &InstalledFederationProviderEffects{input: cloned, files: files, root: root, cancel: cancel, closeDone: make(chan struct{})}
	complete := false
	defer func() {
		if !complete {
			_ = s.Close(context.Background())
		}
	}()
	base := &http.Client{Transport: &http.Transport{}, Timeout: 5 * time.Second}
	k := cloned.KeyService
	for _, fixed := range []struct {
		purpose string
		target  **ownerProviderLifetime
	}{{"audit-wrap", &s.wrap}, {"audit-unwrap", &s.unwrap}, {"client-sign", &s.client}, {"server-sign", &s.server}} {
		control, err := newFederationProviderControl(cloned, *cloned.ProviderAuthentication, fixed.purpose, base, time.Now)
		if err != nil {
			return nil, err
		}
		slot, err := newOwnerProviderLifetime(root, control, s.projectedJWT, ownerProviderCurrent(proof), cloned.Concurrency)
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
	client, role := s.clientPKI, s.input.KeyService.ClientRole
	if usage == "server" {
		client, role = s.serverPKI, s.input.KeyService.ServerRole
	}
	if s == nil || client == nil || (usage != "client" && usage != "server") || !profile.Valid() || profile.Suspended {
		return nil, value.ErrInvalid
	}
	return newConnectorCredentialIssuerWithClient(client, s.input.KeyService.PKIMount, role, usage, profile, time.Now)
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

// newFederationProviderControl reuses the fixed login/self-control wire with
// a role name derived only from the federation recipe.
func newFederationProviderControl(in contracts.FederationDeployment, profile contracts.FederationProviderAuthentication, purpose string, client *http.Client, now func() time.Time) (*ownerProviderControl, error) {
	if now == nil || client == nil || client.Jar != nil {
		return nil, ErrKeyService
	}
	recipe, err := providerconfig.FederationProviderRecipeFor(in, profile)
	if err != nil || recipe.Profile != profile {
		return nil, ErrKeyService
	}
	var name string
	for _, role := range recipe.Roles {
		if role.Purpose == purpose {
			name = role.Name
		}
	}
	return newKubernetesProviderControl(contracts.OwnerProviderEndpoint{Endpoint: in.KeyService.Endpoint, Roots: in.KeyService.Roots}, profile.AuthMount, name, profile.Namespace.Name, profile.ServiceAccount, client, now)
}

// newKubernetesProviderControl is the fixed login/self-control transport for
// one recipe-derived role: pinned provider roots only, no proxy, custom TLS
// hook, cookie jar or redirect.
// ponytail: the owner and configuration controls keep their own copies of
// this transport tail; fold them in here when one of them changes.
func newKubernetesProviderControl(provider contracts.OwnerProviderEndpoint, mount, name, namespace string, account contracts.WorkerObjectReference, client *http.Client, now func() time.Time) (*ownerProviderControl, error) {
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
	return &ownerProviderControl{http: &h, endpoint: u.String(), mount: mount, role: name, namespace: namespace, account: account.Name, accountUID: account.UID, now: now}, nil
}
