package kms

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"asservat.local/asservat/internal/adapters/mounts"
	"asservat.local/asservat/internal/adapters/mtls"
	"asservat.local/asservat/internal/adapters/providerconfig"
	"asservat.local/asservat/internal/contracts"
	value "asservat.local/asservat/internal/domain/authorization"
	bao "github.com/openbao/openbao/api/v2"
)

// publisherProviderBorrows bounds concurrent effects per purpose; the
// publisher works one capture at a time.
const publisherProviderBorrows = 4

// InstalledPublisherProviderEffects owns the publisher's three provider
// lifetimes (ADR-203): Kubernetes-auth logins with the projected publisher
// token for audit wrap/unwrap and verifier leaf signing. Each login and
// renewal runs only under the composition's current proof; effects borrow a
// token and never trigger a login.
type InstalledPublisherProviderEffects struct {
	input              contracts.PublisherDeployment
	files              *os.Root
	wrap, unwrap, sign *ownerProviderLifetime
	seal               *Sealer
	open               *Opener
	verifier           *VerifierCertificateSigner
	root               context.Context
	cancel             context.CancelFunc
	mu                 sync.Mutex
	started, closed    bool
	joined             sync.WaitGroup
	closeWait          sync.Once
	closeDone          chan struct{}
}

// NewInstalledPublisherProviderEffects composes the three lifetimes. proof is
// the publisher's current native proof (hub workload guard and recovery); its
// returned time bounds every login, renewal and borrowed effect.
func NewInstalledPublisherProviderEffects(ctx context.Context, input contracts.PublisherDeployment, files *os.Root, proof func(context.Context) (time.Time, error)) (*InstalledPublisherProviderEffects, error) {
	if ctx == nil || ctx.Err() != nil || files == nil || proof == nil || providerconfig.ValidatePublisherProviderAuthentication(input, input.ProviderAuthentication, time.Now()) != nil {
		return nil, ErrKeyService
	}
	raw, err := json.Marshal(input)
	var cloned contracts.PublisherDeployment
	if err != nil || json.Unmarshal(raw, &cloned) != nil {
		return nil, ErrKeyService
	}
	root, cancel := context.WithCancel(ctx)
	s := &InstalledPublisherProviderEffects{input: cloned, files: files, root: root, cancel: cancel, closeDone: make(chan struct{})}
	complete := false
	defer func() {
		if !complete {
			_ = s.Close(context.Background())
		}
	}()
	recipe, err := providerconfig.PublisherProviderRecipeFor(cloned, cloned.ProviderAuthentication)
	if err != nil || recipe.Profile != cloned.ProviderAuthentication {
		return nil, ErrKeyService
	}
	// The recipe requires one provider for the audit key and the verifier
	// PKI, which also holds the shared auth mount.
	provider := contracts.OwnerProviderEndpoint{Endpoint: cloned.AuditKeys.Endpoint, Roots: cloned.AuditKeys.Roots}
	p := cloned.ProviderAuthentication
	base := &http.Client{Transport: &http.Transport{}, Timeout: 5 * time.Second}
	targets := [3]**ownerProviderLifetime{&s.wrap, &s.unwrap, &s.sign}
	for i, role := range recipe.Roles {
		control, err := newKubernetesProviderControl(provider, p.AuthMount, role.Name, p.Namespace.Name, p.ServiceAccount, base, time.Now)
		if err != nil {
			return nil, err
		}
		slot, err := newOwnerProviderLifetime(root, control, s.projectedJWT, ownerProviderCurrent(proof), publisherProviderBorrows)
		if err != nil {
			control.close()
			return nil, err
		}
		*targets[i] = slot
	}
	a, v := cloned.AuditKeys, cloned.Verifier
	wrap, err := newOwnerProviderEffectClient(s.wrap, a.Mount+"/encrypt/"+a.Key)
	if err != nil {
		return nil, err
	}
	s.seal = &Sealer{client: wrap, mount: a.Mount, key: a.Key, reference: a.Mount + "/" + a.Key}
	unwrap, err := newOwnerProviderEffectClient(s.unwrap, a.Mount+"/decrypt/"+a.Key)
	if err != nil {
		return nil, err
	}
	s.open = &Opener{client: unwrap, mount: a.Mount, key: a.Key, reference: a.Mount + "/" + a.Key}
	sign, err := newOwnerProviderEffectClient(s.sign, v.PKIMount+"/sign/"+v.Role)
	if err != nil {
		return nil, err
	}
	s.verifier = &VerifierCertificateSigner{client: sign, path: v.PKIMount + "/sign/" + v.Role, installation: cloned.InstallationID}
	complete = true
	return s, nil
}

func (s *InstalledPublisherProviderEffects) Sealer() *Sealer { return s.seal }
func (s *InstalledPublisherProviderEffects) Opener() *Opener { return s.open }

// VerifierSigner signs verifier CSRs over the borrowed verifier-sign effect.
func (s *InstalledPublisherProviderEffects) VerifierSigner() *VerifierCertificateSigner {
	return s.verifier
}

func (s *InstalledPublisherProviderEffects) projectedJWT(ctx context.Context) ([]byte, error) {
	b, err := mounts.Read(ctx, s.files, contracts.PublisherProviderTokenFile, 16<<10)
	if err != nil || !contracts.ValidWorkerToken(b) {
		clear(b)
		return nil, ErrKeyService
	}
	return b, nil
}

func (s *InstalledPublisherProviderEffects) slots() []*ownerProviderLifetime {
	return []*ownerProviderLifetime{s.wrap, s.unwrap, s.sign}
}

// Prime funds every purpose before work starts. A failed attempt waits for
// the slot's own backoff inside the caller's bound, as the federation's does.
func (s *InstalledPublisherProviderEffects) Prime(ctx context.Context) error {
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
func (s *InstalledPublisherProviderEffects) Run(ctx context.Context) error {
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
func (s *InstalledPublisherProviderEffects) Close(ctx context.Context) error {
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
	if s.verifier != nil && s.verifier.client != nil {
		s.verifier.client.CloneConfig().HttpClient.CloseIdleConnections()
	}
	select {
	case <-s.closeDone:
		return nil
	case <-call.Done():
		return ErrKeyService
	}
}

func (s *InstalledPublisherProviderEffects) CloseAndJoin(ctx context.Context) error {
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

// VerifierCertificateSigner posts one identity-free verifier CSR to the
// verifier-sign path for exactly one key-client/verifier URI of this
// installation (ADR-203). It decodes only the reply's shape; the in-process
// credential checks the chain against its pinned issuer roots.
type VerifierCertificateSigner struct {
	client             *bao.Client
	path, installation string
}

var _ mtls.VerifierSigner = (*VerifierCertificateSigner)(nil)

func (s *VerifierCertificateSigner) SignVerifierCertificate(ctx context.Context, csr []byte, uri string) ([]byte, [][]byte, error) {
	if s == nil || s.client == nil || ctx == nil || ctx.Err() != nil {
		return nil, nil, ErrKeyService
	}
	u, err := url.Parse(uri)
	peer, found := strings.CutPrefix(uri, "spiffe://asservat."+s.installation+"/key-client/verifier/")
	if err != nil || !found || !value.UUID(peer) || mtls.VerifierCertificateURI(s.installation, peer) != uri || u.String() != uri {
		return nil, nil, ErrKeyService
	}
	if _, err = mtls.EnrollmentKey(csr); err != nil {
		return nil, nil, ErrKeyService
	}
	r := s.client.NewRequest(http.MethodPost, "/v1/"+s.path)
	if r.SetJSONBody(map[string]any{"csr": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr})), "uri_sans": []string{uri}, "exclude_cn_from_sans": true, "format": "pem"}) != nil {
		return nil, nil, ErrKeyService
	}
	response, err := s.client.RawRequestWithContext(ctx, r)
	if response != nil && response.Body != nil {
		defer response.Body.Close()
	}
	if err != nil || response == nil || response.StatusCode != http.StatusOK {
		return nil, nil, ErrKeyService
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 32769))
	defer clear(body)
	if err != nil || len(body) > 32768 {
		return nil, nil, ErrKeyService
	}
	var wire struct {
		Data struct {
			Certificate string   `json:"certificate"`
			Chain       []string `json:"ca_chain"`
			Private     string   `json:"private_key"`
		}
	}
	if json.Unmarshal(body, &wire) != nil || wire.Data.Private != "" || len(wire.Data.Chain) > 3 {
		return nil, nil, ErrKeyService
	}
	decode := func(s string) ([]byte, error) {
		b, rest := pem.Decode([]byte(s))
		if b == nil || b.Type != "CERTIFICATE" || len(b.Headers) != 0 || len(rest) != 0 || len(b.Bytes) > 16<<10 {
			return nil, ErrKeyService
		}
		return b.Bytes, nil
	}
	der, err := decode(wire.Data.Certificate)
	if err != nil {
		return nil, nil, err
	}
	var chain [][]byte
	for _, s := range wire.Data.Chain {
		d, e := decode(s)
		if e != nil {
			return nil, nil, e
		}
		chain = append(chain, d)
	}
	if ctx.Err() != nil {
		return nil, nil, ErrKeyService
	}
	return der, chain, nil
}
