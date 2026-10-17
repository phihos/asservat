package kms

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"asservat.local/asservat/internal/adapters/mtls"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/fleet"
	bao "github.com/openbao/openbao/api/v2"
)

// This private composition has no runtime selector. Its eventual installed
// constructor must supply the concrete original native/source/recovery proof.
// All four adapters and lifetime owners derive from this same validated recipe;
// an unrelated already-authenticated slot cannot be inserted by a caller.
type ownerProviderEffects struct {
	lifetimes      *ownerProviderLifetimes
	seal           *Sealer
	open           *Opener
	server, client *OwnerCertificateIssuer
	// ADR-182 public purposes; nil without a pinned public recipe.
	browserSeal *Sealer
	browserOpen *Opener
	work        *SigningKey
	worker      *WorkerCertificateIssuer
	// channel is the ADR-193 bootstrap credential channel; nil without Fleet.
	channel *BootstrapChannel
}

func newOwnerProviderEffects(ctx context.Context, input contracts.OwnerDeployment, profile contracts.OwnerProviderAuthentication, pool value.OwnerPool, issuerRoots *x509.CertPool, jwt TokenSource, proof ownerProviderCurrent, client *http.Client, concurrency int, now func() time.Time) (*ownerProviderEffects, error) {
	if now == nil || !pool.Valid() || pool.InstallationID != input.InstallationID || pool.ClusterID != input.ClusterID || pool.Namespace != input.Namespace.Name || pool.NamespaceUID != input.Namespace.UID || pool.ServiceAccount != profile.ServiceAccount.Name || pool.AccountUID != profile.ServiceAccount.UID {
		return nil, ErrKeyService
	}
	verifier, err := mtls.NewOwnerPeerVerifierForPool(issuerRoots, pool, now)
	if err != nil {
		return nil, err
	}
	slots, err := newOwnerProviderLifetimes(ctx, input, profile, jwt, proof, client, concurrency, now)
	if err != nil {
		return nil, err
	}
	out := &ownerProviderEffects{lifetimes: slots}
	complete := false
	defer func() {
		if !complete {
			_ = out.close(context.Background())
		}
	}()
	wrap, err := newOwnerProviderEffectClient(slots.auditWrap, input.KeyService.AuditMount+"/encrypt/"+input.KeyService.AuditKey)
	if err != nil {
		return nil, err
	}
	out.seal = &Sealer{client: wrap, mount: input.KeyService.AuditMount, key: input.KeyService.AuditKey, reference: input.KeyService.AuditMount + "/" + input.KeyService.AuditKey}
	unwrap, err := newOwnerProviderEffectClient(slots.auditUnwrap, input.KeyService.AuditMount+"/decrypt/"+input.KeyService.AuditKey)
	if err != nil {
		return nil, err
	}
	out.open = &Opener{client: unwrap, mount: input.KeyService.AuditMount, key: input.KeyService.AuditKey, reference: input.KeyService.AuditMount + "/" + input.KeyService.AuditKey}
	for _, fixed := range []struct {
		slot        *ownerProviderLifetime
		usage, role string
		target      **OwnerCertificateIssuer
	}{
		{slots.serverSign, "server", input.KeyService.ServerRole, &out.server},
		{slots.clientSign, "client", input.KeyService.ClientRole, &out.client},
	} {
		path := input.KeyService.PKIMount + "/sign/" + fixed.role
		c, e := newOwnerProviderEffectClient(fixed.slot, path)
		if e != nil {
			return nil, e
		}
		issuer := &OwnerCertificateIssuer{client: c, path: path, installation: pool.InstallationID, cluster: pool.ClusterID, epoch: pool.IssuerEpoch, usage: fixed.usage, verify: verifier, now: now}
		if pool.NativeBootstrap != "" {
			issuer.pool = pool
		}
		*fixed.target = issuer
	}
	if p := input.Public; p != nil && slots.public[0] != nil {
		if err = out.public(p, pool); err != nil {
			return nil, err
		}
	}
	if f := input.Public; f != nil && f.Fleet != nil && slots.fleet != nil {
		c, e := newOwnerProviderChannelClient(slots.fleet, f.Fleet.ChannelMount+"/data/"+contracts.OwnerFleetChannelPrefix+"/"+input.InstallationID+"/")
		if e != nil {
			return nil, e
		}
		if out.channel, e = newBootstrapChannelWithClient(c, f.Fleet.ChannelMount, contracts.OwnerFleetChannelPrefix, f.Fleet.DeliveryProfile, input.InstallationID, now); e != nil {
			return nil, e
		}
	}
	if ctx.Err() != nil {
		return nil, ErrKeyService
	}
	complete = true
	return out, nil
}

// public composes the four ADR-182 public purposes over their own
// provider-authenticated compartments, each confined to its one path.
func (out *ownerProviderEffects) public(p *contracts.OwnerPublicDeployment, pool value.OwnerPool) error {
	slots := out.lifetimes.public
	seal, err := newOwnerProviderEffectClient(slots[0], p.SessionTransit.Mount+"/encrypt/"+p.SessionTransit.Key)
	if err != nil {
		return err
	}
	out.browserSeal = &Sealer{client: seal, mount: p.SessionTransit.Mount, key: p.SessionTransit.Key, reference: p.SessionTransit.Mount + "/" + p.SessionTransit.Key}
	open, err := newOwnerProviderEffectClient(slots[1], p.SessionTransit.Mount+"/decrypt/"+p.SessionTransit.Key)
	if err != nil {
		return err
	}
	out.browserOpen = &Opener{client: open, mount: p.SessionTransit.Mount, key: p.SessionTransit.Key, reference: p.SessionTransit.Mount + "/" + p.SessionTransit.Key}
	w := p.WorkSigning
	if !keyName.MatchString(w.Mount) || !keyName.MatchString(w.Name) || w.Version < 1 || w.Version > 2147483647 || len(w.PublicKey) != ed25519.PublicKeySize {
		return ErrKeyService
	}
	sign, err := newOwnerProviderEffectClient(slots[2], w.Mount+"/sign/"+w.Name)
	if err != nil {
		return err
	}
	out.work = &SigningKey{client: sign, mount: w.Mount, name: w.Name, version: w.Version, public: bytes.Clone(w.PublicKey)}
	k := p.WorkerPKI
	roots, _, err := mtls.OwnerTrustRoots(k.Roots, time.Now())
	if err != nil || !keyName.MatchString(k.Mount) || !keyName.MatchString(k.Role) || !authorization.UUID(k.IssuerEpoch) {
		return ErrKeyService
	}
	verify, err := mtls.NewKeyPeerVerifier(roots, pool.InstallationID, time.Now)
	if err != nil {
		return err
	}
	issue, err := newOwnerProviderEffectClient(slots[3], k.Mount+"/sign/"+k.Role)
	if err != nil {
		return err
	}
	out.worker = &WorkerCertificateIssuer{issue, k.Mount + "/sign/" + k.Role, pool.InstallationID, k.IssuerEpoch, verify, time.Now}
	return nil
}

func (s *ownerProviderEffects) close(ctx context.Context) error {
	if s == nil || s.lifetimes == nil {
		return ErrKeyService
	}
	if err := s.lifetimes.close(ctx); err != nil {
		return err
	}
	// The actual calls/bodies joined before their idle transports are released.
	// A prior timeout retains these clients and may be joined by a later close.
	s.seal.Close()
	s.open.Close()
	s.server.Close()
	s.client.Close()
	return nil
}

func newOwnerProviderEffectClient(slot *ownerProviderLifetime, path string) (*bao.Client, error) {
	return newOwnerProviderClient(slot, path, false)
}

// newOwnerProviderChannelClient confines a borrowed lifetime to GET and POST
// of single records directly below prefix: one UUID segment, no listing,
// metadata or deeper path (the ADR-193 bootstrap credential channel).
func newOwnerProviderChannelClient(slot *ownerProviderLifetime, prefix string) (*bao.Client, error) {
	return newOwnerProviderClient(slot, prefix, true)
}

func newOwnerProviderClient(slot *ownerProviderLifetime, path string, records bool) (*bao.Client, error) {
	if slot == nil || slot.control == nil || slot.control.http == nil {
		return nil, ErrKeyService
	}
	control := slot.control
	endpoint, err := url.Parse(control.endpoint)
	if err != nil {
		return nil, ErrKeyService
	}
	base, ok := control.http.Transport.(*http.Transport)
	if !ok {
		return nil, ErrKeyService
	}
	// The control constructor already discarded ambient proxies and custom TLS
	// hooks and pinned the original profile's exact provider roots. Clone that
	// transport, never the unvalidated caller's client or another purpose's token.
	transport := base.Clone()
	leased := &ownerProviderLeaseTransport{base: transport, source: slot.borrow, now: control.now}
	httpClient := &http.Client{Timeout: 10 * time.Second, Transport: &ownerProviderEffectTransport{next: leased, endpoint: *endpoint, path: "/v1/" + path, records: records}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	config := bao.NewConfig()
	config.Address, config.Timeout, config.MaxRetries = control.endpoint, 10*time.Second, 0
	config.HttpClient = httpClient
	c, err := bao.NewClient(config)
	if err != nil {
		transport.CloseIdleConnections()
		return nil, ErrKeyService
	}
	c.SetToken("")
	c.SetCheckRedirect(func(*http.Request, []*http.Request) error { return errors.New("KMS redirects disabled") })
	return c, nil
}

// The maintained Bao codecs are used unchanged, but each private client can
// disclose its leased credential to only its fixed original effect endpoint.
type ownerProviderEffectTransport struct {
	next     *ownerProviderLeaseTransport
	endpoint url.URL
	path     string
	// records admits GET or POST of path + one UUID instead of POST to path.
	records bool
}

func (t *ownerProviderEffectTransport) CloseIdleConnections() {
	if t != nil && t.next != nil {
		t.next.CloseIdleConnections()
	}
}
func (t *ownerProviderEffectTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if t == nil || t.next == nil || r == nil || r.URL == nil || r.URL.Scheme != t.endpoint.Scheme || r.URL.Host != t.endpoint.Host || r.URL.User != nil || r.URL.RawQuery != "" || r.URL.ForceQuery || r.URL.Fragment != "" || r.Host != "" && r.Host != t.endpoint.Host {
		return nil, ErrKeyService
	}
	if t.records {
		record, ok := strings.CutPrefix(r.URL.EscapedPath(), t.path)
		if !ok || !authorization.UUID(record) || r.Method != http.MethodGet && r.Method != http.MethodPost {
			return nil, ErrKeyService
		}
	} else if r.Method != http.MethodPost || r.URL.EscapedPath() != t.path {
		return nil, ErrKeyService
	}
	return t.next.RoundTrip(r)
}

func (s *ownerProviderEffects) joinClosed() {
	if s == nil || s.lifetimes == nil {
		return
	}
	s.lifetimes.joinClosed()
	s.seal.Close()
	s.open.Close()
	s.server.Close()
	s.client.Close()
}
