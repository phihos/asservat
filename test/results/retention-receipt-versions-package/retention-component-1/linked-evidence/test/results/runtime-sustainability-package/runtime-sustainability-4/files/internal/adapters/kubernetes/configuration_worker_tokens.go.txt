package kubernetes

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"asservat.local/asservat/internal/adapters/mounts"
	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/util/flowcontrol"
)

// This fixed constructor preserves the existing bearer injector, base HTTP
// transport. Its sole observer bucket is fixed at 40 QPS/burst 20; the probe
// stays at 20/20. No effect creates another client or bucket. It observes the
// bytes that the injector actually sends. The mounted root belongs to the enclosing joined worker lifetime.
func NewConfigurationWorkerPermissionClient(config *rest.Config, files *os.Root, tokenFile, clusterID string, control cfg.NamespaceRef, now func() time.Time) (*PermissionClient, error) {
	if config == nil || config.RateLimiter != nil || files == nil || now == nil || tokenFile != "kube-observer.token" && tokenFile != "kube-probe.token" {
		return nil, cfg.ErrInvalid
	}
	state := &configurationWorkerTokenTransport{files: files, file: tokenFile}
	copy := rest.CopyConfig(config)
	rate := float32(20)
	if tokenFile == "kube-observer.token" {
		rate = 40
	}
	copy.RateLimiter = flowcontrol.NewTokenBucketRateLimiter(rate, 20)
	original := copy.WrapTransport
	copy.WrapTransport = func(next http.RoundTripper) http.RoundTripper {
		// The original bearer injection must be outside this observation so the
		// request contains its actual Authorization bytes before comparison.
		wrapped := http.RoundTripper(configurationWorkerTokenRoundTripper{next, state})
		if original != nil {
			wrapped = original(wrapped)
		}
		return wrapped
	}
	client, err := NewPermissionClient(copy, clusterID, control, now)
	if err != nil {
		return nil, err
	}
	client.workerToken = state
	return client, nil
}

type configurationWorkerTokenTransport struct {
	files *os.Root
	file  string
}

type configurationWorkerTokenContextKey struct{}

// A context value is mechanical request ownership, never native authority.
// Only the concrete reader can mint one, over its two exact loaded clients.
type configurationWorkerTokenInterval struct {
	mu      sync.Mutex
	ctx     context.Context
	cancel  context.CancelFunc
	now     func() time.Time
	until   time.Time
	clients [2]*configurationWorkerTokenTransport
	tokens  [2][]byte
	active  int
	closed  bool
	failed  bool
	changed chan struct{}
}

func (s *ConfigurationWorkerProviderReader) beginTokenInterval(ctx context.Context) (context.Context, *configurationWorkerTokenInterval, error) {
	if !s.providerClientsBound() || ctx == nil || ctx.Err() != nil {
		return nil, nil, cfg.ErrUnavailable
	}
	return beginConfigurationWorkerTokens(ctx, s.worker.client, s.worker.guard.probe)
}

func beginConfigurationWorkerTokens(ctx context.Context, observer, probe *PermissionClient) (context.Context, *configurationWorkerTokenInterval, error) {
	if ctx == nil || ctx.Err() != nil || observer == nil || probe == nil || observer == probe || observer.workerToken == nil || probe.workerToken == nil ||
		observer.workerToken.file != "kube-observer.token" || probe.workerToken.file != "kube-probe.token" || observer.workerToken.files != probe.workerToken.files {
		return nil, nil, cfg.ErrUnavailable
	}
	until, ok := ctx.Deadline()
	if !ok {
		return nil, nil, cfg.ErrInvalid
	}
	call, cancel := context.WithCancel(ctx)
	p := &configurationWorkerTokenInterval{ctx: call, cancel: cancel, until: until, now: observer.now,
		clients: [2]*configurationWorkerTokenTransport{observer.workerToken, probe.workerToken}, changed: make(chan struct{})}
	return context.WithValue(call, configurationWorkerTokenContextKey{}, p), p, nil
}

func (p *configurationWorkerTokenInterval) signalLocked() {
	close(p.changed)
	p.changed = make(chan struct{})
}

func (p *configurationWorkerTokenInterval) failLocked() {
	p.failed = true
	p.cancel()
	p.signalLocked()
}

func (p *configurationWorkerTokenInterval) enter(ctx context.Context, client *configurationWorkerTokenTransport, header string) (func(), error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if until, ok := ctx.Deadline(); ok && until.Before(p.until) {
		p.until = until
	}
	if p.closed || p.failed || p.ctx.Err() != nil || ctx.Err() != nil || !p.now().Before(p.until) {
		p.failLocked()
		return nil, cfg.ErrUnavailable
	}
	index := -1
	for i, expected := range p.clients {
		if client == expected {
			index = i
		}
	}
	if index < 0 || !strings.HasPrefix(header, "Bearer ") {
		p.failLocked()
		return nil, cfg.ErrDenied
	}
	token := []byte(strings.TrimPrefix(header, "Bearer "))
	defer clear(token)
	if !contracts.ValidWorkerToken(token) {
		p.failLocked()
		return nil, cfg.ErrDenied
	}
	if len(p.tokens[index]) == 0 {
		p.tokens[index] = bytes.Clone(token)
	} else if !bytes.Equal(p.tokens[index], token) {
		p.failLocked()
		return nil, cfg.ErrChanged
	}
	p.active++
	var once sync.Once
	return func() {
		once.Do(func() {
			p.mu.Lock()
			p.active--
			p.signalLocked()
			p.mu.Unlock()
		})
	}, nil
}

func (p *configurationWorkerTokenInterval) current(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if until, ok := ctx.Deadline(); ok && until.Before(p.until) {
		p.until = until
	}
	if p.closed || p.failed || p.ctx.Err() != nil || ctx.Err() != nil || !p.now().Before(p.until) {
		p.failLocked()
		return cfg.ErrUnavailable
	}
	return nil
}

// In particular this detects a rotated probe token when final native reads
// contain no probe HTTP request. It does not authenticate a token or reread a
// source observation. Later operations must perform their own native proof.
func (p *configurationWorkerTokenInterval) mountedCurrent(ctx context.Context) error {
	for i, client := range p.clients {
		if err := p.current(ctx); err != nil {
			return err
		}
		value, err := mounts.Read(ctx, client.files, client.file, 16<<10)
		p.mu.Lock()
		match := err == nil && contracts.ValidWorkerToken(value) && len(p.tokens[i]) != 0 && bytes.Equal(value, p.tokens[i])
		clear(value)
		if !match {
			p.failLocked()
		}
		p.mu.Unlock()
		if !match {
			if err != nil {
				return cfg.ErrUnavailable
			}
			return cfg.ErrChanged
		}
	}
	return p.current(ctx)
}

func (p *configurationWorkerTokenInterval) close() {
	if p == nil {
		return
	}
	p.mu.Lock()
	p.closed = true
	p.cancel()
	for p.active != 0 {
		changed := p.changed
		p.mu.Unlock()
		<-changed
		p.mu.Lock()
	}
	for i := range p.tokens {
		clear(p.tokens[i])
		p.tokens[i] = nil
	}
	p.mu.Unlock()
}

type configurationWorkerTokenRoundTripper struct {
	next   http.RoundTripper
	client *configurationWorkerTokenTransport
}

// providerInputs retains this exact inner transport for shutdown. Forward the
// idle close to its original owner; inserting token observation must not hide
// transport cleanup or create a separate client lifetime.
func (t configurationWorkerTokenRoundTripper) CloseIdleConnections() {
	if closer, ok := t.next.(interface{ CloseIdleConnections() }); ok {
		closer.CloseIdleConnections()
	}
}

func (t configurationWorkerTokenRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	p, ok := r.Context().Value(configurationWorkerTokenContextKey{}).(*configurationWorkerTokenInterval)
	if !ok {
		return t.next.RoundTrip(r) // unrelated legacy reads retain their full proof
	}
	release, err := p.enter(r.Context(), t.client, r.Header.Get("Authorization"))
	if err != nil {
		return nil, err
	}
	response, err := t.next.RoundTrip(r)
	if err != nil || response == nil || response.Body == nil || p.current(r.Context()) != nil {
		if response != nil && response.Body != nil {
			_ = response.Body.Close()
		}
		release()
		return nil, cfg.ErrUnavailable
	}
	response.Body = &configurationWorkerTokenBody{ReadCloser: response.Body, interval: p, ctx: r.Context(), release: release, changed: make(chan struct{})}
	return response, nil
}

type configurationWorkerTokenBody struct {
	io.ReadCloser
	interval *configurationWorkerTokenInterval
	ctx      context.Context
	release  func()
	mu       sync.Mutex
	changed  chan struct{}
	reads    int
	closing  bool
	closed   bool
	closeOne sync.Once
	closeErr error
}

func (b *configurationWorkerTokenBody) Read(p []byte) (int, error) {
	b.mu.Lock()
	if b.closing {
		b.mu.Unlock()
		return 0, cfg.ErrUnavailable
	}
	b.reads++
	b.mu.Unlock()
	defer func() {
		b.mu.Lock()
		b.reads--
		b.signalLocked()
		release := b.closed && b.reads == 0
		b.mu.Unlock()
		if release {
			b.release()
		}
	}()
	if err := b.interval.current(b.ctx); err != nil {
		b.closeUnderlying()
		return 0, err
	}
	n, err := b.ReadCloser.Read(p)
	b.mu.Lock()
	closing := b.closing
	b.mu.Unlock()
	if closing {
		clear(p[:n])
		return 0, cfg.ErrUnavailable
	}
	if after := b.interval.current(b.ctx); after != nil {
		clear(p[:n])
		b.closeUnderlying()
		return 0, after
	}
	return n, err
}

func (b *configurationWorkerTokenBody) signalLocked() {
	close(b.changed)
	b.changed = make(chan struct{})
}

// Read may initiate closure after detecting expiry without waiting for itself.
// The interval's response owner releases only after Close and every admitted
// Read have actually returned, even if the underlying Close does not join Read.
func (b *configurationWorkerTokenBody) closeUnderlying() {
	b.closeOne.Do(func() {
		b.mu.Lock()
		b.closing = true
		b.mu.Unlock()
		err := b.ReadCloser.Close()
		b.mu.Lock()
		b.closed, b.closeErr = true, err
		b.signalLocked()
		release := b.reads == 0
		b.mu.Unlock()
		if release {
			b.release()
		}
	})
}

func (b *configurationWorkerTokenBody) Close() error {
	b.closeUnderlying()
	b.mu.Lock()
	for b.reads != 0 {
		changed := b.changed
		b.mu.Unlock()
		<-changed
		b.mu.Lock()
	}
	err := b.closeErr
	b.mu.Unlock()
	return err
}
