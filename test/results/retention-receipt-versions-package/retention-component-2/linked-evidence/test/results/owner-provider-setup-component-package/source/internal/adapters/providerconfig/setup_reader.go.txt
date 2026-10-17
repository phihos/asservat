package providerconfig

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"encoding/json/jsontext"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"asservat.local/asservat/internal/adapters/mtls"
	"asservat.local/asservat/internal/contracts"
)

// ErrSetupUnavailable deliberately excludes provider bodies, tokens and URLs.
var ErrSetupUnavailable = errors.New("provider setup unavailable or does not match the selected profile")

// SetupReader is an installation-only, read-only provider client. The credential
// needs only the exact named reads in the generated inspection policy. It is
// never a runtime key credential and is never included in a setup observation.
// The public methods select fixed recipes; there is no generic request method.
type SetupReader struct {
	mu       sync.Mutex
	endpoint contracts.OwnerProviderEndpoint
	token    []byte
	http     *http.Client
	closed   bool
	active   *setupObservation
}

func NewSetupReader(endpoint contracts.OwnerProviderEndpoint, inspectionToken []byte) (*SetupReader, error) {
	if !validEndpoint(endpoint.Endpoint) || len(inspectionToken) < 1 || len(inspectionToken) > 4096 {
		return nil, ErrSetupUnavailable
	}
	for _, b := range inspectionToken {
		if b < 0x21 || b > 0x7e {
			return nil, ErrSetupUnavailable
		}
	}
	roots, _, err := mtls.OwnerTrustRoots(endpoint.Roots, time.Now())
	if err != nil {
		return nil, ErrSetupUnavailable
	}
	endpoint.Roots = cloneSetupRoots(endpoint.Roots)
	transport := &http.Transport{
		Proxy: nil, DialContext: (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots},
		TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 5 * time.Second,
		MaxResponseHeaderBytes: 16 << 10, MaxConnsPerHost: 1,
		// Each named GET uses a fresh connection, avoiding transparent retry of
		// a reused connection. The whole inspection has one original deadline.
		DisableKeepAlives: true, DisableCompression: true,
	}
	return &SetupReader{endpoint: endpoint, token: bytes.Clone(inspectionToken), http: &http.Client{
		Transport: transport, Timeout: 5 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}, nil
}

func cloneSetupRoots(roots [][]byte) [][]byte {
	out := make([][]byte, len(roots))
	for i, b := range roots {
		out[i] = bytes.Clone(b)
	}
	return out
}

func sameSetupEndpoint(a, b contracts.OwnerProviderEndpoint) bool {
	if a.Endpoint != b.Endpoint || len(a.Roots) != len(b.Roots) {
		return false
	}
	for i := range a.Roots {
		if !bytes.Equal(a.Roots[i], b.Roots[i]) {
			return false
		}
	}
	return true
}

type setupObservation struct {
	reader            *SetupReader
	ctx               context.Context
	cancel            context.CancelFunc
	observedAt, until time.Time
	paths             map[string]bool
	done              chan struct{}
	finished          sync.Once
}

// begin admits one finite inspection without queuing or renewing a prior one.
// Only validated same-package recipe verifiers supply the finite path list.
func (r *SetupReader) begin(ctx context.Context, endpoint contracts.OwnerProviderEndpoint, paths []string) (*setupObservation, error) {
	if r == nil || ctx == nil || ctx.Err() != nil || len(paths) < 1 || len(paths) > 24 {
		return nil, ErrSetupUnavailable
	}
	allowed := make(map[string]bool, len(paths))
	for _, path := range paths {
		if len(path) > 512 || strings.ContainsAny(path, "?#%\\") {
			return nil, ErrSetupUnavailable
		}
		for _, part := range strings.Split(path, "/") {
			if !providerName.MatchString(part) {
				return nil, ErrSetupUnavailable
			}
		}
		if allowed[path] {
			return nil, ErrSetupUnavailable
		}
		allowed[path] = true
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now()
	_, rootUntil, err := mtls.OwnerTrustRoots(r.endpoint.Roots, now)
	if err != nil || r.closed || r.active != nil || ctx.Err() != nil || !sameSetupEndpoint(endpoint, r.endpoint) {
		return nil, ErrSetupUnavailable
	}
	until := now.Add(5 * time.Second)
	if rootUntil.Before(until) {
		until = rootUntil
	}
	if deadline, ok := ctx.Deadline(); ok && deadline.Before(until) {
		until = deadline
	}
	if !now.Before(until) {
		return nil, ErrSetupUnavailable
	}
	call, cancel := context.WithDeadline(ctx, until)
	o := &setupObservation{reader: r, ctx: call, cancel: cancel, observedAt: now, until: until, paths: allowed, done: make(chan struct{})}
	r.active = o
	return o, nil
}

func (o *setupObservation) valid() bool {
	if o == nil || o.reader == nil || o.ctx.Err() != nil || !time.Now().Before(o.until) {
		return false
	}
	o.reader.mu.Lock()
	defer o.reader.mu.Unlock()
	return !o.reader.closed && o.reader.active == o
}

func (o *setupObservation) finish() {
	if o == nil {
		return
	}
	o.finished.Do(func() {
		o.cancel()
		r := o.reader
		r.mu.Lock()
		defer r.mu.Unlock()
		if r.active == o {
			r.active = nil
		}
		if r.closed {
			clear(r.token)
			r.token = nil
		}
		close(o.done)
	})
}

// Close rejects further reads, cancels an active inspection and joins it. A
// caller timeout does not make the still-owned inspection disappear. Go/HTTP
// temporary strings are not claimed to be erased by clearing the owned bytes.
func (r *SetupReader) Close(ctx context.Context) error {
	if r == nil {
		return nil
	}
	if ctx == nil {
		return ErrSetupUnavailable
	}
	r.mu.Lock()
	r.closed = true
	o := r.active
	if o != nil {
		o.cancel()
	} else {
		clear(r.token)
		r.token = nil
	}
	r.mu.Unlock()
	r.http.CloseIdleConnections()
	if o == nil {
		return nil
	}
	select {
	case <-o.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// get never returns a raw HTTP/provider error. Bounded public configuration is
// decoded only after authenticated HTTPS, a complete body and a current lease.
func (o *setupObservation) get(path string) (map[string]json.RawMessage, error) {
	if !o.valid() || !o.paths[path] {
		return nil, ErrSetupUnavailable
	}
	req, err := http.NewRequestWithContext(o.ctx, http.MethodGet, strings.TrimSuffix(o.reader.endpoint.Endpoint, "/")+"/v1/"+path, nil)
	if err != nil {
		return nil, ErrSetupUnavailable
	}
	o.reader.mu.Lock()
	if o.reader.closed || o.reader.active != o {
		o.reader.mu.Unlock()
		return nil, ErrSetupUnavailable
	}
	req.Header.Set("X-Vault-Token", string(o.reader.token))
	o.reader.mu.Unlock()
	req.Header.Set("Accept", "application/json")
	response, err := o.reader.http.Do(req)
	if err != nil {
		return nil, ErrSetupUnavailable
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || response.ContentLength > 64<<10 {
		return nil, ErrSetupUnavailable
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, (64<<10)+1))
	if err != nil || len(raw) == 0 || len(raw) > 64<<10 {
		return nil, ErrSetupUnavailable
	}
	defer clear(raw)
	canonical := jsontext.Value(raw)
	if canonical.Canonicalize() != nil {
		return nil, ErrSetupUnavailable
	}
	var envelope struct {
		Data          map[string]json.RawMessage `json:"data"`
		Auth          json.RawMessage            `json:"auth"`
		Wrap          json.RawMessage            `json:"wrap_info"`
		Warnings      []string                   `json:"warnings"`
		Errors        []string                   `json:"errors"`
		LeaseID       string                     `json:"lease_id"`
		Renewable     bool                       `json:"renewable"`
		LeaseDuration int64                      `json:"lease_duration"`
	}
	if json.Unmarshal(canonical, &envelope) != nil || len(envelope.Data) == 0 || !setupNull(envelope.Auth) || !setupNull(envelope.Wrap) || len(envelope.Warnings) != 0 || len(envelope.Errors) != 0 || envelope.LeaseID != "" || envelope.Renewable || envelope.LeaseDuration != 0 || !o.valid() {
		return nil, ErrSetupUnavailable
	}
	return envelope.Data, nil
}

func setupNull(raw json.RawMessage) bool { return len(raw) == 0 || bytes.Equal(raw, []byte("null")) }
