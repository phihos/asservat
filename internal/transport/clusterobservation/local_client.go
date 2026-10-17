package clusterobservation

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	app "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
)

// LocalClient has one installed HTTPS origin and one process Pod identity. It
// opens no Kubernetes, SQL or credential-issuer connection. The trusted local
// hub relay remains explicit; server roots/hostname come from protected input.
type LocalClient struct {
	root                     context.Context
	cancel                   context.CancelFunc
	endpoint, rootID, podUID string
	tokens                   app.ClusterObservationTokenReader
	now                      func() time.Time
	client                   *http.Client
	transport                *http.Transport
	mu                       sync.Mutex
	closed                   bool
	maximum, active          int
	joined                   sync.WaitGroup
}

var _ app.ClusterObservationExchange = (*LocalClient)(nil)

func NewLocalClient(ctx context.Context, origin, rootID, podUID string, roots *x509.CertPool, tokens app.ClusterObservationTokenReader, maximum int, now func() time.Time) (*LocalClient, error) {
	u, e := url.Parse(origin)
	if ctx == nil || ctx.Err() != nil || e != nil || len(origin) > 2048 || u.Scheme != "https" || u.Host == "" || u.Hostname() == "" || u.User != nil || u.Opaque != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.Contains(origin, "#") || u.RawPath != "" || (u.Path != "" && u.Path != "/") || !authorization.UUID(rootID) || !authorization.UUID(podUID) || roots == nil || len(roots.Subjects()) == 0 || tokens == nil || maximum < 1 || maximum > 16 || now == nil {
		return nil, fleet.ErrInvalid
	}
	u.Path = contracts.ClusterObservationLocalPath
	tr := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots.Clone(), MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, Time: now}, ForceAttemptHTTP2: true, DisableKeepAlives: true, DisableCompression: true, MaxConnsPerHost: maximum, MaxIdleConns: 0, MaxResponseHeaderBytes: 4096, TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 5 * time.Second, DialContext: (&net.Dialer{Timeout: 5 * time.Second}).DialContext}
	client := &http.Client{Transport: tr, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	root, cancel := context.WithCancel(ctx)
	return &LocalClient{root: root, cancel: cancel, endpoint: u.String(), rootID: rootID, podUID: podUID, tokens: tokens, now: now, client: client, transport: tr, maximum: maximum}, nil
}
func (c *LocalClient) enter() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || c.root.Err() != nil || c.active >= c.maximum {
		return false
	}
	c.active++
	c.joined.Add(1)
	return true
}
func (c *LocalClient) leave() { c.mu.Lock(); c.active--; c.mu.Unlock(); c.joined.Done() }
func (c *LocalClient) Close() {
	if c == nil {
		return
	}
	c.mu.Lock()
	c.closed = true
	c.cancel()
	c.mu.Unlock()
	c.joined.Wait()
	c.transport.CloseIdleConnections()
}

func (c *LocalClient) ObserveCluster(ctx context.Context, request fleet.ClusterObservationRequest) (fleet.ClusterObservationResult, error) {
	var zero fleet.ClusterObservationResult
	if c == nil || ctx == nil || ctx.Err() != nil || !request.Valid(c.now()) || request.RootID != c.rootID || !c.enter() {
		return zero, fleet.ErrUnavailable
	}
	defer c.leave()
	request = request.Clone()
	started := c.now()
	until := identity.Earlier(started.Add(5*time.Second), request.NotAfter)
	if d, ok := ctx.Deadline(); ok {
		until = identity.Earlier(until, d)
	}
	call, cancel := context.WithDeadline(ctx, until)
	defer cancel()
	done := make(chan struct{})
	stop := context.AfterFunc(c.root, func() { cancel(); close(done) })
	defer func() {
		if !stop() {
			<-done
		}
	}()
	token, e := c.tokens.ReadClusterObservationToken(call)
	defer clear(token)
	if e != nil || len(token) < 1 || len(token) > 16<<10 || !bytes.Equal(bytes.TrimSpace(token), token) || bytes.ContainsAny(token, " \t\r\n") || call.Err() != nil || !c.now().Before(until) {
		return zero, fleet.ErrUnavailable
	}
	digest, e := RequestDigest(request)
	if e != nil {
		return zero, fleet.ErrInvalid
	}
	b, e := contracts.EncodeClusterObservationLocalRequest(contracts.ClusterObservationLocalRequest{Format: contracts.ClusterObservationLocalFormat, PodUID: c.podUID, Observation: RequestWire(request)})
	if e != nil {
		return zero, fleet.ErrInvalid
	}
	// No GetBody/redirect/cookie/proxy/retry path. An unknown POST is returned
	// unavailable; the caller retains its original reconciliation disposition.
	r, e := http.NewRequestWithContext(call, http.MethodPost, c.endpoint, io.NopCloser(bytes.NewReader(b)))
	if e != nil {
		return zero, fleet.ErrUnavailable
	}
	r.ContentLength = int64(len(b))
	r.Header.Set("Authorization", "Bearer "+string(token))
	r.Header.Set("Content-Type", contracts.ClusterObservationLocalMedia)
	r.Header.Set("Accept", contracts.ClusterObservationLocalMedia)
	response, e := c.client.Do(r)
	if e != nil {
		return zero, fleet.ErrUnavailable
	}
	defer response.Body.Close()
	if response.TLS == nil || !response.TLS.HandshakeComplete || response.TLS.Version != tls.VersionTLS13 || response.TLS.NegotiatedProtocol != "h2" || len(response.TLS.VerifiedChains) == 0 || response.ProtoMajor != 2 || response.StatusCode != http.StatusOK || response.ContentLength < 1 || response.ContentLength > contracts.ClusterObservationBytes || len(response.TransferEncoding) != 0 || len(response.Header.Values("Content-Encoding")) != 0 || len(response.Header.Values("Set-Cookie")) != 0 || len(response.Header.Values("Content-Type")) != 1 || response.Header.Get("Content-Type") != contracts.ClusterObservationLocalMedia || len(response.Header.Values("Cache-Control")) != 1 || response.Header.Get("Cache-Control") != "no-store" {
		return zero, fleet.ErrUnavailable
	}
	data, e := io.ReadAll(io.LimitReader(response.Body, contracts.ClusterObservationBytes+1))
	if e != nil || len(data) != int(response.ContentLength) || len(data) > contracts.ClusterObservationBytes || call.Err() != nil || !c.now().Before(until) {
		return zero, fleet.ErrUnavailable
	}
	w, e := contracts.DecodeClusterObservationResult(data)
	if e != nil {
		return zero, fleet.ErrUnavailable
	}
	v, e := ParseResult(w, request, digest, c.now())
	if e != nil {
		return zero, e
	}
	v = v.Restrict(started, until)
	if !v.Matches(request, digest, c.now()) || call.Err() != nil {
		return zero, fleet.ErrUnavailable
	}
	return v, nil
}
