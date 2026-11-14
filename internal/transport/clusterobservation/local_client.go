package clusterobservation

import (
	"context"
	"crypto/tls"
	"crypto/x509"
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
