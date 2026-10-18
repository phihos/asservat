package mtls

import (
	"asservat.local/asservat/internal/contracts"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// NativeClient is an installation-configured client for the native-only wire.
// The live request body is never rewindable. No header marks its POST retryable.
// This client does not possess human authentication or acquire evidence rights.
type NativeClient struct {
	endpoint string
	trust    *tls.Config
	dial     func(context.Context, string, string) (net.Conn, error)
}

func NewNativeClient(endpoint string, trust *tls.Config) (*NativeClient, error) {
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Opaque != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawPath != "" || (u.Path != contracts.NativeWorkerPath && u.Path != contracts.NativeOwnerPath) || strings.ContainsAny(endpoint, "\\\r\n\t ") || trust == nil || trust.InsecureSkipVerify || trust.RootCAs == nil || len(trust.RootCAs.Subjects()) == 0 || trust.GetClientCertificate == nil && len(trust.Certificates) == 0 {
		return nil, contracts.ErrNativeProtocol
	}
	t := trust.Clone()
	t.RootCAs = trust.RootCAs.Clone()
	t.MinVersion = tls.VersionTLS13
	t.MaxVersion = tls.VersionTLS13
	t.NextProtos = []string{"h2"}
	t.ServerName = u.Hostname()
	previous := t.VerifyConnection
	t.VerifyConnection = func(s tls.ConnectionState) error {
		if s.Version != tls.VersionTLS13 || s.NegotiatedProtocol != "h2" || len(s.VerifiedChains) == 0 {
			return contracts.ErrNativeProtocol
		}
		if previous != nil {
			return previous(s)
		}
		return nil
	}
	return &NativeClient{endpoint: endpoint, trust: t}, nil
}

// NewNativeClientVia is NewNativeClient with an installation-pinned,
// connectivity-only address: TCP goes to address, while TLS still verifies
// the endpoint's host and the request names the endpoint's authority. An
// empty address is NewNativeClient.
func NewNativeClientVia(endpoint, address string, trust *tls.Config) (*NativeClient, error) {
	c, err := NewNativeClient(endpoint, trust)
	if err != nil || workerAddress(address) != nil {
		return nil, contracts.ErrNativeProtocol
	}
	u, _ := url.Parse(endpoint)
	c.dial = workerDial(u, address, (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: -1}).DialContext)
	return c, nil
}

// NativeClientStream has one read and one write owner. Close interrupts and
// joins their actual I/O before returning; no spent command is retransmitted.
type NativeClientStream struct {
	ctx                     context.Context
	cancel                  context.CancelFunc
	writer                  *io.PipeWriter
	reader                  *io.PipeReader
	response                io.ReadCloser
	transport               *http.Transport
	peer                    tls.ConnectionState
	mu                      sync.Mutex
	reads, writes           int
	closed                  bool
	interrupted             bool
	done                    chan struct{}
	doneClosed              bool
	readFrames, writeFrames int
}

func (c *NativeClient) Open(ctx context.Context, hello contracts.NativeHello) (*NativeClientStream, error) {
	if c == nil || ctx == nil || ctx.Err() != nil {
		return nil, contracts.ErrNativeProtocol
	}
	// The owner supplies a finite original operation lifetime. Frame calls carry
	// their shorter current lease; this bound never becomes a byte permit.
	d, ok := ctx.Deadline()
	if !ok || !time.Now().Before(d) || d.After(time.Now().Add(8*time.Hour)) {
		return nil, contracts.ErrNativeProtocol
	}
	work, cancel := context.WithCancel(ctx)
	r, w := io.Pipe()
	// The entire first handshake/header/Hello exchange shares one original
	// setup bound. Separate per-stage HTTP timeouts must not add up or leave a
	// peer that replied without consuming Hello blocking the writer for hours.
	setup, stopSetup := context.WithTimeout(ctx, 5*time.Second)
	setupJoined := make(chan struct{})
	stopSetupCallback := context.AfterFunc(setup, func() {
		cancel()
		w.CloseWithError(contracts.ErrNativeProtocol)
		r.CloseWithError(contracts.ErrNativeProtocol)
		close(setupJoined)
	})
	defer func() {
		if !stopSetupCallback() {
			<-setupJoined
		}
		stopSetup()
	}()
	t := &http.Transport{TLSClientConfig: c.trust.Clone(), ForceAttemptHTTP2: true, DisableKeepAlives: true, DisableCompression: true, MaxResponseHeaderBytes: 4096, MaxConnsPerHost: 1, MaxIdleConns: 0, TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 5 * time.Second}
	if c.dial != nil {
		t.DialContext = c.dial
	}
	client := &http.Client{Transport: t, CheckRedirect: func(*http.Request, []*http.Request) error { return contracts.ErrNativeProtocol }}
	req, err := http.NewRequestWithContext(work, http.MethodPost, c.endpoint, r)
	if err != nil {
		cancel()
		r.Close()
		w.Close()
		return nil, contracts.ErrNativeProtocol
	}
	req.Header.Set("Content-Type", contracts.NativeExchangeMedia)
	req.Header.Set("Accept", contracts.NativeExchangeMedia)
	// io.PipeReader gives ContentLength=-1 and no GetBody. Deliberately no
	// Idempotency-Key, X-Idempotency-Key, Authorization, Cookie or redirects.
	helloBytes, err := encodeNativeHello(hello)
	if err != nil {
		cancel()
		r.Close()
		w.Close()
		return nil, err
	}
	wrote := make(chan error, 1)
	go func() {
		defer clear(helloBytes)
		wrote <- contracts.WriteNativeFrame(w, contracts.NativeFrame{Kind: contracts.NativeHelloFrame, Payload: helloBytes})
	}()
	resp, err := client.Do(req)
	if err == nil && resp != nil && resp.StatusCode == http.StatusNoContent && resp.ProtoMajor == 2 && resp.TLS != nil && resp.TLS.Version == tls.VersionTLS13 && resp.TLS.NegotiatedProtocol == "h2" {
		single := func(name, want string) bool {
			values := resp.Header.Values(name)
			return len(values) == 1 && values[0] == want
		}
		text := resp.Header.Get("Asservat-Native-Until")
		until, parseErr := time.Parse(time.RFC3339Nano, text)
		valid := parseErr == nil && text == until.UTC().Format(time.RFC3339Nano) && time.Now().Before(until) && !until.After(time.Now().Add(5*time.Second)) && single("Asservat-Native-Disposition", "no-command") && single("Asservat-Native-Nonce", hello.Nonce) && single("Asservat-Native-Installation", hello.Reference.InstallationID) && single("Asservat-Native-Session", hello.Reference.SessionID) && single("Asservat-Native-Worker", hello.Reference.WorkerID) && single("Retry-After", "1") && len(resp.Header.Values("Asservat-Native-Until")) == 1 && resp.ContentLength == 0 && hello.Reference.OperationID == "" && hello.Reference.Fence == 0
		// Finish the actual Hello write before classifying this as no-command; an
		// uncertain POST body must never acquire a retryable disposition.
		written := <-wrote
		cancel()
		w.Close()
		r.Close()
		resp.Body.Close()
		t.CloseIdleConnections()
		if valid && written == nil && setup.Err() == nil && ctx.Err() == nil && time.Now().Before(until) {
			return nil, &contracts.NativeNoCommand{Reference: hello.Reference, Nonce: hello.Nonce, Until: until}
		}
		return nil, contracts.ErrNativeProtocol
	}
	if err != nil || resp == nil || resp.StatusCode != http.StatusOK || resp.ProtoMajor != 2 || resp.TLS == nil || resp.TLS.Version != tls.VersionTLS13 || resp.TLS.NegotiatedProtocol != "h2" || resp.Header.Get("Content-Type") != contracts.NativeExchangeMedia || resp.Header.Get("Content-Encoding") != "" || resp.ContentLength != -1 {
		cancel()
		w.CloseWithError(contracts.ErrNativeProtocol)
		r.CloseWithError(contracts.ErrNativeProtocol)
		if resp != nil {
			resp.Body.Close()
		}
		t.CloseIdleConnections()
		<-wrote
		return nil, contracts.ErrNativeProtocol
	}
	if err = <-wrote; err != nil || setup.Err() != nil || work.Err() != nil {
		cancel()
		resp.Body.Close()
		r.Close()
		w.Close()
		t.CloseIdleConnections()
		return nil, contracts.ErrNativeProtocol
	}
	s := &NativeClientStream{ctx: work, cancel: cancel, writer: w, reader: r, response: resp.Body, transport: t, peer: *resp.TLS, done: make(chan struct{}), writeFrames: 1}
	context.AfterFunc(work, s.interrupt)
	return s, nil
}

func (s *NativeClientStream) Peer() tls.ConnectionState { return s.peer }
func (s *NativeClientStream) Context() context.Context  { return s.ctx }
func (s *NativeClientStream) finishLocked() {
	if s.closed && s.interrupted && s.reads == 0 && s.writes == 0 && !s.doneClosed {
		s.doneClosed = true
		close(s.done)
	}
}
func (s *NativeClientStream) interrupt() {
	if s == nil {
		return
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	s.cancel()
	s.mu.Unlock()
	s.writer.CloseWithError(contracts.ErrNativeProtocol)
	s.reader.CloseWithError(contracts.ErrNativeProtocol)
	s.response.Close()
	s.transport.CloseIdleConnections()
	s.mu.Lock()
	s.interrupted = true
	s.finishLocked()
	s.mu.Unlock()
}
func (s *NativeClientStream) Close() error {
	if s == nil {
		return nil
	}
	s.interrupt()
	<-s.done
	return nil
}
func (s *NativeClientStream) begin(ctx context.Context, read bool) (func(), error) {
	if s == nil || ctx == nil || ctx.Err() != nil {
		return nil, contracts.ErrNativeProtocol
	}
	d, ok := ctx.Deadline()
	if !ok || !time.Now().Before(d) || d.After(time.Now().Add(5*time.Second)) {
		return nil, contracts.ErrNativeProtocol
	}
	s.mu.Lock()
	if s.closed || s.ctx.Err() != nil || read && (s.reads != 0 || s.readFrames >= contracts.NativeMaximumFrames) || !read && (s.writes != 0 || s.writeFrames >= contracts.NativeMaximumFrames) {
		s.mu.Unlock()
		return nil, contracts.ErrNativeProtocol
	}
	if read {
		s.reads++
		s.readFrames++
	} else {
		s.writes++
		s.writeFrames++
	}
	s.mu.Unlock()
	finished := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { s.interrupt(); close(finished) })
	return func() {
		if !stop() {
			<-finished
		}
		s.mu.Lock()
		if read {
			s.reads--
		} else {
			s.writes--
		}
		s.finishLocked()
		s.mu.Unlock()
	}, nil
}
func (s *NativeClientStream) Receive(ctx context.Context) (contracts.NativeFrame, error) {
	end, err := s.begin(ctx, true)
	if err != nil {
		return contracts.NativeFrame{}, err
	}
	defer end()
	f, err := contracts.ReadNativeFrame(s.response)
	if err != nil || ctx.Err() != nil || s.ctx.Err() != nil {
		clear(f.Payload)
		s.interrupt()
		return contracts.NativeFrame{}, contracts.ErrNativeProtocol
	}
	return f, nil
}
func (s *NativeClientStream) Send(ctx context.Context, f contracts.NativeFrame) error {
	end, err := s.begin(ctx, false)
	if err != nil {
		return err
	}
	defer end()
	if err = contracts.WriteNativeFrame(s.writer, f); err != nil || ctx.Err() != nil || s.ctx.Err() != nil {
		s.interrupt()
		return contracts.ErrNativeProtocol
	}
	return nil
}
