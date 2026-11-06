package mtls

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"

	"asservat.local/asservat/internal/contracts"
)

// LiveOwnerClient opens exactly one fixed-purpose conversation over the current
// exact owner route. There is no worker Hello/token/lease, redirect or replay.
// Bootstrap supplies TLS VerifyConnection backed by current owner admission.
type LiveOwnerClient struct {
	endpoint, address string
	trust             *tls.Config
}

func NewLiveOwnerClient(endpoint, address string, trust *tls.Config) (*LiveOwnerClient, error) {
	u, e := url.Parse(endpoint)
	if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Path != contracts.LiveOwnerPath || u.RawPath != "" || u.RawQuery != "" || u.Fragment != "" || u.ForceQuery || trust == nil || trust.InsecureSkipVerify || trust.RootCAs == nil || len(trust.RootCAs.Subjects()) == 0 || trust.VerifyConnection == nil || trust.GetClientCertificate == nil && len(trust.Certificates) == 0 || workerAddress(address) != nil {
		return nil, contracts.ErrNativeProtocol
	}
	c := trust.Clone()
	c.RootCAs = trust.RootCAs.Clone()
	c.ServerName = u.Hostname()
	c.MinVersion = tls.VersionTLS13
	c.MaxVersion = tls.VersionTLS13
	c.NextProtos = []string{"h2"}
	c.SessionTicketsDisabled = true
	check := c.VerifyConnection
	c.VerifyConnection = func(s tls.ConnectionState) error {
		if s.DidResume || s.Version != tls.VersionTLS13 || s.NegotiatedProtocol != "h2" || len(s.VerifiedChains) == 0 {
			return contracts.ErrNativeProtocol
		}
		return check(s)
	}
	return &LiveOwnerClient{endpoint, address, c}, nil
}
func (c *LiveOwnerClient) Open(ctx context.Context, h contracts.LiveOwnerHello) (*NativeClientStream, error) {
	if c == nil || ctx == nil || ctx.Err() != nil {
		return nil, contracts.ErrNativeProtocol
	}
	end, ok := ctx.Deadline()
	if !ok || !time.Now().Before(end) || end.After(time.Now().Add(5*time.Second)) || !time.Now().Before(h.Until) {
		return nil, contracts.ErrNativeProtocol
	}
	hello, e := json.Marshal(h)
	if e != nil {
		return nil, contracts.ErrNativeProtocol
	}
	// Closed shape and limits are checked independently before network I/O.
	if _, e = contracts.DecodeLiveOwnerHello(bytes.NewReader(hello)); e != nil {
		clear(hello)
		return nil, e
	}
	work, cancel := context.WithDeadline(ctx, earlierLiveOwner(end, h.Until))
	r, w := io.Pipe()
	u, _ := url.Parse(c.endpoint)
	transport := &http.Transport{TLSClientConfig: c.trust.Clone(), ForceAttemptHTTP2: true, DisableKeepAlives: true, DisableCompression: true, MaxResponseHeaderBytes: 4096, MaxConnsPerHost: 1, MaxIdleConns: 0, TLSHandshakeTimeout: 2 * time.Second, ResponseHeaderTimeout: 2 * time.Second}
	dial := workerDial(u, c.address, (&net.Dialer{Timeout: 2 * time.Second, KeepAlive: -1}).DialContext)
	// OwnerPeerVerifier consumes a completed handshake, whereas Go invokes
	// VerifyConnection before HandshakeComplete. Authenticate the actual TLS
	// socket after HandshakeContext and before HTTP can write Hello or callbacks.
	transport.DialTLSContext = func(call context.Context, network, address string) (net.Conn, error) {
		raw, err := dial(call, network, address)
		if err != nil {
			return nil, err
		}
		config := c.trust.Clone()
		check := config.VerifyConnection
		config.VerifyConnection = nil
		socket := tls.Client(raw, config)
		if err = socket.HandshakeContext(call); err == nil {
			state := socket.ConnectionState()
			err = check(state)
		}
		if err != nil {
			_ = socket.Close()
			return nil, err
		}
		return socket, nil
	}
	request, e := http.NewRequestWithContext(work, http.MethodPost, c.endpoint, r)
	if e != nil {
		cancel()
		r.Close()
		w.Close()
		clear(hello)
		return nil, e
	}
	request.Header.Set("Content-Type", contracts.LiveOwnerMedia)
	request.Header.Set("Accept", contracts.LiveOwnerMedia)
	written := make(chan error, 1)
	go func() {
		defer clear(hello)
		written <- contracts.WriteNativeFrame(w, contracts.NativeFrame{Kind: contracts.NativeHelloFrame, Payload: hello})
	}()
	response, e := (&http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return contracts.ErrNativeProtocol }}).Do(request)
	if e != nil || response == nil || response.StatusCode != http.StatusOK || response.ProtoMajor != 2 || response.TLS == nil || response.TLS.Version != tls.VersionTLS13 || response.TLS.NegotiatedProtocol != "h2" || response.Header.Get("Content-Type") != contracts.LiveOwnerMedia || response.Header.Get("Content-Encoding") != "" || response.ContentLength != -1 {
		cancel()
		r.CloseWithError(contracts.ErrNativeProtocol)
		w.CloseWithError(contracts.ErrNativeProtocol)
		if response != nil {
			response.Body.Close()
		}
		transport.CloseIdleConnections()
		<-written
		return nil, contracts.ErrNativeProtocol
	}
	if e = <-written; e != nil || work.Err() != nil {
		cancel()
		r.Close()
		w.Close()
		response.Body.Close()
		transport.CloseIdleConnections()
		return nil, contracts.ErrNativeProtocol
	}
	stream := &NativeClientStream{ctx: work, cancel: cancel, writer: w, reader: r, response: response.Body, transport: transport, peer: *response.TLS, done: make(chan struct{}), writeFrames: 1}
	context.AfterFunc(work, stream.interrupt)
	return stream, nil
}

func earlierLiveOwner(a, b time.Time) time.Time {
	if b.Before(a) {
		return b
	}
	return a
}
