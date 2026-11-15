package connectorlifecycle

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"
)

// Client is the regional side of one ADR-169 conversation. It dials the
// pinned hub, authenticates with the connector's ServiceAccount token and answers
// each phase request with the local in-cluster lifecycle reader. No retry.
type Client struct {
	address, host string
	roots         *x509.CertPool
	token         func() ([]byte, error)
}

// NewClient pins the hub endpoint, the server name its certificate must carry
// and the issuer roots. The name is separate from the dialed address so an
// installer-pinned identity survives any reachable address.
func NewClient(endpoint, serverName string, roots *x509.CertPool, token func() ([]byte, error)) (*Client, error) {
	u, err := url.Parse(endpoint)
	if err != nil || roots == nil || token == nil || serverName == "" || u.Scheme != "https" || u.Host == "" || u.Path != "" || u.RawQuery != "" || u.User != nil || u.Port() == "" {
		return nil, ErrChannel
	}
	return &Client{address: u.Host, host: serverName, roots: roots, token: token}, nil
}

// Run returns the hub's final frame; local answers a delivery request and
// may be nil for a read-only purpose.
func (c *Client) Run(ctx context.Context, opening Opening, local any) (HubFrame, error) {
	var zero HubFrame
	if c == nil || ctx == nil {
		return zero, ErrChannel
	}
	token, err := c.token()
	if err != nil {
		return zero, ErrChannel
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	dialer := tls.Dialer{Config: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: c.roots, ServerName: c.host, NextProtos: []string{"h2"}}}
	raw, err := dialer.DialContext(ctx, "tcp", c.address)
	if err != nil {
		return zero, ErrChannel
	}
	conn := raw.(*tls.Conn)
	defer conn.Close()
	if conn.ConnectionState().NegotiatedProtocol != "h2" {
		return zero, ErrChannel
	}
	var once sync.Once
	transport := &http.Transport{
		DialTLSContext: func(context.Context, string, string) (net.Conn, error) {
			var out net.Conn
			once.Do(func() { out = conn })
			if out == nil {
				return nil, errors.New("connector lifecycle connection already used")
			}
			return out, nil
		},
		ForceAttemptHTTP2: true, DisableKeepAlives: true, Proxy: nil, MaxResponseHeaderBytes: 4 << 10,
	}
	defer transport.CloseIdleConnections()
	body, writer := io.Pipe()
	defer writer.Close()
	out := NewConn(nil, writer, nil, nil)
	sent := make(chan error, 1)
	go func() { sent <- out.Send(opening) }()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+c.address+Path, body)
	if err != nil {
		return zero, ErrChannel
	}
	req.Header.Set("Content-Type", ContentType)
	req.Header.Set("Authorization", "Bearer "+string(token))
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		return zero, ErrChannel
	}
	defer resp.Body.Close()
	if <-sent != nil || resp.StatusCode != http.StatusOK || resp.Header.Get("Content-Type") != ContentType {
		return zero, ErrChannel
	}
	in := NewConn(resp.Body, nil, nil, func(time.Time) error { return nil }) // ctx bounds the client
	for range 2 * MaxRegionFrame {
		var frame HubFrame
		if in.Receive(ctx, &frame) != nil {
			return zero, ErrChannel
		}
		var reply RegionFrame
		switch {
		case frame.Kind == "access-bindings":
			reader, ok := local.(AccessBindingsLocal)
			if !ok {
				_ = out.Send(RegionFrame{Kind: "error"})
				return zero, ErrChannel
			}
			delivery, err := reader.ReadAccessBindings(ctx)
			if err != nil {
				_ = out.Send(RegionFrame{Kind: "error"})
				return zero, ErrChannel
			}
			reply = RegionFrame{Kind: "access-bindings", AccessBindings: &delivery}
			if frame.Digest != "" && frame.Digest == delivery.Digest() {
				reply = RegionFrame{Kind: "access-bindings", Unchanged: true}
			}
		case frame.Kind == "result" || frame.Kind == "failure":
			return frame, nil
		default:
			return zero, ErrChannel
		}
		if out.Send(reply) != nil {
			return zero, ErrChannel
		}
	}
	return zero, ErrChannel
}
