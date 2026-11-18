package connectorlifecycle

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Client is the connector's side of its hub connection: one HTTP/2
// connection to the hub URL that carries the finite lifecycle conversations
// and the tunnels to the hub's in-cluster services. Every request presents
// the connector's ServiceAccount token (ADR-334). No retry.
type Client struct {
	base      string
	http      *http.Client
	transport *http.Transport
	token     func() ([]byte, error)
}

// NewClient dials hubURL (https, no path, query or user) and verifies the
// hub's certificate for the URL's host against roots, or the system roots
// when roots is nil.
func NewClient(hubURL string, roots *x509.CertPool, token func() ([]byte, error)) (*Client, error) {
	u, err := url.Parse(hubURL)
	if err != nil || token == nil || u.Scheme != "https" || u.Host == "" || strings.Trim(u.Path, "/") != "" || u.RawQuery != "" || u.User != nil || u.Fragment != "" {
		return nil, ErrChannel
	}
	t := &http.Transport{
		Proxy:               nil,
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, NextProtos: []string{"h2"}},
		ForceAttemptHTTP2:   true,
		DialContext:         (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
		TLSHandshakeTimeout: 5 * time.Second, MaxResponseHeaderBytes: 4 << 10, IdleConnTimeout: 90 * time.Second,
	}
	return &Client{base: "https://" + u.Host, transport: t, token: token,
		http: &http.Client{Transport: t, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}

// Close closes the idle hub connection.
func (c *Client) Close() {
	if c != nil {
		c.transport.CloseIdleConnections()
	}
}

// open starts one full-duplex request on the hub connection: body is what
// the request streams, and the returned response is HTTP/2 200.
func (c *Client) open(ctx context.Context, path string, header http.Header, body io.Reader) (*http.Response, error) {
	token, err := c.token()
	if err != nil {
		return nil, ErrChannel
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+path, body)
	if err != nil {
		return nil, ErrChannel
	}
	for k, v := range header {
		req.Header[k] = v
	}
	req.Header.Set("Authorization", "Bearer "+string(token))
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, ErrChannel
	}
	if resp.StatusCode == http.StatusUpgradeRequired && resp.ProtoMajor == 2 {
		defer resp.Body.Close()
		var mismatch ProtocolMismatch
		if json.NewDecoder(io.LimitReader(resp.Body, MaxFrameBytes)).Decode(&mismatch) == nil && mismatch.Required > 0 {
			return nil, &mismatch
		}
		return nil, ErrChannel
	}
	if resp.StatusCode != http.StatusOK || resp.ProtoMajor != 2 {
		resp.Body.Close()
		return nil, ErrChannel
	}
	return resp, nil
}

// Run returns the hub's final frame; local answers a delivery request and
// may be nil for a read-only purpose.
func (c *Client) Run(ctx context.Context, opening Opening, local any) (HubFrame, error) {
	var zero HubFrame
	if c == nil || ctx == nil {
		return zero, ErrChannel
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	body, writer := io.Pipe()
	defer writer.Close()
	out := NewConn(nil, writer, nil, nil)
	sent := make(chan error, 1)
	go func() { sent <- out.Send(opening) }()
	resp, err := c.open(ctx, Path, http.Header{"Content-Type": {ContentType}}, body)
	if err != nil {
		writer.CloseWithError(err)
		<-sent
		return zero, err
	}
	defer resp.Body.Close()
	if <-sent != nil || resp.Header.Get("Content-Type") != ContentType {
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
			delivery = delivery.Bounded()
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
