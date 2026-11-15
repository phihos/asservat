package node

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"asservat.local/asservat/internal/application/delivery"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/collector"
)

var (
	ErrRefused     = errors.New("node channel: request refused")
	ErrUnavailable = errors.New("node channel: connector unavailable")
)

// Client is the collector's side of the channel: HTTP/2 over server TLS,
// verified against the pinned roots and server name only, with HTTP/2 PING
// as liveness. Every request carries the current projected token. It sends
// no request twice, follows no redirect and uses no proxy.
type Client struct {
	base  *url.URL
	http  *http.Client
	token func(context.Context) ([]byte, error)
}

func NewClient(endpoint, serverName string, roots *x509.CertPool, token func(context.Context) ([]byte, error)) (*Client, error) {
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" ||
		serverName == "" || roots == nil || len(roots.Subjects()) == 0 || token == nil {
		return nil, ErrRefused
	}
	u.Path = ""
	protocols := new(http.Protocols)
	protocols.SetHTTP2(true)
	t := &http.Transport{
		Proxy:               nil,
		DialContext:         (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		TLSClientConfig:     &tls.Config{RootCAs: roots.Clone(), ServerName: serverName, MinVersion: tls.VersionTLS13},
		TLSHandshakeTimeout: 5 * time.Second, MaxResponseHeaderBytes: 4096, DisableCompression: true,
		Protocols: protocols, HTTP2: &http.HTTP2Config{SendPingTimeout: 30 * time.Second, PingTimeout: 15 * time.Second},
	}
	c := &http.Client{Transport: t, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return &Client{base: u, http: c, token: token}, nil
}

func (c *Client) request(ctx context.Context, path, contentType string, body io.Reader) (*http.Request, error) {
	token, err := c.token(ctx)
	if err != nil {
		return nil, ErrUnavailable
	}
	defer clear(token)
	u := *c.base
	u.Path = path
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), body)
	if err != nil {
		return nil, ErrRefused
	}
	req.Header.Set("Authorization", "Bearer "+string(token))
	req.Header.Set("Content-Type", contentType)
	return req, nil
}

func outcome(code int) error {
	switch code {
	case http.StatusBadRequest, http.StatusForbidden, http.StatusConflict:
		return ErrRefused
	}
	return ErrUnavailable
}

// send posts one bounded upload of exactly length bytes.
func (c *Client) send(ctx context.Context, path, contentType string, length int64, body io.Reader) error {
	ctx, cancel := context.WithTimeout(ctx, UploadTimeout)
	defer cancel()
	req, err := c.request(ctx, path, contentType, body)
	if err != nil {
		return err
	}
	req.ContentLength = length
	resp, err := c.http.Do(req)
	if err != nil {
		return ErrUnavailable
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode != http.StatusNoContent {
		return outcome(resp.StatusCode)
	}
	return nil
}

// Stream is one open node stream.
type Stream struct {
	mu   sync.Mutex
	up   *io.PipeWriter
	down io.ReadCloser
}

// Connect opens the stream and sends Hello.
func (c *Client) Connect(ctx context.Context, capabilities []collector.WorkKind) (*Stream, error) {
	hello := &contracts.NodeHello{Version: contracts.NodeChannelVersion, Capabilities: []string{}}
	for _, k := range capabilities {
		hello.Capabilities = append(hello.Capabilities, string(k))
	}
	pr, pw := io.Pipe()
	req, err := c.request(ctx, contracts.NodeConnectPath, "application/octet-stream", pr)
	if err != nil {
		return nil, err
	}
	sent := make(chan error, 1)
	go func() { sent <- contracts.WriteNodeFrame(pw, contracts.NodeUp{Hello: hello}) }()
	resp, err := c.http.Do(req)
	if err != nil {
		pw.CloseWithError(err)
		<-sent
		return nil, ErrUnavailable
	}
	if resp.StatusCode != http.StatusOK {
		pw.CloseWithError(ErrRefused)
		<-sent
		resp.Body.Close()
		return nil, outcome(resp.StatusCode)
	}
	if err = <-sent; err != nil {
		pw.Close()
		resp.Body.Close()
		return nil, ErrUnavailable
	}
	return &Stream{up: pw, down: resp.Body}, nil
}

// Status sends one report.
func (s *Stream) Status(r collector.Report) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	status := WireStatus(r)
	return contracts.WriteNodeFrame(s.up, contracts.NodeUp{Status: &status})
}

// Receive returns the next pushed work item.
func (s *Stream) Receive() (delivery.NodeWorkDelivery, error) {
	wire, err := contracts.ReadNodeFrame[contracts.NodeWork](s.down)
	if err != nil {
		return delivery.NodeWorkDelivery{}, ErrUnavailable
	}
	defer func() {
		if wire.ProfileCapture != nil {
			clear(wire.ProfileCapture.Authorization)
		}
	}()
	work, ok := ReceivedWork(wire)
	if !ok {
		return delivery.NodeWorkDelivery{}, ErrUnavailable
	}
	return work, nil
}

func (s *Stream) Close() {
	s.up.Close()
	s.down.Close()
}

// UploadCapture sends one finished capture with its header (ADR-248). It is
// sent once: a failure leaves the capture unrecorded at the connector.
func (c *Client) UploadCapture(ctx context.Context, r collector.PacketResult, pcapng []byte) error {
	head, err := json.Marshal(WirePacketResult(r))
	if err != nil || len(head) > contracts.NodeCaptureMaxHeader || int64(len(pcapng)) != r.CapturedBytes {
		return ErrRefused
	}
	var size [4]byte
	binary.BigEndian.PutUint32(size[:], uint32(len(head)))
	return c.send(ctx, contracts.NodeCapturePath, contracts.NodeCaptureContentType, int64(4+len(head)+len(pcapng)), io.MultiReader(bytes.NewReader(size[:]), bytes.NewReader(head), bytes.NewReader(pcapng)))
}
