package node

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/collector"
)

var (
	// ErrUnauthenticated means the connector no longer knows this process's
	// certificate (connector restart, replacement or expiry): enroll again.
	ErrUnauthenticated = errors.New("node channel: enroll again")
	ErrRefused         = errors.New("node channel: request refused")
	ErrUnavailable     = errors.New("node channel: connector unavailable")
)

// Client is the collector's side of the channel. It verifies the connector
// against the pinned roots and server name only (no system roots), sends no
// request twice, follows no redirect and uses no proxy.
type Client struct {
	base   *url.URL
	http   *http.Client
	closer func()
}

func NewClient(endpoint, serverName string, roots *x509.CertPool, certificate func(*tls.CertificateRequestInfo) (*tls.Certificate, error)) (*Client, error) {
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" ||
		serverName == "" || roots == nil || len(roots.Subjects()) == 0 || certificate == nil {
		return nil, ErrRefused
	}
	u.Path = ""
	t := &http.Transport{
		Proxy:               nil,
		DialContext:         (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		TLSClientConfig:     &tls.Config{RootCAs: roots.Clone(), ServerName: serverName, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, GetClientCertificate: certificate},
		TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: collector.PollHold + 10*time.Second,
		MaxIdleConns: 2, MaxIdleConnsPerHost: 2, MaxConnsPerHost: 2, IdleConnTimeout: 60 * time.Second,
		MaxResponseHeaderBytes: 4096, DisableCompression: true, ForceAttemptHTTP2: false,
	}
	c := &http.Client{Transport: t, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return &Client{base: u, http: c, closer: t.CloseIdleConnections}, nil
}

// CloseIdle drops kept-alive connections, so the next request handshakes with
// the current certificate.
func (c *Client) CloseIdle() { c.closer() }

func (c *Client) post(ctx context.Context, path string, timeout time.Duration, in any) ([]byte, int, error) {
	body, err := encode(in)
	if err != nil {
		return nil, 0, ErrRefused
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	u := *c.base
	u.Path = path
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), body)
	if err != nil {
		return nil, 0, ErrRefused
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, 0, ErrUnavailable
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, contracts.NodeMaxResponse+1))
	if err != nil || len(b) > contracts.NodeMaxResponse {
		return nil, resp.StatusCode, ErrUnavailable
	}
	switch resp.StatusCode {
	case http.StatusOK, http.StatusNoContent:
		return b, resp.StatusCode, nil
	case http.StatusUnauthorized:
		return nil, resp.StatusCode, ErrUnauthenticated
	case http.StatusBadRequest, http.StatusForbidden, http.StatusConflict:
		return nil, resp.StatusCode, ErrRefused
	}
	return nil, resp.StatusCode, ErrUnavailable
}

func (c *Client) Enroll(ctx context.Context, r contracts.NodeEnrollRequest) (contracts.NodeEnrollResponse, error) {
	r.Format = contracts.NodeEnrollFormat
	b, code, err := c.post(ctx, contracts.NodeEnrollPath, 30*time.Second, r)
	if err != nil {
		return contracts.NodeEnrollResponse{}, err
	}
	out, err := contracts.DecodeNodeEnrollResponse(bytesReader(b))
	if code != http.StatusOK || err != nil || out.Format != contracts.NodeEnrollFormat || len(out.Certificate) == 0 || len(out.Certificate) > contracts.NodeMaxCertificate {
		return contracts.NodeEnrollResponse{}, ErrUnavailable
	}
	return out, nil
}

func (c *Client) Poll(ctx context.Context, epoch string, after uint64) ([]collector.Work, error) {
	b, code, err := c.post(ctx, contracts.NodePollPath, collector.PollHold+15*time.Second, contracts.NodePollRequest{Format: contracts.NodePollFormat, Epoch: epoch, After: after})
	if err != nil {
		return nil, err
	}
	out, err := contracts.DecodeNodePollResponse(bytesReader(b))
	if code != http.StatusOK || err != nil || out.Format != contracts.NodePollFormat || len(out.Work) > collector.MaxWorkPerPoll {
		return nil, ErrUnavailable
	}
	work := make([]collector.Work, 0, len(out.Work))
	for _, w := range out.Work {
		item, ok := DomainWork(w)
		if !ok {
			return nil, ErrUnavailable
		}
		work = append(work, item)
	}
	return work, nil
}

func (c *Client) Status(ctx context.Context, epoch string, r collector.Report) error {
	_, code, err := c.post(ctx, contracts.NodeStatusPath, 10*time.Second, WireStatus(epoch, r))
	if err == nil && code != http.StatusNoContent {
		return ErrUnavailable
	}
	return err
}
