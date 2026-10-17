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

	app "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/contracts"
	value "asservat.local/asservat/internal/domain/fleet"
)

// Client is the regional side of one ADR-169 conversation. It dials the
// pinned hub, signs the opening over this connection's exporter and answers
// each phase request with the local in-cluster lifecycle reader. No retry.
type Client struct {
	address, host string
	roots         *x509.CertPool
}

// NewClient pins the hub endpoint, the server name its certificate must carry
// and the issuer roots. The name is separate from the dialed address so an
// installer-pinned identity survives any reachable address.
func NewClient(endpoint, serverName string, roots *x509.CertPool) (*Client, error) {
	u, err := url.Parse(endpoint)
	if err != nil || roots == nil || serverName == "" || u.Scheme != "https" || u.Host == "" || u.Path != "" || u.RawQuery != "" || u.User != nil || u.Port() == "" {
		return nil, ErrChannel
	}
	return &Client{address: u.Host, host: serverName, roots: roots}, nil
}

// Run returns the hub's final frame. open builds the opening for this
// connection's exporter; local performs the in-cluster native and source reads.
func (c *Client) Run(ctx context.Context, open func(exporter []byte) (Opening, error), local Local) (HubFrame, error) {
	var zero HubFrame
	if c == nil || ctx == nil || open == nil || local == nil {
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
	state := conn.ConnectionState()
	exporter, err := state.ExportKeyingMaterial(value.ClusterCredentialExporter, nil, contracts.ClusterCredentialExporterLen)
	if err != nil || state.NegotiatedProtocol != "h2" {
		return zero, ErrChannel
	}
	opening, err := open(exporter)
	if err != nil {
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
	var operation app.ConnectorLifecycleOperation
	// The begun operation and its reads end no later than its original
	// NotAfter; the conversation's own longer bound never extends them.
	opCtx, begun := ctx, false
	defer func() {
		if operation != nil {
			operation.Close()
		}
	}()
	for range 2 * MaxRegionFrame {
		var frame HubFrame
		if in.Receive(ctx, &frame) != nil {
			return zero, ErrChannel
		}
		var reply RegionFrame
		switch {
		case frame.Kind == "begin" && frame.Begin != nil && !begun: // one operation per conversation
			begun = true
			var stop context.CancelFunc
			opCtx, stop = context.WithDeadline(ctx, frame.Begin.Binding.NotAfter)
			defer stop()
			if operation, err = local.BeginConnectorLifecycle(opCtx, *frame.Begin); err != nil {
				_ = out.Send(RegionFrame{Kind: "error"})
				return zero, ErrChannel
			}
			reply.Kind = "begun"
		case frame.Kind == "read" && operation != nil:
			obs, err := operation.Read(opCtx, frame.Phase)
			if err != nil {
				_ = out.Send(RegionFrame{Kind: "error"})
				return zero, ErrChannel
			}
			reply = RegionFrame{Kind: "observation", Observation: &obs}
		case frame.Kind == "source":
			src, err := local.ReadConnectorIdentitySource(ctx)
			if err != nil {
				_ = out.Send(RegionFrame{Kind: "error"})
				return zero, ErrChannel
			}
			reply = RegionFrame{Kind: "source", Source: &src}
		case frame.Kind == "configuration":
			cfg, err := local.ReadConnectorIdentityConfiguration(ctx)
			if err != nil {
				_ = out.Send(RegionFrame{Kind: "error"})
				return zero, ErrChannel
			}
			reply = RegionFrame{Kind: "configuration", Configuration: &cfg}
		case frame.Kind == "close" && operation != nil:
			operation.Close()
			operation = nil
			continue
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
