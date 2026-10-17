package mtls

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"asservat.local/asservat/internal/contracts"
	value "asservat.local/asservat/internal/domain/fleet"
)

// ClusterCredentialClient performs one ADR-168 exchange per TLS connection.
// The signature covers this connection's exporter, so the request is built
// after the handshake and sent over exactly that connection: no reuse, retry,
// redirect or proxy. Server trust is the installation-pinned hub roots only.
type ClusterCredentialClient struct {
	address, host string
	roots         *x509.CertPool
}

// NewClusterCredentialClient pins the hub endpoint, the server name its
// certificate must carry and the issuer roots, independently of the address.
func NewClusterCredentialClient(endpoint, serverName string, roots *x509.CertPool) (*ClusterCredentialClient, error) {
	u, err := url.Parse(endpoint)
	if err != nil || roots == nil || serverName == "" || u.Scheme != "https" || u.Host == "" || u.Path != "" || u.RawQuery != "" || u.User != nil || u.Port() == "" {
		return nil, value.ErrClusterCredentialDenied
	}
	return &ClusterCredentialClient{address: u.Host, host: serverName, roots: roots}, nil
}

// Exchange signs r over the connection's exporter with sign. A 409 reply is
// the permanent fence; every other failure is a denial or an unknown outcome
// that the caller may only repeat as the same logical request.
func (c *ClusterCredentialClient) Exchange(ctx context.Context, r value.ClusterCredentialRequest, sign func(exporter []byte) ([]byte, error)) (contracts.ClusterCredentialReply, error) {
	var zero contracts.ClusterCredentialReply
	if c == nil || ctx == nil || sign == nil || !r.Valid() {
		return zero, value.ErrClusterCredentialDenied
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	dialer := tls.Dialer{Config: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: c.roots, ServerName: c.host, NextProtos: []string{"http/1.1"}}}
	raw, err := dialer.DialContext(ctx, "tcp", c.address)
	if err != nil {
		return zero, value.ErrClusterCredentialDenied
	}
	conn := raw.(*tls.Conn)
	defer conn.Close()
	state := conn.ConnectionState()
	exporter, err := state.ExportKeyingMaterial(value.ClusterCredentialExporter, nil, contracts.ClusterCredentialExporterLen)
	if err != nil || state.Version != tls.VersionTLS13 {
		return zero, value.ErrClusterCredentialDenied
	}
	signature, err := sign(exporter)
	if err != nil {
		return zero, value.ErrClusterCredentialDenied
	}
	wire := contracts.ClusterCredentialWire{Format: contracts.ClusterCredentialWireFormat, Operation: r.Operation, RootID: r.Profile.RootID, PeerID: r.Profile.PeerID, InstallationID: r.Profile.InstallationID, ClusterID: r.Profile.ClusterID, Generation: r.Generation, PodUID: r.PodUID, ProcessEpoch: r.ProcessEpoch, NextKey: r.NextKey, RequestedAt: r.RequestedAt, Signature: signature}
	if r.Operation != value.ClusterRotation {
		wire.ClientKey, wire.ServerKey = r.ClientKey[:], r.ServerKey[:]
	}
	body, err := json.Marshal(wire)
	if err != nil || len(body) > contracts.ClusterCredentialMaxRequest {
		return zero, value.ErrClusterCredentialDenied
	}
	var once sync.Once
	transport := &http.Transport{
		DialTLSContext: func(context.Context, string, string) (net.Conn, error) {
			var out net.Conn
			once.Do(func() { out = conn })
			if out == nil {
				return nil, errors.New("cluster enrollment connection already used")
			}
			return out, nil
		},
		DisableKeepAlives: true, MaxResponseHeaderBytes: 4 << 10, Proxy: nil,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+c.address+contracts.ClusterCredentialPath, bytes.NewReader(body))
	if err != nil {
		return zero, value.ErrClusterCredentialDenied
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return zero, value.ErrClusterCredentialDenied
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusConflict:
		return zero, value.ErrClusterCredentialFenced
	default:
		return zero, value.ErrClusterCredentialDenied
	}
	reply, err := contracts.DecodeClusterCredentialReply(resp.Body)
	if err != nil || reply.Generation < 1 || !reply.CheckedAt.Before(reply.ValidUntil) {
		return zero, value.ErrClusterCredentialDenied
	}
	return reply, nil
}

// ExchangeClusterCredential adapts Exchange to the application port.
func (c *ClusterCredentialClient) ExchangeClusterCredential(ctx context.Context, r value.ClusterCredentialRequest, sign func([]byte) ([]byte, error)) (int64, error) {
	reply, err := c.Exchange(ctx, r, sign)
	return reply.Generation, err
}
