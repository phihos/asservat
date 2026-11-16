package connectorlifecycle

import (
	"context"
	"crypto/x509"
	"io"
	"net"
	"net/http/httptest"
	"testing"
	"time"

	value "asservat.local/asservat/internal/domain/fleet"
)

type tunnelTokens struct{ until time.Time }

func (t tunnelTokens) VerifyConnectorUntil(_ context.Context, token string) (value.ConnectorCluster, time.Time, error) {
	if token != "synthetic-token" {
		return value.ConnectorCluster{}, time.Time{}, value.ErrDenied
	}
	return value.ConnectorCluster{}, t.until, nil
}

// The tunnel relays a connector's byte stream to an allowed hub service over
// the hub connection; other targets and tokens are refused, and the token's
// expiry ends it.
func TestTunnelRelaysOnlyAllowedTargets(t *testing.T) {
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		for {
			c, err := echo.Accept()
			if err != nil {
				return
			}
			go func() { _, _ = io.Copy(c, c); c.Close() }()
		}
	}()
	allowed := echo.Addr().String()
	tokens := &tunnelTokens{until: time.Now().Add(time.Minute)}
	h := &TunnelHandler{Tokens: tokens, Allowed: func(_ context.Context, target string) bool { return target == allowed }, Dial: (&net.Dialer{}).DialContext}
	server := httptest.NewUnstartedServer(h)
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	client, err := NewClient(server.URL, roots, syntheticToken)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	conn, err := client.DialTunnel(t.Context(), "tcp", allowed)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = conn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 4)
	if _, err = io.ReadFull(conn, got); err != nil || string(got) != "ping" {
		t.Fatal("echo", string(got), err)
	}
	// A deadline ends the tunnel.
	_ = conn.SetDeadline(time.Now().Add(50 * time.Millisecond))
	if _, err = conn.Read(got); err == nil {
		t.Fatal("read after the deadline")
	}
	if _, err = client.DialTunnel(t.Context(), "tcp", "127.0.0.1:1"); err == nil {
		t.Fatal("unlisted target relayed")
	}
	stranger, _ := NewClient(server.URL, roots, func() ([]byte, error) { return []byte("other"), nil })
	defer stranger.Close()
	if _, err = stranger.DialTunnel(t.Context(), "tcp", allowed); err == nil {
		t.Fatal("unknown token relayed")
	}
	// An expired token ends the relay at once.
	tokens.until = time.Now()
	if conn, err = client.DialTunnel(t.Context(), "tcp", allowed); err == nil {
		_, _ = conn.Write([]byte("x"))
		if _, err = io.ReadFull(conn, got[:1]); err == nil {
			t.Fatal("relay past the token's expiry")
		}
		conn.Close()
	}
}
