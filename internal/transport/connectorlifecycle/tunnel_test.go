package connectorlifecycle

import (
	"context"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	value "asservat.local/asservat/internal/domain/fleet"
)

type tunnelTokens struct{ until time.Time }

func (t *tunnelTokens) VerifyConnectorUntil(_ context.Context, token string) (value.ConnectorCluster, time.Time, error) {
	if token != "synthetic-token" {
		return value.ConnectorCluster{}, time.Time{}, value.ErrDenied
	}
	return value.ConnectorCluster{}, t.until, nil
}

// tunnelFixture serves the tunnel over real HTTP/2 to a local echo service.
func tunnelFixture(t *testing.T) (*Client, string, *httptest.Server, *x509.CertPool, *tunnelTokens) {
	t.Helper()
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { echo.Close() })
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
	client, server, roots := serveTunnel(t, h)
	return client, allowed, server, roots, tokens
}

func serveTunnel(t *testing.T, h *TunnelHandler) (*Client, *httptest.Server, *x509.CertPool) {
	t.Helper()
	server := httptest.NewUnstartedServer(h)
	server.EnableHTTP2 = true
	server.StartTLS()
	t.Cleanup(server.Close)
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	client, err := NewClient(server.URL, roots, syntheticToken)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	return client, server, roots
}

func echoOnce(t *testing.T, conn net.Conn, msg string) {
	t.Helper()
	if _, err := conn.Write([]byte(msg)); err != nil {
		t.Fatal("write", err)
	}
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, got); err != nil || string(got) != msg {
		t.Fatal("echo", string(got), err)
	}
}

// The tunnel relays a connector's byte stream to an allowed hub service over
// the hub connection; other targets and tokens are refused, and the token's
// expiry ends it.
func TestTunnelRelaysOnlyAllowedTargets(t *testing.T) {
	client, allowed, server, roots, tokens := tunnelFixture(t)
	conn, err := client.DialTunnel(t.Context(), "tcp", allowed)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	echoOnce(t, conn, "ping")
	if _, err = client.DialTunnel(t.Context(), "tcp", "127.0.0.1:1"); err == nil {
		t.Fatal("unlisted target relayed")
	}
	stranger, _ := NewClient(server.URL, roots, func() ([]byte, error) { return []byte("other"), nil })
	defer stranger.Close()
	if _, err = stranger.DialTunnel(t.Context(), "tcp", allowed); err == nil {
		t.Fatal("unknown token relayed")
	}
	tokens.until = time.Now()
	if late, err := client.DialTunnel(t.Context(), "tcp", allowed); err == nil {
		_, _ = late.Write([]byte("x"))
		if _, err = io.ReadFull(late, make([]byte, 1)); err == nil {
			t.Fatal("relay past the token's expiry")
		}
		late.Close()
	}
}

// Deadlines follow net.Conn: per direction, an expired one fails only the
// blocked call with os.ErrDeadlineExceeded and the stream stays usable.
func TestTunnelDeadlinesArePerDirection(t *testing.T) {
	client, allowed, _, _, _ := tunnelFixture(t)
	conn, err := client.DialTunnel(t.Context(), "tcp", allowed)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	buf := make([]byte, 1)

	// An expired read deadline fails the read; writes still work.
	_ = conn.SetReadDeadline(time.Now().Add(30 * time.Millisecond))
	if _, err = conn.Read(buf); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatal("read deadline", err)
	}
	if _, err = conn.Write([]byte("a")); err != nil {
		t.Fatal("write after a read deadline", err)
	}
	// Clearing the read deadline restores reads on the same stream.
	_ = conn.SetReadDeadline(time.Time{})
	if _, err = io.ReadFull(conn, buf); err != nil || buf[0] != 'a' {
		t.Fatal("read after clearing", err)
	}

	// A write deadline does not affect reads, and clearing the read
	// deadline keeps the write deadline.
	_ = conn.SetWriteDeadline(time.Now().Add(time.Hour))
	_ = conn.SetReadDeadline(time.Now().Add(time.Hour))
	_ = conn.SetReadDeadline(time.Time{})
	echoOnce(t, conn, "b")
	_ = conn.SetWriteDeadline(time.Now().Add(-time.Second))
	if _, err = conn.Write([]byte("c")); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatal("expired write deadline", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(30 * time.Millisecond))
	if _, err = conn.Read(buf); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatal("read deadline beside an expired write deadline", err)
	}
	_ = conn.SetDeadline(time.Time{})
	echoOnce(t, conn, "d")
}

// Close with pending deadlines ends the tunnel and the conn at once.
func TestTunnelCloseStopsDeadlines(t *testing.T) {
	client, allowed, _, _, _ := tunnelFixture(t)
	conn, err := client.DialTunnel(t.Context(), "tcp", allowed)
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.SetDeadline(time.Now().Add(time.Hour))
	tc := conn.(*tunnelConn)
	if err = conn.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = conn.Read(make([]byte, 1)); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatal("read after close", err)
	}
	if err = tc.Conn.SetDeadline(time.Now()); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatal("deadline after close", err)
	}
}

type tunnelOwnerRoutes map[value.OwnerBinding]string

func (r tunnelOwnerRoutes) CurrentOwnerRoute(_ context.Context, owner value.OwnerBinding) (value.OwnerRoute, error) {
	ip, ok := r[owner]
	if !ok {
		return value.OwnerRoute{}, value.ErrUnavailable
	}
	return value.OwnerRoute{Endpoint: value.OwnerEndpoint{Binding: owner, Pool: value.OwnerPool{NativePort: 9444}, Addresses: []string{ip}}}, nil
}

// Both replicas sit behind the same native Service. Only the hub's endpoint
// lookup can choose a Pod IP. The connector supplies the waiting binding.
func TestOwnerTunnelReachesTheRequestedReplica(t *testing.T) {
	id := func(n string) string { return "10000000-0000-4000-8000-0000000000" + n }
	first := value.OwnerBinding{InstallationID: id("01"), ClusterID: id("02"), IssuerEpoch: id("03"), PodUID: id("04"), ProcessEpoch: id("05")}
	second := first
	second.PodUID, second.ProcessEpoch = id("06"), id("07")
	routes := tunnelOwnerRoutes{first: "10.0.0.11", second: "10.0.0.12"}
	tokens := &tunnelTokens{until: time.Now().Add(time.Minute)}
	dials := make(chan string, 2)
	h := &TunnelHandler{Tokens: tokens, Owners: routes, Allowed: func(context.Context, string) bool { return false },
		Dial: func(_ context.Context, _, address string) (net.Conn, error) {
			dials <- address
			local, remote := net.Pipe()
			go func() { _, _ = io.Copy(remote, remote); remote.Close() }()
			return local, nil
		},
	}
	client, _, _ := serveTunnel(t, h)
	for _, owner := range []value.OwnerBinding{first, second} {
		conn, err := client.DialOwner(t.Context(), owner)
		if err != nil {
			t.Fatal(err)
		}
		echoOnce(t, conn, owner.PodUID)
		conn.Close()
		if got, want := <-dials, net.JoinHostPort(routes[owner], "9444"); got != want {
			t.Fatalf("tunnel to %s dialed %s, want %s", owner.PodUID, got, want)
		}
	}
	unknown := second
	unknown.PodUID = id("08")
	if conn, err := client.DialOwner(t.Context(), unknown); err == nil {
		conn.Close()
		t.Fatal("opened for an unknown owner binding")
	}
	if conn, err := client.DialTunnel(t.Context(), "tcp", "10.0.0.12:9444"); err == nil {
		conn.Close()
		t.Fatal("opened directly to a caller-supplied Pod address")
	}
	if len(dials) != 0 {
		t.Fatal("refused owner or address reached a backend")
	}
}
