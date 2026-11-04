package bootstrap

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/diagnostics"
	"asservat.local/asservat/internal/adapters/mtls"
	executionapp "asservat.local/asservat/internal/application/execution"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/collector"
	"asservat.local/asservat/internal/domain/execution"
)

type profileTLSFixtureDialer struct {
	connection net.Conn
	material   execution.GoProfileTLSMaterial
	calls      int
}

func (d *profileTLSFixtureDialer) DialGoProfile(ctx context.Context, r execution.GoProfileRequest) (executionapp.GoProfileChannel, error) {
	d.calls++
	connection, err := nodeProfileTLSConnection(ctx, d.connection, d.material)
	return executionapp.GoProfileChannel{Connection: connection, Host: "profile.internal", ValidUntil: r.Deadline}, err
}

func TestNodeProfileTLSCollectsOnlyOverExactVerifiedSocket(t *testing.T) {
	cert, _, roots := serverCertificate(t)
	canonical, digest, err := mtls.CanonicalProfileRoots(roots)
	if err != nil {
		t.Fatal(err)
	}
	material := execution.GoProfileTLSMaterial{RootsPEM: canonical, RootsDigest: digest, ServerName: "asservat-connector-nodes"}
	for _, mode := range []string{"verified", "wrong-name", "wrong-roots", "noncanonical", "bad-digest"} {
		t.Run(mode, func(t *testing.T) {
			var requests atomic.Int32
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				if r.TLS == nil || r.TLS.ServerName != material.ServerName || r.ProtoMajor != 1 || r.URL.Path != "/debug/pprof/heap" || r.URL.RawQuery != "debug=0" || r.Header.Get("Authorization") != "" {
					t.Error("TLS acquisition route or credential changed")
				}
				w.Header().Set("Content-Type", execution.GoProfileMediaType)
				_, _ = w.Write([]byte("native-profile"))
			}))
			server.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}}
			server.StartTLS()
			defer server.Close()
			ctx, cancel := context.WithTimeout(t.Context(), 4*time.Second)
			defer cancel()
			raw, err := (&net.Dialer{}).DialContext(ctx, "tcp", server.Listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer raw.Close()
			bad := material
			switch mode {
			case "wrong-name":
				bad.ServerName = "different.internal"
			case "wrong-roots":
				_, _, other := serverCertificate(t)
				bad.RootsPEM, bad.RootsDigest, err = mtls.CanonicalProfileRoots(other)
			case "noncanonical":
				bad.RootsPEM = "\n" + bad.RootsPEM
				bad.RootsDigest = artifact.Digest(sha256.Sum256([]byte(bad.RootsPEM)))
			case "bad-digest":
				bad.RootsDigest[0] ^= 1
			}
			now := time.Now().UTC().Truncate(time.Microsecond)
			const id = "11111111-1111-4111-8111-111111111111"
			request := execution.GoProfileRequest{Binding: artifact.Binding{ClusterID: id, ArtifactID: id, AttemptID: id, MediaType: artifact.ProfileMediaType}, Pin: artifact.PinnedPod{Namespace: "app", NamespaceUID: id, Name: "app", UID: id, NodeName: "node"}, NodeUID: id, NodeBootID: id, SourceRef: "pprof", EndpointDigest: artifact.Digest{1}, Parameters: execution.GoProfileParameters{Type: "heap", Mode: "snapshot"}, NativeLimit: 16 << 20, NotBefore: now, Deadline: now.Add(4 * time.Second)}
			p := collector.ProfileCapture{CollectorEpoch: id, Request: request}
			guard := nodeProfileMechanism{p: p, identity: func() collector.Identity { return collector.Identity{Epoch: id, NodeUID: id, BootID: id} }, now: time.Now}
			dialer := &profileTLSFixtureDialer{connection: raw, material: bad}
			collector, err := diagnostics.NewGoProfileCollector(dialer, guard, time.Now)
			if err != nil {
				t.Fatal(err)
			}
			var native bytes.Buffer
			outcome, err := collector.CollectGoProfileNative(ctx, request, &native)
			if mode == "verified" {
				if err != nil || !outcome.ResponseComplete || native.String() != "native-profile" || requests.Load() != 1 {
					t.Fatal("verified TLS profile", outcome, err, requests.Load())
				}
			} else if err == nil || requests.Load() != 0 || native.Len() != 0 || outcome.MayHaveStarted {
				t.Fatal("unverified peer reached application HTTP", err, requests.Load(), outcome)
			}
			if dialer.calls != 1 {
				t.Fatal("TLS acquisition retried", dialer.calls)
			}
		})
	}
}

func TestNodeProfileTLSHandshakePreservesCancellationAndClosesSocket(t *testing.T) {
	_, _, roots := serverCertificate(t)
	canonical, digest, err := mtls.CanonicalProfileRoots(roots)
	if err != nil {
		t.Fatal(err)
	}
	material := execution.GoProfileTLSMaterial{RootsPEM: canonical, RootsDigest: digest, ServerName: "asservat-connector-nodes"}
	for _, mode := range []string{"cancelled", "deadline", "plaintext"} {
		t.Run(mode, func(t *testing.T) {
			client, server := net.Pipe()
			defer server.Close()
			joined := make(chan struct{})
			go func() {
				defer close(joined)
				if mode == "plaintext" {
					b := make([]byte, 4096)
					_, _ = server.Read(b)
					_, _ = io.WriteString(server, "HTTP/1.1 200 OK\r\n\r\n")
				}
				_, _ = io.Copy(io.Discard, server)
			}()
			ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
			defer cancel()
			if mode == "cancelled" {
				cancel()
			}
			start := time.Now()
			secure, err := nodeProfileTLSConnection(ctx, client, material)
			if err == nil || secure != nil || time.Since(start) > time.Second {
				t.Fatal("TLS handshake escaped original cutoff", err, time.Since(start))
			}
			select {
			case <-joined:
			case <-time.After(time.Second):
				t.Fatal("failed handshake left socket open")
			}
		})
	}
}
