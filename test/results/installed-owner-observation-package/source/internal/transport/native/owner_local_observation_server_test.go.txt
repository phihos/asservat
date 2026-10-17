package native_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	cfg "asservat.local/asservat/internal/domain/configuration"
	value "asservat.local/asservat/internal/domain/fleet"
	wire "asservat.local/asservat/internal/transport/clusterobservation"
	native "asservat.local/asservat/internal/transport/native"
)

type observationLocalCaller func(context.Context, []byte, string, value.ClusterObservationRequest) (value.ClusterObservationCaller, error)

func (f observationLocalCaller) ObserveClusterObservationCaller(ctx context.Context, token []byte, pod string, r value.ClusterObservationRequest) (value.ClusterObservationCaller, error) {
	return f(ctx, token, pod, r)
}

type observationLocalExchange struct{}

func (observationLocalExchange) ObserveCluster(context.Context, value.ClusterObservationRequest) (value.ClusterObservationResult, error) {
	return value.ClusterObservationResult{}, value.ErrDenied
}

// Actual TLS/path separation; the local caller and owner ingress are synthetic
// denial fixtures. This does not qualify a projection receipt or TokenReview.
func TestOwnerObservationDualListenerKeepsPerPathAuthentication(t *testing.T) {
	for _, mode := range []string{"local-without-cert", "own-without-cert", "own-with-cert", "wrong-route", "wrong-sni", "wrong-host"} {
		t.Run(mode, func(t *testing.T) {
			roots, serverCert, clientCert := observationTLSFixture(t)
			listener, e := net.Listen("tcp", "127.0.0.1:0")
			if e != nil {
				t.Fatal(e)
			}
			_, port, _ := net.SplitHostPort(listener.Addr().String())
			authority := net.JoinHostPort("owner-proof.test", port)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			var ownCalls, localCalls atomic.Int32
			own, e := wire.NewOwnerHandler(ctx, authority, ownerObservationCall(func(context.Context, *tls.ConnectionState, contracts.OwnerObservationRequest) (contracts.OwnerObservationReply, error) {
				ownCalls.Add(1)
				return contracts.OwnerObservationReply{}, value.ErrDenied
			}), 1, time.Now)
			if e != nil {
				listener.Close()
				t.Fatal(e)
			}
			pin := value.ClusterObservationCallerPin{RootID: nativeID, InstallationID: nativeID, ClusterID: nativeID, Namespace: cfg.NamespaceRef{Name: "hub", UID: nativeID}, Account: "hwork", AccountUID: nativeID, Deployment: "hwork", DeploymentUID: nativeID, TemplateDigest: artifact.Digest{1}, ImageDigest: artifact.Digest{2}, ProtectionDigest: artifact.Digest{3}}
			local, e := wire.NewLocalHandler(ctx, authority, pin, observationLocalCaller(func(context.Context, []byte, string, value.ClusterObservationRequest) (value.ClusterObservationCaller, error) {
				localCalls.Add(1)
				return value.ClusterObservationCaller{}, value.ErrDenied
			}), observationLocalExchange{}, 1, time.Now)
			if e != nil {
				listener.Close()
				own.Close()
				t.Fatal(e)
			}
			done := make(chan error, 1)
			go func() {
				done <- native.ServeOwnerLocalObservation(ctx, listener, roots, syntheticServingCertificate{serverCert}, own, local, 2)
			}()
			defer func() {
				cancel()
				_ = listener.Close()
				own.Close()
				local.Close()
				select {
				case <-done:
				case <-time.After(time.Second):
					t.Error("listener did not join")
				}
			}()
			config := &tls.Config{RootCAs: roots, ServerName: "owner-proof.test", MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13}
			if mode == "own-with-cert" {
				config.Certificates = []tls.Certificate{clientCert}
			}
			if mode == "wrong-sni" {
				config.ServerName = "exact-owner.test"
			}
			tr := &http.Transport{TLSClientConfig: config, ForceAttemptHTTP2: true, DisableKeepAlives: true, DialContext: func(c context.Context, network, address string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(c, network, listener.Addr().String())
			}}
			defer tr.CloseIdleConnections()
			path, media := contracts.ClusterObservationLocalPath, contracts.ClusterObservationLocalMedia
			now := time.Now()
			request := value.ClusterObservationRequest{ID: nativeID, Challenge: nativeID, RootID: nativeID, ClusterID: nativeID, Purpose: value.ObserveCapacityNamespaces, RequestedAt: now, NotAfter: now.Add(3 * time.Second)}
			body, e := contracts.EncodeClusterObservationLocalRequest(contracts.ClusterObservationLocalRequest{Format: contracts.ClusterObservationLocalFormat, PodUID: nativeID, Observation: wire.RequestWire(request)})
			if e != nil {
				t.Fatal(e)
			}
			if mode == "own-without-cert" || mode == "own-with-cert" {
				path, media = contracts.OwnerObservationPath, contracts.OwnerObservationMedia
				body, e = contracts.EncodeOwnerObservationRequest(observationWireRequest())
				if e != nil {
					t.Fatal(e)
				}
			}
			if mode == "wrong-route" {
				path = contracts.NativeOwnerPath
			}
			r, e := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+authority+path, io.NopCloser(bytes.NewReader(body)))
			if e != nil {
				t.Fatal(e)
			}
			r.ContentLength = int64(len(body))
			r.Header.Set("Content-Type", media)
			r.Header.Set("Accept", media)
			if path != contracts.OwnerObservationPath {
				r.Header.Set("Authorization", "Bearer synthetic-observation-token")
			}
			if mode == "wrong-host" {
				r.Host = "exact-owner.test:" + port
			}
			response, e := (&http.Client{Transport: tr, Timeout: 3 * time.Second}).Do(r)
			if e == nil {
				_, _ = io.Copy(io.Discard, response.Body)
				response.Body.Close()
				if response.StatusCode != http.StatusNotFound {
					t.Fatal("unexpected admission status", response.StatusCode)
				}
			} else if mode != "wrong-sni" {
				t.Fatal(e)
			}
			wantLocal, wantOwn := int32(0), int32(0)
			if mode == "local-without-cert" {
				wantLocal = 1
			}
			if mode == "own-with-cert" {
				wantOwn = 1
			}
			if localCalls.Load() != wantLocal || ownCalls.Load() != wantOwn {
				t.Fatal("route crossed authentication purpose", localCalls.Load(), ownCalls.Load())
			}
		})
	}
}
