package native_test

import (
	fleetapp "asservat.local/asservat/internal/application/fleet"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/transport/contextstart"
	native "asservat.local/asservat/internal/transport/native"
)

// Deliberately permissive synthetic serving credentials return a two-name leaf.
// Actual TLS/h2 and the receiving mux must keep existing purposes on exact SNI;
// application authority is synthetic and always denies after counting admission.
type ownerBootstrapAdmission struct{ calls atomic.Int64 }

func (a *ownerBootstrapAdmission) OpenNative(context.Context, *tls.ConnectionState, contracts.NativeHello) (native.Conversation, error) {
	a.calls.Add(1)
	return nil, value.ErrDenied
}
func (a *ownerBootstrapAdmission) AuthenticateContextStart(context.Context, *tls.ConnectionState, contracts.APIContextHello, fleetapp.ConnectorIdentitySourceReader) (value.APIContextReceiver, contextstart.ReceiverCheck, error) {
	a.calls.Add(1)
	return value.APIContextReceiver{}, nil, value.ErrDenied
}

func TestOwnerBootstrapCommonNameCannotEnterExistingNativePurposes(t *testing.T) {
	const exact = "exact-owner.test"
	const common = "bootstrap-owner.test"
	now := time.Now()
	caKey, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour)}
	caDER, e := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caKey.Public(), caKey)
	if e != nil {
		t.Fatal(e)
	}
	ca, e := x509.ParseCertificate(caDER)
	if e != nil {
		t.Fatal(e)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	leaf := func(server bool) tls.Certificate {
		t.Helper()
		key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if e != nil {
			t.Fatal(e)
		}
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(2), BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, NotBefore: ca.NotBefore, NotAfter: ca.NotAfter}
		if server {
			tmpl.SerialNumber = big.NewInt(3)
			tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
			tmpl.DNSNames = []string{exact, common}
		}
		der, e := x509.CreateCertificate(rand.Reader, tmpl, ca, key.Public(), caKey)
		if e != nil {
			t.Fatal(e)
		}
		return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	}
	serverCert, clientCert := leaf(true), leaf(false)
	for _, purpose := range []string{"native", "context-start"} {
		for _, mode := range []string{"exact", "common-sni-exact-host", "common-both", "exact-sni-common-host"} {
			t.Run(purpose+"/"+mode, func(t *testing.T) {
				listener, e := net.Listen("tcp", "127.0.0.1:0")
				if e != nil {
					t.Fatal(e)
				}
				_, port, _ := net.SplitHostPort(listener.Addr().String())
				authority := net.JoinHostPort(exact, port)
				admission := &ownerBootstrapAdmission{}
				handler, e := native.NewHandler(contracts.NativeWorkerPath, authority, admission, 1)
				if e != nil {
					listener.Close()
					t.Fatal(e)
				}
				router, e := contextstart.NewRouter(contextstart.RouterLimits{Standby: 1, Captures: 1, Clusters: []contextstart.ClusterLimit{{ClusterID: nativeID, Standby: 1, Captures: 1}}})
				if e != nil {
					listener.Close()
					t.Fatal(e)
				}
				starts, e := contextstart.NewHandler(authority, router, admission, 1)
				if e != nil {
					listener.Close()
					router.Close()
					t.Fatal(e)
				}
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				done := make(chan error, 1)
				go func() {
					done <- native.ServeWithContextStart(ctx, listener, roots, syntheticServingCertificate{serverCert}, handler, starts, 1, 1)
				}()
				defer func() {
					cancel()
					router.Close()
					if e := <-done; !errors.Is(e, context.Canceled) && !errors.Is(e, context.DeadlineExceeded) {
						t.Error(e)
					}
				}()
				sni, host := exact, authority
				if mode == "common-sni-exact-host" || mode == "common-both" {
					sni = common
				}
				if mode == "common-both" || mode == "exact-sni-common-host" {
					host = net.JoinHostPort(common, port)
				}
				tr := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, Certificates: []tls.Certificate{clientCert}, ServerName: sni, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13}, ForceAttemptHTTP2: true, DisableKeepAlives: true, DialContext: func(call context.Context, network, address string) (net.Conn, error) {
					return (&net.Dialer{}).DialContext(call, network, listener.Addr().String())
				}}
				defer tr.CloseIdleConnections()
				var b bytes.Buffer
				path, media := contracts.NativeWorkerPath, contracts.NativeExchangeMedia
				if purpose == "native" {
					hello, e := json.Marshal(workerHello())
					if e != nil {
						t.Fatal(e)
					}
					if e = contracts.WriteNativeFrame(&b, contracts.NativeFrame{Kind: contracts.NativeHelloFrame, Payload: hello}); e != nil {
						t.Fatal(e)
					}
				} else {
					path, media = contracts.APIContextStartPath, contracts.APIContextStartMedia
					hello, e := contracts.EncodeAPIContextHello(contracts.APIContextHello{Format: contracts.APIContextExchangeFormat, Channel: contracts.APIContextChannel{ExchangeID: nativeID}})
					if e != nil {
						t.Fatal(e)
					}
					if e = contracts.WriteAPIContextFrame(&b, contracts.APIContextFrame{Kind: contracts.APIContextHelloFrame, Payload: hello}); e != nil {
						t.Fatal(e)
					}
					if e = writeTestSource(&b, nativeID); e != nil {
						t.Fatal(e)
					}
				}
				req, e := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+authority+path, io.NopCloser(&b))
				if e != nil {
					t.Fatal(e)
				}
				req.Host = host
				req.ContentLength = -1
				req.Header.Set("Content-Type", media)
				req.Header.Set("Accept", media)
				response, callErr := tr.RoundTrip(req)
				if response != nil {
					io.Copy(io.Discard, response.Body)
					response.Body.Close()
				}
				want := int64(0)
				if mode == "exact" {
					want = 1
					if callErr != nil || response == nil || response.ProtoMajor != 2 {
						t.Fatal("exact h2 route unavailable", callErr)
					}
				}
				if got := admission.calls.Load(); got != want {
					t.Fatalf("existing purpose admission=%d want=%d", got, want)
				}
			})
		}
	}
}
