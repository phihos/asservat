package native

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/transport/clusterobservation"
	"golang.org/x/net/netutil"
)

// OwnerLocalObservationOperationReceiver is the closed receiving port owned by
// this listener. Bootstrap supplies its concrete current SQL/native receiver;
// transport cannot import bootstrap. These two authorities select only the
// fixed locator/claim purposes, never a caller-populated router or URL callback.
type OwnerLocalObservationOperationReceiver interface {
	CommonAuthority() string
	ExactAuthority() string
	ServeHTTP(http.ResponseWriter, *http.Request)
}

// ServeOwnerObservationOperation is the separate ADR150 v2 listener. It serves
// exactly common-SNI local locator GET, exact-SNI local claim POST and the
// common-SNI regional v2 standby POST. Only the two dedicated HWORK token paths
// may omit a client certificate. All native/SQL/token authority remains with
// the concrete receiving handlers. Existing v1 listeners are unchanged.
//
// The shared nativeListener/nativeConn retain original accept-time thirty-second
// residency, two-second TLS/header prelude, five-second finite-proof shortening,
// one HTTP request, leaf shortening and joined close before releasing a slot.
// Purpose and total ceilings are per process, not installation capacity. This
// entry point does not acknowledge backend inputs or select an installed mode.
func ServeOwnerObservationOperation(ctx context.Context, listener net.Listener, roots *x509.CertPool, credentials ServerCredentials, local OwnerLocalObservationOperationReceiver, regional *clusterobservation.HubObservationOperationHandler, proofConnections, regionalConnections int) error {
	connections := proofConnections + regionalConnections
	if ctx == nil || ctx.Err() != nil || listener == nil || roots == nil || len(roots.Subjects()) == 0 || credentials == nil || local == nil || regional == nil || proofConnections < 1 || proofConnections > 64 || regionalConnections < 1 || regionalConnections > 64 || connections > 64 {
		return contracts.ErrNativeProtocol
	}
	commonHost, exactHost := local.CommonAuthority(), local.ExactAuthority()
	commonName, commonPort, validCommon := ownerOperationAuthority(commonHost)
	exactName, exactPort, validExact := ownerOperationAuthority(exactHost)
	if !validCommon || !validExact || commonName == exactName || commonPort != exactPort || regional.Authority() != commonHost {
		return contracts.ErrNativeProtocol
	}
	root, cancel := context.WithCancel(ctx)
	defer cancel()
	residency, prelude := 30*time.Second, 2*time.Second
	owned := &nativeListener{Listener: netutil.LimitListener(listener, connections), root: root, residency: residency, prelude: prelude}
	proofSlots, regionalSlots := make(chan struct{}, proofConnections), make(chan struct{}, regionalConnections)
	defer owned.Close()
	config := &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, ClientAuth: tls.VerifyClientCertIfGiven, ClientCAs: roots.Clone(), SessionTicketsDisabled: true, NextProtos: []string{"h2"}}
	config.VerifyConnection = func(s tls.ConnectionState) error {
		if root.Err() != nil || s.DidResume || s.Version != tls.VersionTLS13 || s.NegotiatedProtocol != "h2" || (s.ServerName != commonName && s.ServerName != exactName) || len(s.PeerCertificates) > 0 && len(s.VerifiedChains) == 0 {
			return contracts.ErrNativeProtocol
		}
		return nil
	}
	config.GetCertificate = func(h *tls.ClientHelloInfo) (*tls.Certificate, error) {
		if h == nil || (h.ServerName != commonName && h.ServerName != exactName) || !slices.Contains(h.SupportedProtos, "h2") || root.Err() != nil {
			return nil, contracts.ErrNativeProtocol
		}
		connection, ok := h.Conn.(*nativeConn)
		if !ok || connection.ctx.Err() != nil {
			return nil, contracts.ErrNativeProtocol
		}
		cert, e := credentials.GetCertificate(h)
		if e != nil || cert == nil || cert.PrivateKey == nil || len(cert.Certificate) < 1 || len(cert.Certificate) > 4 {
			return nil, contracts.ErrNativeProtocol
		}
		leaf, e := x509.ParseCertificate(cert.Certificate[0])
		now := time.Now()
		if e != nil || leaf.IsCA || len(leaf.ExtKeyUsage) != 1 || leaf.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth || len(leaf.UnknownExtKeyUsage) != 0 || now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) || leaf.VerifyHostname(h.ServerName) != nil || connection.ctx.Err() != nil || root.Err() != nil || connection.shorten(leaf.NotAfter) != nil {
			return nil, contracts.ErrNativeProtocol
		}
		return cert, nil
	}
	protocols := &http.Protocols{}
	protocols.SetHTTP2(true)
	server := &http.Server{TLSConfig: config, Protocols: protocols, HTTP2: &http.HTTP2Config{MaxConcurrentStreams: 1, MaxDecoderHeaderTableSize: 4096, MaxEncoderHeaderTableSize: 4096, MaxReadFrameSize: 16 << 10, MaxReceiveBufferPerConnection: 16 << 10, MaxReceiveBufferPerStream: 16 << 10}, ReadHeaderTimeout: 2 * time.Second, ReadTimeout: residency, WriteTimeout: residency, IdleTimeout: time.Second, MaxHeaderBytes: 8 << 10, ErrorLog: log.New(io.Discard, "", 0)}
	server.BaseContext = func(net.Listener) context.Context { return root }
	server.ConnContext = func(_ context.Context, c net.Conn) context.Context {
		if t, ok := c.(*tls.Conn); ok {
			if b, ok := t.NetConn().(*nativeConn); ok {
				return context.WithValue(b.ctx, nativeConnectionKey{}, b)
			}
		}
		denied, stop := context.WithCancel(root)
		stop()
		return denied
	}
	server.SetKeepAlivesEnabled(false)
	var mu sync.Mutex
	var active sync.WaitGroup
	closing := false
	server.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		connection, ok := r.Context().Value(nativeConnectionKey{}).(*nativeConn)
		if !ok || !connection.beginRequest() {
			return
		}
		defer close(connection.handlerDone)
		// Classify only the closed actual SNI + authority + method + path tuple.
		// Local locator's canonical query is decoded by its concrete receiver.
		if r.TLS == nil || r.URL == nil || r.URL.Host != "" || r.URL.Scheme != "" || r.URL.User != nil || r.URL.RawPath != "" || r.URL.Fragment != "" || r.URL.RequestURI() != r.RequestURI {
			unavailable(w)
			return
		}
		locator := r.Method == http.MethodGet && r.TLS.ServerName == commonName && r.Host == commonHost && r.URL.Path == contracts.ClusterObservationLocalLocatorPath
		claim := r.Method == http.MethodPost && r.TLS.ServerName == exactName && r.Host == exactHost && r.RequestURI == contracts.ClusterObservationLocalClaimPath
		standby := r.Method == http.MethodPost && r.TLS.ServerName == commonName && r.Host == commonHost && r.RequestURI == contracts.ClusterObservationOperationExchangePath
		if (!locator && !claim && !standby) || (locator || claim) && len(r.TLS.PeerCertificates) != 0 || standby && (len(r.TLS.PeerCertificates) == 0 || len(r.TLS.VerifiedChains) == 0) {
			unavailable(w)
			return
		}
		{
			// Original accept time owns both purposes. Selecting a valid path
			// can only shorten residency; idle standby cannot consume the
			// separately prepaid finite-proof slots.
			lifetime, slots := 5*time.Second, proofSlots
			if standby {
				lifetime, slots = 30*time.Second, regionalSlots
			}
			select {
			case slots <- struct{}{}:
				connection.mu.Lock()
				connection.release = func() { <-slots }
				connection.mu.Unlock()
			default:
				unavailable(w)
				return
			}
			if connection.finishPrelude() != nil || connection.shorten(connection.accepted.Add(lifetime)) != nil {
				return
			}
			// The TLS pre-authentication root union does not select a peer.
			// The concrete per-path handler verifies its installed identity;
			// even before that, a presented leaf may only shorten this socket.
			if len(r.TLS.PeerCertificates) > 0 && connection.shorten(r.TLS.PeerCertificates[0].NotAfter) != nil {
				return
			}
			connection.mu.Lock()
			until := connection.until
			connection.mu.Unlock()
			call, end := context.WithDeadline(r.Context(), until)
			interrupted := make(chan struct{})
			stopCall := context.AfterFunc(call, func() {
				connection.cancel()
				_ = connection.Conn.Close()
				close(interrupted)
			})
			defer func() {
				if !stopCall() {
					<-interrupted
				}
				end()
			}()
			r = r.WithContext(call)
		}
		mu.Lock()
		if closing || root.Err() != nil || r.Context().Err() != nil {
			mu.Unlock()
			unavailable(w)
			return
		}
		active.Add(1)
		mu.Unlock()
		defer active.Done()
		if standby {
			regional.ServeHTTP(w, r)
			return
		}
		local.ServeHTTP(w, r)
	})
	done := make(chan struct{})
	stop := context.AfterFunc(root, func() { _ = server.Close(); close(done) })
	err := server.Serve(tls.NewListener(owned, config))
	cancel()
	_ = server.Close()
	if !stop() {
		<-done
	}
	mu.Lock()
	closing = true
	mu.Unlock()
	active.Wait()
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if errors.Is(err, http.ErrServerClosed) {
		return contracts.ErrNativeProtocol
	}
	return err
}

// The original accepted tuple is immutable for the server lifetime. Reject
// ambiguous/noncanonical names and ports before opening TLS or receiving work.
func ownerOperationAuthority(authority string) (string, int, bool) {
	name, port, err := net.SplitHostPort(authority)
	n, parse := strconv.Atoi(port)
	if err != nil || parse != nil || n < 1024 || n > 65535 || strconv.Itoa(n) != port || name == "" || len(name) > 253 || name != strings.ToLower(name) || net.ParseIP(name) != nil || strings.HasSuffix(name, ".") {
		return "", 0, false
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", 0, false
		}
		for _, c := range label {
			if c != '-' && (c < 'a' || c > 'z') && (c < '0' || c > '9') {
				return "", 0, false
			}
		}
	}
	return name, n, true
}
