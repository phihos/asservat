package mtls

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/fleet"
)

// Actual TLS/h2 and unchanged product certificate verification; current native
// and SQL facts remain the synthetic channel fixture. The separately fixed TCP
// endpoint is not an installed endpoint producer or native availability proof.
type translatedObservationFixture struct {
	x               *observationChannelFixture
	mode            string
	base            *OwnerObservationClient
	v1              *ConnectorObservationClient
	v2              *ConnectorObservationOperationClient
	calls           atomic.Int32
	handshakes      atomic.Int32
	entered, joined chan struct{}
}

func newTranslatedObservationFixture(t *testing.T, mode, response string) *translatedObservationFixture {
	t.Helper()
	d := &translatedObservationFixture{x: newObservationChannelFixture(t), mode: mode, entered: make(chan struct{}), joined: make(chan struct{})}
	changeTLS := func(config *tls.Config) {
		config.GetConfigForClient = func(*tls.ClientHelloInfo) (*tls.Config, error) {
			d.handshakes.Add(1)
			return nil, nil
		}
	}
	handler := func(w http.ResponseWriter, r *http.Request) {
		count := d.calls.Add(1)
		if count == 1 {
			close(d.entered)
			defer close(d.joined)
		}
		common, _ := OwnerBootstrapServerName(d.x.ownerPin.Pool)
		path := contracts.OwnerObservationPath
		if mode == "v1" {
			path = contracts.ClusterObservationExchangePath
		}
		if mode == "v2" {
			path = contracts.ClusterObservationOperationExchangePath
		}
		if r.TLS == nil || !r.TLS.HandshakeComplete || r.TLS.Version != tls.VersionTLS13 || r.TLS.ServerName != common || r.TLS.NegotiatedProtocol != "h2" || len(r.TLS.VerifiedChains) == 0 || r.Host != net.JoinHostPort(common, "9444") || r.URL.Path != path || r.Method != http.MethodPost || r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" {
			t.Error("translated connection changed actual SNI, authority, purpose or mutual TLS")
			w.WriteHeader(http.StatusForbidden)
			return
		}
		if response == "block" {
			if mode == "finite" {
				_, _ = io.Copy(io.Discard, r.Body)
			} else {
				_, _ = contracts.ReadClusterObservationFrame(r.Body)
			}
			<-r.Context().Done()
			return
		}
		if response == "redirect" || response == "unavailable" {
			if mode == "finite" {
				_, _ = io.Copy(io.Discard, r.Body)
			} else {
				_, _ = contracts.ReadClusterObservationFrame(r.Body)
			}
			w.Header().Set("Location", "https://unselected.invalid:1234/")
			if response == "redirect" {
				w.WriteHeader(http.StatusTemporaryRedirect)
			} else {
				w.WriteHeader(http.StatusServiceUnavailable)
			}
			return
		}
		if mode == "finite" {
			if err := d.finiteReply(w, r); err != nil {
				t.Errorf("finite synthetic reply: %v", err)
				w.WriteHeader(http.StatusInternalServerError)
			}
			return
		}
		var err error
		if mode == "v1" {
			_, err = streamHello(w, r)
		} else {
			_, err = operationStreamHello(w, r)
		}
		if err != nil {
			t.Errorf("translated Hello: %v", err)
			return
		}
		<-r.Context().Done()
	}
	if mode == "v1" {
		d.v1 = observationStreamClientAtPort(t, d.x, handler, 1, 9444, changeTLS)
		d.base = d.v1.base
	} else {
		d.v2 = operationStreamClientAtPort(t, d.x, handler, 1, 9444, changeTLS)
		d.base = d.v2.base
	}
	_, port, err := net.SplitHostPort(d.base.address)
	if err != nil || port == "9444" || d.base.pin.Pool.NativePort != 9444 || !d.base.pin.Valid() {
		t.Fatal("translated fixture did not preserve independent dial/internal ports", err)
	}
	return d
}

func (d *translatedObservationFixture) finiteReply(w http.ResponseWriter, r *http.Request) error {
	raw, err := io.ReadAll(io.LimitReader(r.Body, contracts.OwnerObservationBytes+1))
	if err != nil {
		return err
	}
	wire, err := contracts.DecodeOwnerObservationRequest(raw)
	if err != nil {
		return err
	}
	q, err := ownerObservationRequest(wire, d.x.f.clock())
	if err != nil {
		return err
	}
	binding, err := ownerObservationConnection(r.TLS, q)
	if err != nil {
		return err
	}
	n := d.x.f.clock()
	config := ownerBootstrapConfiguration(d.x.ownerPin.Pool, d.x.ownerCA, n)
	leaf := d.x.leaf
	proof := value.OwnerObservation{Request: q, ConnectionBinding: binding, Connector: value.PeerCertificate{Binding: leaf.Binding, Digest: leaf.Digest, NotBefore: leaf.NotBefore, NotAfter: leaf.NotAfter}, Owner: value.AuthenticatedOwner{Certificate: d.x.owner, EnrollmentID: ownerTestID, Pool: d.x.ownerPin.Pool, Pod: "owner-1", ReplicaSetUID: ownerTestID, ConfigurationRevision: config.Configuration.Revision, ProtectionDigest: d.x.ownerPin.ProtectionDigest, VerifiedAt: n, ValidUntil: q.NotAfter}, Workload: value.OwnerObservationWorkload{Pin: d.x.ownerPin, Binding: d.x.owner.Binding, Pod: "owner-1", ReplicaSetUID: ownerTestID, WorkloadDigest: artifact.Digest{18}, ObservedAt: n, FreshUntil: q.NotAfter}, ObservedAt: n, FreshUntil: q.NotAfter}
	reply, err := ownerObservationReplyWire(proof)
	if err != nil {
		return err
	}
	encoded, err := contracts.EncodeOwnerObservationReply(reply)
	if err != nil {
		return err
	}
	w.Header().Set("Content-Type", contracts.OwnerObservationMedia)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Length", strconv.Itoa(len(encoded)))
	_, err = w.Write(encoded)
	return err
}

func (d *translatedObservationFixture) open(ctx context.Context) (io.Closer, error) {
	if d.mode == "finite" {
		q := value.OwnerObservationRequest{RootID: d.x.ownerPin.RootID, ID: ownerTestID, Challenge: ownerOtherID, RequestedAt: d.x.f.clock(), NotAfter: d.x.f.clock().Add(3 * time.Second)}
		out, err := d.base.ObserveOwner(ctx, q)
		if err == nil && (!out.Valid(d.x.f.clock()) || out.Workload.Pin != d.x.ownerPin || out.FreshUntil.After(q.NotAfter)) {
			return nil, value.ErrDenied
		}
		return nil, err
	}
	if d.v1 != nil {
		s, e := d.v1.Open(ctx, ownerOtherID)
		if e != nil {
			return nil, e
		}
		return s, nil
	}
	s, e := d.v2.Open(ctx, ownerOtherID)
	if e != nil {
		return nil, e
	}
	return s, nil
}

func TestOwnerObservationTranslatedDialKeepsOriginalTLSAuthority(t *testing.T) {
	for _, mode := range []string{"finite", "v1", "v2"} {
		t.Run(mode, func(t *testing.T) {
			d := newTranslatedObservationFixture(t, mode, "success")
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			stream, err := d.open(ctx)
			if err != nil {
				t.Fatal("translated original endpoint failed", err)
			}
			if stream != nil {
				if err = stream.Close(); err != nil {
					t.Fatal("joined stream close", err)
				}
			}
			select {
			case <-d.joined:
			case <-time.After(time.Second):
				t.Fatal("translated request did not join")
			}
			if d.calls.Load() != 1 || d.handshakes.Load() != 1 {
				t.Fatal("translated dial sent more than one request", d.calls.Load())
			}
			d.base.mu.Lock()
			active := d.base.active
			d.base.mu.Unlock()
			if active != 0 {
				t.Fatal("slot released without joined completion", active)
			}
			if mode == "finite" && d.x.registryCalls < 2 {
				t.Fatal("finite pre/post current registry checks missing")
			}
		})
	}
}

func TestOwnerObservationTranslatedDialPreservesTLSAndCandidateDenial(t *testing.T) {
	for _, mode := range []string{"finite", "v1", "v2"} {
		for _, negative := range []string{"wrong-name", "wrong-roots", "excluded-candidate"} {
			t.Run(mode+"/"+negative, func(t *testing.T) {
				d := newTranslatedObservationFixture(t, mode, "success")
				switch negative {
				case "wrong-name":
					d.base.name = "wrong.invalid"
				case "wrong-roots":
					d.base.roots = newOwnerTestCA(t, d.x.f.clock()).roots
				case "excluded-candidate":
					d.x.missing = true
				}
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				defer cancel()
				stream, err := d.open(ctx)
				if err == nil || stream != nil || d.calls.Load() != 0 {
					t.Fatal("unqualified translated TLS/candidate reached HTTP", err, d.calls.Load())
				}
			})
		}
	}
}

func TestOwnerObservationTranslatedDialNeverReplaysUnknownPOST(t *testing.T) {
	for _, mode := range []string{"finite", "v1", "v2"} {
		for _, response := range []string{"redirect", "unavailable"} {
			t.Run(mode+"/"+response, func(t *testing.T) {
				d := newTranslatedObservationFixture(t, mode, response)
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				defer cancel()
				stream, err := d.open(ctx)
				if err == nil || stream != nil || d.calls.Load() != 1 || d.handshakes.Load() != 1 {
					t.Fatal("unknown translated POST succeeded or replayed", err, d.calls.Load())
				}
				select {
				case <-d.joined:
				case <-time.After(time.Second):
					t.Fatal("failed request not joined")
				}
			})
		}
	}
}

func TestOwnerObservationTranslatedDialCancellationJoins(t *testing.T) {
	for _, mode := range []string{"finite", "v1", "v2"} {
		t.Run(mode, func(t *testing.T) {
			d := newTranslatedObservationFixture(t, mode, "block")
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			done := make(chan error, 1)
			go func() {
				stream, err := d.open(ctx)
				if stream != nil {
					_ = stream.Close()
				}
				done <- err
			}()
			select {
			case <-d.entered:
			case <-time.After(time.Second):
				t.Fatal("did not enter translated request")
			}
			cancel()
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("cancelled original request succeeded")
				}
			case <-time.After(time.Second):
				t.Fatal("cancelled request did not join")
			}
			select {
			case <-d.joined:
			case <-time.After(time.Second):
				t.Fatal("server request did not observe original cancellation")
			}
			d.base.mu.Lock()
			active := d.base.active
			d.base.mu.Unlock()
			if active != 0 || d.calls.Load() != 1 {
				t.Fatal("cancellation lost slot or replayed request", active, d.calls.Load())
			}
		})
	}
}

func TestOwnerObservationDialConstructorStillBoundsInput(t *testing.T) {
	d := newTranslatedObservationFixture(t, "finite", "success")
	b := d.base
	candidates := observationCandidatesFunc(func(context.Context) (value.APIContextOwnerCandidates, error) {
		t.Error("constructor performed current authority I/O")
		return value.APIContextOwnerCandidates{}, value.ErrUnavailable
	})
	for _, address := range []string{"", ":9444", "localhost", "https://localhost:9444", "localhost:0", "localhost:65536", "localhost:-1", "localhost:nope", "localhost:1.5", "localhost:1e3", "localhost/path:9444", "localhost\n:9444", "user@localhost:9444", "[fe80::1%eth0]:9444"} {
		t.Run(address, func(t *testing.T) {
			client, err := NewOwnerObservationClient(context.Background(), b.pin, address, b.roots, b.connector, candidates, b.registry, 1, b.now)
			if err == nil || client != nil {
				if client != nil {
					client.Close()
				}
				t.Fatal("malformed endpoint admitted")
			}
		})
	}
	for _, address := range []string{"127.0.0.1:9444", "127.0.0.1:30444", "example.invalid:443", "[::1]:65535"} {
		t.Run(address, func(t *testing.T) {
			client, err := NewOwnerObservationClient(context.Background(), b.pin, address, b.roots, b.connector, candidates, b.registry, 1, b.now)
			if err != nil {
				t.Fatal("valid fixed endpoint rejected", err)
			}
			client.Close()
		})
	}
	if d.calls.Load() != 0 {
		t.Fatal("constructor dialed before explicit operation")
	}
}
