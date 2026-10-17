package diagnostics_test

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	httppprof "net/http/pprof"
	"runtime/pprof"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/diagnostics"
	"asservat.local/asservat/internal/adapters/objectstore/framed"
	port "asservat.local/asservat/internal/application/execution"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/execution"
)

type profileGuardFunc func(context.Context, value.GoProfileRequest) (value.GoProfileCurrent, error)

func (f profileGuardFunc) ObserveGoProfile(c context.Context, r value.GoProfileRequest) (value.GoProfileCurrent, error) {
	return f(c, r)
}

type profileDialFunc func(context.Context, value.GoProfileRequest) (port.GoProfileChannel, error)

func (f profileDialFunc) DialGoProfile(c context.Context, r value.GoProfileRequest) (port.GoProfileChannel, error) {
	return f(c, r)
}

type profileSinkFunc struct {
	fn    func(context.Context, value.GoProfileRequest, io.Reader) (artifact.Layout, error)
	close func()
}

func (f profileSinkFunc) ConsumeGoProfile(c context.Context, r value.GoProfileRequest, s io.Reader) (artifact.Layout, error) {
	return f.fn(c, r, s)
}
func (f profileSinkFunc) Close() { f.close() }

func profileRequest() value.GoProfileRequest {
	const id = "00000000-0000-4000-8000-000000000001"
	n := time.Now().UTC().Truncate(time.Microsecond)
	return value.GoProfileRequest{Binding: artifact.Binding{ClusterID: id, ArtifactID: id, AttemptID: id, MediaType: value.GoProfileMediaType}, Pin: artifact.PinnedPod{Namespace: "synthetic", NamespaceUID: id, Name: "app-0", UID: id, ControllerUID: id, NodeName: "fixture-node"}, NodeUID: id, NodeBootID: id, SourceRef: "go-debug", EndpointDigest: artifact.Digest{3}, Parameters: value.GoProfileParameters{Type: "heap", Mode: "snapshot"}, NativeLimit: 4096, NotBefore: n, Deadline: n.Add(5 * time.Second)}
}

func freshProfileGuard(ctx context.Context, r value.GoProfileRequest) (value.GoProfileCurrent, error) {
	n := time.Now().UTC()
	until := n.Add(5 * time.Second)
	if r.Deadline.Before(until) {
		until = r.Deadline
	}
	return value.GoProfileCurrent{CheckedAt: n, ValidUntil: until}, ctx.Err()
}

// This dialer is test-only. It maps a synthetic pinned Pod to the private test
// listener. It provides no product node/netns/authority qualification.
func profileDialer(t *testing.T, server *httptest.Server, want value.GoProfileRequest, calls *atomic.Int32, authorization string) profileDialFunc {
	t.Helper()
	return func(ctx context.Context, r value.GoProfileRequest) (port.GoProfileChannel, error) {
		if r != want {
			return port.GoProfileChannel{}, errors.New("replacement request")
		}
		calls.Add(1)
		var conn net.Conn
		var err error
		if server.TLS != nil {
			cfg := server.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
			cfg.NextProtos = []string{"http/1.1"}
			d := tls.Dialer{Config: cfg}
			conn, err = d.DialContext(ctx, "tcp", server.Listener.Addr().String())
		} else {
			d := net.Dialer{}
			conn, err = d.DialContext(ctx, "tcp", server.Listener.Addr().String())
		}
		return port.GoProfileChannel{Connection: conn, Host: "approved-profile.invalid", Authorization: authorization, ValidUntil: r.Deadline}, err
	}
}

// Real authenticated test wrapping, with an ephemeral in-memory AES key. This
// helper is never a product key provider or collector unwrap capability.
type profileTestKeys struct {
	a     cipher.AEAD
	wraps int
}

func newProfileKeys(t *testing.T) *profileTestKeys {
	t.Helper()
	key := make([]byte, 32)
	if _, e := rand.Read(key); e != nil {
		t.Fatal(e)
	}
	b, e := aes.NewCipher(key)
	clear(key)
	if e != nil {
		t.Fatal(e)
	}
	a, e := cipher.NewGCM(b)
	if e != nil {
		t.Fatal(e)
	}
	return &profileTestKeys{a: a}
}
func (k *profileTestKeys) Seal(ctx context.Context, b, aad []byte) (artifact.SealedKey, error) {
	if ctx.Err() != nil || len(b) > 4096 {
		return artifact.SealedKey{}, errors.New("invalid test wrap")
	}
	k.wraps++
	nonce := make([]byte, k.a.NonceSize())
	if _, e := rand.Read(nonce); e != nil {
		return artifact.SealedKey{}, e
	}
	return artifact.SealedKey{Reference: "synthetic-test-key", Ciphertext: base64.StdEncoding.EncodeToString(k.a.Seal(nonce, nonce, b, aad))}, nil
}
func (k *profileTestKeys) Open(ctx context.Context, s artifact.SealedKey, aad []byte) ([]byte, error) {
	b, e := base64.StdEncoding.DecodeString(s.Ciphertext)
	if e != nil || len(b) < k.a.NonceSize() {
		return nil, errors.New("test key invalid")
	}
	return k.a.Open(nil, b[:k.a.NonceSize()], b[k.a.NonceSize():], aad)
}

type profileBytesSource []byte

func (s profileBytesSource) ReadRange(_ context.Context, o, n int64) ([]byte, error) {
	if o < 0 || n < 1 || o+n > int64(len(s)) {
		return nil, io.ErrUnexpectedEOF
	}
	return bytes.Clone(s[o : o+n]), nil
}

type profileDelivery struct{ bytes.Buffer }

func (d *profileDelivery) Send(ctx context.Context, b []byte) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	_, e := d.Write(b)
	return e
}

type profileOutput struct {
	sink        *port.GoProfileEncodingSink
	keys        *profileTestKeys
	data, index bytes.Buffer
}

func newProfileOutput(t *testing.T, r value.GoProfileRequest) *profileOutput {
	t.Helper()
	o := &profileOutput{keys: newProfileKeys(t)}
	encoder, e := framed.Prepare(context.Background(), r.Binding, o.keys)
	if e != nil {
		t.Fatal(e)
	}
	o.sink, e = port.NewGoProfileEncodingSink(r, encoder, &o.data, &o.index)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(o.sink.Close)
	return o
}
func (o *profileOutput) native(t *testing.T, layout artifact.Layout) []byte {
	t.Helper()
	r, e := framed.Open(context.Background(), layout, o.keys, profileBytesSource(o.data.Bytes()), profileBytesSource(o.index.Bytes()))
	if e != nil {
		t.Fatal(e)
	}
	d := &profileDelivery{}
	if e = r.Read(context.Background(), 0, layout.NativeBytes, d); e != nil {
		t.Fatal(e)
	}
	return d.Bytes()
}
func profileCollector(t *testing.T, d port.GoProfileDialer, g port.GoProfileGuard) *diagnostics.GoProfileCollector {
	t.Helper()
	c, e := diagnostics.NewGoProfileCollector(d, g, time.Now)
	if e != nil {
		t.Fatal(e)
	}
	return c
}

func TestGoProfileEncryptedNativeBytesAndFixedQueries(t *testing.T) {
	for _, tc := range []struct {
		name        string
		p           value.GoProfileParameters
		path, query string
	}{
		{"heap", value.GoProfileParameters{Type: "heap", Mode: "snapshot"}, "/debug/pprof/heap", "debug=0"},
		{"heap-gc", value.GoProfileParameters{Type: "heap", Mode: "snapshot", ForceGC: true}, "/debug/pprof/heap", "debug=0&gc=1"},
		{"cpu", value.GoProfileParameters{Type: "cpu", Mode: "interval", Duration: time.Second}, "/debug/pprof/profile", "debug=0&seconds=1"},
		{"delta", value.GoProfileParameters{Type: "allocs", Mode: "delta", Duration: time.Second}, "/debug/pprof/allocs", "debug=0&seconds=1"},
		{"trace", value.GoProfileParameters{Type: "runtimeTrace", Mode: "interval", Duration: time.Second}, "/debug/pprof/trace", "debug=0&seconds=1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := profileRequest()
			r.Parameters = tc.p
			var compressed bytes.Buffer
			z := gzip.NewWriter(&compressed)
			_, _ = z.Write([]byte("synthetic native bytes and user-data label"))
			_ = z.Close()
			native := bytes.Clone(compressed.Bytes())
			o := newProfileOutput(t, r)
			var calls atomic.Int32
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, q *http.Request) {
				if q.Method != "GET" || q.URL.Path != tc.path || q.URL.RawQuery != tc.query || q.Host != "approved-profile.invalid" || q.Header.Get("Accept-Encoding") != "identity" || o.keys.wraps != 2 {
					t.Error("changed request or keys not prepared before acquisition")
				}
				w.Header().Set("Content-Type", "application/octet-stream")
				// A caller may label the already gzipped native body. It must not be
				// transparently decoded by HTTP transport or rewritten by encryption.
				w.Header().Set("Content-Encoding", "gzip")
				_, _ = w.Write(native)
			}))
			defer s.Close()
			c := profileCollector(t, profileDialer(t, s, r, &calls, ""), profileGuardFunc(freshProfileGuard))
			got, e := c.CollectGoProfile(context.Background(), r, o.sink)
			if e != nil || !got.Outcome.ResponseComplete || !got.Outcome.MayHaveStarted || got.Outcome.Format != r.Parameters.Format() || calls.Load() != 1 {
				t.Fatalf("acquisition: %+v %v", got.Outcome, e)
			}
			if !bytes.Equal(o.native(t, got.Layout), native) || got.Layout.NativeSHA256 != artifact.Digest(sha256.Sum256(native)) {
				t.Fatal("native profile changed")
			}
			if bytes.Contains(o.data.Bytes(), []byte("user-data label")) || o.keys.wraps != 2 {
				t.Fatal("plaintext storage or payload key calls")
			}
		})
	}
}

func TestGoProfileRealCPUProviderAndBusyClassification(t *testing.T) {
	t.Run("native-provider", func(t *testing.T) {
		r := profileRequest()
		r.Parameters = value.GoProfileParameters{Type: "cpu", Mode: "interval", Duration: time.Second}
		r.NativeLimit = 1 << 20
		var calls atomic.Int32
		o := newProfileOutput(t, r)
		s := httptest.NewServer(http.HandlerFunc(httppprof.Profile))
		defer s.Close()
		got, e := profileCollector(t, profileDialer(t, s, r, &calls, ""), profileGuardFunc(freshProfileGuard)).CollectGoProfile(context.Background(), r, o.sink)
		if e != nil || !got.Outcome.ResponseComplete || calls.Load() != 1 {
			t.Fatalf("real Go handler: %v", e)
		}
		z, e := gzip.NewReader(bytes.NewReader(o.native(t, got.Layout)))
		if e != nil {
			t.Fatal("native pprof gzip", e)
		}
		defer z.Close()
		b, e := io.ReadAll(io.LimitReader(z, 1<<20))
		if e != nil || len(b) == 0 {
			t.Fatal("empty native pprof", e)
		}
	})
	t.Run("application-owned-profiler", func(t *testing.T) {
		if e := pprof.StartCPUProfile(io.Discard); e != nil {
			t.Fatal(e)
		}
		defer pprof.StopCPUProfile()
		r := profileRequest()
		r.Parameters = value.GoProfileParameters{Type: "cpu", Mode: "interval", Duration: time.Second}
		o := newProfileOutput(t, r)
		var calls atomic.Int32
		s := httptest.NewServer(http.HandlerFunc(httppprof.Profile))
		defer s.Close()
		got, e := profileCollector(t, profileDialer(t, s, r, &calls, ""), profileGuardFunc(freshProfileGuard)).CollectGoProfile(context.Background(), r, o.sink)
		if !errors.Is(e, value.ErrProfilerBusy) || got.Outcome.ResponseComplete || o.data.Len() != 0 || calls.Load() != 1 {
			t.Fatalf("busy: %+v %v", got.Outcome, e)
		}
		if e := pprof.StartCPUProfile(io.Discard); e == nil {
			pprof.StopCPUProfile()
			t.Fatal("collector stopped application-owned profiler")
		}
	})
}

func TestGoProfileRedirectStatusAndErrorsNeverEscape(t *testing.T) {
	var followed atomic.Int32
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { followed.Add(1) }))
	defer other.Close()
	for _, status := range []int{301, 302, 307, 308, 401, 403, 404, 500} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			r := profileRequest()
			o := newProfileOutput(t, r)
			var calls atomic.Int32
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, q *http.Request) {
				w.Header().Set("Location", other.URL+"/secret")
				w.Header().Set("X-Go-Pprof", "1")
				w.WriteHeader(status)
				_, _ = w.Write([]byte("secret upstream body and endpoint credentials"))
			}))
			defer s.Close()
			got, e := profileCollector(t, profileDialer(t, s, r, &calls, ""), profileGuardFunc(freshProfileGuard)).CollectGoProfile(context.Background(), r, o.sink)
			if !errors.Is(e, value.ErrProfileUnavailable) || got.Outcome.ResponseComplete || got.Layout.Format != "" || o.data.Len() != 0 || calls.Load() != 1 || strings.Contains(e.Error(), "secret") {
				t.Fatalf("response handling: %+v %v", got.Outcome, e)
			}
		})
	}
	if followed.Load() != 0 {
		t.Fatal("redirect followed")
	}
}

func TestGoProfileBodyBoundsAndIncompleteResponses(t *testing.T) {
	for _, tc := range []struct {
		name   string
		body   string
		length string
		ctype  string
		want   error
	}{
		{"oversized-known", strings.Repeat("x", 65), "65", "application/octet-stream", value.ErrProfileLimit},
		{"oversized-chunked", strings.Repeat("x", 65), "", "application/octet-stream", value.ErrProfileLimit},
		{"truncated", "xyz", "60", "application/octet-stream", value.ErrProfileUnavailable},
		{"empty", "", "0", "application/octet-stream", value.ErrProfileUnavailable},
		{"wrong-media", "secret-login-page", "", "text/html", value.ErrProfileUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := profileRequest()
			r.NativeLimit = 64
			o := newProfileOutput(t, r)
			var calls atomic.Int32
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, q *http.Request) {
				w.Header().Set("Content-Type", tc.ctype)
				if tc.length != "" {
					w.Header().Set("Content-Length", tc.length)
				}
				w.WriteHeader(200)
				if tc.length == "" {
					w.(http.Flusher).Flush()
				}
				_, _ = io.WriteString(w, tc.body)
			}))
			defer s.Close()
			got, e := profileCollector(t, profileDialer(t, s, r, &calls, ""), profileGuardFunc(freshProfileGuard)).CollectGoProfile(context.Background(), r, o.sink)
			if !errors.Is(e, tc.want) || got.Layout.Format != "" || got.Outcome.ResponseComplete || calls.Load() != 1 {
				t.Fatalf("bounds: %+v %v", got.Outcome, e)
			}
		})
	}
}

func TestGoProfileCurrentDenialAndBlockedRefreshCancelOriginalSocket(t *testing.T) {
	for _, blocked := range []bool{false, true} {
		t.Run(map[bool]string{false: "denied", true: "blocked"}[blocked], func(t *testing.T) {
			r := profileRequest()
			o := newProfileOutput(t, r)
			var calls, checks atomic.Int32
			started := make(chan struct{})
			stopped := make(chan struct{})
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, q *http.Request) { close(started); <-q.Context().Done(); close(stopped) }))
			defer s.Close()
			firstUntil := time.Now().Add(350 * time.Millisecond)
			guard := profileGuardFunc(func(ctx context.Context, got value.GoProfileRequest) (value.GoProfileCurrent, error) {
				if got != r {
					t.Error("request changed during observation")
				}
				if checks.Add(1) == 1 {
					return value.GoProfileCurrent{CheckedAt: time.Now(), ValidUntil: firstUntil}, nil
				}
				if blocked {
					deadline, ok := ctx.Deadline()
					if !ok || !deadline.Equal(firstUntil) {
						t.Error("previous original expiry not retained")
					}
					<-ctx.Done()
					n := time.Now()
					return value.GoProfileCurrent{CheckedAt: n, ValidUntil: n.Add(time.Second)}, nil
				}
				return value.GoProfileCurrent{}, errors.New("private denial details")
			})
			got, e := profileCollector(t, profileDialer(t, s, r, &calls, ""), guard).CollectGoProfile(context.Background(), r, o.sink)
			if e == nil || got.Outcome.ResponseComplete || got.Layout.Format != "" || !got.Outcome.MayHaveStarted || calls.Load() != 1 || checks.Load() != 2 {
				t.Fatalf("guard: %+v %v %d", got.Outcome, e, checks.Load())
			}
			select {
			case <-started:
			default:
				t.Fatal("request never reached original endpoint")
			}
			select {
			case <-stopped:
			case <-time.After(time.Second):
				t.Fatal("revoked socket survived")
			}
		})
	}
}

func TestGoProfileCallerCancellationRetainsUncertainStart(t *testing.T) {
	r := profileRequest()
	r.Parameters = value.GoProfileParameters{Type: "cpu", Mode: "interval", Duration: time.Second}
	o := newProfileOutput(t, r)
	var calls atomic.Int32
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stopped := make(chan struct{})
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, q *http.Request) { cancel(); <-q.Context().Done(); close(stopped) }))
	defer s.Close()
	got, e := profileCollector(t, profileDialer(t, s, r, &calls, ""), profileGuardFunc(freshProfileGuard)).CollectGoProfile(ctx, r, o.sink)
	if !errors.Is(e, value.ErrExpired) || !got.Outcome.MayHaveStarted || got.Outcome.ResponseComplete || got.Layout.Format != "" || calls.Load() != 1 {
		t.Fatalf("cancellation: %+v %v", got.Outcome, e)
	}
	select {
	case <-stopped:
	case <-time.After(time.Second):
		t.Fatal("socket not closed")
	}
}

func TestGoProfileRefusesCredentialOnClearChannel(t *testing.T) {
	for _, secure := range []bool{false, true} {
		t.Run(map[bool]string{false: "clear-denied", true: "verified-tls"}[secure], func(t *testing.T) {
			r := profileRequest()
			o := newProfileOutput(t, r)
			var calls, requests atomic.Int32
			h := http.HandlerFunc(func(w http.ResponseWriter, q *http.Request) {
				requests.Add(1)
				if q.Header.Get("Authorization") != "Bearer synthetic-fixture-token" {
					t.Error("named credential missing")
				}
				w.Header().Set("Content-Type", "application/octet-stream")
				_, _ = w.Write([]byte("synthetic"))
			})
			var s *httptest.Server
			if secure {
				s = httptest.NewTLSServer(h)
			} else {
				s = httptest.NewServer(h)
			}
			defer s.Close()
			got, e := profileCollector(t, profileDialer(t, s, r, &calls, "Bearer synthetic-fixture-token"), profileGuardFunc(freshProfileGuard)).CollectGoProfile(context.Background(), r, o.sink)
			if secure {
				if e != nil || !got.Outcome.ResponseComplete || requests.Load() != 1 {
					t.Fatal("verified TLS", e)
				}
			} else {
				if !errors.Is(e, value.ErrDenied) || got.Outcome.MayHaveStarted || requests.Load() != 0 {
					t.Fatal("credential sent before TLS qualification", e)
				}
			}
		})
	}
}

func TestGoProfileSinkMustConsumeCompleteOriginalStream(t *testing.T) {
	r := profileRequest()
	o := newProfileOutput(t, r)
	var calls atomic.Int32
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, q *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write([]byte("native-profile-with-more-than-three-bytes"))
	}))
	defer s.Close()
	sink := profileSinkFunc{close: o.sink.Close, fn: func(ctx context.Context, v value.GoProfileRequest, body io.Reader) (artifact.Layout, error) {
		return o.sink.ConsumeGoProfile(ctx, v, io.LimitReader(body, 3))
	}}
	got, e := profileCollector(t, profileDialer(t, s, r, &calls, ""), profileGuardFunc(freshProfileGuard)).CollectGoProfile(context.Background(), r, sink)
	if !errors.Is(e, value.ErrProfileOutput) || got.Outcome.ResponseComplete || got.Layout.Format != "" {
		t.Fatalf("early output was accepted: %+v %v", got.Outcome, e)
	}
}

func TestGoProfileObserverJoinsBeforeReturningOutput(t *testing.T) {
	r := profileRequest()
	o := newProfileOutput(t, r)
	var calls, checks atomic.Int32
	entered := make(chan struct{})
	finished := make(chan struct{})
	guard := profileGuardFunc(func(ctx context.Context, v value.GoProfileRequest) (value.GoProfileCurrent, error) {
		if checks.Add(1) == 1 {
			n := time.Now()
			return value.GoProfileCurrent{CheckedAt: n, ValidUntil: n.Add(2 * time.Second)}, nil
		}
		close(entered)
		<-ctx.Done()
		close(finished)
		return value.GoProfileCurrent{}, ctx.Err()
	})
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, q *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write([]byte("synthetic"))
	}))
	defer s.Close()
	sink := profileSinkFunc{close: o.sink.Close, fn: func(ctx context.Context, v value.GoProfileRequest, body io.Reader) (artifact.Layout, error) {
		select {
		case <-entered:
		case <-ctx.Done():
			return artifact.Layout{}, ctx.Err()
		}
		return o.sink.ConsumeGoProfile(ctx, v, body)
	}}
	got, e := profileCollector(t, profileDialer(t, s, r, &calls, ""), guard).CollectGoProfile(context.Background(), r, sink)
	if e != nil || !got.Outcome.ResponseComplete {
		t.Fatalf("observer join: %+v %v", got.Outcome, e)
	}
	select {
	case <-finished:
	default:
		t.Fatal("returned while current authority read remained active")
	}
}

func TestGoProfileInvalidCompositionClosesPreparedAttempt(t *testing.T) {
	for _, name := range []string{"nil-parent", "zero-collector", "nil-collector", "denied", "invalid-request"} {
		t.Run(name, func(t *testing.T) {
			r := profileRequest()
			o := newProfileOutput(t, r)
			var dials atomic.Int32
			d := profileDialFunc(func(context.Context, value.GoProfileRequest) (port.GoProfileChannel, error) {
				dials.Add(1)
				return port.GoProfileChannel{}, errors.New("unexpected dial")
			})
			c := profileCollector(t, d, profileGuardFunc(func(context.Context, value.GoProfileRequest) (value.GoProfileCurrent, error) {
				return value.GoProfileCurrent{}, errors.New("synthetic denied")
			}))
			ctx := context.Background()
			sent := r
			switch name {
			case "nil-parent":
				ctx = nil
			case "zero-collector":
				c = &diagnostics.GoProfileCollector{}
			case "nil-collector":
				c = nil
			case "invalid-request":
				sent.EndpointDigest = artifact.Digest{}
			}
			got, e := c.CollectGoProfile(ctx, sent, o.sink)
			if e == nil || got.Outcome.MayHaveStarted || got.Layout.Format != "" || dials.Load() != 0 {
				t.Fatalf("invalid composition: %+v %v", got.Outcome, e)
			}
			if _, e = o.sink.ConsumeGoProfile(context.Background(), r, strings.NewReader("synthetic")); !errors.Is(e, value.ErrProfileOutput) {
				t.Fatal("unopened prepared attempt was reusable", e)
			}
		})
	}
}

func TestGoProfileRevocationWhileBodyBlocked(t *testing.T) {
	r := profileRequest()
	o := newProfileOutput(t, r)
	var calls, checks atomic.Int32
	bodyReady := make(chan struct{})
	stopped := make(chan struct{})
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, q *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(200)
		w.(http.Flusher).Flush()
		close(bodyReady)
		<-q.Context().Done()
		close(stopped)
	}))
	defer s.Close()
	guard := profileGuardFunc(func(ctx context.Context, v value.GoProfileRequest) (value.GoProfileCurrent, error) {
		if checks.Add(1) == 1 {
			n := time.Now()
			return value.GoProfileCurrent{CheckedAt: n, ValidUntil: n.Add(800 * time.Millisecond)}, nil
		}
		select {
		case <-bodyReady:
		case <-ctx.Done():
			return value.GoProfileCurrent{}, ctx.Err()
		}
		return value.GoProfileCurrent{}, errors.New("revoked")
	})
	got, e := profileCollector(t, profileDialer(t, s, r, &calls, ""), guard).CollectGoProfile(context.Background(), r, o.sink)
	if !errors.Is(e, value.ErrExpired) || !got.Outcome.MayHaveStarted || got.Outcome.ResponseComplete || got.Layout.Format != "" || checks.Load() != 2 {
		t.Fatalf("body read remained authorized: %+v %v", got.Outcome, e)
	}
	select {
	case <-stopped:
	case <-time.After(time.Second):
		t.Fatal("blocked body outlived revocation")
	}
}

func TestGoProfileShortOriginalChannelDeadlineCannotBeExtended(t *testing.T) {
	r := profileRequest()
	o := newProfileOutput(t, r)
	var calls atomic.Int32
	stopped := make(chan struct{})
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, q *http.Request) { <-q.Context().Done(); close(stopped) }))
	defer s.Close()
	base := profileDialer(t, s, r, &calls, "")
	var original time.Time
	d := profileDialFunc(func(ctx context.Context, v value.GoProfileRequest) (port.GoProfileChannel, error) {
		ch, e := base(ctx, v)
		original = time.Now().Add(1500 * time.Millisecond)
		ch.ValidUntil = original
		return ch, e
	})
	got, e := profileCollector(t, d, profileGuardFunc(freshProfileGuard)).CollectGoProfile(context.Background(), r, o.sink)
	if !errors.Is(e, value.ErrExpired) || got.Outcome.ResponseComplete || got.Layout.Format != "" || !got.Outcome.MayHaveStarted || time.Now().After(original.Add(time.Second)) {
		t.Fatalf("channel lifetime changed: %+v %v", got.Outcome, e)
	}
	select {
	case <-stopped:
	case <-time.After(time.Second):
		t.Fatal("original channel still open")
	}
}

func TestGoProfileShortChannelCannotStartUnfinishableRecording(t *testing.T) {
	r := profileRequest()
	r.Parameters = value.GoProfileParameters{Type: "cpu", Mode: "interval", Duration: 10 * time.Second}
	r.Deadline = r.NotBefore.Add(15 * time.Second)
	o := newProfileOutput(t, r)
	var dials, requests atomic.Int32
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, q *http.Request) {
		requests.Add(1)
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write([]byte("must-not-be-requested"))
	}))
	defer s.Close()
	original := profileDialer(t, s, r, &dials, "")
	d := profileDialFunc(func(ctx context.Context, v value.GoProfileRequest) (port.GoProfileChannel, error) {
		channel, e := original(ctx, v)
		channel.ValidUntil = time.Now().Add(3 * time.Second)
		return channel, e
	})
	got, e := profileCollector(t, d, profileGuardFunc(freshProfileGuard)).CollectGoProfile(context.Background(), r, o.sink)
	if !errors.Is(e, value.ErrExpired) || got.Outcome.MayHaveStarted || got.Outcome.ResponseComplete || got.Layout.Format != "" || dials.Load() != 1 || requests.Load() != 0 || o.data.Len() != 0 {
		t.Fatalf("short original channel started recording: %+v %v dials=%d requests=%d", got.Outcome, e, dials.Load(), requests.Load())
	}
	if _, e = o.sink.ConsumeGoProfile(context.Background(), r, strings.NewReader("synthetic")); !errors.Is(e, value.ErrProfileOutput) {
		t.Fatal("failed acquisition left prepared sink reusable", e)
	}
}

// The original caller lifetime is shorter than the requested recording. This
// regression must fail against the v1 mechanism until the effective deadline
// participates in the pre-request duration check; cancellation alone is too late.
func TestGoProfileShortCallerCannotStartUnfinishableRecording(t *testing.T) {
	r := profileRequest()
	r.Parameters = value.GoProfileParameters{Type: "cpu", Mode: "interval", Duration: 10 * time.Second}
	r.Deadline = r.NotBefore.Add(15 * time.Second)
	o := newProfileOutput(t, r)
	var dials, requests atomic.Int32
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, q *http.Request) {
		requests.Add(1)
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write([]byte("synthetic-profile-that-should-not-be-requested"))
	}))
	defer s.Close()
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(3*time.Second))
	defer cancel()
	got, e := profileCollector(t, profileDialer(t, s, r, &dials, ""), profileGuardFunc(freshProfileGuard)).CollectGoProfile(ctx, r, o.sink)
	if !errors.Is(e, value.ErrExpired) || got.Outcome.MayHaveStarted || got.Outcome.ResponseComplete || got.Layout.Format != "" || requests.Load() != 0 || o.data.Len() != 0 {
		t.Fatalf("short original caller started recording: %+v %v dials=%d requests=%d", got.Outcome, e, dials.Load(), requests.Load())
	}
	if _, e = o.sink.ConsumeGoProfile(context.Background(), r, strings.NewReader("synthetic")); !errors.Is(e, value.ErrProfileOutput) {
		t.Fatal("failed acquisition left prepared sink reusable", e)
	}
}
