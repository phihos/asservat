package kubernetes

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"sync"
	"testing"
	"time"

	"k8s.io/client-go/rest"
)

// The API fixture uses the ordinary REST pipeline with a fresh file bearer
// injector. This asserts the inner observer sees the actual emitted bytes;
// observing the outer pre-injection request would not pass the initial proof.
func TestConfigurationWorkerTokensObserveActualBearerAndOriginalClients(t *testing.T) {
	f := newConfigurationProviderRuntimeFixture(t)
	p, err := f.reader.BeginConfigurationProviderOperation(t.Context(), f.manifest.Roles[0].Claim.Sources.IssuerEpoch, f.manifest, f.mounted)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	p.tokens.mu.Lock()
	got := [2][]byte{bytes.Clone(p.tokens.tokens[0]), bytes.Clone(p.tokens.tokens[1])}
	p.tokens.mu.Unlock()
	defer clear(got[0])
	defer clear(got[1])
	if !bytes.Equal(got[0], []byte("observer")) || !bytes.Equal(got[1], []byte("probe")) {
		t.Fatal("token interval did not observe both actual transport identities")
	}
	foreign := &configurationWorkerTokenTransport{files: f.files, file: "kube-observer.token"}
	if release, e := p.tokens.enter(p.ctx, foreign, "Bearer observer"); e == nil {
		release()
		t.Fatal("same file on another transport adopted original client")
	}
	if p.ctx.Err() == nil {
		t.Fatal("changed client did not permanently close original operation")
	}
}

func TestConfigurationWorkerTokenIntervalNeverReextendsAdmittedChild(t *testing.T) {
	f := newConfigurationProviderRuntimeFixture(t)
	root, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	ctx, p, err := f.reader.beginTokenInterval(root)
	if err != nil {
		t.Fatal(err)
	}
	defer p.close()
	child, stop := context.WithTimeout(ctx, 40*time.Millisecond)
	defer stop()
	release, err := p.enter(child, p.clients[0], "Bearer observer")
	if err != nil {
		t.Fatal(err)
	}
	release()
	<-child.Done()
	if release, e := p.enter(ctx, p.clients[0], "Bearer observer"); e == nil {
		release()
		t.Fatal("broader later phase renewed first admitted deadline")
	}
	if ctx.Err() == nil {
		t.Fatal("expired child did not cancel whole token interval")
	}
}

type configurationTokenRoundTripFunc func(*http.Request) (*http.Response, error)

func (f configurationTokenRoundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

type configurationTokenIdleTransport struct{ closed int }

func (*configurationTokenIdleTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, io.ErrClosedPipe
}
func (t *configurationTokenIdleTransport) CloseIdleConnections() { t.closed++ }

func TestConfigurationWorkerTokenTransportRetainsOriginalIdleClose(t *testing.T) {
	original := &configurationTokenIdleTransport{}
	var recorded http.RoundTripper = configurationWorkerTokenRoundTripper{next: original}
	// The real providerInputs loader stores the inner transport through this
	// interface, then invokes only this optional method after children join.
	closer, ok := recorded.(interface{ CloseIdleConnections() })
	if !ok {
		t.Fatal("token observation hid the original transport close")
	}
	closer.CloseIdleConnections()
	if original.closed != 1 {
		t.Fatal("original transport was not closed exactly once by its owner")
	}
}

type configurationTokenBlockedBody struct {
	entered, release chan struct{}
	once             sync.Once
}

func (b *configurationTokenBlockedBody) Read(p []byte) (int, error) {
	b.once.Do(func() { close(b.entered) })
	<-b.release
	return copy(p, []byte("late")), io.EOF
}
func (b *configurationTokenBlockedBody) Close() error { return nil }

func TestConfigurationWorkerTokenBodyCloseDoesNotReleaseBlockedRead(t *testing.T) {
	f := newConfigurationProviderRuntimeFixture(t)
	root, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	ctx, p, err := f.reader.beginTokenInterval(root)
	if err != nil {
		t.Fatal(err)
	}
	body := &configurationTokenBlockedBody{entered: make(chan struct{}), release: make(chan struct{})}
	var unblockOnce sync.Once
	unblock := func() { unblockOnce.Do(func() { close(body.release) }) }
	defer func() { unblock(); p.close() }()
	transport := configurationWorkerTokenRoundTripper{client: p.clients[0], next: configurationTokenRoundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: body}, nil
	})}
	r, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://fixed.example.test/", nil)
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Authorization", "Bearer observer")
	response, err := transport.RoundTrip(r)
	if err != nil {
		t.Fatal(err)
	}
	readDone := make(chan struct{})
	go func() { _, _ = response.Body.Read(make([]byte, 8)); close(readDone) }()
	<-body.entered
	closeDone := make(chan struct{})
	go func() { _ = response.Body.Close(); close(closeDone) }()
	defer func() { unblock(); <-readDone; <-closeDone }()
	wrapped := response.Body.(*configurationWorkerTokenBody)
	// Wait for the actual underlying Close result. It intentionally does not
	// unblock Read, so only our outer ownership can retain the interval slot.
	for {
		wrapped.mu.Lock()
		closed, changed := wrapped.closed, wrapped.changed
		wrapped.mu.Unlock()
		if closed {
			break
		}
		select {
		case <-changed:
		case <-root.Done():
			t.Fatal("underlying Close did not run")
		}
	}
	p.mu.Lock()
	active := p.active
	p.mu.Unlock()
	if active != 1 {
		t.Fatal("response owner released while admitted Read remained blocked")
	}
	select {
	case <-closeDone:
		t.Fatal("outer Close reported joined while Read remained blocked")
	default:
	}
	cancel()
	unblock()
	<-readDone
	<-closeDone
	p.close()
}

func TestConfigurationWorkerTokenCloseJoinsBlockedResponseAndDiscardsLateBytes(t *testing.T) {
	f := newConfigurationProviderRuntimeFixture(t)
	root, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	ctx, p, err := f.reader.beginTokenInterval(root)
	if err != nil {
		t.Fatal(err)
	}
	body := &configurationTokenBlockedBody{entered: make(chan struct{}), release: make(chan struct{})}
	var unblockOnce sync.Once
	unblock := func() { unblockOnce.Do(func() { close(body.release) }) }
	defer func() { unblock(); p.close() }()
	transport := configurationWorkerTokenRoundTripper{client: p.clients[0], next: configurationTokenRoundTripFunc(func(*http.Request) (*http.Response, error) { return &http.Response{StatusCode: 200, Body: body}, nil })}
	r, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://fixed.example.test/", nil)
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Authorization", "Bearer observer")
	response, err := transport.RoundTrip(r)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	read := make(chan error, 1)
	go func() {
		buf := make([]byte, 8)
		n, e := response.Body.Read(buf)
		if n != 0 || !bytes.Equal(buf, make([]byte, 8)) {
			read <- io.ErrUnexpectedEOF
			return
		}
		read <- e
	}()
	<-body.entered
	closed := make(chan struct{})
	go func() { p.close(); close(closed) }()
	<-ctx.Done()
	select {
	case <-closed:
		t.Fatal("body still admitted while Close reported join")
	default:
	}
	unblock()
	if err = <-read; err == nil || err == io.ErrUnexpectedEOF {
		t.Fatal("late response bytes escaped original cancellation", err)
	}
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("released response did not join")
	}
}

func TestConfigurationWorkerObserverHasOneExplicitFixedCapacity(t *testing.T) {
	f := newConfigurationProviderRuntimeFixture(t)
	observer, probe := f.reader.worker.client, f.reader.worker.guard.probe
	if observer.api.GetRateLimiter() != f.observerLimiter || probe.api.GetRateLimiter() != f.probeLimiter || f.observerLimiter == f.probeLimiter {
		t.Fatal("fixture did not retain actual constructor buckets")
	}
	if f.observerLimiter.QPS() != 40 || f.probeLimiter.QPS() != 20 {
		t.Fatal("fresh worker private capacities changed")
	}
	// The fixed constructor cannot accept a caller-supplied alternate bucket.
	if client, err := NewConfigurationWorkerPermissionClient(&rest.Config{Host: "https://api.example", RateLimiter: f.observerLimiter}, f.files, "kube-observer.token", observer.clusterID, observer.control, time.Now); err == nil || client != nil {
		t.Fatal("caller supplied another worker rate policy")
	}
	// Independent source and effect paths must share this one observer bucket.
	if f.reader.fleet.settings.client != observer || f.reader.owner.client != observer || f.reader.fleet.protection.probe != probe || f.reader.owner.protection.probe != probe {
		t.Fatal("effect/source work gained a separate client or bucket")
	}
}
