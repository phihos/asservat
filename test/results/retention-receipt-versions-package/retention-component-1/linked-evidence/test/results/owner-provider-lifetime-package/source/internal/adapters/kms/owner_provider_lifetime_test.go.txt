package kms

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TLS/provider replies are synthetic here. The current-proof hook is explicitly
// a component fixture; the installed native/SQL composition remains separate.
func newOwnerProviderLifetimeFixture(t *testing.T, f *ownerProviderControlFixture, source TokenSource, proof ownerProviderCurrent, limit int) *ownerProviderLifetime {
	t.Helper()
	if source == nil {
		source = func(context.Context) ([]byte, error) {
			return ownerProviderTestJWT(f.control.now().Add(600 * time.Second)), nil
		}
	}
	if proof == nil {
		proof = func(ctx context.Context) (time.Time, error) { return f.control.now().Add(5 * time.Second), ctx.Err() }
	}
	s, err := newOwnerProviderLifetime(context.Background(), f.control, source, proof, limit)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, end := context.WithTimeout(context.Background(), time.Second)
		defer end()
		if err := s.close(ctx); err != nil {
			t.Error("fixture did not join provider lifetime", err)
		}
	})
	return s
}

func TestOwnerProviderLifetimeSingleFlightDoesNotBorrowCallerDeadline(t *testing.T) {
	f := newOwnerProviderControlFixture(t)
	entered, release := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	finish := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(finish)
	var reads atomic.Int32
	source := func(ctx context.Context) ([]byte, error) {
		if reads.Add(1) == 1 {
			close(entered)
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-release:
		}
		return ownerProviderTestJWT(time.Now().Add(600 * time.Second)), nil
	}
	s := newOwnerProviderLifetimeFixture(t, f, source, nil, 2)
	done := make(chan error, 1)
	original, end := context.WithTimeout(context.Background(), 5*time.Second)
	defer end()
	go func() { done <- s.refresh(original) }()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		finish()
		t.Fatal("first control did not reach JWT source")
	}
	var group sync.WaitGroup
	for range 24 {
		group.Add(1)
		go func() {
			defer group.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
			defer cancel()
			if err := s.refresh(ctx); err == nil {
				t.Error("concurrent caller created control operation")
			}
		}()
	}
	group.Wait()
	finish()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if reads.Load() != 1 {
		t.Fatal("concurrent readiness read another JWT")
	}
	lease, err := s.borrow(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer clear(lease.token)
	lease.release()
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.loginCalls != 1 || f.lookups != 1 || f.renewCalls != 0 {
		t.Fatal("concurrent readiness or effect dispatched provider work")
	}
}

func TestOwnerProviderLifetimeUnknownLoginKeepsBoundedBackoffAndNoLookup(t *testing.T) {
	f := newOwnerProviderControlFixture(t)
	f.mode = "unknown-login"
	s := newOwnerProviderLifetimeFixture(t, f, nil, nil, 1)
	delays := []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second, 16 * time.Second, 30 * time.Second, 30 * time.Second}
	for i, delay := range delays {
		if err := s.refresh(context.Background()); err == nil {
			t.Fatal("unknown login became ready")
		}
		if lease, err := s.borrow(context.Background()); err == nil {
			lease.release()
			clear(lease.token)
			t.Fatal("unknown provider credential was adopted")
		}
		f.mu.Lock()
		before := f.loginCalls
		f.mu.Unlock()
		for range 8 {
			if err := s.refresh(context.Background()); err == nil {
				t.Fatal("backoff ignored")
			}
		}
		f.mu.Lock()
		calls, lookups, renewals := f.loginCalls, f.lookups, f.renewCalls
		f.shift += delay + 10*time.Millisecond
		f.mu.Unlock()
		if calls != before || before != i+1 || lookups != 0 || renewals != 0 {
			t.Fatal("unknown login replayed or searched")
		}
	}
}

func TestOwnerProviderLifetimeLostRenewalReconcilesOnlySameToken(t *testing.T) {
	f := newOwnerProviderControlFixture(t)
	s := newOwnerProviderLifetimeFixture(t, f, nil, nil, 2)
	if err := s.refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	first, err := s.borrow(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer clear(first.token)
	defer first.release()
	original := first.until
	f.mu.Lock()
	f.shift = 120 * time.Second
	f.mode = "unknown-renewal"
	f.mu.Unlock()
	if err = s.refresh(context.Background()); err == nil {
		t.Fatal("unknown renewal published")
	}
	if !first.until.Equal(original) {
		t.Fatal("unknown renewal extended existing borrow")
	}
	if second, err := s.borrow(context.Background()); err == nil {
		second.release()
		clear(second.token)
		t.Fatal("unverified control observation stayed actionable")
	}
	f.mu.Lock()
	f.shift += 2 * time.Second
	f.mu.Unlock()
	if err = s.refresh(context.Background()); err != nil {
		t.Fatal("same-token reconciliation", err)
	}
	second, err := s.borrow(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer clear(second.token)
	defer second.release()
	if !second.until.After(original) || !first.until.Equal(original) || !bytes.Equal(first.token, second.token) {
		t.Fatal("reconciliation replaced original borrow")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.loginCalls != 1 || f.renewCalls != 1 || f.lookups != 2 {
		t.Fatal("lost renewal was repeated instead of read")
	}
}

func TestOwnerProviderLifetimeFinalCurrentProofPrecedesPublication(t *testing.T) {
	f := newOwnerProviderControlFixture(t)
	var checks atomic.Int32
	proof := func(ctx context.Context) (time.Time, error) {
		if checks.Add(1) == 2 {
			return time.Time{}, errors.New("synthetic current source changed")
		}
		return time.Now().Add(5 * time.Second), ctx.Err()
	}
	s := newOwnerProviderLifetimeFixture(t, f, nil, proof, 1)
	if err := s.refresh(context.Background()); err == nil {
		t.Fatal("changed current source published provider lease")
	}
	if lease, err := s.borrow(context.Background()); err == nil {
		lease.release()
		clear(lease.token)
		t.Fatal("changed current proof allowed effect")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if checks.Load() != 2 || f.loginCalls != 1 || f.lookups != 1 || f.revokes != 1 {
		t.Fatal("proof ordering/restrictive retirement mismatch")
	}
}

func TestOwnerProviderLifetimeCloseTimeoutRetainsOutstandingBorrow(t *testing.T) {
	f := newOwnerProviderControlFixture(t)
	s := newOwnerProviderLifetimeFixture(t, f, nil, nil, 1)
	if err := s.refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	lease, err := s.borrow(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer clear(lease.token)
	defer lease.release()
	if extra, err := s.borrow(context.Background()); err == nil {
		extra.release()
		clear(extra.token)
		t.Fatal("per-purpose bound exceeded")
	}
	short, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	err = s.close(short)
	cancel()
	if err == nil {
		t.Fatal("close claimed joined while response remained open")
	}
	select {
	case <-lease.ctx.Done():
	default:
		t.Fatal("close did not cancel original request")
	}
	s.mu.Lock()
	retained := s.borrows == 1 && s.current != nil && len(s.current.value.token) != 0 && !s.finished
	s.mu.Unlock()
	if !retained {
		t.Fatal("close timeout released token/response ownership")
	}
	f.mu.Lock()
	revokes := f.revokes
	f.mu.Unlock()
	if revokes != 0 {
		t.Fatal("token revoked before body joined")
	}
	lease.release()
	if err = s.close(context.Background()); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.revokes != 1 {
		t.Fatal("joined token was not retired once")
	}
}

func TestOwnerProviderLifetimeExpiredBorrowCannotAuthenticateOnEffectPath(t *testing.T) {
	f := newOwnerProviderControlFixture(t)
	s := newOwnerProviderLifetimeFixture(t, f, nil, nil, 1)
	if err := s.refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.shift = 301 * time.Second
	f.mu.Unlock()
	if lease, err := s.borrow(context.Background()); err == nil {
		lease.release()
		clear(lease.token)
		t.Fatal("expired provider lease borrowed")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.loginCalls != 1 || f.lookups != 1 || f.renewCalls != 0 {
		t.Fatal("effect refreshed provider authentication")
	}
}

func TestOwnerProviderLifetimeTransportCloseKeepsBlockedBodyOwned(t *testing.T) {
	f := newOwnerProviderControlFixture(t)
	s := newOwnerProviderLifetimeFixture(t, f, nil, nil, 1)
	if err := s.refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	body := &ownerLeaseBlockingClose{entered: make(chan struct{}), finish: make(chan struct{})}
	var release sync.Once
	finish := func() { release.Do(func() { close(body.finish) }) }
	t.Cleanup(finish)
	var effect context.Context
	transport := &ownerProviderLeaseTransport{now: time.Now, source: s.borrow, base: ownerLeaseRoundTrip(func(r *http.Request) (*http.Response, error) {
		effect = r.Context()
		if r.Header.Get("X-Vault-Token") != "exact-service-token" {
			t.Error("effect lost original token")
		}
		return &http.Response{StatusCode: http.StatusOK, Body: body}, nil
	})}
	request, _ := http.NewRequest(http.MethodPost, "https://provider.invalid/v1/transit/encrypt/fixed", nil)
	response, err := transport.RoundTrip(request)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { _ = response.Body.Close(); close(done) }()
	// Every assertion failure still releases and joins the fixture's blocked I/O.
	defer func() { finish(); <-done }()
	select {
	case <-body.entered:
	case <-time.After(time.Second):
		t.Fatal("response Close did not enter")
	}
	short, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	err = s.close(short)
	cancel()
	if err == nil {
		t.Fatal("holder declared closed while underlying body remained unjoined")
	}
	if effect.Err() == nil {
		t.Fatal("holder shutdown did not cancel credentialed HTTP effect")
	}
	s.mu.Lock()
	retained := s.borrows == 1 && !s.finished
	s.mu.Unlock()
	f.mu.Lock()
	revokes := f.revokes
	f.mu.Unlock()
	if !retained || revokes != 0 {
		t.Fatal("blocked body lost its original slot/token")
	}
	finish()
	<-done
	if err = s.close(context.Background()); err != nil {
		t.Fatal("joined body did not release holder", err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if body.closes.Load() != 1 || f.revokes != 1 {
		t.Fatal("body closure or token retirement repeated")
	}
}

func TestOwnerProviderLifetimesCancelAllPurposesBeforeJoining(t *testing.T) {
	f := newOwnerProviderControlFixture(t)
	in, account, secret, now := ownerProviderRecipeInput(t)
	in.KeyService.Endpoint, in.KeyService.Roots = f.server.URL, [][]byte{f.server.Certificate().Raw}
	recipe, err := OwnerProviderRecipeFor(in, "owner-auth", "auth_kubernetes_original", account, secret, now)
	if err != nil {
		t.Fatal(err)
	}
	entered := make(chan struct{}, 2)
	jwt := func(ctx context.Context) ([]byte, error) { entered <- struct{}{}; <-ctx.Done(); return nil, ctx.Err() }
	proof := func(ctx context.Context) (time.Time, error) { return time.Now().Add(5 * time.Second), ctx.Err() }
	owners, err := newOwnerProviderLifetimes(context.Background(), in, recipe.Profile, jwt, proof, f.server.Client(), 1, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = owners.close(context.Background()) })
	done := make(chan error, 2)
	go func() { done <- owners.auditWrap.refresh(context.Background()) }()
	go func() { done <- owners.serverSign.refresh(context.Background()) }()
	for range 2 {
		select {
		case <-entered:
		case <-time.After(time.Second):
			t.Fatal("independent purpose was serialized behind another login")
		}
	}
	call, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err = owners.close(call); err != nil {
		t.Fatal("four-purpose close did not join original calls", err)
	}
	for range 2 {
		if err = <-done; err == nil {
			t.Fatal("closed purpose published credential")
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.loginCalls != 0 {
		t.Fatal("canceled JWT read continued to provider")
	}
}
