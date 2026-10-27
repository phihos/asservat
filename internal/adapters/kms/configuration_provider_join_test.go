package kms

import (
	"context"
	"net/http"
	"sync"
	"testing"
	"time"
)

// The fixture supplies synthetic current authority. It exercises actual token
// login/lookup and the concrete lifetime/HTTP-body owner, not installed setup.
func configurationJoinFixture(t *testing.T) (*InstalledConfigurationProviderEffects, *ownerProviderControlFixture) {
	t.Helper()
	return configurationJoinFixtureWithClock(t, time.Now)
}

func configurationJoinFixtureWithClock(t *testing.T, now func() time.Time) (*InstalledConfigurationProviderEffects, *ownerProviderControlFixture) {
	t.Helper()
	f, in, profile := configurationControlFixture(t, "audit-wrap")
	f.mu.Lock()
	f.clock = now
	f.mu.Unlock()
	root, cancel := context.WithCancel(context.Background())
	effects, err := newConfigurationProviderEffects(root, in, profile,
		func(context.Context) ([]byte, error) {
			return ownerProviderTestJWT(now().Add(600 * time.Second)), nil
		},
		func(context.Context) (time.Time, error) { return now().Add(5 * time.Second), nil }, f.server.Client(), now)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	s := &InstalledConfigurationProviderEffects{effects: effects, root: root, cancel: cancel, closeDone: make(chan struct{})}
	t.Cleanup(func() { _ = s.CloseAndJoin(context.Background()) })
	return s, f
}

func TestConfigurationProviderCloseAndJoinKeepsNativeOwnership(t *testing.T) {
	s, f := configurationJoinFixture(t)
	read, release, err := s.borrow(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var once sync.Once
	finish := func() { once.Do(release) }
	defer finish()
	original, _ := read.Deadline()
	short, stop := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer stop()
	done, joined := make(chan error, 1), make(chan struct{})
	go func() { done <- s.CloseAndJoin(short); close(joined) }()
	defer func() { finish(); <-joined }()
	<-short.Done()
	if read.Err() == nil {
		t.Fatal("original native read was not cancelled")
	}
	select {
	case <-done:
		t.Fatal("bounded shutdown returned before native read joined")
	case <-time.After(50 * time.Millisecond):
	}
	if got, _ := read.Deadline(); !got.Equal(original) {
		t.Fatal("shutdown renewed original native interval")
	}
	finish()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("joining discarded original bounded error")
		}
	case <-time.After(time.Second):
		t.Fatal("released native read did not join")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.loginCalls != 0 || f.lookups != 0 || f.revokes != 0 {
		t.Fatal("local joining created provider work")
	}
}

func TestConfigurationProviderCloseAndJoinDoesNotRenewRevocationWindow(t *testing.T) {
	s, f := configurationJoinFixture(t)
	if err := s.effects.wrap.refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	body := &ownerLeaseBlockingClose{entered: make(chan struct{}), finish: make(chan struct{})}
	var once sync.Once
	finish := func() { once.Do(func() { close(body.finish) }) }
	defer finish()
	var original context.Context
	transport := &ownerProviderLeaseTransport{source: s.effects.wrap.borrow, now: time.Now, base: ownerLeaseRoundTrip(func(r *http.Request) (*http.Response, error) {
		original = r.Context()
		return &http.Response{StatusCode: http.StatusOK, Body: body}, nil
	})}
	request, _ := http.NewRequest(http.MethodPost, "https://provider.invalid/v1/audit/encrypt/configuration", nil)
	response, err := transport.RoundTrip(request)
	if err != nil {
		t.Fatal(err)
	}
	bodyDone := make(chan struct{})
	go func() { _ = response.Body.Close(); close(bodyDone) }()
	defer func() { finish(); <-bodyDone }()
	<-body.entered
	short, stop := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer stop()
	done, joined := make(chan error, 1), make(chan struct{})
	go func() { done <- s.CloseAndJoin(short); close(joined) }()
	defer func() { finish(); <-joined }()
	<-short.Done()
	select {
	case <-done:
		t.Fatal("shutdown detached provider body")
	case <-time.After(50 * time.Millisecond):
	}
	if original.Err() == nil {
		t.Fatal("original provider body was not cancelled")
	}
	finish()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("local completion hid original bounded close failure")
		}
	case <-time.After(time.Second):
		t.Fatal("released provider body did not join")
	}
	if err := s.CloseAndJoin(context.Background()); err != nil {
		t.Fatal("joined close was not idempotent", err)
	}
	for _, slot := range []*ownerProviderLifetime{s.effects.wrap, s.effects.unwrap} {
		slot.mu.Lock()
		complete := slot.finished && slot.current == nil && slot.draining == nil && slot.borrows == 0 && !slot.active
		slot.mu.Unlock()
		if !complete {
			t.Fatal("local lifetime still owns admitted work")
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.loginCalls != 1 || f.lookups != 1 || f.renewCalls != 0 || f.revokes != 0 {
		t.Fatal("shutdown retried provider work after the original close bound")
	}
}
