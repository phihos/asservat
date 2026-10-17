package kms

import (
	"context"
	"net/http"
	"sync"
	"testing"
	"time"
)

func TestInstalledOwnerProviderCloseAndJoinRetainsCancelledNativeRead(t *testing.T) {
	s, f := installedProviderSupervisorFixture(t)
	read, release, err := s.borrow(context.Background(), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	var once sync.Once
	finish := func() { once.Do(release) }
	defer finish()
	original, _ := read.Deadline()
	short, end := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer end()
	done := make(chan error, 1)
	joined := make(chan struct{})
	go func() { done <- s.CloseAndJoin(short); close(joined) }()
	defer func() { finish(); <-joined }()
	<-short.Done()
	if read.Err() == nil {
		t.Fatal("shutdown did not cancel the original native read")
	}
	select {
	case <-done:
		t.Fatal("bounded close error returned before native work joined")
	case <-time.After(50 * time.Millisecond):
	}
	if got, _ := read.Deadline(); !got.Equal(original) {
		t.Fatal("joining widened the native read interval")
	}
	finish()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("join discarded the original bounded Close failure")
		}
	case <-time.After(time.Second):
		t.Fatal("released read did not join")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.logins != 0 || f.lookups != 0 || f.revokes != 0 || len(f.calls) != 0 {
		t.Fatal("local finalization created provider traffic")
	}
}

func TestInstalledOwnerProviderCloseAndJoinRetainsBodyAfterOriginalBound(t *testing.T) {
	s, f := installedProviderSupervisorFixture(t)
	if err := s.Prime(context.Background()); err != nil {
		t.Fatal(err)
	}
	body := &ownerLeaseBlockingClose{entered: make(chan struct{}), finish: make(chan struct{})}
	var once sync.Once
	finish := func() { once.Do(func() { close(body.finish) }) }
	defer finish()
	var original context.Context
	transport := &ownerProviderLeaseTransport{source: s.effects.lifetimes.auditWrap.borrow, now: time.Now, base: ownerLeaseRoundTrip(func(r *http.Request) (*http.Response, error) {
		original = r.Context()
		return &http.Response{StatusCode: http.StatusOK, Body: body}, nil
	})}
	request, _ := http.NewRequest(http.MethodPost, "https://provider.invalid/v1/audit/encrypt/owner", nil)
	response, err := transport.RoundTrip(request)
	if err != nil {
		t.Fatal(err)
	}
	closed := make(chan struct{})
	go func() { _ = response.Body.Close(); close(closed) }()
	defer func() { finish(); <-closed }()
	<-body.entered
	short, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	joined := make(chan struct{})
	go func() { done <- s.CloseAndJoin(short); close(joined) }()
	defer func() { finish(); <-joined }()
	<-short.Done()
	select {
	case <-done:
		t.Fatal("CloseAndJoin detached an original provider body")
	case <-time.After(50 * time.Millisecond):
	}
	if original.Err() == nil {
		t.Fatal("provider body was not cancelled")
	}
	slot := s.effects.lifetimes.auditWrap
	slot.mu.Lock()
	retained := slot.borrows == 1 && slot.current != nil && len(slot.current.value.token) != 0 && !slot.finished
	slot.mu.Unlock()
	if !retained {
		t.Fatal("bounded failure lost token/body ownership")
	}
	finish()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("post-deadline local completion reinterpreted bounded failure")
		}
	case <-time.After(time.Second):
		t.Fatal("released provider body did not join")
	}
	for _, slot := range s.slots() {
		slot.mu.Lock()
		complete := slot.finished && slot.current == nil && slot.draining == nil && slot.borrows == 0 && !slot.active
		slot.mu.Unlock()
		if !complete {
			t.Fatal("joined finalization retained an active local slot")
		}
	}
	if err := s.CloseAndJoin(context.Background()); err != nil {
		t.Fatal("already joined close did not remain idempotent", err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.logins != 4 || f.lookups != 4 || f.revokes != 0 || len(f.calls) != 0 {
		t.Fatal("local finalization retried provider I/O after the original interval")
	}
}

func TestInstalledOwnerProviderCloseAndJoinRetainsOriginalControlProof(t *testing.T) {
	s, f := installedProviderSupervisorFixture(t)
	entered, cancelled, release := make(chan context.Context, 1), make(chan struct{}), make(chan struct{})
	var once sync.Once
	finish := func() { once.Do(func() { close(release) }) }
	defer finish()
	slot := s.effects.lifetimes.auditWrap
	slot.currentProof = func(ctx context.Context) (time.Time, error) {
		entered <- ctx
		<-ctx.Done()
		close(cancelled)
		<-release
		return time.Time{}, ctx.Err()
	}
	control := make(chan error, 1)
	go func() { control <- slot.refresh(context.Background()) }()
	defer func() { finish(); <-control }()
	var original context.Context
	select {
	case original = <-entered:
	case <-time.After(time.Second):
		t.Fatal("control did not enter its original native proof")
	}
	until, ok := original.Deadline()
	if !ok || time.Until(until) > 5*time.Second {
		t.Fatal("control lost its original five-second maximum")
	}
	short, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	joined := make(chan struct{})
	go func() { done <- s.CloseAndJoin(short); close(joined) }()
	defer func() { finish(); <-joined }()
	select {
	case <-cancelled:
	case <-time.After(time.Second):
		t.Fatal("shutdown did not cancel the original control proof")
	}
	<-short.Done()
	select {
	case <-done:
		t.Fatal("bounded close detached its active control proof")
	case <-time.After(50 * time.Millisecond):
	}
	if got, _ := original.Deadline(); !got.Equal(until) {
		t.Fatal("joining changed the original control deadline")
	}
	finish()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("joined control discarded the bounded shutdown error")
		}
	case <-time.After(time.Second):
		t.Fatal("released control proof did not join")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.logins != 0 || f.lookups != 0 || f.revokes != 0 || len(f.calls) != 0 {
		t.Fatal("cancelled control dispatched provider I/O")
	}
}

func TestInstalledOwnerProviderCloseAndJoinKeepsSuccessfulRetirement(t *testing.T) {
	s, f := installedProviderSupervisorFixture(t)
	if err := s.Prime(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := s.CloseAndJoin(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := s.CloseAndJoin(context.Background()); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.revokes != 4 || f.logins != 4 || f.lookups != 4 || len(f.calls) != 0 {
		t.Fatal("successful bounded retirement was skipped or repeated")
	}
}
