package bootstrap

import (
	"context"
	"testing"
	"time"

	app "asservat.local/asservat/internal/application/capacity"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/identity"
)

// These tests exercise only private ordering/cancellation. A zero concrete SQL
// adapter is deliberately never entered; no synthetic phase is asserted to be
// native or PostgreSQL acceptance evidence.
func TestProviderCapacityInvocationKeepsEarliestDeadlineAndExactContext(t *testing.T) {
	p := newProviderCapacitySourceOperation(t.Context(), &providerCapacitySourceInvocation{})
	defer p.close()
	original, end := context.WithTimeout(p.ctx, 40*time.Millisecond)
	defer end()
	call, done, err := p.enter(original, providerCapacityReading, providerCapacityNew)
	if err != nil {
		t.Fatal(err)
	}
	until, _ := call.Deadline()
	done(providerCapacityRead)
	foreign, stop := context.WithTimeout(t.Context(), time.Second)
	defer stop()
	if _, _, err := p.enter(foreign, providerCapacityProving, providerCapacityRead); err == nil {
		t.Fatal("foreign invocation context admitted")
	}
	later, stopLater := context.WithTimeout(p.ctx, time.Second)
	defer stopLater()
	call, done, err = p.enter(later, providerCapacityProving, providerCapacityRead)
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := call.Deadline(); !got.Equal(until) {
		t.Fatal("later phase extended original admitted child")
	}
	done(providerCapacityProtected)
	<-original.Done()
	if _, _, err := p.enter(later, providerCapacityFinalizing, providerCapacityProtected); err == nil {
		t.Fatal("expired child reopened under later deadline")
	}
}

func TestProviderCapacityInvocationRejectsRepeatedOutOfOrderAndCopiedCalls(t *testing.T) {
	p := newProviderCapacitySourceOperation(t.Context(), &providerCapacitySourceInvocation{})
	defer p.close()
	call, end := context.WithTimeout(p.ctx, time.Second)
	defer end()
	if _, err := p.AcceptCapacitySource(call, app.CapacitySourceAcceptance{}); err == nil {
		t.Fatal("accept before actual proof reached journal")
	}
	if _, err := p.CapacityProtection(call); err == nil {
		t.Fatal("Begin before original recovery/revision reached native reader")
	}
	// A manually reconstructed outer value has the original self pointer and
	// cannot enter, alter the original phase or close its original context.
	copied := &providerCapacitySourceOperation{self: p, owner: p.owner, ctx: p.ctx, cancel: p.cancel}
	if _, _, err := copied.enter(call, providerCapacityReading, providerCapacityNew); err == nil {
		t.Fatal("copied outer admitted")
	}
	copied.close()
	if p.ctx.Err() != nil {
		t.Fatal("copy closed original")
	}
	_, done, err := p.enter(call, providerCapacityReading, providerCapacityNew)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := p.enter(call, providerCapacityReading, providerCapacityNew); err == nil {
		t.Fatal("parallel phase admitted")
	}
	done(providerCapacityRead)
	if _, _, err := p.enter(call, providerCapacityReading, providerCapacityNew); err == nil {
		t.Fatal("original revision lookup repeated")
	}
}

func TestProviderCapacityInvocationCloseJoinsAdmittedWork(t *testing.T) {
	p := newProviderCapacitySourceOperation(t.Context(), &providerCapacitySourceInvocation{})
	call, end := context.WithTimeout(p.ctx, time.Second)
	defer end()
	active, finish, err := p.enter(call, providerCapacityReading, providerCapacityNew)
	if err != nil {
		t.Fatal(err)
	}
	closed := make(chan struct{})
	go func() { p.close(); close(closed) }()
	defer func() { finish(providerCapacityRead); <-closed }()
	<-active.Done()
	select {
	case <-closed:
		t.Fatal("Close detached admitted adapter work")
	default:
	}
	finish(providerCapacityRead)
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("released adapter did not join")
	}
	if _, _, err := p.enter(call, providerCapacityReading, providerCapacityNew); err == nil {
		t.Fatal("joined operation reopened")
	}
}

func TestProviderCapacityNativeContextSurvivesPhaseReturnWithinOriginalEnd(t *testing.T) {
	p := newProviderCapacitySourceOperation(t.Context(), &providerCapacitySourceInvocation{})
	defer p.close()
	// Only the private mechanical phase owner is exercised here. No synthetic
	// Kubernetes proof or SQL acceptance is provided by these contexts.
	original, end := context.WithTimeout(p.ctx, time.Second)
	defer end()
	_, readDone, err := p.enter(original, providerCapacityReading, providerCapacityNew)
	if err != nil {
		t.Fatal(err)
	}
	readDone(providerCapacityRead)
	phase, phaseDone, err := p.enter(original, providerCapacityProving, providerCapacityRead)
	if err != nil {
		t.Fatal(err)
	}
	defer phaseDone(providerCapacityProtected)
	native, err := p.retainNativeContext(original, phase)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = p.retainNativeContext(original, phase); err == nil {
		t.Fatal("second native context replaced the original owner")
	}
	want, _ := phase.Deadline()
	if got, _ := native.Deadline(); !got.Equal(want) {
		t.Fatal("retained native context changed the admitted deadline")
	}
	phaseDone(providerCapacityProtected)
	if phase.Err() == nil {
		t.Fatal("completed phase did not release its local context")
	}
	if native.Err() != nil {
		t.Fatal("phase completion cancelled native bracket before final acceptance")
	}
	final, finalDone, err := p.enter(original, providerCapacityFinalizing, providerCapacityProtected)
	if err != nil {
		t.Fatal(err)
	}
	defer finalDone(providerCapacityAccepted)
	if got, _ := final.Deadline(); !got.Equal(want) {
		t.Fatal("later acceptance extended retained native end")
	}
	end()
	<-native.Done()
	if final.Err() == nil {
		t.Fatal("original caller cancellation failed to close final phase")
	}
	finalDone(providerCapacityAccepted)
}

func TestProviderCapacityInvalidationKeepsOriginalCASAndRecovery(t *testing.T) {
	const root = "6a079394-20bb-4b4f-a4e2-246761fbe10c"
	now := time.Now().UTC().Truncate(time.Microsecond)
	recovery := artifact.RecoveryProof{InstallationID: root, IssuerEpoch: root, Revision: identity.Revision{UID: root, Generation: 1, Digest: [32]byte{1}}, ObservedAt: now, FreshUntil: now.Add(5 * time.Second)}
	p := newProviderCapacitySourceOperation(t.Context(), &providerCapacitySourceInvocation{observer: app.CapacitySourceObserver{RootID: root}})
	defer p.close()
	p.recovery, p.revision, p.until = recovery, 8, now.Add(4*time.Second)
	if !p.invalidationBound(root, 8, recovery, now, p.until) {
		t.Fatal("original failure CAS unavailable")
	}
	shifted := recovery
	shifted.ObservedAt = shifted.ObservedAt.In(time.FixedZone("same instant", 3600))
	shifted.FreshUntil = shifted.FreshUntil.In(time.FixedZone("same instant", 3600))
	if !p.invalidationBound(root, 8, shifted, now, p.until) {
		t.Fatal("same instants rejected")
	}
	shifted = recovery
	shifted.FreshUntil = shifted.FreshUntil.Add(-time.Microsecond)
	if p.invalidationBound(root, 9, recovery, now, p.until) || p.invalidationBound(root, 8, shifted, now, p.until) || p.invalidationBound(root, 8, recovery, now, p.until.Add(time.Microsecond)) {
		t.Fatal("original failure adopted a different revision, recovery observation or end")
	}
}
