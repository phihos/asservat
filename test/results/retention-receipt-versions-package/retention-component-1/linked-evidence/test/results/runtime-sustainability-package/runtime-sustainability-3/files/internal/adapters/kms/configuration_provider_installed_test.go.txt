package kms

import (
	"context"
	"sync"
	"testing"
	"time"
)

// Native/SQL facts are deliberately absent: this exercises only the concrete
// runtime owner's cancellation/join around the existing private lease owner.
// The synthetic legacy proof is invoked directly under a real native borrow;
// the fresh Run path is separately required never to fall back to this hook.
func TestConfigurationProviderCloseRetainsBlockedControlOwnership(t *testing.T) {
	f, in, profile := configurationControlFixture(t, "audit-wrap")
	root, cancel := context.WithCancel(context.Background())
	defer cancel()
	entered, release := make(chan struct{}), make(chan struct{})
	var released sync.Once
	unblock := func() { released.Do(func() { close(release) }) }
	jwt := func(context.Context) ([]byte, error) {
		t.Error("blocked current proof reached provider JWT")
		return nil, ErrKeyService
	}
	proof := func(ctx context.Context) (time.Time, error) { close(entered); <-release; return time.Time{}, ctx.Err() }
	effects, err := newConfigurationProviderEffects(root, in, profile, jwt, proof, f.server.Client(), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	s := &InstalledConfigurationProviderEffects{effects: effects, root: root, cancel: cancel, closeDone: make(chan struct{})}
	t.Cleanup(func() { cancel(); unblock(); _ = s.Close(context.Background()) })
	done := make(chan error, 1)
	native, releaseNative, err := s.borrow(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		err := s.effects.wrap.refresh(native)
		releaseNative()
		done <- err
	}()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("control did not enter its original proof")
	}
	short, end := context.WithTimeout(context.Background(), 40*time.Millisecond)
	if err = s.Close(short); err == nil {
		t.Fatal("Close reported join while proof still owns caller work")
	}
	end()
	if err = s.Run(context.Background()); err == nil {
		t.Fatal("closing runtime admitted another owner")
	}
	select {
	case <-done:
		t.Fatal("Run returned before blocked child joined")
	default:
	}
	unblock()
	select {
	case err = <-done:
		if err == nil {
			t.Fatal("cancelled runtime returned success")
		}
	case <-time.After(time.Second):
		t.Fatal("released control failed to join")
	}
	if err = s.Close(context.Background()); err != nil {
		t.Fatal("positive retry did not join original owned controls", err)
	}
	f.mu.Lock()
	logins := f.loginCalls
	f.mu.Unlock()
	if logins != 0 {
		t.Fatal("cancelled unavailable proof dispatched provider login")
	}
}
