package kubernetes

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
)

func configurationPathRoot(t *testing.T, f *configurationSourcePathFixture) *ConfigurationRuntimeRoleRoot {
	t.Helper()
	r, err := NewConfigurationRuntimeRoleRoot(context.Background(), f.source, f.source.input)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(r.Close)
	return r
}

// The SQL effect itself is qualified separately against PostgreSQL. This test
// measures the actual Kubernetes graph at its supported rate, including the
// root read that the SQL producer requires after recovery/installation locks.
func TestConfigurationRoleRootCompleteOriginalOperation(t *testing.T) {
	f := newConfigurationSourcePathFixture(t)
	root := configurationPathRoot(t, f)
	opened, err := root.OpenConfigurationRuntimeRoles(context.Background())
	if err != nil {
		t.Fatal("open", err)
	}
	for n, purpose := range contracts.ConfigurationRuntimeRolePurposes() {
		start, requests, probes := time.Now(), f.requests.Load(), f.probes.Load()
		var claimed contracts.ConfigurationRuntimeRoleSnapshot
		call, cancel := context.WithDeadline(context.Background(), start.Add(5*time.Second))
		err = root.WithConfigurationRoleOperation(call, func(ctx context.Context) error {
			var fresh bool
			var e error
			claimed, fresh, e = root.ClaimConfigurationRuntimeRole(ctx, purpose, 42, start.Add(-time.Minute))
			if e != nil || !fresh {
				return fmt.Errorf("first claim: %w", e)
			}
			// The SQL producer intersects its context with the persisted original
			// claim end before waiting for locks or completing the receipt.
			ctx, cancel := context.WithDeadline(ctx, claimed.ValidUntil)
			defer cancel()
			current, e := root.ReadConfigurationRuntimeRoles(ctx)
			if e != nil {
				return fmt.Errorf("post-lock current read: %w", e)
			}
			if !reflect.DeepEqual(current.State, claimed.State) || current.UID != claimed.UID || current.Sources != claimed.Sources || current.ValidUntil.After(claimed.ValidUntil) {
				return fmt.Errorf("post-lock read replaced or renewed the original snapshot")
			}
			receipt := contracts.PublicRuntimeRoleReceipt{RoleName: "as_" + strings.ReplaceAll(f.source.input.InstallationID, "-", "") + fmt.Sprintf("_cfg_%02d", n), RoleOID: uint32(100 + n), LayoutDigest: f.source.input.LayoutDigest}
			if e = root.CompleteConfigurationRuntimeRole(ctx, claimed, purpose, receipt); e != nil {
				return fmt.Errorf("complete: %w", e)
			}
			return nil
		})
		cancel()
		used := f.requests.Load() - requests
		t.Logf("purpose=%s elapsed=%s requests=%d negative_probes=%d", purpose, time.Since(start), used, f.probes.Load()-probes)
		// ADR-188: opening proof, post-lock recheck, completion under it.
		if used > 90 {
			t.Fatalf("role operation used %d API requests, want at most 90", used)
		}
		if err != nil {
			t.Fatal("original five-second role operation", err)
		}
		if claimed.UID != opened.UID || claimed.State.OperationID != opened.State.OperationID {
			t.Fatal("root identity changed")
		}
		if !claimed.State.Until.Equal(opened.State.Until) {
			t.Fatal("root lifetime changed")
		}
		if claimed.ValidUntil.After(start.Add(5 * time.Second)) {
			t.Fatal("original caller deadline extended")
		}
	}
	// A later independent call reads the original claim. It cannot grant another
	// CREATE, replace credentials, or refill its expired first-effect interval.
	priorWrites := f.secretWrites.Load()
	old, fresh, err := root.ClaimConfigurationRuntimeRole(context.Background(), contracts.ConfigurationRuntimeRolePurposes()[0], 42, time.Now().Add(-time.Minute))
	if err != nil || fresh || old.State.Roles[0].Receipt == nil || f.secretWrites.Load() != priorWrites {
		t.Fatal("passive claim replay changed original state", err)
	}
	start, requests, probes := time.Now(), f.requests.Load(), f.probes.Load()
	err = root.WithConfigurationRoleOperation(context.Background(), func(ctx context.Context) error {
		// This is the real root read after the SQL verifier's locks. SQL role
		// verification is separate native evidence, never supplied by this fake.
		verified, e := root.ReadConfigurationRuntimeRoles(ctx)
		if e != nil {
			return e
		}
		ref, e := root.PublishConfigurationRuntimeProjection(ctx, verified)
		if e != nil {
			return e
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		if f.projection == nil || ref.UID != string(f.projection.UID) || ref.Name != f.projection.Name || f.projection.Immutable == nil || !*f.projection.Immutable || len(f.projection.Data) != 4 {
			return fmt.Errorf("original immutable three-role projection missing")
		}
		return nil
	})
	used := f.requests.Load() - requests
	t.Logf("final inventory/projection elapsed=%s requests=%d negative_probes=%d", time.Since(start), used, f.probes.Load()-probes)
	if used > 90 {
		t.Fatalf("projection operation used %d API requests, want at most 90", used)
	}
	if err != nil {
		t.Fatal("original five-second projection operation", err)
	}
}

func TestConfigurationRoleOperationRechecksChangedEnforcementAndSources(t *testing.T) {
	for _, c := range []struct {
		name  string
		fault int32
	}{
		{"rbac", 1}, {"admission", 2}, {"fleet", 3}, {"owner", 4},
		{"workload", 5}, {"guard", 6}, {"account", 7}, {"administrator", 8}, {"probe-became-administrator", 9},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newConfigurationSourcePathFixture(t)
			root := configurationPathRoot(t, f)
			if _, err := root.OpenConfigurationRuntimeRoles(context.Background()); err != nil {
				t.Fatal(err)
			}
			err := root.WithConfigurationRoleOperation(context.Background(), func(ctx context.Context) error {
				original, e := f.source.ReadConfigurationRoleSource(ctx)
				if e != nil {
					return e
				}
				writes := f.secretWrites.Load()
				if c.fault == 6 {
					f.guardVersion.Add(1)
				} else {
					f.fault.Store(c.fault)
				}
				if _, fresh, e := root.ClaimConfigurationRuntimeRole(ctx, contracts.ConfigurationRuntimeRolePurposes()[0], 42, time.Now().Add(-time.Minute)); e == nil || fresh {
					t.Fatal("known changed current proof allowed claim")
				}
				if f.secretWrites.Load() != writes {
					t.Fatal("denied proof changed Secret")
				}
				// A -> B -> A does not revive this operation after a known negative.
				f.fault.Store(0)
				if c.fault == 6 {
					f.guardVersion.Add(-1)
				}
				if _, e = f.source.ReadConfigurationRoleSource(ctx); e == nil {
					t.Fatal("invalidated original operation revived")
				}
				if !time.Now().Before(original.FreshUntil) {
					t.Log("negative also reached original deadline")
				}
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestConfigurationRoleOperationChecksGuardAroundNegativeProbes(t *testing.T) {
	for _, initial := range []bool{true, false} {
		t.Run(fmt.Sprint("initial=", initial), func(t *testing.T) {
			f := newConfigurationSourcePathFixture(t)
			root := configurationPathRoot(t, f)
			err := root.WithConfigurationRoleOperation(context.Background(), func(ctx context.Context) error {
				if !initial {
					if _, e := f.source.ReadConfigurationRoleSource(ctx); e != nil {
						return e
					}
				}
				f.flipGuard.Store(true)
				if _, e := f.source.ReadConfigurationRoleSource(ctx); e == nil {
					t.Fatal("guard changed during negative probes was accepted")
				}
				if f.secretWrites.Load() != 0 {
					t.Fatal("source proof wrote Secret")
				}
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestConfigurationRoleOperationDoesNotEscapeOrRenew(t *testing.T) {
	f := newConfigurationSourcePathFixture(t)
	root := configurationPathRoot(t, f)
	var escaped context.Context
	var first contracts.ConfigurationRoleObservation
	if err := root.WithConfigurationRoleOperation(context.Background(), func(ctx context.Context) error {
		escaped = ctx
		var e error
		first, e = f.source.ReadConfigurationRoleSource(ctx)
		if e != nil {
			return e
		}
		// A short child cancels the current recheck instead of obtaining a fresh
		// five-second interval. Every dependent I/O remains joined on return.
		child, end := context.WithTimeout(ctx, time.Millisecond)
		defer end()
		if _, e = f.source.ReadConfigurationRoleSource(child); e == nil {
			t.Fatal("short child obtained detached authority")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	requests := f.requests.Load()
	if _, err := f.source.ReadConfigurationRoleSource(escaped); err == nil || f.requests.Load() != requests {
		t.Fatal("completed operation context escaped")
	}
	counts := [3]int32{f.purposeProbes[0].Load(), f.purposeProbes[1].Load(), f.purposeProbes[2].Load()}
	second, err := f.source.ReadConfigurationRoleSource(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !second.ObservedAt.After(first.ObservedAt) {
		t.Fatal("independent operation borrowed original observation")
	}
	for n, c := range counts {
		if f.purposeProbes[n].Load() <= c {
			t.Fatal("independent operation omitted current purpose proof", n)
		}
	}
}

func TestConfigurationRoleOperationCloseCancelsAndJoins(t *testing.T) {
	f := newConfigurationSourcePathFixture(t)
	root := configurationPathRoot(t, f)
	entered, cancelled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	defer unblock()
	done := make(chan error, 1)
	go func() {
		done <- root.WithConfigurationRoleOperation(context.Background(), func(ctx context.Context) error { close(entered); <-ctx.Done(); close(cancelled); <-release; return nil })
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("operation did not start")
	}
	closed := make(chan struct{})
	go func() { root.Close(); close(closed) }()
	select {
	case <-cancelled:
	case <-time.After(time.Second):
		t.Fatal("close did not cancel operation")
	}
	select {
	case <-closed:
		t.Fatal("close returned before operation joined")
	default:
	}
	unblock()
	select {
	case err := <-done:
		if err != cfg.ErrUnavailable {
			t.Fatal("cancelled operation reported success", err)
		}
	case <-time.After(time.Second):
		t.Fatal("operation did not join")
	}
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("close did not join")
	}
}

// ADR-188: completion reuses only a recheck that followed the opening proof.
// Without the role step's post-lock read it proves afresh.
func TestConfigurationRoleCompletionNeverReusesOpeningProof(t *testing.T) {
	f := newConfigurationSourcePathFixture(t)
	root := configurationPathRoot(t, f)
	if _, err := root.OpenConfigurationRuntimeRoles(context.Background()); err != nil {
		t.Fatal("open", err)
	}
	purpose := contracts.ConfigurationRuntimeRolePurposes()[0]
	start := time.Now()
	err := root.WithConfigurationRoleOperation(context.Background(), func(ctx context.Context) error {
		claimed, fresh, e := root.ClaimConfigurationRuntimeRole(ctx, purpose, 42, start.Add(-time.Minute))
		if e != nil || !fresh {
			return fmt.Errorf("claim: %w", e)
		}
		before := f.requests.Load()
		receipt := contracts.PublicRuntimeRoleReceipt{RoleName: "as_" + strings.ReplaceAll(f.source.input.InstallationID, "-", "") + "_cfg_00", RoleOID: 100, LayoutDigest: f.source.input.LayoutDigest}
		if e = root.CompleteConfigurationRuntimeRole(ctx, claimed, purpose, receipt); e != nil {
			return fmt.Errorf("complete: %w", e)
		}
		// A full recheck plus journal GET and PUT; reuse would be two requests.
		if used := f.requests.Load() - before; used < 20 {
			return fmt.Errorf("completion reused the opening proof (%d requests)", used)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
