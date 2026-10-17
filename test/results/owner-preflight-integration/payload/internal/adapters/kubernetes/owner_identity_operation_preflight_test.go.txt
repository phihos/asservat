package kubernetes

import (
	"context"
	"errors"
	"net/http"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/audit"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/fleet"
)

// Explicit synthetic SQL lock boundary; all native reads below still traverse
// the concrete API clients. Real row blocking is qualified separately.
type ownerPreflightBridgeFixture struct {
	*rootPinEffectFixture
	before func(context.Context, fleet.Administration) error
	held   atomic.Bool
	calls  atomic.Int32
}

func (s *ownerPreflightBridgeFixture) WithInitialRuntimeOwnerBridge(ctx context.Context, a fleet.Administration, run func(context.Context) error) error {
	s.calls.Add(1)
	if !a.Valid(time.Now()) || a.Suspended {
		return cfg.ErrUnavailable
	}
	if s.before != nil {
		if err := s.before(ctx, a); err != nil {
			return err
		}
	}
	s.held.Store(true)
	defer s.held.Store(false)
	return run(ctx)
}

func TestOwnerPreflightActualGraphsAndLockOrder(t *testing.T) {
	for _, withRoles := range []bool{false, true} {
		t.Run(map[bool]string{false: "without-roles", true: "with-roles"}[withRoles], func(t *testing.T) {
			f := newOwnerIdentityOperationFixture(t)
			effects := &ownerPreflightBridgeFixture{rootPinEffectFixture: f.effects}
			f.bridge.effects = effects
			var phase atomic.Int32
			var counts [3]atomic.Int32
			f.api.mu.Lock()
			previous := f.api.extra
			f.api.extra = func(w http.ResponseWriter, r *http.Request) bool {
				counts[phase.Load()].Add(1)
				if phase.Load() == 0 && effects.held.Load() {
					t.Error("initial native request under long SQL lock")
				}
				if phase.Load() != 0 && !effects.held.Load() {
					t.Error("current/final native request outside SQL lock")
				}
				return previous(w, r)
			}
			f.api.mu.Unlock()
			var reads []bool
			f.root.accepted = ownerDiagnosticAcceptedReader(func(ctx context.Context) (fleet.OwnerConfigurationObservation, error) {
				reads = append(reads, effects.held.Load())
				return f.accepted.ReadOwnerConfiguration(ctx)
			})
			var first ownerIdentityOperationNative
			effects.before = func(ctx context.Context, a fleet.Administration) error {
				if phase.Load() != 1 || a.Revision != first.source.fleet.Revision || a.InstallationID != first.source.fleet.InstallationID || a.IssuerEpoch != first.source.fleet.IssuerEpoch || !a.ObservedAt.Equal(first.source.fleet.ObservedAt) || !a.FreshUntil.Equal(first.source.fleet.FreshUntil) {
					t.Error("bridge did not receive exact completed preflight")
				}
				return nil
			}
			err := f.root.providerOperation(context.Background(), withRoles, func(ctx context.Context) (ownerIdentityOperationNative, error) {
				var err error
				first, err = f.root.readOwnerIdentityOperationNative(ctx, f.root.input.LayoutDigest, withRoles)
				phase.Store(1)
				return first, err
			}, func(ctx context.Context, admitted ownerIdentityOperationNative) error {
				phase.Store(2)
				deadline, ok := ctx.Deadline()
				if !ok || deadline.After(first.until) || admitted.until.After(first.until) || admitted.source.proof.native != first.source.proof.native || !admitted.source.proof.observation.ObservedAt.Equal(first.source.proof.observation.ObservedAt) {
					t.Error("post-lock read replaced original native proof or deadline")
				}
				last, err := f.root.readOwnerIdentityOperationNative(ctx, f.root.input.LayoutDigest, withRoles)
				if err == nil && !ownerIdentityOperationOriginalsEqual(admitted, last) {
					return cfg.ErrChanged
				}
				return err
			})
			if err != nil {
				t.Fatal(err)
			}
			// Full C12/B13/H7/S26/W4/T9 twice; added current C4/S16.
			// Role mode adds exactly one S request to each of the three graphs.
			want := [3]int32{71, 20, 71}
			if withRoles {
				want = [3]int32{72, 21, 72}
			}
			got := [3]int32{counts[0].Load(), counts[1].Load(), counts[2].Load()}
			if got != want || !reflect.DeepEqual(reads, []bool{false, true, true}) || effects.calls.Load() != 1 {
				t.Fatal("changed native graphs or accepted-reader lock order", got, want, reads, effects.calls.Load())
			}
		})
	}
}

func TestOwnerPreflightPostLockChangesDenyBeforeSelectionClaims(t *testing.T) {
	for _, name := range []string{"fleet-source-version", "owner-source-version", "source-guard", "bridge-journal", "resource-journal", "owner-account", "owner-service", "administrator", "accepted-configuration"} {
		t.Run(name, func(t *testing.T) {
			f := newOwnerIdentityOperationFixture(t)
			api := installOwnerBootstrapAPI(t, f)
			p, err := NewOwnerBootstrapSelectionProducer(f.root, ownerBootstrapPlanFixture(f))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(p.Close)
			effects := &ownerPreflightBridgeFixture{rootPinEffectFixture: f.effects}
			effects.before = func(context.Context, fleet.Administration) error {
				if p.parentAttempted || p.childAttempted || p.receiptAttempted || api.writes.Load() != 0 || api.creates.Load() != 0 {
					t.Error("attempt/effect preceded locked guard")
				}
				if name == "administrator" {
					f.fault.Store(6)
					return nil
				}
				if name == "accepted-configuration" {
					f.fault.Store(3)
					return nil
				}
				prefix := "/api/v1/namespaces/" + f.root.input.Namespace.Name
				path := ""
				switch name {
				case "fleet-source-version":
					path = prefix + "/configmaps/" + f.source.input.FleetSource.Name
				case "owner-source-version":
					path = prefix + "/configmaps/" + f.source.input.OwnerSource.Name
				case "source-guard":
					path = "/apis/admissionregistration.k8s.io/v1/validatingadmissionpolicies/" + f.source.protection.plan.Name
				case "bridge-journal":
					path = f.bridge.path()
				case "resource-journal":
					path = f.resources.path()
				case "owner-account":
					path = prefix + "/serviceaccounts/" + f.root.input.ServiceAccount.Name
				case "owner-service":
					f.accepted.mu.Lock()
					path = prefix + "/services/" + f.accepted.value.Configuration.Pool.Service
					f.accepted.mu.Unlock()
				}
				f.api.mu.Lock()
				defer f.api.mu.Unlock()
				object := f.api.objects[path]
				if object == nil {
					t.Error("missing exact fixture object", path)
					return cfg.ErrUnavailable
				}
				metadata := object["metadata"].(map[string]any)
				if name == "source-guard" {
					metadata["generation"] = float64(91)
				} else {
					metadata["resourceVersion"] = "991"
				}
				return nil
			}
			f.bridge.effects = effects
			out, err := p.Advance(context.Background())
			if err == nil || out.Status != OwnerBootstrapStopped || effects.calls.Load() != 1 || api.writes.Load() != 0 || api.creates.Load() != 0 || p.parentAttempted || p.childAttempted || p.receiptAttempted || p.pendingParent != nil {
				t.Fatal("post-wait change admitted first claim", out.Status, err, effects.calls.Load(), api.writes.Load(), api.creates.Load())
			}
		})
	}
}

func TestOwnerPreflightAcceptedFailurePrecedesPrivateJournal(t *testing.T) {
	for _, name := range []string{"reader-unavailable", "expired", "different-configuration"} {
		t.Run(name, func(t *testing.T) {
			f := newOwnerIdentityOperationFixture(t)
			effects := &ownerPreflightBridgeFixture{rootPinEffectFixture: f.effects}
			f.bridge.effects = effects
			var privateGets atomic.Int32
			f.api.mu.Lock()
			previous := f.api.extra
			f.api.extra = func(w http.ResponseWriter, r *http.Request) bool {
				if r.Method == http.MethodGet && r.URL.Path == f.root.path()+"/"+f.root.name() {
					privateGets.Add(1)
				}
				return previous(w, r)
			}
			f.api.mu.Unlock()
			f.root.accepted = ownerDiagnosticAcceptedReader(func(ctx context.Context) (fleet.OwnerConfigurationObservation, error) {
				v, err := f.accepted.ReadOwnerConfiguration(ctx)
				switch name {
				case "reader-unavailable":
					return v, cfg.ErrUnavailable
				case "expired":
					v.FreshUntil = v.ObservedAt
				case "different-configuration":
					v.Configuration.Pool.ServiceUID = ownerID(9900)
				}
				return v, err
			})
			_, err := f.root.OpenProviderOwnerIdentityRoles(context.Background())
			if !errors.Is(err, cfg.ErrUnavailable) || privateGets.Load() != 0 || effects.calls.Load() != 0 || f.root.createAttempted || f.root.pendingOperationRoot != nil {
				t.Fatal("failed short accepted check reached private data or effects", err, privateGets.Load(), effects.calls.Load())
			}
		})
	}
}

func TestOwnerPreflightRoleAbsenceCannotAdoptAppearingOrLostRoot(t *testing.T) {
	for _, present := range []bool{false, true} {
		t.Run(map[bool]string{false: "appeared-during-wait", true: "original-disappeared"}[present], func(t *testing.T) {
			f := newOwnerIdentityOperationFixture(t)
			if present {
				if _, err := f.root.OpenProviderOwnerIdentityRoles(context.Background()); err != nil {
					t.Fatal(err)
				}
			}
			path := f.root.path() + "/" + f.root.name()
			f.api.mu.Lock()
			originalPosts := f.api.posts[path]
			f.api.mu.Unlock()
			effects := &ownerPreflightBridgeFixture{rootPinEffectFixture: f.effects}
			effects.before = func(context.Context, fleet.Administration) error {
				f.api.mu.Lock()
				defer f.api.mu.Unlock()
				if present {
					delete(f.api.objects, path)
				} else {
					f.api.objects[path] = map[string]any{"apiVersion": "v1", "kind": "Secret"}
				}
				return nil
			}
			f.bridge.effects = effects
			_, err := f.root.OpenProviderOwnerIdentityRoles(context.Background())
			f.api.mu.Lock()
			posts := f.api.posts[path]
			f.api.mu.Unlock()
			if err == nil || posts != originalPosts || effects.calls.Load() != 1 || !present && f.root.createAttempted {
				t.Fatal("post-lock role replacement became creation/adoption authority", err, posts, originalPosts, effects.calls.Load())
			}
		})
	}
}

func TestOwnerPreflightCallerCancellationBeforeLockDeniesEffects(t *testing.T) {
	f := newOwnerIdentityOperationFixture(t)
	api := installOwnerBootstrapAPI(t, f)
	p, err := NewOwnerBootstrapSelectionProducer(f.root, ownerBootstrapPlanFixture(f))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	effects := &ownerPreflightBridgeFixture{rootPinEffectFixture: f.effects, before: func(context.Context, fleet.Administration) error { cancel(); return nil }}
	f.bridge.effects = effects
	_, err = p.Advance(ctx)
	if err == nil || effects.calls.Load() != 1 || api.writes.Load() != 0 || api.creates.Load() != 0 || p.parentAttempted {
		t.Fatal("canceled original caller admitted effect", err)
	}
}

func TestOwnerPreflightCloseJoinsInitialRead(t *testing.T) {
	for _, name := range []string{"root", "bridge", "resources"} {
		t.Run(name, func(t *testing.T) {
			f := newOwnerIdentityOperationFixture(t)
			entered, canceled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
			var once sync.Once
			unblock := func() { once.Do(func() { close(release) }) }
			defer unblock()
			result := make(chan error, 1)
			go func() {
				result <- f.root.providerOperation(context.Background(), false, func(ctx context.Context) (ownerIdentityOperationNative, error) {
					close(entered)
					<-ctx.Done()
					close(canceled)
					<-release
					return ownerIdentityOperationNative{}, cfg.ErrUnavailable
				}, func(context.Context, ownerIdentityOperationNative) error {
					t.Error("canceled preflight entered effects")
					return nil
				})
			}()
			select {
			case <-entered:
			case err := <-result:
				t.Fatal("preflight failed before lifetime barrier", err)
			case <-time.After(2 * time.Second):
				t.Fatal("preflight did not enter lifetime barrier")
			}
			closed := make(chan struct{})
			go func() {
				switch name {
				case "root":
					f.root.Close()
				case "bridge":
					f.bridge.Close()
				case "resources":
					f.resources.Close()
				}
				close(closed)
			}()
			select {
			case <-canceled:
			case <-time.After(time.Second):
				t.Fatal("original close did not cancel preflight")
			}
			select {
			case <-closed:
				t.Fatal("close returned before admitted preflight joined")
			default:
			}
			unblock()
			select {
			case err := <-result:
				if err == nil {
					t.Fatal("closed preflight succeeded")
				}
			case <-time.After(time.Second):
				t.Fatal("preflight did not join")
			}
			select {
			case <-closed:
			case <-time.After(time.Second):
				t.Fatal("close did not join")
			}
		})
	}
}

type ownerPreflightLegacyOnly struct {
	base  *rootPinEffectFixture
	calls int
}

func (s *ownerPreflightLegacyOnly) InitialRuntimeBridgeRecord() (audit.InitialInstallation, audit.Receipt) {
	return s.base.InitialRuntimeBridgeRecord()
}
func (s *ownerPreflightLegacyOnly) WithInitialRuntimeBridge(ctx context.Context, run func(context.Context) error) error {
	s.calls++
	return run(ctx)
}
func TestOwnerPreflightNoLegacyFallback(t *testing.T) {
	f := newOwnerIdentityOperationFixture(t)
	legacy := &ownerPreflightLegacyOnly{base: f.effects}
	f.bridge.effects = legacy
	entered := false
	err := f.root.providerOperation(context.Background(), false, func(context.Context) (ownerIdentityOperationNative, error) {
		entered = true
		return ownerIdentityOperationNative{}, nil
	}, func(context.Context, ownerIdentityOperationNative) error { entered = true; return nil })
	if !errors.Is(err, cfg.ErrUnavailable) || entered || legacy.calls != 0 {
		t.Fatal("fresh path fell back to legacy bridge", err, entered, legacy.calls)
	}
	if err = f.root.operation(context.Background(), func(context.Context) error { return nil }); err != nil || legacy.calls != 1 {
		t.Fatal("legacy path changed", err, legacy.calls)
	}
}

func TestOwnerPreflightOriginalAgeNotReplacedAfterLockWait(t *testing.T) {
	f := newOwnerIdentityOperationFixture(t)
	api := installOwnerBootstrapAPI(t, f)
	p, err := NewOwnerBootstrapSelectionProducer(f.root, ownerBootstrapPlanFixture(f))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	effects := &ownerPreflightBridgeFixture{rootPinEffectFixture: f.effects}
	effects.before = func(context.Context, fleet.Administration) error {
		// This simulates elapsed waiting, never refreshes the original native proof.
		// A later accepted observation deliberately cannot rescue the old operation.
		f.api.mu.Lock()
		f.api.shift += 6 * time.Second
		f.api.mu.Unlock()
		now := f.api.clock().UTC().Truncate(time.Microsecond)
		f.accepted.mu.Lock()
		f.accepted.value.ObservedAt = now
		f.accepted.value.FreshUntil = now.Add(5 * time.Second)
		f.accepted.mu.Unlock()
		return nil
	}
	f.bridge.effects = effects
	_, err = p.Advance(context.Background())
	if err == nil || effects.calls.Load() != 1 || api.writes.Load() != 0 || api.creates.Load() != 0 || p.parentAttempted {
		t.Fatal("fresh accepted projection revived expired initial native interval", err)
	}
}

func TestOwnerPreflightShortParentDeadlineSurvivesBothAdmissions(t *testing.T) {
	f := newOwnerIdentityOperationFixture(t)
	end := time.Now().Add(2 * time.Second)
	ctx, cancel := context.WithDeadline(context.Background(), end)
	defer cancel()
	effects := &ownerPreflightBridgeFixture{rootPinEffectFixture: f.effects}
	effects.before = func(ctx context.Context, _ fleet.Administration) error {
		actual, ok := ctx.Deadline()
		if !ok || !actual.Equal(end) {
			t.Error("SQL entry extended or replaced original caller deadline", actual, end)
		}
		return nil
	}
	f.bridge.effects = effects
	entered := false
	err := f.root.providerOperation(ctx, false, func(ctx context.Context) (ownerIdentityOperationNative, error) {
		return f.root.readOwnerIdentityOperationNative(ctx, f.root.input.LayoutDigest, false)
	}, func(ctx context.Context, first ownerIdentityOperationNative) error {
		entered = true
		actual, ok := ctx.Deadline()
		if !ok || !actual.Equal(end) || !first.until.Equal(end) {
			t.Error("locked native admission extended original caller deadline", actual, first.until, end)
		}
		return nil
	})
	if err != nil || !entered || effects.calls.Load() != 1 {
		t.Fatal("short valid caller admission failed", err, entered, effects.calls.Load())
	}
}

func TestOwnerPreflightActualSelectionWriteRemainsLocked(t *testing.T) {
	f := newOwnerIdentityOperationFixture(t)
	api := installOwnerBootstrapAPI(t, f)
	p, err := NewOwnerBootstrapSelectionProducer(f.root, ownerBootstrapPlanFixture(f))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	effects := &ownerPreflightBridgeFixture{rootPinEffectFixture: f.effects}
	f.bridge.effects = effects
	var lockedWrites atomic.Int32
	f.api.mu.Lock()
	previous := f.api.extra
	f.api.extra = func(w http.ResponseWriter, r *http.Request) bool {
		if r.Method == http.MethodPut && r.URL.Path == f.resources.path() && r.URL.Query().Get("dryRun") == "" {
			if !effects.held.Load() {
				t.Error("selection CAS escaped original SQL bridge")
			}
			lockedWrites.Add(1)
		}
		return previous(w, r)
	}
	f.api.mu.Unlock()
	out, err := p.Advance(context.Background())
	if err != nil || out.Status != OwnerBootstrapIntentRecorded || lockedWrites.Load() != 1 || api.writes.Load() != 1 || api.creates.Load() != 0 || effects.calls.Load() != 1 {
		t.Fatal("positive original selection phase changed", err, out.Status, lockedWrites.Load(), api.writes.Load(), api.creates.Load())
	}
}
