package kubernetes

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	cfg "asservat.local/asservat/internal/domain/configuration"
	apps "k8s.io/api/apps/v1"
	auth "k8s.io/api/authentication/v1"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/flowcontrol"
)

func TestConfigurationWorkerStatusUpdatesKeepOriginalProofAndLatestCAS(t *testing.T) {
	f := newConfigurationSourcePathFixture(t)
	var reads atomic.Int32
	f.deploymentEdit = func(d *apps.Deployment) {
		if d.Name != f.source.input.Deployment.Name {
			return
		}
		n := reads.Add(1)
		d.ResourceVersion = strconv.Itoa(int(n))
		d.Status = apps.DeploymentStatus{ObservedGeneration: d.Generation, Replicas: 1, ReadyReplicas: n % 2, AvailableReplicas: n % 2}
		d.ManagedFields = []meta.ManagedFieldsEntry{{Manager: "controller", Subresource: "status", Time: &meta.Time{Time: time.Unix(int64(n), 0)}}}
	}
	ctx, stop := context.WithTimeout(context.Background(), 5*time.Second)
	defer stop()
	initial, err := f.source.readConfigurationWorkerNative(ctx)
	if err != nil {
		t.Fatal("status-only first/final reads refused", err)
	}
	if initial.deployment.ResourceVersion != "2" {
		t.Fatal("initial native proof did not retain latest CAS version")
	}
	current, err := f.source.readConfigurationWorkerCurrent(ctx, initial)
	if err != nil || current.proof.observation != initial.proof.observation || current.deployment.ResourceVersion != "3" {
		t.Fatal("status-only post-lock read refused, renewed proof or lost latest CAS version", err)
	}
	final, err := f.source.readConfigurationWorkerNative(ctx)
	if err != nil || final.deployment.ResourceVersion != "5" || !configurationRoleSameSources(initial.proof.observation, final.proof.observation) {
		t.Fatal("status-only final bracket refused or lost exact source/latest version", err)
	}
	if f.requests.Load() != 46 || f.probes.Load() != 2 || f.secretWrites.Load() != 0 {
		t.Fatal("status updates changed API/probe/effect counts", f.requests.Load(), f.probes.Load(), f.secretWrites.Load())
	}
}

func TestConfigurationWorkerStatusUpdatesDoNotHideProtectedChanges(t *testing.T) {
	changes := map[string]func(*apps.Deployment){
		"uid":        func(d *apps.Deployment) { d.UID = types.UID(ownerID(16000)) },
		"generation": func(d *apps.Deployment) { d.Generation++ },
		"spec": func(d *apps.Deployment) {
			d.Spec.Template.Spec.Containers = []core.Container{{Name: "replacement", Image: "foreign"}}
		},
		"service-account": func(d *apps.Deployment) { d.Spec.Template.Spec.ServiceAccountName = "replacement" },
		"labels":          func(d *apps.Deployment) { d.Labels = map[string]string{"changed": "protected"} },
		"annotations":     func(d *apps.Deployment) { d.Annotations = map[string]string{"changed": "protected"} },
		"owner-references": func(d *apps.Deployment) {
			d.OwnerReferences = []meta.OwnerReference{{APIVersion: "v1", Kind: "Pod", Name: "foreign", UID: types.UID(ownerID(16001))}}
		},
		"finalizers":     func(d *apps.Deployment) { d.Finalizers = []string{"example.test/hold"} },
		"deletion":       func(d *apps.Deployment) { at := meta.Now(); d.DeletionTimestamp = &at },
		"deletion-grace": func(d *apps.Deployment) { seconds := int64(30); d.DeletionGracePeriodSeconds = &seconds },
		"zero-one-zero":  func(d *apps.Deployment) { d.Generation += 2 },
	}
	for _, boundary := range []string{"first-final", "post-lock"} {
		for name, change := range changes {
			t.Run(boundary+"/"+name, func(t *testing.T) {
				f := newConfigurationSourcePathFixture(t)
				if name == "zero-one-zero" {
					f.replicas.Store(0)
				}
				var reads atomic.Int32
				f.deploymentEdit = func(d *apps.Deployment) {
					if d.Name != f.source.input.Deployment.Name {
						return
					}
					n := reads.Add(1)
					d.ResourceVersion = strconv.Itoa(int(n))
					d.Status.ReadyReplicas = n % 2
					at := int32(2)
					if boundary == "post-lock" {
						at = 3
					}
					if n >= at {
						change(d)
					}
				}
				ctx, stop := context.WithTimeout(context.Background(), 5*time.Second)
				defer stop()
				initial, err := f.source.readConfigurationWorkerNative(ctx)
				if boundary == "post-lock" {
					if err != nil {
						t.Fatal("unchanged opening bracket refused", err)
					}
					_, err = f.source.readConfigurationWorkerCurrent(ctx, initial)
				}
				if err == nil || f.secretWrites.Load() != 0 || f.probes.Load() != 1 {
					t.Fatal("protected change hidden behind status update or added an effect/probe", err)
				}
			})
		}
	}
}

func TestConfigurationRoleStatusUpdatesKeepOriginalSourceAndRecheck(t *testing.T) {
	f := newConfigurationSourcePathFixture(t)
	var reads atomic.Int32
	f.deploymentEdit = func(d *apps.Deployment) {
		if d.Name == f.source.input.Deployment.Name {
			n := reads.Add(1)
			d.ResourceVersion = strconv.Itoa(int(n))
			d.Status.ReadyReplicas = n % 2
		}
	}
	ctx, stop := context.WithTimeout(context.Background(), 5*time.Second)
	defer stop()
	initial, err := f.source.readConfigurationRoleSource(ctx)
	if err != nil {
		t.Fatal("ordinary source rejected status-only first/final bracket", err)
	}
	current, err := f.source.recheckConfigurationRoleSource(ctx, initial)
	if err != nil || current.observation != initial.observation || current.deployment == nil || current.deployment.ResourceVersion != "3" {
		t.Fatal("ordinary post-lock recheck lost source/deadline/latest snapshot", err)
	}
	if f.secretWrites.Load() != 0 || f.probes.Load() != 2 {
		t.Fatal("ordinary status update recheck added a write or changed probe count")
	}
}

func TestOwnerProjectionSourceTailKeepsControllerStatusAndOriginalBounds(t *testing.T) {
	f := newConfigurationSourcePathFixture(t)
	var reads atomic.Int32
	f.deploymentEdit = func(d *apps.Deployment) {
		if d.Name == f.source.input.Deployment.Name {
			n := reads.Add(1)
			d.ResourceVersion = strconv.Itoa(int(n))
			d.Status.ReadyReplicas = n % 2
		}
	}
	ctx, stop := context.WithTimeout(context.Background(), 5*time.Second)
	defer stop()
	prefix, err := f.source.readOwnerProjectionSourcePrefix(ctx)
	if err != nil {
		t.Fatal(err)
	}
	tail, err := prefix.readTail(ctx)
	if err != nil {
		t.Fatal("owner source tail rejected a controller-only update", err)
	}
	finished, err := prefix.finish(ctx, tail)
	if err != nil || finished.deployment.ResourceVersion != "2" || finished.proof.deployment == nil || finished.proof.deployment.ResourceVersion != "2" ||
		!finished.proof.observation.ObservedAt.Equal(prefix.started) || finished.proof.observation.FreshUntil.After(prefix.until) {
		t.Fatal("owner source tail lost original proof bounds or latest complete deployment", err)
	}
	if f.requests.Load() != 19 || f.probes.Load() != 1 || f.secretWrites.Load() != 0 {
		t.Fatal("owner source tail changed API/probe/effect counts", f.requests.Load(), f.probes.Load(), f.secretWrites.Load())
	}
}

// Actual production HTTP clients/20QPS buckets and concrete source code against
// loopback simulated enforcement. This does not qualify a real Kubernetes
// guard, complete bridge/SQL operation, or fresh installed startup.
func TestConfigurationWorkerNativeAndPostLockReadsAreExplicit(t *testing.T) {
	f := newConfigurationSourcePathFixture(t)
	ctx, stop := context.WithTimeout(context.Background(), 5*time.Second)
	defer stop()
	initial, err := f.source.readConfigurationWorkerNative(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if f.requests.Load() != 19 || f.probes.Load() != 1 {
		t.Fatalf("initial expected 16 observer+3 workload native, got requests=%d denials=%d", f.requests.Load(), f.probes.Load())
	}
	current, err := f.source.readConfigurationWorkerCurrent(ctx, initial)
	if err != nil {
		t.Fatal(err)
	}
	if f.requests.Load() != 27 || f.probes.Load() != 1 || current.proof.observation != initial.proof.observation {
		t.Fatal("post-lock read hid native I/O, renewed dates, or failed to read its 8 actual values")
	}
	final, err := f.source.readConfigurationWorkerNative(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if f.requests.Load() != 46 || f.probes.Load() != 2 || !configurationRoleSameSources(initial.proof.observation, final.proof.observation) {
		t.Fatal("final independent native bracket missing or source changed")
	}
	until, _ := ctx.Deadline()
	if final.proof.observation.FreshUntil.After(until) {
		t.Fatal("final native bracket escaped original caller end")
	}
	// Only the workload guard is probed; the sources are plain reads.
	if f.purposeProbes[0].Load() != 2 || f.purposeProbes[1].Load() != 0 || f.purposeProbes[2].Load() != 0 {
		t.Fatal("workload denied probe omitted from a bracket or a source was probed")
	}
}

func TestConfigurationWorkerPostLockRejectsChangedCompleteValues(t *testing.T) {
	for name, fault := range map[string]int32{"fleet": 3, "owner": 4, "workload": 5, "account": 7, "administrator": 8, "guard": 10} {
		t.Run(name, func(t *testing.T) {
			f := newConfigurationSourcePathFixture(t)
			ctx, stop := context.WithTimeout(context.Background(), 5*time.Second)
			defer stop()
			initial, err := f.source.readConfigurationWorkerNative(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if fault == 10 {
				f.guardVersion.Add(1)
			} else {
				f.fault.Store(fault)
			}
			if _, err = f.source.readConfigurationWorkerCurrent(ctx, initial); err == nil {
				t.Fatal("post-lock read returned retained values despite current change")
			}
			if f.probes.Load() != 1 {
				t.Fatal("post-lock comparison silently acquired replacement enforcement")
			}
		})
	}
}

func TestConfigurationWorkerFinalBracketNeedsNewNativeEnforcement(t *testing.T) {
	f := newConfigurationSourcePathFixture(t)
	ctx, stop := context.WithTimeout(context.Background(), 5*time.Second)
	defer stop()
	initial, err := f.source.readConfigurationWorkerNative(ctx)
	if err != nil {
		t.Fatal(err)
	}
	f.fault.Store(2) // Same objects/guards, but the independent denied PUT now succeeds.
	if _, err := f.source.readConfigurationWorkerCurrent(ctx, initial); err != nil {
		t.Fatal("fixture changed ordinary values instead of enforcement", err)
	}
	if _, err := f.source.readConfigurationWorkerNative(ctx); err == nil || f.probes.Load() <= 1 {
		t.Fatal("old native proof hid actual enforcement loss in final bracket")
	}
}

func TestConfigurationWorkerReadsSourceAfterFinalGuard(t *testing.T) {
	f := newConfigurationSourcePathFixture(t)
	var ownerReads atomic.Int32
	f.extraHandler = func(w http.ResponseWriter, r *http.Request) bool {
		if r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/configmaps/"+f.source.input.OwnerSource.Name) && ownerReads.Add(1) == 2 {
			f.fault.Store(4) // Before the final value read, after the first owner GET.
		}
		return false
	}
	ctx, stop := context.WithTimeout(context.Background(), 5*time.Second)
	defer stop()
	if _, err := f.source.readConfigurationWorkerNative(ctx); err == nil || ownerReads.Load() != 2 {
		t.Fatal("source mutation before the final value read was hidden behind the first read")
	}
}

func TestConfigurationWorkerBlockedPostLockReadRetainsOriginalEnd(t *testing.T) {
	f := newConfigurationSourcePathFixture(t)
	ctx, stop := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer stop()
	initial, err := f.source.readConfigurationWorkerNative(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var blocked atomic.Bool
	f.extraHandler = func(w http.ResponseWriter, r *http.Request) bool {
		if r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/configmaps/owner") {
			blocked.Store(true)
			<-r.Context().Done()
			return true
		}
		return false
	}
	// The derived timer may fire a moment before ctx records expiry; the read
	// must return at the original end, neither early nor late.
	end, _ := ctx.Deadline()
	if _, err = f.source.readConfigurationWorkerCurrent(ctx, initial); err == nil || !blocked.Load() || time.Until(end) > 50*time.Millisecond || time.Since(end) > time.Second {
		t.Fatal("blocked read escaped original bound", err)
	}
	<-ctx.Done()
	requests := f.requests.Load()
	if _, err = f.source.readConfigurationWorkerCurrent(ctx, initial); !errors.Is(err, cfg.ErrUnavailable) || f.requests.Load() != requests {
		t.Fatal("expired original proof restarted reads or changed expiry classification", err)
	}
}

func TestConfigurationWorkerAliasedDepletedLimiterCannotInventAvailability(t *testing.T) {
	// A shared bucket is allowed to reduce availability. It is not replaced,
	// refilled, or given a fresh operation end by the native composition.
	limiter := flowcontrol.NewTokenBucketRateLimiter(20, 20)
	f := newConfigurationSourcePathFixtureLimiter(t, limiter)
	for limiter.TryAccept() {
	}
	ctx, stop := context.WithTimeout(context.Background(), 700*time.Millisecond)
	defer stop()
	started := time.Now()
	if _, err := f.source.readConfigurationWorkerNative(ctx); err == nil {
		t.Fatal("depleted shared bucket fabricated a complete native bracket")
	}
	if elapsed := time.Since(started); elapsed > 1500*time.Millisecond || f.requests.Load() >= 33 {
		t.Fatal("aliased bucket escaped the original short bound", elapsed, f.requests.Load())
	}
}

func TestConfigurationWorkerNativeConstructorKeepsExactClientsAndPins(t *testing.T) {
	f := newConfigurationSourcePathFixture(t)
	s := f.source
	if got, err := NewConfigurationRoleSource(s.client, s.protection, s.fleet, s.owner, s.input); err != nil || got.client != s.client || got.protection != s.protection || got.fleet != s.fleet || got.owner != s.owner {
		t.Fatal("constructor replaced an original configured client", err)
	}
	for _, mode := range []string{"client", "namespace", "fleet-client", "owner-client", "fleet-pin", "owner-pin", "guard-client", "guard-namespace"} {
		t.Run(mode, func(t *testing.T) {
			client, protection, fleetSource, owner := s.client, *s.protection, *s.fleet, *s.owner
			settings := *s.fleet.settings
			fleetSource.settings = &settings
			input := s.input
			switch mode {
			case "client":
				copy := *client
				client = &copy
			case "namespace":
				input.Namespace.UID = ownerID(15000)
			case "fleet-client":
				copy := *client
				settings.client = &copy
			case "owner-client":
				copy := *client
				owner.client = &copy
			case "fleet-pin":
				input.FleetSource.UID = ownerID(15000)
			case "owner-pin":
				input.OwnerSource.UID = ownerID(15000)
			case "guard-client":
				copy := *client
				protection.observer = &copy
			case "guard-namespace":
				protection.plan.ControlNamespace.UID = ownerID(15000)
			}
			if _, err := NewConfigurationRoleSource(client, &protection, &fleetSource, &owner, input); err == nil {
				t.Fatal("constructor adopted a substituted client or input pin")
			}
		})
	}
	if f.requests.Load() != 0 {
		t.Fatal("pure constructor claimed current readiness through network I/O")
	}
}

// A kubelet refresh of the administrator's projected token changes only its
// credential ID; the principal compares equal, a different Pod does not.
func TestAdministratorPrincipalIgnoresTokenRefresh(t *testing.T) {
	user := func(jti, pod string) auth.UserInfo {
		return auth.UserInfo{Username: "system:serviceaccount:install:runner", UID: ownerID(1), Groups: []string{"system:serviceaccounts"},
			Extra: map[string]auth.ExtraValue{tokenCredentialExtra: {"JTI=" + jti}, "authentication.kubernetes.io/pod-uid": {pod}}}
	}
	before, after := administratorPrincipal(user("a", ownerID(2))), administratorPrincipal(user("b", ownerID(2)))
	if !equalJSON(before, after) {
		t.Fatal("token refresh changed the administrator principal")
	}
	if equalJSON(before, administratorPrincipal(user("a", ownerID(3)))) {
		t.Fatal("another Pod's token compared equal")
	}
	original := user("a", ownerID(2))
	_ = administratorPrincipal(original)
	if len(original.Extra) != 2 {
		t.Fatal("caller's extra map mutated")
	}
}
