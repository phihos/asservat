package kubernetes

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
	apps "k8s.io/api/apps/v1"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/utils/ptr"
)

func TestConfigurationRoleInertDeploymentPreservesFutureRolloutBound(t *testing.T) {
	in, _ := configurationRoleProofExample(time.Now())
	d := apps.Deployment{ObjectMeta: meta.ObjectMeta{Name: in.Deployment.Name, Namespace: in.Namespace.Name, UID: types.UID(in.Deployment.UID), ResourceVersion: "1"}, Spec: apps.DeploymentSpec{Replicas: ptr.To(int32(0)), Template: core.PodTemplateSpec{Spec: core.PodSpec{ServiceAccountName: in.ServiceAccount.Name}}, Strategy: apps.DeploymentStrategy{Type: apps.RecreateDeploymentStrategyType}}}
	if !configurationRoleDeploymentBound(d, in) {
		t.Fatal("inert Restricted-workload provisioning phase denied")
	}
	for _, c := range []struct {
		name    string
		surge   intstr.IntOrString
		allowed bool
	}{
		{"no-overlap", intstr.FromInt(0), true},
		{"one-overlap", intstr.FromInt(1), true},
		{"default-quarter", intstr.FromString("25%"), true},
		{"one-full-overlap", intstr.FromString("100%"), true},
		{"too-many", intstr.FromInt(2), false},
		{"hidden-at-zero", intstr.FromString("200%"), false},
	} {
		t.Run(c.name, func(t *testing.T) {
			x := d.DeepCopy()
			x.Spec.Strategy = apps.DeploymentStrategy{Type: apps.RollingUpdateDeploymentStrategyType, RollingUpdate: &apps.RollingUpdateDeployment{MaxSurge: &c.surge}}
			if got := configurationRoleDeploymentBound(*x, in); got != c.allowed {
				t.Fatalf("inert rollout bound=%v, want %v", got, c.allowed)
			}
		})
	}
	for _, edit := range []func(*apps.Deployment){
		func(x *apps.Deployment) { x.Spec.Replicas = nil },
		func(x *apps.Deployment) { x.Spec.Replicas = ptr.To(int32(-1)) },
		func(x *apps.Deployment) { x.Spec.Replicas = ptr.To(int32(2)) },
		func(x *apps.Deployment) { x.UID = types.UID(ownerID(99)) },
		func(x *apps.Deployment) { x.Spec.Template.Spec.ServiceAccountName = "replacement" },
	} {
		x := d.DeepCopy()
		edit(x)
		if configurationRoleDeploymentBound(*x, in) {
			t.Fatal("inert phase weakened exact identity or process bound")
		}
	}
}

// Kubernetes enforcement and the SQL receipt are explicitly synthetic here.
// Actual original-rate source/claim/current checks and Secret CAS run through
// production adapters. The SQL14-case matrix qualifies SQL effects separately.
func TestConfigurationRoleInertClaimCanCompleteWithoutLaunchingPod(t *testing.T) {
	f := newConfigurationSourcePathFixture(t)
	f.replicas.Store(0)
	root := configurationPathRoot(t, f)
	opened, err := root.OpenConfigurationRuntimeRoles(context.Background())
	if err != nil {
		t.Fatal("inert root", err)
	}
	start := time.Now()
	call, cancel := context.WithDeadline(context.Background(), start.Add(5*time.Second))
	defer cancel()
	err = root.WithConfigurationRoleOperation(call, func(ctx context.Context) error {
		claimed, fresh, e := root.ClaimConfigurationRuntimeRole(ctx, "configuration-fleet", 42, start.Add(-time.Minute))
		if e != nil || !fresh {
			return fmt.Errorf("inert first claim: %w", e)
		}
		if claimed.UID != opened.UID || !claimed.State.Until.Equal(opened.State.Until) || claimed.ValidUntil.After(start.Add(5*time.Second)) {
			return fmt.Errorf("inert claim changed original identity or interval")
		}
		receipt := contracts.PublicRuntimeRoleReceipt{RoleName: "as_" + strings.ReplaceAll(f.source.input.InstallationID, "-", "") + "_cfg_00", RoleOID: 100, LayoutDigest: f.source.input.LayoutDigest}
		return root.CompleteConfigurationRuntimeRole(ctx, claimed, "configuration-fleet", receipt)
	})
	if err != nil {
		t.Fatal(err)
	}
	if f.replicas.Load() != 0 || f.workloadVersion.Load() != 1 {
		t.Fatal("credential provisioning launched or rewrote workload")
	}
}

func TestConfigurationRoleZeroToOneAfterClaimInvalidatesOriginalOperation(t *testing.T) {
	f := newConfigurationSourcePathFixture(t)
	f.replicas.Store(0)
	root := configurationPathRoot(t, f)
	if _, err := root.OpenConfigurationRuntimeRoles(context.Background()); err != nil {
		t.Fatal(err)
	}
	err := root.WithConfigurationRoleOperation(context.Background(), func(ctx context.Context) error {
		claimed, fresh, e := root.ClaimConfigurationRuntimeRole(ctx, "configuration-fleet", 42, time.Now().Add(-time.Minute))
		if e != nil || !fresh {
			return fmt.Errorf("first inert claim: %w", e)
		}
		writes := f.secretWrites.Load()
		f.replicas.Store(1)
		f.workloadVersion.Add(1)
		if _, e = root.ReadConfigurationRuntimeRoles(ctx); e == nil {
			t.Fatal("post-lock current read accepted changed launch phase")
		}
		receipt := contracts.PublicRuntimeRoleReceipt{RoleName: "as_" + strings.ReplaceAll(f.source.input.InstallationID, "-", "") + "_cfg_00", RoleOID: 100, LayoutDigest: f.source.input.LayoutDigest}
		if e = root.CompleteConfigurationRuntimeRole(ctx, claimed, "configuration-fleet", receipt); e == nil {
			t.Fatal("changed launch phase completed original claim")
		}
		f.replicas.Store(0)
		f.workloadVersion.Add(1)
		if _, e = root.ReadConfigurationRuntimeRoles(ctx); e == nil {
			t.Fatal("zero-one-zero revived invalidated original operation")
		}
		if f.secretWrites.Load() != writes {
			t.Fatal("changed phase wrote or refunded root state")
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		state, e := contracts.DecodeConfigurationRuntimeRoleState(strings.NewReader(string(f.secret.Data["state.json"])))
		if e != nil || !reflect.DeepEqual(state.Roles[0].Claim, claimed.State.Roles[0].Claim) || state.Roles[0].Receipt != nil {
			t.Fatal("uncertain original claim was replaced or completed", e)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
