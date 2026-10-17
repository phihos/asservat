package kubernetes

import (
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

func configurationRoleProofExample(now time.Time) (contracts.ConfigurationRuntimeRoles, contracts.ConfigurationRoleObservation) {
	in := contracts.ConfigurationRuntimeRoles{Format: contracts.ConfigurationRuntimeRolesFormat, InstallationID: ownerID(1), InitialClaimID: ownerID(2), ClusterID: ownerID(3), Namespace: contracts.WorkerObjectReference{Name: "owners", UID: ownerID(4)}, Deployment: contracts.WorkerObjectReference{Name: "hub-worker", UID: ownerID(5)}, ServiceAccount: contracts.WorkerObjectReference{Name: "hub-worker", UID: ownerID(6)}, FleetSource: contracts.WorkerObjectReference{Name: "fleet", UID: ownerID(7)}, OwnerSource: contracts.WorkerObjectReference{Name: "owner", UID: ownerID(8)}, LayoutDigest: strings.Repeat("1", 64)}
	start := now.Add(-time.Second)
	until := now.Add(time.Second)
	proof := contracts.ConfigurationRoleObservation{InstallationID: in.InstallationID, ClusterID: in.ClusterID, IssuerEpoch: ownerID(9), NamespaceUID: in.Namespace.UID, DeploymentUID: in.Deployment.UID, AccountUID: in.ServiceAccount.UID, WorkloadDigest: strings.Repeat("2", 64), GuardDigest: strings.Repeat("3", 64), Fleet: contracts.ConfigurationRoleSourceRevision{UID: in.FleetSource.UID, Generation: 1, Digest: strings.Repeat("4", 64), ObservedAt: start, FreshUntil: until}, Owner: contracts.ConfigurationRoleSourceRevision{UID: in.OwnerSource.UID, Generation: 1, Digest: strings.Repeat("5", 64), ObservedAt: start, FreshUntil: until}, ObservedAt: start, FreshUntil: until}
	return in, proof
}
func TestConfigurationRoleSourceKeepsOriginalIdentityAndBounds(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	in, original := configurationRoleProofExample(now)
	if !configurationRoleSourceMatches(in, original, now) {
		t.Fatal("valid structural observation rejected")
	}
	cases := map[string]func(*contracts.ConfigurationRoleObservation){
		"installation":    func(p *contracts.ConfigurationRoleObservation) { p.InstallationID = ownerID(10) },
		"cluster":         func(p *contracts.ConfigurationRoleObservation) { p.ClusterID = ownerID(10) },
		"namespace":       func(p *contracts.ConfigurationRoleObservation) { p.NamespaceUID = ownerID(10) },
		"deployment":      func(p *contracts.ConfigurationRoleObservation) { p.DeploymentUID = ownerID(10) },
		"account":         func(p *contracts.ConfigurationRoleObservation) { p.AccountUID = ownerID(10) },
		"fleet-source":    func(p *contracts.ConfigurationRoleObservation) { p.Fleet.UID = ownerID(10) },
		"owner-source":    func(p *contracts.ConfigurationRoleObservation) { p.Owner.UID = ownerID(10) },
		"expired":         func(p *contracts.ConfigurationRoleObservation) { p.FreshUntil = now },
		"future":          func(p *contracts.ConfigurationRoleObservation) { p.ObservedAt = now.Add(time.Microsecond) },
		"shortened-fleet": func(p *contracts.ConfigurationRoleObservation) { p.Fleet.FreshUntil = now.Add(100 * time.Millisecond) },
		"shortened-owner": func(p *contracts.ConfigurationRoleObservation) { p.Owner.FreshUntil = now.Add(100 * time.Millisecond) },
		"missing-guard":   func(p *contracts.ConfigurationRoleObservation) { p.GuardDigest = strings.Repeat("0", 64) },
	}
	for name, edit := range cases {
		t.Run(name, func(t *testing.T) {
			p := original
			edit(&p)
			if configurationRoleSourceMatches(in, p, now) {
				t.Fatal("changed or detached observation accepted")
			}
		})
	}
	same := original
	same.ObservedAt = now
	same.Fleet.ObservedAt = now
	same.Owner.ObservedAt = now
	if !configurationRoleSameSources(original, same) {
		t.Fatal("same actual sources could not be compared")
	}
	same.Owner.Generation++
	if configurationRoleSameSources(original, same) {
		t.Fatal("new source revision considered original")
	}
	same = original
	same.WorkloadDigest = strings.Repeat("6", 64)
	if configurationRoleSameSources(original, same) {
		t.Fatal("changed protected workload considered original")
	}
}
func TestConfigurationRoleDeploymentUsesItsOwnTwoProcessBound(t *testing.T) {
	in, _ := configurationRoleProofExample(time.Now())
	d := apps.Deployment{ObjectMeta: meta.ObjectMeta{Name: in.Deployment.Name, Namespace: in.Namespace.Name, UID: types.UID(in.Deployment.UID), ResourceVersion: "1"}, Spec: apps.DeploymentSpec{Replicas: ptr.To(int32(1)), Template: core.PodTemplateSpec{Spec: core.PodSpec{ServiceAccountName: in.ServiceAccount.Name}}, Strategy: apps.DeploymentStrategy{Type: apps.RollingUpdateDeploymentStrategyType, RollingUpdate: &apps.RollingUpdateDeployment{MaxSurge: ptr.To(intstr.FromInt(1))}}}}
	if !configurationRoleDeploymentBound(d, in) {
		t.Fatal("bounded active/standby rollout denied")
	}
	d.Spec.Replicas = ptr.To(int32(2))
	if configurationRoleDeploymentBound(d, in) {
		t.Fatal("public replica allowance leaked into reconciler")
	}
	d.Spec.Replicas = ptr.To(int32(1))
	d.Spec.Strategy.RollingUpdate.MaxSurge = ptr.To(intstr.FromInt(2))
	if configurationRoleDeploymentBound(d, in) {
		t.Fatal("unbacked rollout accepted")
	}
}
