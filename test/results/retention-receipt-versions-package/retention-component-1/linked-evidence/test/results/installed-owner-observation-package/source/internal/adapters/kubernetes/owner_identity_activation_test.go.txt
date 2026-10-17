package kubernetes

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
	core "k8s.io/api/core/v1"
)

func installedOwnerResourceFixture(t *testing.T) (*InitialRuntimeResources, contracts.InitialRuntimeResourceState) {
	t.Helper()
	s, v := installedWorkerResourceFixture(t)
	s.ownerLayout, v.OwnerLayout = contracts.OwnerInstalledLayout, contracts.OwnerInstalledLayout
	for i := range v.Objects {
		o, e := s.object(v, i)
		if e != nil {
			t.Fatal(e)
		}
		v.Objects[i].TemplateDigest = preparationDigest(o.object)
	}
	return s, v
}

func ownerIdentityActivationFixture(t *testing.T) (*InitialRuntimeResources, contracts.InitialRuntimeResourceState, contracts.OwnerDeployment, contracts.OwnerIdentityActivation) {
	t.Helper()
	s, v := installedOwnerResourceFixture(t)
	n := s.names
	in := contracts.OwnerDeployment{Format: contracts.OwnerDeploymentFormat, InstallationID: s.initial.InstallationID, ClusterID: s.initial.ClusterID, Namespace: s.initial.Namespace, ConfigurationUID: v.Objects[14].Receipt.UID}
	in.WorkloadGuard = contracts.OwnerDeploymentGuard{Name: n.WorkloadGuard, PolicyUID: v.Objects[17].Receipt.UID, PolicyGeneration: v.Objects[17].Receipt.Generation, BindingUID: v.Objects[18].Receipt.UID, BindingResourceVersion: v.Objects[18].Receipt.ResourceVersion}
	a := contracts.OwnerIdentityActivation{Input: contracts.OwnerIdentityRoles{Format: contracts.OwnerIdentityRolesFormat, InstallationID: in.InstallationID, InitialClaimID: ownerID(3000), ClusterID: in.ClusterID, Namespace: in.Namespace, OwnerConfigurationUID: in.ConfigurationUID, Resources: contracts.WorkerObjectReference{Name: s.name(), UID: ownerID(3001)}, ResourceSetupID: v.SetupID, ResourceBinding: v.BindingDigest, OwnerLayout: v.OwnerLayout, Deployment: contracts.WorkerObjectReference{Name: n.Owner, UID: v.Objects[10].Receipt.UID}, ServiceAccount: contracts.WorkerObjectReference{Name: n.Owner, UID: v.Objects[0].Receipt.UID}, LayoutDigest: strings.Repeat("d", 64)}, RoleRoot: contracts.WorkerObjectReference{Name: "asservat-owner-identity-roles-" + strings.ReplaceAll(in.InstallationID, "-", ""), UID: ownerID(3002)}, RoleSetupID: ownerID(3003), ResourcesCreatedAt: v.CreatedAt, ResourcesUntil: v.Until}
	now := time.Now().UTC().Truncate(time.Microsecond)
	v.OwnerIdentity = &contracts.OwnerIdentityProjectionClaim{OperationID: ownerID(3004), PublicDigest: strings.Repeat("e", 64), RoleRoot: a.RoleRoot, RoleSetupID: a.RoleSetupID, ClaimedAt: now.Add(-4 * time.Second), Until: now.Add(-3 * time.Second), Receipt: &contracts.OwnerIdentityProjectionReceipt{Configuration: contracts.WorkerObjectReference{Name: n.OwnerInputs, UID: ownerID(3005)}, Credentials: contracts.WorkerObjectReference{Name: n.OwnerProviders, UID: ownerID(3006)}, ConfigurationResourceVersion: "1", CredentialsResourceVersion: "1", ObservedAt: now.Add(-3 * time.Second)}}
	v.OwnerIdentity.Credentials = &contracts.OwnerIdentityObjectAttempt{OperationID: ownerID(3008), ClaimedAt: now.Add(-3500 * time.Millisecond), Until: now.Add(-3 * time.Second), Receipt: &contracts.OwnerIdentityObjectReceipt{Object: v.OwnerIdentity.Receipt.Credentials, ResourceVersion: "1", ObservedAt: now.Add(-3400 * time.Millisecond)}}
	v.OwnerIdentity.Configuration = &contracts.OwnerIdentityObjectAttempt{OperationID: ownerID(3009), ClaimedAt: now.Add(-3300 * time.Millisecond), Until: now.Add(-3 * time.Second), Receipt: &contracts.OwnerIdentityObjectReceipt{Object: v.OwnerIdentity.Receipt.Configuration, ResourceVersion: "1", ObservedAt: now.Add(-3200 * time.Millisecond)}}
	v.OwnerLaunch = &contracts.OwnerIdentityLaunchClaim{OperationID: ownerID(3007), ProjectionOperationID: v.OwnerIdentity.OperationID, InertResourceVersion: "1", InertDigest: strings.Repeat("f", 64), RunningDigest: strings.Repeat("b", 64), ClaimedAt: now.Add(-2 * time.Second), Until: now.Add(-time.Second), Receipt: &contracts.OwnerIdentityLaunchReceipt{ResourceVersion: "2", Generation: 2, ObservedAt: now.Add(-time.Second)}}
	return s, v, in, a
}

func TestInstalledOwnerOriginalLayoutDoesNotAdoptLegacyJournal(t *testing.T) {
	s, v := installedOwnerResourceFixture(t)
	if !s.valid(v) {
		t.Fatal("fresh original owner layout denied")
	}
	legacy, old := installedWorkerResourceFixture(t)
	if legacy.valid(v) || s.valid(old) {
		t.Fatal("original owner template adopted across layouts")
	}
	b, _ := json.Marshal(old)
	if strings.Contains(string(b), "ownerLayout") || strings.Contains(string(b), "ownerIdentity") || strings.Contains(string(b), "ownerLaunch") {
		t.Fatal("legacy omission changed")
	}
	obj, e := s.object(v, 14)
	if e != nil {
		t.Fatal(e)
	}
	raw := obj.object.(*core.ConfigMap).Data["owner-pool.json"]
	var source contracts.OwnerConfiguration
	if json.Unmarshal([]byte(raw), &source) != nil || source.NativePort != contracts.OwnerInstalledNativePort || source.NativeBootstrap != "owner-bootstrap/v1" {
		t.Fatal("fresh source omitted reviewed bootstrap profile")
	}
	v.OwnerLayout = "future"
	if s.valid(v) {
		t.Fatal("unknown owner layout accepted")
	}
}

func TestOwnerIdentityActivationKeepsOriginalRolesAndResources(t *testing.T) {
	_, _, in, a := ownerIdentityActivationFixture(t)
	if !OwnerIdentityActivationBound(in, a) {
		t.Fatal("valid original public pins denied")
	}
	for _, mode := range []string{"role-root", "resource-root", "role-setup", "source", "account", "deployment", "layout", "long-root", "future", "zero-binding"} {
		t.Run(mode, func(t *testing.T) {
			bad := a
			switch mode {
			case "role-root":
				bad.RoleRoot.Name = "other"
			case "resource-root":
				bad.Input.Resources.Name = "other"
			case "role-setup":
				bad.RoleSetupID = ""
			case "source":
				bad.Input.OwnerConfigurationUID = ownerID(3100)
			case "account":
				bad.Input.ServiceAccount.UID = bad.Input.Deployment.UID
			case "deployment":
				bad.Input.Deployment.Name = "other"
			case "layout":
				bad.Input.OwnerLayout = ""
			case "long-root":
				bad.ResourcesUntil = bad.ResourcesUntil.Add(time.Second)
			case "future":
				bad.ResourcesCreatedAt = time.Now().Add(time.Hour)
				bad.ResourcesUntil = bad.ResourcesCreatedAt.Add(30 * time.Minute)
			case "zero-binding":
				bad.Input.ResourceBinding = strings.Repeat("0", 64)
			}
			if OwnerIdentityActivationBound(in, bad) {
				t.Fatal("changed original pins accepted")
			}
		})
	}
}

func TestOwnerIdentityJournalRequiresSeparatePositiveLaunch(t *testing.T) {
	_, v, _, _ := ownerIdentityActivationFixture(t)
	if !ownerIdentityResourceStateValid(v, time.Now()) {
		t.Fatal("valid completed historical disposition denied")
	}
	for _, mode := range []string{"no-projection", "no-projection-receipt", "reused-role-setup", "reused-launch", "foreign-projection", "early-launch", "long-launch", "changed-inert", "new-generation", "unknown-owner-layout", "pending-object", "reused-provider-uid"} {
		t.Run(mode, func(t *testing.T) {
			raw, _ := json.Marshal(v)
			var bad contracts.InitialRuntimeResourceState
			_ = json.Unmarshal(raw, &bad)
			switch mode {
			case "no-projection":
				bad.OwnerIdentity = nil
			case "no-projection-receipt":
				bad.OwnerIdentity.Receipt = nil
			case "reused-role-setup":
				bad.OwnerIdentity.RoleSetupID = bad.Objects[0].OperationID
			case "reused-launch":
				bad.OwnerLaunch.OperationID = bad.OwnerIdentity.OperationID
			case "foreign-projection":
				bad.OwnerLaunch.ProjectionOperationID = ownerID(3200)
			case "early-launch":
				bad.OwnerLaunch.ClaimedAt = bad.OwnerIdentity.ClaimedAt
			case "long-launch":
				bad.OwnerLaunch.Until = bad.OwnerLaunch.ClaimedAt.Add(6 * time.Second)
			case "changed-inert":
				bad.OwnerLaunch.InertDigest = bad.OwnerLaunch.RunningDigest
			case "new-generation":
				bad.OwnerLaunch.Receipt.Generation = 3
			case "unknown-owner-layout":
				bad.OwnerLayout = ""
			case "pending-object":
				bad.Objects[18].Receipt = nil
			case "reused-provider-uid":
				bad.OwnerIdentity.Receipt.Credentials.UID = bad.Objects[0].Receipt.UID
			}
			if ownerIdentityResourceStateValid(bad, time.Now()) {
				t.Fatal("invalid original disposition accepted")
			}
		})
	}
	// Pending claims remain representable, but the concrete reader requires both
	// receipts before using the native projection. Shape is not launch authority.
	v.OwnerLaunch.Receipt = nil
	if !ownerIdentityResourceStateValid(v, time.Now()) {
		t.Fatal("unknown launch lost its lookup-only state")
	}
	v.OwnerLaunch = nil
	v.OwnerIdentity.Receipt = nil
	if !ownerIdentityResourceStateValid(v, time.Now()) {
		t.Fatal("unknown projection lost its original claim")
	}
}

func TestOwnerIdentityChildrenKeepIndependentAttemptsAndSiblingIsolation(t *testing.T) {
	_, original, _, _ := ownerIdentityActivationFixture(t)
	for _, mode := range []string{"missing-first", "pending-first", "reused-child", "early-second", "long-child", "joint-uid", "joint-version", "joint-before-children", "reused-object", "capacity-operation", "cleanup-child", "sibling-root", "sibling-setup", "sibling-object", "launch-sibling"} {
		t.Run(mode, func(t *testing.T) {
			b, _ := json.Marshal(original)
			var v contracts.InitialRuntimeResourceState
			_ = json.Unmarshal(b, &v)
			p := v.OwnerIdentity
			switch mode {
			case "missing-first":
				p.Credentials = nil
			case "pending-first":
				p.Credentials.Receipt = nil
			case "reused-child":
				p.Configuration.OperationID = p.Credentials.OperationID
			case "early-second":
				p.Configuration.ClaimedAt = p.Credentials.ClaimedAt
			case "long-child":
				p.Configuration.Until = p.Configuration.ClaimedAt.Add(6 * time.Second)
			case "joint-uid":
				p.Receipt.Configuration.UID = ownerID(3500)
			case "joint-version":
				p.Receipt.CredentialsResourceVersion = "replacement"
			case "joint-before-children":
				p.Receipt.ObservedAt = p.Credentials.ClaimedAt
			case "reused-object":
				p.Configuration.Receipt.Object.UID = p.Credentials.Receipt.Object.UID
			case "capacity-operation":
				v.CapacityProjection = &contracts.CapacityRuntimeProjectionClaim{OperationID: p.OperationID}
			case "cleanup-child":
				v.CleanupProjection = &contracts.CaptureCleanupProjectionClaim{OperationID: p.Configuration.OperationID}
			case "sibling-root":
				v.CapacityProjection = &contracts.CapacityRuntimeProjectionClaim{Setup: contracts.CapacityRootSetupReceipt{RoleRootUID: p.RoleRoot.UID}}
			case "sibling-setup":
				v.CleanupProjection = &contracts.CaptureCleanupProjectionClaim{Setup: contracts.CapacityRootSetupReceipt{RoleSetupID: p.RoleSetupID}}
			case "sibling-object":
				v.CapacityProjection = &contracts.CapacityRuntimeProjectionClaim{Receipt: &contracts.CapacityRuntimeProjectionReceipt{Secret: p.Credentials.Receipt.Object}}
			case "launch-sibling":
				v.CleanupProjection = &contracts.CaptureCleanupProjectionClaim{OperationID: v.OwnerLaunch.OperationID}
			}
			if ownerIdentityResourceStateValid(v, time.Now()) {
				t.Fatal("reused, incomplete or reordered identity accepted")
			}
		})
	}
	// The parent attempt's deadline does not become a replacement CREATE grant.
	// The unattempted second child can be claimed after a positive first receipt
	// with fresh authority, still bounded by the original resource lifetime.
	original.OwnerLaunch = nil
	original.OwnerIdentity.Receipt = nil
	original.OwnerIdentity.Configuration = nil
	if !ownerIdentityResourceStateValid(original, time.Now()) {
		t.Fatal("positive first child cannot resume")
	}
	original.OwnerIdentity.Credentials.Receipt = nil
	if !ownerIdentityResourceStateValid(original, time.Now()) {
		t.Fatal("uncertain first child cannot be looked up")
	}
	original.OwnerIdentity.Credentials = nil
	if !ownerIdentityResourceStateValid(original, time.Now()) {
		t.Fatal("parent-only intent cannot resume")
	}
}
