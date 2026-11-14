package kubernetes

import (
	"asservat.local/asservat/internal/contracts"
)

func initialRuntimeLayoutStateValid(v contracts.InitialRuntimeResourceState) bool {
	if !initialRuntimeObservationSelectionValid(v.WorkerLayout, v.OwnerLayout, v.ObservationFormat) || !contracts.InitialRuntimeLayoutsSupported(v.WorkerLayout, v.OwnerLayout) {
		return false
	}
	if v.WorkerLayout == contracts.HubWorkerProviderInstalledLayout {
		return v.WorkerProvider != nil && v.OwnerProvider != nil
	}
	return v.WorkerProvider == nil && v.OwnerProvider == nil && v.WorkerInputs == nil
}

// Original rotating provider sources cannot alias an immutable resource or a
// later compartment's private credential/root object. This check is shared by
// the installer decoder and runtime readers, including before WorkerInputs is
// present. It grants no authority to any of these public references.
func initialRuntimeProviderUIDsDistinct(v contracts.InitialRuntimeResourceState) bool {
	if v.WorkerProvider == nil && v.OwnerProvider == nil {
		return true
	}
	if v.WorkerProvider == nil || v.OwnerProvider == nil || v.WorkerProvider.AuditCredentials.UID == v.OwnerProvider.AuditCredentials.UID {
		return false
	}
	selected := func(uid string) bool {
		return uid == v.WorkerProvider.AuditCredentials.UID || uid == v.OwnerProvider.AuditCredentials.UID
	}
	for _, object := range v.Objects {
		if object.Receipt != nil && selected(object.Receipt.UID) {
			return false
		}
	}
	if p := v.OwnerIdentity; p != nil {
		if selected(p.RoleRoot.UID) {
			return false
		}
		for _, child := range []*contracts.OwnerIdentityObjectAttempt{p.Credentials, p.Configuration} {
			if child != nil && child.Receipt != nil && selected(child.Receipt.Object.UID) {
				return false
			}
		}
	}
	if p := v.CapacityProjection; p != nil && (selected(p.Setup.RoleRootUID) || p.Receipt != nil && selected(p.Receipt.Secret.UID)) {
		return false
	}
	if p := v.CleanupProjection; p != nil && (selected(p.Setup.RoleRootUID) || p.Receipt != nil && selected(p.Receipt.Secret.UID)) {
		return false
	}
	if p := v.PermissionProjection; p != nil && p.Receipt != nil && selected(p.Receipt.Secret.UID) {
		return false
	}
	if p := v.WorkerInputs; p != nil && (selected(p.ConfigurationRoot.UID) || selected(p.SQLProjection.UID) || p.Receipt != nil && selected(p.Receipt.Configuration.UID)) {
		return false
	}
	return true
}
