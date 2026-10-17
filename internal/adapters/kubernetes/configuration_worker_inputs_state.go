package kubernetes

import (
	"strings"
	"time"

	"asservat.local/asservat/internal/adapters/providerconfig"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
)

// This validates retained public provenance, never present effect authority.
// Pending attempts remain structurally readable after expiry for exact result
// reconciliation. Only the producer can distinguish its acknowledged first
// claim from an old or uncertain attempt, and all effects retain the old end.
func configurationWorkerInputsStateValid(installation string, state contracts.InitialRuntimeResourceState, now time.Time) bool {
	p := state.WorkerInputs
	if p == nil {
		return true
	}
	if !authorization.UUID(installation) || state.Format != contracts.InitialRuntimeResourcesFormat || state.WorkerLayout != contracts.HubWorkerProviderInstalledLayout ||
		state.OwnerLayout != contracts.OwnerProviderInstalledLayout || state.WorkerProvider == nil || state.OwnerProvider == nil ||
		providerconfig.ValidateConfigurationProviderSelection(installation, *state.WorkerProvider) != nil ||
		!authorization.UUID(state.SetupID) || len(state.Objects) != contracts.InitialRuntimeResourceCount ||
		state.CreatedAt.Year() < 2020 || state.CreatedAt.After(now) || !capacityProjectionMicrotime(state.CreatedAt) ||
		state.Until.Sub(state.CreatedAt) != 30*time.Minute {
		return false
	}
	ids, uids := map[string]bool{state.SetupID: true}, map[string]bool{}
	addID := func(v string) bool {
		if !authorization.UUID(v) || ids[v] {
			return false
		}
		ids[v] = true
		return true
	}
	addUID := func(v string) bool {
		if !authorization.UUID(v) || uids[v] {
			return false
		}
		uids[v] = true
		return true
	}
	for _, object := range state.Objects {
		if object.Receipt == nil || !addID(object.OperationID) || !addUID(object.Receipt.UID) {
			return false
		}
	}
	// Every sibling is validated by its own closed validator. Here retain
	// cross-purpose uniqueness, including pending object attempts whose CREATE
	// outcome may be unknown. No sibling value is rewritten by this producer.
	if v := state.OwnerIdentity; v != nil {
		if !addID(v.OperationID) || !addID(v.RoleSetupID) || !addUID(v.RoleRoot.UID) {
			return false
		}
		for _, child := range []*contracts.OwnerIdentityObjectAttempt{v.Configuration, v.Credentials} {
			if child != nil && !addID(child.OperationID) {
				return false
			}
			if child != nil && child.Receipt != nil && !addUID(child.Receipt.Object.UID) {
				return false
			}
		}
		if v.Receipt != nil && (v.Configuration == nil || v.Configuration.Receipt == nil || v.Credentials == nil || v.Credentials.Receipt == nil ||
			v.Receipt.Configuration != v.Configuration.Receipt.Object || v.Receipt.Credentials != v.Credentials.Receipt.Object) {
			return false
		}
	}
	if v := state.OwnerLaunch; v != nil && !addID(v.OperationID) {
		return false
	}
	if v := state.CapacityProjection; v != nil {
		if !addID(v.OperationID) || v.Receipt != nil && !addUID(v.Receipt.Secret.UID) {
			return false
		}
		// Capacity and cleanup intentionally share these original predecessor
		// references. Reserve them against this new child without allocating
		// or rejecting the same legitimate predecessor in the other sibling.
		ids[v.Setup.OperationID], ids[v.Setup.RoleSetupID] = true, true
		uids[v.Setup.RoleRootUID] = true
	}
	if v := state.PermissionProjection; v != nil {
		if !addID(v.OperationID) || v.Receipt != nil && !addUID(v.Receipt.Secret.UID) {
			return false
		}
	}
	if v := state.CleanupProjection; v != nil {
		if !addID(v.OperationID) || v.Receipt != nil && !addUID(v.Receipt.Secret.UID) {
			return false
		}
		ids[v.Setup.OperationID], ids[v.Setup.RoleSetupID] = true, true
		uids[v.Setup.RoleRootUID] = true
	}
	if !addUID(state.OwnerProvider.AuditCredentials.UID) {
		return false
	}
	prefix := strings.ReplaceAll(installation, "-", "")
	if !addID(p.OperationID) || !addID(p.ConfigurationSetupID) || !ownerIdentityDigestValid(p.PublicDigest) ||
		p.AuditCredentials != state.WorkerProvider.AuditCredentials ||
		p.ConfigurationRoot.Name != "asservat-configuration-roles-"+prefix ||
		p.SQLProjection.Name != "asservat-configuration-runtime-"+prefix ||
		!addUID(p.ConfigurationRoot.UID) || !addUID(p.SQLProjection.UID) || !addUID(p.AuditCredentials.UID) ||
		p.ClaimedAt.Before(state.CreatedAt) || p.ClaimedAt.After(now) || !capacityProjectionMicrotime(p.ClaimedAt) ||
		!capacityProjectionMicrotime(p.Until) || !p.Until.After(p.ClaimedAt) || p.Until.Sub(p.ClaimedAt) > 5*time.Second || p.Until.After(state.Until) {
		return false
	}
	if r := p.Receipt; r != nil {
		if r.Configuration.Name != runtimeResourceNames(installation).WorkerInputs || !addUID(r.Configuration.UID) ||
			!identity.Text(r.ResourceVersion, 128) || !capacityProjectionMicrotime(r.ObservedAt) ||
			r.ObservedAt.Before(p.ClaimedAt) || r.ObservedAt.After(now) || !r.ObservedAt.Before(state.Until) {
			return false
		}
	}
	return true
}

func configurationWorkerInputProvenance(p *contracts.ConfigurationWorkerInputClaim) *contracts.ConfigurationWorkerInputProvenance {
	if p == nil {
		return nil
	}
	return &contracts.ConfigurationWorkerInputProvenance{OperationID: p.OperationID, ConfigurationRoot: p.ConfigurationRoot,
		ConfigurationSetupID: p.ConfigurationSetupID, SQLProjection: p.SQLProjection}
}
