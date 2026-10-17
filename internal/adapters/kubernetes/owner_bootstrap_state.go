package kubernetes

import (
	"time"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
)

// Historical public shape only. Current proofs and positive one-use admission
// remain the concrete producer's responsibility. Expired attempts stay readable.
func ownerBootstrapStateValid(installation string, state contracts.InitialRuntimeResourceState, now time.Time) bool {
	if !initialRuntimeObservationSelectionValid(state.WorkerLayout, state.OwnerLayout, state.ObservationFormat) {
		return false
	}
	p := state.OwnerBootstrap
	if p == nil {
		return true
	}
	if p.ObservationFormat != state.ObservationFormat || !authorization.UUID(installation) || state.Format != contracts.InitialRuntimeResourcesFormat ||
		state.OwnerLayout != contracts.OwnerProviderInstalledLayout || state.WorkerLayout != contracts.HubWorkerProviderInstalledLayout ||
		state.OwnerProvider == nil || state.WorkerProvider == nil || !authorization.UUID(state.SetupID) ||
		len(state.Objects) != contracts.InitialRuntimeResourceCount || !ownerIdentityMicrotime(state.CreatedAt) || state.CreatedAt.After(now) || state.Until.Sub(state.CreatedAt) != 30*time.Minute ||
		!authorization.UUID(p.IssuerEpoch) || !ownerBootstrapMount(p.PKIMount) || !ownerBootstrapLimits(p.Connections, p.Concurrency) || !ownerIdentityDigestValid(p.PublicDigest) || len(p.Peers) < 1 || len(p.Peers) > contracts.OwnerBootstrapInitialPeers ||
		!ownerIdentityInterval(p.ClaimedAt, p.Until, state.CreatedAt, state.Until, now) {
		return false
	}
	for _, object := range state.Objects {
		if object.Receipt == nil || !authorization.UUID(object.OperationID) || !authorization.UUID(object.Receipt.UID) {
			return false
		}
	}
	if c := state.CapacityProjection; c != nil && c.Setup.PermissionRootID != p.PermissionRootID {
		return false
	}
	if c := state.CleanupProjection; c != nil && c.Setup.PermissionRootID != p.PermissionRootID {
		return false
	}
	if c := state.PermissionProjection; c != nil && c.RootID != p.PermissionRootID {
		return false
	}
	reserved := ownerBootstrapReserved(installation, state)
	reserved[p.IssuerEpoch] = true
	add := func(id string) bool {
		if !authorization.UUID(id) || reserved[id] {
			return false
		}
		reserved[id] = true
		return true
	}
	// Cluster identities are selected original logical scope, not allocations.
	// Reserve all of them before admitting any generated identity.
	for _, peer := range p.Peers {
		if !authorization.UUID(peer.ClusterID) || !ownerIdentityDigestValid(peer.RootsDigest) {
			return false
		}
		reserved[peer.ClusterID] = true
	}
	if !add(p.OperationID) || !add(p.PermissionRootID) {
		return false
	}
	for _, peer := range p.Peers {
		if !add(peer.PeerID) {
			return false
		}
	}
	if c := p.Child; c != nil {
		if !add(c.OperationID) || !ownerIdentityInterval(c.ClaimedAt, c.Until, p.ClaimedAt, state.Until, now) {
			return false
		}
		if r := c.Receipt; r != nil {
			if r.Object.Name != contracts.OwnerBootstrapSelectionName(installation) || !add(r.Object.UID) || !identity.Text(r.ResourceVersion, 128) ||
				!ownerIdentityMicrotime(r.ObservedAt) || r.ObservedAt.Before(c.ClaimedAt) || r.ObservedAt.After(now) || !r.ObservedAt.Before(state.Until) {
				return false
			}
		}
	}
	// A later identity child cannot be admitted before this public child has a
	// positive receipt. Existing roots without this optional field stay readable.
	return state.OwnerIdentity == nil || p.Child != nil && p.Child.Receipt != nil
}

// Reserve sibling references without rejecting intentionally shared predecessor
// identities (capacity and cleanup share their original paired setup). Their own
// validators check their shapes. Only the new allocations must be distinct.
func ownerBootstrapReserved(installation string, s contracts.InitialRuntimeResourceState) map[string]bool {
	out := map[string]bool{installation: true, s.SetupID: true}
	reserve := func(ids ...string) {
		for _, id := range ids {
			if id != "" {
				out[id] = true
			}
		}
	}
	for _, o := range s.Objects {
		reserve(o.OperationID)
		if o.Receipt != nil {
			reserve(o.Receipt.UID)
		}
	}
	if p := s.WorkerProvider; p != nil {
		reserve(p.AuditCredentials.UID)
	}
	if p := s.OwnerProvider; p != nil {
		reserve(p.AuditCredentials.UID)
	}
	if p := s.WorkerInputs; p != nil {
		reserve(p.OperationID, p.ConfigurationSetupID, p.ConfigurationRoot.UID, p.SQLProjection.UID, p.AuditCredentials.UID)
		if p.Receipt != nil {
			reserve(p.Receipt.Configuration.UID)
		}
	}
	if p := s.OwnerIdentity; p != nil {
		reserve(p.OperationID, p.RoleSetupID, p.RoleRoot.UID)
		for _, c := range []*contracts.OwnerIdentityObjectAttempt{p.Credentials, p.Configuration} {
			if c != nil {
				reserve(c.OperationID)
				if c.Receipt != nil {
					reserve(c.Receipt.Object.UID)
				}
			}
		}
	}
	if p := s.OwnerLaunch; p != nil {
		reserve(p.OperationID)
	}
	if p := s.CapacityProjection; p != nil {
		reserve(p.OperationID, p.Setup.OperationID, p.Setup.RoleSetupID, p.Setup.RoleRootUID)
		if p.Receipt != nil {
			reserve(p.Receipt.Secret.UID)
		}
	}
	if p := s.CleanupProjection; p != nil {
		reserve(p.OperationID, p.Setup.OperationID, p.Setup.RoleSetupID, p.Setup.RoleRootUID)
		if p.Receipt != nil {
			reserve(p.Receipt.Secret.UID)
		}
	}
	if p := s.PermissionProjection; p != nil {
		reserve(p.OperationID)
		if p.Receipt != nil {
			reserve(p.Receipt.Secret.UID)
		}
	}
	return out
}

// Exactly one optional parent, child admission or child acknowledgement changes.
// Every other byte, including all sibling effects, remains original.
func ownerBootstrapTransition(a, b contracts.InitialRuntimeResourceState) bool {
	if a.OwnerIdentity != nil || b.OwnerIdentity != nil || a.OwnerLaunch != nil || b.OwnerLaunch != nil || b.OwnerBootstrap == nil {
		return false
	}
	x, y := a, b
	x.OwnerBootstrap = nil
	y.OwnerBootstrap = nil
	if !equalJSON(x, y) {
		return false
	}
	p, q := a.OwnerBootstrap, b.OwnerBootstrap
	if p == nil {
		return q.Child == nil
	}
	first, last := *p, *q
	first.Child = nil
	last.Child = nil
	if !equalJSON(first, last) || q.Child == nil {
		return false
	}
	if p.Child == nil {
		return q.Child.Receipt == nil
	}
	if p.Child.Receipt != nil || q.Child.Receipt == nil {
		return false
	}
	old, next := *p.Child, *q.Child
	old.Receipt = nil
	next.Receipt = nil
	return equalJSON(old, next)
}
