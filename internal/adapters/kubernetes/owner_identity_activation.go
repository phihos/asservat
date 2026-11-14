package kubernetes

import (
	"strings"
	"time"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
)

func ownerIdentityDigestValid(v string) bool {
	return preparationDigestValid(v) && v != strings.Repeat("0", 64)
}

func ownerIdentityMicrotime(t time.Time) bool {
	return t.Year() >= 2020 && t.Equal(t.Truncate(time.Microsecond))
}

func ownerIdentityInterval(start, until, first, last, now time.Time) bool {
	return ownerIdentityMicrotime(start) && ownerIdentityMicrotime(until) && !start.Before(first) && !start.After(now) && until.After(start) && until.Sub(start) <= 5*time.Second && !until.After(last)
}

func ownerIdentityResourceStateValid(v contracts.InitialRuntimeResourceState, now time.Time) bool {
	p, l := v.OwnerIdentity, v.OwnerLaunch
	if p == nil {
		return l == nil
	}
	if v.OwnerLayout == "" || !initialRuntimeLayoutStateValid(v) || len(v.Objects) != contracts.InitialRuntimeResourceCount || !authorization.UUID(p.OperationID) || !ownerIdentityDigestValid(p.PublicDigest) || !installationRefValid(p.RoleRoot.Name, p.RoleRoot.UID) || !authorization.UUID(p.RoleRoot.UID) || !authorization.UUID(p.RoleSetupID) || !ownerIdentityInterval(p.ClaimedAt, p.Until, v.CreatedAt, v.Until, now) {
		return false
	}
	ids := map[string]bool{v.SetupID: true}
	uids := map[string]bool{}
	for _, o := range v.Objects {
		if o.Receipt == nil || !authorization.UUID(o.OperationID) || ids[o.OperationID] || !authorization.UUID(o.Receipt.UID) || uids[o.Receipt.UID] {
			return false
		}
		ids[o.OperationID], uids[o.Receipt.UID] = true, true
	}
	// Worker projection siblings may share their paired-root setup, but none of
	// their claims, setup identities or positive objects belongs to the owner.
	if c := v.CapacityProjection; c != nil {
		ids[c.OperationID], ids[c.Setup.OperationID], ids[c.Setup.RoleSetupID] = true, true, true
		uids[c.Setup.RoleRootUID] = true
		if c.Receipt != nil {
			uids[c.Receipt.Secret.UID] = true
		}
	}
	if c := v.CleanupProjection; c != nil {
		ids[c.OperationID], ids[c.Setup.OperationID], ids[c.Setup.RoleSetupID] = true, true, true
		uids[c.Setup.RoleRootUID] = true
		if c.Receipt != nil {
			uids[c.Receipt.Secret.UID] = true
		}
	}
	if c := v.PermissionProjection; c != nil {
		ids[c.OperationID] = true
		if c.Receipt != nil {
			uids[c.Receipt.Secret.UID] = true
		}
	}
	if ids[p.OperationID] || ids[p.RoleSetupID] || p.RoleSetupID == p.OperationID || uids[p.RoleRoot.UID] {
		return false
	}
	ids[p.OperationID], ids[p.RoleSetupID], uids[p.RoleRoot.UID] = true, true, true
	// Fixed order, independent one-use CREATE claims. An expired child remains
	// representable for exact result lookup; it cannot be reused to CREATE.
	previous := p.ClaimedAt
	for i, child := range []*contracts.OwnerIdentityObjectAttempt{p.Credentials, p.Configuration} {
		if child == nil {
			if i == 0 && p.Configuration != nil || p.Receipt != nil || l != nil {
				return false
			}
			break
		}
		if i == 1 && p.Credentials.Receipt == nil {
			return false
		}
		if !authorization.UUID(child.OperationID) || ids[child.OperationID] || !ownerIdentityInterval(child.ClaimedAt, child.Until, previous, v.Until, now) {
			return false
		}
		ids[child.OperationID] = true
		if r := child.Receipt; r != nil {
			if !installationRefValid(r.Object.Name, r.Object.UID) || !authorization.UUID(r.Object.UID) || uids[r.Object.UID] || !identity.Text(r.ResourceVersion, 128) || !ownerIdentityMicrotime(r.ObservedAt) || r.ObservedAt.Before(child.ClaimedAt) || r.ObservedAt.After(now) || !r.ObservedAt.Before(v.Until) {
				return false
			}
			uids[r.Object.UID] = true
			previous = r.ObservedAt
		} else if p.Receipt != nil || l != nil {
			return false
		}
	}
	if r := p.Receipt; r != nil {
		if p.Credentials == nil || p.Credentials.Receipt == nil || p.Configuration == nil || p.Configuration.Receipt == nil || !ownerIdentityMicrotime(r.ObservedAt) || r.ObservedAt.Before(previous) || r.ObservedAt.After(now) || !r.ObservedAt.Before(v.Until) || r.Credentials != p.Credentials.Receipt.Object || r.CredentialsResourceVersion != p.Credentials.Receipt.ResourceVersion || r.Configuration != p.Configuration.Receipt.Object || r.ConfigurationResourceVersion != p.Configuration.Receipt.ResourceVersion {
			return false
		}
	}

	if l == nil {
		return true
	}
	if p.Receipt == nil || !authorization.UUID(l.OperationID) || ids[l.OperationID] || l.ProjectionOperationID != p.OperationID || !identity.Text(l.InertResourceVersion, 128) || !ownerIdentityDigestValid(l.InertDigest) || !ownerIdentityDigestValid(l.RunningDigest) || l.InertDigest == l.RunningDigest || !ownerIdentityInterval(l.ClaimedAt, l.Until, p.Receipt.ObservedAt, v.Until, now) {
		return false
	}
	if r := l.Receipt; r != nil {
		if !identity.Text(r.ResourceVersion, 128) || r.ResourceVersion == l.InertResourceVersion || r.Generation != 2 || !ownerIdentityMicrotime(r.ObservedAt) || r.ObservedAt.Before(l.ClaimedAt) || r.ObservedAt.After(now) || r.ObservedAt.After(v.Until) {
			return false
		}
	}
	return true
}
