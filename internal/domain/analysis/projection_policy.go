package analysis

import (
	"slices"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
)

// ContextProjectionPolicy is independent of download policy. It selects only
// the approved context source; it supplies neither ordinary read permission nor
// processing release authority. Empty clients/purposes are explicit denial.
type ContextProjectionClient struct {
	Issuer, ID string
	Kind       identity.Kind
	Purposes   []string
}

type ContextProjectionPolicy struct {
	RootID, InstallationID, RecoveryEpoch string
	Revision                              identity.Revision
	ProtectionDigest                      artifact.Digest
	Path                                  ContextProjectionPath
	PermittedRegions                      []string
	Clients                               []ContextProjectionClient
	Suspended                             bool
	ObservedAt, FreshUntil                time.Time
}

func (p ContextProjectionPolicy) WellFormed() bool {
	if !authorization.UUID(p.RootID) || !authorization.UUID(p.InstallationID) || !authorization.UUID(p.RecoveryEpoch) || !p.Revision.Valid() || !p.Path.Valid() || p.PermittedRegions == nil || !identity.Strings(p.PermittedRegions, 64, 63) || p.Clients == nil || len(p.Clients) > 64 {
		return false
	}
	seen := map[[2]string]bool{}
	for _, c := range p.Clients {
		key := [2]string{c.Issuer, c.ID}
		if !identity.Text(c.Issuer, 2048) || !identity.Text(c.ID, 256) || !identity.ValidKind(c.Kind) || c.Purposes == nil || !identity.Strings(c.Purposes, 32, 128) || seen[key] {
			return false
		}
		seen[key] = true
	}
	return true
}

func (p ContextProjectionPolicy) Valid(now time.Time) bool {
	return p.WellFormed() && p.ProtectionDigest != (artifact.Digest{}) && identity.Fresh(p.ObservedAt, p.FreshUntil, now, 5*time.Second)
}

func (p ContextProjectionPolicy) Permits(actor identity.Principal, target, store, purpose string, now time.Time) bool {
	if !p.Valid(now) || p.Suspended || !actor.Valid() || p.Path.TargetClusterID != target || p.Path.StoreID != store {
		return false
	}
	for _, region := range []string{p.Path.StorageRegion, p.Path.AcquisitionRegion, p.Path.ConnectorRegion, p.Path.HubRegion} {
		if !slices.Contains(p.PermittedRegions, region) {
			return false
		}
	}
	for _, c := range p.Clients {
		if c.Issuer == actor.Issuer && c.ID == actor.ClientID && c.Kind == actor.Kind && slices.Contains(c.Purposes, purpose) {
			return true
		}
	}
	return false
}
