package privacy

import (
	"slices"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
)

// DownloadPolicyObservationInterval bounds download-only reuse of a protected
// policy observation. It does not extend an operation or administrative proof.
const DownloadPolicyObservationInterval = 60 * time.Second

type DownloadPath = artifact.DownloadPath

type DownloadClient struct {
	Issuer, ID                                                    string
	Kind                                                          identity.Kind
	DataClasses, PrivacyClasses, EvidenceTypes, Purposes, PathIDs []string
}

// A privacy operator is separate from an evidence owner or reviewer. Exact
// stable issuer subjects/groups are evaluated only against a current identity.
type ProcessingOperator struct{ Issuer, ClientID, Kind, ID string }

type DownloadPolicy struct {
	RootID, InstallationID, RecoveryEpoch string
	Revision                              identity.Revision
	ProtectionDigest                      artifact.Digest
	Suspended                             bool
	PermittedRegions                      []string
	Paths                                 []DownloadPath
	Clients                               []DownloadClient
	Operators                             []ProcessingOperator
	ObservedAt, FreshUntil                time.Time
}

func (p DownloadPolicy) Valid(now time.Time) bool {
	return p.WellFormed() && p.ProtectionDigest != (artifact.Digest{}) && identity.Fresh(p.ObservedAt, p.FreshUntil, now, 5*time.Second)
}

// DownloadValid accepts the separately bounded download-policy observation.
// Administrative and capacity consumers continue to require Valid.
func (p DownloadPolicy) DownloadValid(now time.Time) bool {
	return p.WellFormed() && p.ProtectionDigest != (artifact.Digest{}) && identity.Fresh(p.ObservedAt, p.FreshUntil, now, DownloadPolicyObservationInterval)
}

// WellFormed validates configuration only, never its current protection.
func (p DownloadPolicy) WellFormed() bool {
	if !authorization.UUID(p.RootID) || !authorization.UUID(p.InstallationID) || !authorization.UUID(p.RecoveryEpoch) || !p.Revision.Valid() ||
		p.PermittedRegions == nil || !identity.Strings(p.PermittedRegions, 64, 63) ||
		p.Paths == nil || len(p.Paths) > 32 || p.Clients == nil || len(p.Clients) > 64 || len(p.Operators) < 1 || len(p.Operators) > 32 {
		return false
	}
	paths := map[string]bool{}
	for _, x := range p.Paths {
		if !x.Valid() || paths[x.ID] {
			return false
		}
		paths[x.ID] = true
	}
	clients := map[[2]string]bool{}
	for _, c := range p.Clients {
		key := [2]string{c.Issuer, c.ID}
		if !identity.Text(c.Issuer, 2048) || !identity.Text(c.ID, 256) || !identity.ValidKind(c.Kind) || clients[key] ||
			c.DataClasses == nil || !identity.Strings(c.DataClasses, 1, 32) || c.PrivacyClasses == nil || !identity.Strings(c.PrivacyClasses, 1, 32) ||
			c.EvidenceTypes == nil || !identity.Strings(c.EvidenceTypes, 2, 32) || c.Purposes == nil || !identity.Strings(c.Purposes, 32, 128) ||
			c.PathIDs == nil || !identity.Strings(c.PathIDs, 32, 36) {
			return false
		}
		clients[key] = true
		for _, v := range c.DataClasses {
			if v != "metadata" {
				return false
			}
		}
		for _, v := range c.PrivacyClasses {
			if v != "potentialPersonalData" {
				return false
			}
		}
		for _, v := range c.EvidenceTypes {
			if !artifact.DownloadEvidenceType(v) {
				return false
			}
		}
		for _, v := range c.PathIDs {
			if !paths[v] {
				return false
			}
		}
	}
	operators := map[ProcessingOperator]bool{}
	for _, o := range p.Operators {
		if !identity.Text(o.Issuer, 2048) || !identity.Text(o.ClientID, 256) || !identity.Text(o.ID, 256) || o.Kind != "User" && o.Kind != "Group" || operators[o] {
			return false
		}
		operators[o] = true
	}
	return true
}

// Select requires one unambiguous explicitly permitted path. Empty lists are
// explicit denial; missing lists are invalid. Authentication allowlists are
// deliberately not an input to this disclosure-policy evaluator.
func (p DownloadPolicy) Select(principal identity.Principal, target, store, purpose, dataClass, privacyClass, evidenceType string, now time.Time) (DownloadPath, bool) {
	return p.selectPath(principal, target, store, purpose, dataClass, privacyClass, evidenceType, p.Valid(now))
}

// SelectDownload evaluates each exact caller and path against a bounded
// download observation; it never caches an authorization decision.
func (p DownloadPolicy) SelectDownload(principal identity.Principal, target, store, purpose, dataClass, privacyClass, evidenceType string, now time.Time) (DownloadPath, bool) {
	return p.selectPath(principal, target, store, purpose, dataClass, privacyClass, evidenceType, p.DownloadValid(now))
}

func (p DownloadPolicy) selectPath(principal identity.Principal, target, store, purpose, dataClass, privacyClass, evidenceType string, current bool) (DownloadPath, bool) {
	var zero DownloadPath
	if !current || p.Suspended || !principal.Valid() || !authorization.UUID(target) || !authorization.UUID(store) {
		return zero, false
	}
	var client *DownloadClient
	for i := range p.Clients {
		c := &p.Clients[i]
		if c.Issuer == principal.Issuer && c.ID == principal.ClientID && c.Kind == principal.Kind {
			client = c
			break
		}
	}
	if client == nil || !slices.Contains(client.DataClasses, dataClass) || !slices.Contains(client.PrivacyClasses, privacyClass) || !slices.Contains(client.EvidenceTypes, evidenceType) || !slices.Contains(client.Purposes, purpose) {
		return zero, false
	}
	var selected DownloadPath
	found := false
	for _, x := range p.Paths {
		if x.TargetClusterID != target || x.StoreID != store || !slices.Contains(client.PathIDs, x.ID) {
			continue
		}
		if !slices.Contains(p.PermittedRegions, x.StorageRegion) || !slices.Contains(p.PermittedRegions, x.AcquisitionRegion) || !slices.Contains(p.PermittedRegions, x.ConnectorRegion) || !slices.Contains(p.PermittedRegions, x.HubRegion) {
			continue
		}
		if found {
			return zero, false
		}
		selected = x
		found = true
	}
	return selected, found
}

func (p DownloadPolicy) Operator(i identity.Identity, now time.Time) bool {
	if !p.Valid(now) || p.Suspended || !i.Valid(now) || i.Principal.Kind != identity.Human {
		return false
	}
	for _, o := range p.Operators {
		if o.Issuer == i.Principal.Issuer && o.ClientID == i.Principal.ClientID && (o.Kind == "User" && o.ID == i.Principal.Subject || o.Kind == "Group" && slices.Contains(i.Groups, o.ID)) {
			return true
		}
	}
	return false
}
