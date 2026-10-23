package authorization

import (
	"context"
	"slices"
	"time"

	value "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
)

// ContextProjectionPolicies selects approved metadata placement from the same
// protected installation configuration as native delivery. It never consumes a
// DownloadAuthority or evaluates download entitlement. ReadApproved remains a
// separate ordinary permission check by ContextProjectionAuthority.
type ContextProjectionPolicies struct {
	source DownloadPolicyReader
	now    func() time.Time
}

func NewContextProjectionPolicies(source DownloadPolicyReader, now func() time.Time) (*ContextProjectionPolicies, error) {
	if source == nil || now == nil {
		return nil, value.ErrUnavailable
	}
	return &ContextProjectionPolicies{source, now}, nil
}

func (s *ContextProjectionPolicies) ContextProjectionPolicy(ctx context.Context, target, store string) (value.ContextProjectionPolicy, error) {
	var out value.ContextProjectionPolicy
	if s == nil || s.source == nil || s.now == nil || ctx == nil || ctx.Err() != nil || !authorization.UUID(target) || !authorization.UUID(store) {
		return out, value.ErrUnavailable
	}
	call, stop := context.WithDeadline(ctx, s.now().Add(5*time.Second))
	defer stop()
	raw, e := s.source.DownloadPolicy(call)
	if e != nil || !raw.Valid(s.now()) || raw.Suspended || call.Err() != nil {
		return out, value.ErrUnavailable
	}
	found := false
	for _, p := range raw.Paths {
		if p.TargetClusterID != target || p.StoreID != store {
			continue
		}
		if found {
			return value.ContextProjectionPolicy{}, value.ErrUnavailable
		}
		found = true
		out.Path = value.ContextProjectionPath{Purpose: value.ContextProjectionPurpose, ID: p.ID, TargetClusterID: p.TargetClusterID, StoreID: p.StoreID, StorageRegion: p.StorageRegion,
			AcquisitionClusterID: p.AcquisitionClusterID, AcquisitionRegion: p.AcquisitionRegion, ConnectorClusterID: p.ConnectorClusterID, ConnectorRegion: p.ConnectorRegion,
			HubClusterID: p.HubClusterID, HubRegion: p.HubRegion, WorkerConfiguration: p.WorkerConfiguration, HubConfiguration: p.HubConfiguration}
	}
	if !found {
		return value.ContextProjectionPolicy{}, value.ErrUnavailable
	}
	out.RootID, out.InstallationID, out.RecoveryEpoch = raw.RootID, raw.InstallationID, raw.RecoveryEpoch
	out.Revision, out.ProtectionDigest = raw.Revision, raw.ProtectionDigest
	out.PermittedRegions = slices.Clone(raw.PermittedRegions)
	out.Clients = []value.ContextProjectionClient{}
	for _, c := range raw.Clients {
		if !slices.Contains(c.PathIDs, out.Path.ID) || !slices.Contains(c.DataClasses, "metadata") || !slices.Contains(c.PrivacyClasses, "potentialPersonalData") || !slices.Contains(c.EvidenceTypes, "context") {
			continue
		}
		out.Clients = append(out.Clients, value.ContextProjectionClient{Issuer: c.Issuer, ID: c.ID, Kind: c.Kind, Purposes: slices.Clone(c.Purposes)})
	}
	out.ObservedAt, out.FreshUntil = raw.ObservedAt, raw.FreshUntil
	if d, ok := call.Deadline(); ok {
		out.FreshUntil = identity.Earlier(out.FreshUntil, d)
	}
	if call.Err() != nil || !out.Valid(s.now()) {
		return value.ContextProjectionPolicy{}, value.ErrUnavailable
	}
	return out, nil
}
