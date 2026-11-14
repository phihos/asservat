package kubernetes

import (
	"context"
	"slices"
	"time"

	app "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
)

// ConnectorWorkTrust is a region's verify-only work trust: the hub's public
// work key from the regional offer for this cluster (ADR-196 decision 7).
// Each observation keeps the hub's delegated recovery read around it; no
// Kubernetes source or guard is read.
type ConnectorWorkTrust struct {
	client    *PermissionClient
	recovery  app.RecoveryReader
	uid       string
	installed contracts.APIContextWorkTrustSettings

	mu     ctxMutex
	cached *fleet.APIContextWorkTrust
}

var _ app.APIContextWorkTrustReader = (*ConnectorWorkTrust)(nil)

// ConnectorWorkTrustSettings is the region's trust document for offer's work
// key; uid names its revision (the cluster ID).
func ConnectorWorkTrustSettings(offer contracts.RegionalOffer, clusterID string) (contracts.APIContextWorkTrustSettings, error) {
	if offer.WorkKey == nil {
		return contracts.APIContextWorkTrustSettings{}, cfg.ErrInvalid
	}
	return contracts.APIContextWorkTrustSettings{Format: contracts.APIContextTrustFormat, RootID: offer.PermissionRootID, InstallationID: offer.InstallationID, ClusterID: clusterID, IssuerEpoch: offer.IssuerEpoch, Revision: 1, Enabled: true, Keys: []contracts.APIContextWorkPublicKey{*offer.WorkKey}}, nil
}

func NewConnectorWorkTrust(c *PermissionClient, recovery app.RecoveryReader, uid string, installed contracts.APIContextWorkTrustSettings) (*ConnectorWorkTrust, error) {
	if c == nil || recovery == nil || installed.ClusterID != c.clusterID {
		return nil, cfg.ErrInvalid
	}
	n := c.now()
	if _, e := apiWorkTrustValue(installed, uid, n, n.Add(5*time.Second)); e != nil {
		return nil, e
	}
	installed.Keys = slices.Clone(installed.Keys)
	return &ConnectorWorkTrust{client: c, recovery: recovery, uid: uid, installed: installed}, nil
}

func (s *ConnectorWorkTrust) APIContextWorkTrust(ctx context.Context) (fleet.APIContextWorkTrust, error) {
	if s == nil || ctx == nil || ctx.Err() != nil {
		return fleet.APIContextWorkTrust{}, cfg.ErrInvalid
	}
	if !s.mu.lock(ctx) {
		return fleet.APIContextWorkTrust{}, cfg.ErrUnavailable
	}
	defer s.mu.unlock()
	if c := s.cached; c != nil && c.Valid(s.client.now().Add(trustReuseMargin)) {
		out := *c
		out.Trust.Keys = slices.Clone(c.Trust.Keys)
		return out, nil
	}
	s.cached = nil
	out, err := s.read(ctx)
	if err != nil {
		return out, err
	}
	c := out
	c.Trust.Keys = slices.Clone(out.Trust.Keys)
	s.cached = &c
	return out, nil
}

func (s *ConnectorWorkTrust) read(ctx context.Context) (fleet.APIContextWorkTrust, error) {
	var zero fleet.APIContextWorkTrust
	start := s.client.now()
	until := identity.Check(start, identity.SQLFenced).Until()
	valid := start.Add(identity.AuthorityRecheckInterval)
	if d, ok := ctx.Deadline(); ok {
		until = identity.Earlier(until, d)
	}
	call, cancel := context.WithDeadline(ctx, until)
	defer cancel()
	recovery, e := s.recovery.RecoveryState(call)
	if e != nil || !recovery.Valid(s.client.now()) || recovery.InstallationID != s.installed.InstallationID || recovery.IssuerEpoch != s.installed.IssuerEpoch {
		return zero, trustStep{"recovery", cfg.ErrUnavailable}
	}
	valid = identity.Earlier(valid, recovery.FreshUntil)
	out, e := apiWorkTrustValue(s.installed, s.uid, start, valid)
	if e != nil || call.Err() != nil || !out.Valid(s.client.now()) {
		return zero, trustStep{"value", cfg.ErrUnavailable}
	}
	return out, nil
}
