package kubernetes

import (
	"context"
	"sync/atomic"
	"time"

	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
)

type syntheticInitialIssuer struct {
	parent     contracts.InitialProviderParent
	issues     atomic.Int32
	fail       bool
	afterIssue func()
}

func (s *syntheticInitialIssuer) Check(context.Context, time.Time) (contracts.InitialProviderParent, time.Time, error) {
	return s.parent, time.Now().Add(5 * time.Second), nil
}
func (s *syntheticInitialIssuer) Issue(_ context.Context, purpose string, i contracts.InitialProviderIssue, p contracts.InitialProviderParent) (contracts.InitialProviderResponse, error) {
	s.issues.Add(1)
	if s.afterIssue != nil {
		s.afterIssue()
	}
	if s.fail {
		return contracts.InitialProviderResponse{}, cfg.ErrUnavailable
	}
	return contracts.InitialProviderResponse{Token: "synthetic-" + purpose + "-token", Accessor: "synthetic-" + purpose + "-accessor", IssuedAt: time.Now().UTC(), ExpiresAt: p.ExpiresAt.Add(-time.Second)}, nil
}
func (s *syntheticInitialIssuer) Verify(_ context.Context, purpose string, _ contracts.InitialProviderIssue, _ contracts.InitialProviderParent, r contracts.InitialProviderResponse) error {
	if r.Token != "synthetic-"+purpose+"-token" {
		return cfg.ErrChanged
	}
	return nil
}
