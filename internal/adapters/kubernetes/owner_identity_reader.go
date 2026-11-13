package kubernetes

import (
	"context"
	"errors"

	app "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
)

// InstalledOwnerIdentityReader is what remains of the hub-api's former
// startup provenance check (ADR-328 removed it from the hub-api): the
// hub-worker's capacity owner check still reads the original Deployment
// through get and deployment until that path is removed.
type InstalledOwnerIdentityReader struct {
	client     *PermissionClient
	protection *OwnerWorkloadProtection
	input      contracts.OwnerDeployment
	activation contracts.OwnerIdentityActivation
	tokens     app.OwnerPodToken
	podUID     string
}

func (s *InstalledOwnerIdentityReader) get(ctx context.Context, path string, out any) error {
	raw, e := s.client.api.Get().AbsPath(path).MaxRetries(0).DoRaw(ctx)
	defer clear(raw)
	if e != nil {
		return errors.Join(cfg.ErrUnavailable, e)
	}
	if permissionJSON(raw, 1<<20, 131072) != nil || strictGuardJSON(raw, out) != nil {
		return cfg.ErrChanged
	}
	until, ok := ctx.Deadline()
	if !ok {
		return cfg.ErrInvalid
	}
	return initialHandoverDeadline(ctx, s.client.now, until)
}
