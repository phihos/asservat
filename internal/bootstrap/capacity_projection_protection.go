package bootstrap

import (
	"context"
	"reflect"
	"time"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/adapters/mounts"
	app "asservat.local/asservat/internal/application/capacity"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/identity"
)

// The installed worker observes its original activation on every bounded source
// pass. The existing source observer invalidates the accepted revision on a
// failed proof and joins active work; SQL keeps its independent post-lock fences.
// This does not change the capacity guard digest or renew an earlier operation.
type installedCapacitySourceProtection struct {
	reader   *kube.InstalledWorkerProjectionReader
	claim    contracts.CapacityRuntimeProjectionClaim
	worker   contracts.HubWorkerDeployment
	input    contracts.CapacityDeployment
	manifest contracts.CapacityCredentialManifest
	source   app.CapacitySourceProtectionReader
}

func (s *installedCapacitySourceProtection) CapacityProtection(ctx context.Context) (app.CapacitySourceProtection, error) {
	var zero app.CapacitySourceProtection
	if s == nil || s.reader == nil || s.source == nil || ctx == nil || ctx.Err() != nil {
		return zero, mounts.ErrUnavailable
	}
	current, ready, until, err := s.reader.ReadCapacity(ctx)
	if err != nil || !ready || !reflect.DeepEqual(current, s.claim) || !capacityProjectionMatches(s.input, s.manifest, current, s.worker) || !time.Now().Before(until) {
		return zero, mounts.ErrUnavailable
	}
	live, end := context.WithDeadline(ctx, until)
	defer end()
	proof, err := s.source.CapacityProtection(live)
	if err != nil || live.Err() != nil || !proof.Valid(time.Now()) {
		return zero, mounts.ErrUnavailable
	}
	proof.FreshUntil = identity.Earlier(proof.FreshUntil, until)
	if !proof.Valid(time.Now()) {
		return zero, mounts.ErrUnavailable
	}
	return proof, nil
}
