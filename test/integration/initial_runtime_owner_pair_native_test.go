package integration

import (
	"bytes"
	"context"
	"errors"
	"testing"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/adapters/postgres"
	fleet "asservat.local/asservat/internal/domain/fleet"
)

// This continuation is deliberately not called by the input-only native
// selector. Its caller must retain the original bridge/resources and the actual
// running configuration worker through this bundle's Close. The concrete SQL
// reader below reads that worker's audited accepted projection; no fixture
// observer, acceptance write, host Pod token or generated timestamp is accepted.
type initialRuntimeNativeOwner struct {
	root      *kube.OwnerIdentityRoleRoot
	sql       *postgres.OwnerIdentityOperationSQL
	selection *kube.OwnerBootstrapSelectionProducer
	bootstrap kube.OwnerBootstrapAdvance
	caller    kube.OwnerBootstrapWorkerCaller
	providers *initialRuntimeNativeProviders
}

// This fixture observes only the concrete accepted reader's already-returned
// fixed diagnostic. It delegates exactly once with the original context and
// returns the observation/error unchanged; no extra query, clock or authority.
// Product native normalization remains unchanged and still exposes unavailable.
type providerOwnerDiagnosticReader struct {
	t      *testing.T
	reader *postgres.OwnerConfigurations
}

func (r providerOwnerDiagnosticReader) ReadOwnerConfiguration(ctx context.Context) (fleet.OwnerConfigurationObservation, error) {
	out, err := r.reader.ReadOwnerConfiguration(ctx)
	var failure *postgres.OwnerConfigurationReadFailure
	if errors.As(err, &failure) {
		r.t.Logf("actual accepted owner SQL read refused check=%s reason=%s; original statements and database clock only", failure.Check(), failure.Reason())
	}
	return out, err
}

func sameNativeOwnerRoots(a, b [][]byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !bytes.Equal(a[i], b[i]) {
			return false
		}
	}
	return true
}
