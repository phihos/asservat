package bootstrap

import (
	"context"
	"errors"
	"testing"

	"asservat.local/asservat/internal/adapters/mounts"
	"asservat.local/asservat/internal/adapters/postgres"
	cfg "asservat.local/asservat/internal/domain/configuration"
)

// An upgrade's new hub-worker waits for its scheduling Lease while the
// accepted owner configuration's SQL intervals lapse; hub-api retries that
// read in-process instead of exiting into the kubelet back-off.
func TestHubAPIRetriesLapsedOwnerConfiguration(t *testing.T) {
	fastStartupWait(t)
	lapsed := ownerStartupError(startupAcceptedConfiguration, "none", errors.Join(mounts.ErrUnavailable, &postgres.OwnerConfigurationReadFailure{}))
	if !ownerStartupRetryable(lapsed) {
		t.Fatal("lapsed owner configuration is not retried")
	}
	for _, fatal := range []error{
		ownerStartupError(startupWorkloadGuard, "none", mounts.ErrUnavailable),
		ownerStartupError(startupAcceptedConfiguration, "none", errors.Join(cfg.ErrInvalid, &postgres.OwnerConfigurationReadFailure{})),
	} {
		if ownerStartupRetryable(fatal) {
			t.Fatalf("%v is retried", fatal)
		}
	}
	n := 0
	err := waitStartup(t.Context(), "hub-api", nil, func(context.Context) error {
		if n++; n < 3 {
			return lapsed
		}
		return nil
	}, ownerStartupRetryable)
	if err != nil || n != 3 {
		t.Fatal(err, n)
	}
}
