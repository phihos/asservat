package bootstrap

import (
	"context"
	"errors"

	captureapp "asservat.local/asservat/internal/application/capture"
	executionapp "asservat.local/asservat/internal/application/execution"
	identities "asservat.local/asservat/internal/application/identity"
	capturevalue "asservat.local/asservat/internal/domain/capture"
	value "asservat.local/asservat/internal/domain/execution"
)

// APIContextStart is a local composition adapter for an actual regional runner.
// It is not a remote route, a dispatcher, or permission to put collector keys in
// the public hub. No installed command constructs it in this checkpoint.
type APIContextStart struct{ Runner executionapp.APIContextRunner }

var _ captureapp.ContextAcceptedStart = APIContextStart{}

func (s APIContextStart) StartContext(ctx context.Context, current identities.CurrentIdentity, id string) error {
	r, err := s.Runner.Execute(ctx, current, id)
	if errors.Is(err, value.ErrPreparationUncertain) {
		return capturevalue.ErrPreparationUncertain
	}
	if errors.Is(err, value.ErrNotStarted) {
		return errors.Join(err, capturevalue.ErrAcquisitionNotStarted)
	}
	if err != nil {
		return err
	}
	if r.State != "AlreadyStarted" && r.State != "StoredPendingVerification" {
		return value.ErrUnavailable
	}
	return nil
}
