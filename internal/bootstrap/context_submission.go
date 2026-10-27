package bootstrap

import (
	"context"
	"errors"
	"strings"

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
	// Not started: the ADR-212 headroom rollback, or a read-only check that
	// failed as temporarily unavailable (ADR-250). The runner itself never
	// inspects dependency errors; this composition classifies them.
	var fixed interface{ FixedStep() string }
	if errors.Is(err, value.ErrNotStarted) || errors.As(err, &fixed) && strings.HasPrefix(fixed.FixedStep(), "Check") && executionapp.TemporarilyUnavailable(err) {
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
