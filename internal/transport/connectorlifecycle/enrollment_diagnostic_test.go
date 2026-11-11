package connectorlifecycle

import (
	"context"
	"errors"
	"testing"

	value "asservat.local/asservat/internal/domain/fleet"
)

type privateEnrollmentError struct{}

func (privateEnrollmentError) Error() string { panic("private provider text inspected") }
func TestEnrollmentResolutionReportsClosedStageAndPreservesError(t *testing.T) {
	private := privateEnrollmentError{}
	runner := Runners(func(context.Context, value.ClusterCredentialProfile) (PeerDuties, error) {
		return PeerDuties{}, private
	})
	_, err := runner.Enroll(context.Background(), &Region{}, "", value.ConnectorProcessRequest{})
	if EnrollmentStep(err) != "resolve" || !errors.Is(err, private) || err.Error() != "connector enrollment resolve" {
		t.Fatal("resolution diagnostic/class changed")
	}
}
