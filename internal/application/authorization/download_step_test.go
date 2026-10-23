package authorization

import (
	"context"
	"errors"
	"strings"
	"testing"

	"asservat.local/asservat/internal/domain/artifact"
)

// Each refusing authority reader is named by a closed stage; the returned
// class is unchanged and the dependency text is never part of the label.
func TestContextDownloadAuthorityNamesTheRefusingReader(t *testing.T) {
	for _, stage := range []string{"catalog", "retention", "environment"} {
		f, s, scope := newDownloadAuthorityFixture()
		f.fail = stage
		_, err := s.CheckDownload(context.Background(), "synthetic-token", scope)
		var fixed interface{ FixedStep() string }
		var cause interface{ StepCause() error }
		if !errors.Is(err, artifact.ErrDownloadUnavailable) || !errors.As(err, &fixed) || fixed.FixedStep() != stage || strings.Contains(fixed.FixedStep(), "private") {
			t.Fatalf("%s: %v", stage, err)
		}
		if !errors.As(err, &cause) || cause.StepCause() == nil || strings.Contains(err.Error(), "private") {
			t.Fatalf("%s: cause not retained separately: %v", stage, err)
		}
	}
}
