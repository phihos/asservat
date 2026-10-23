package evidence

import (
	"context"
	"errors"
	"testing"

	"asservat.local/asservat/internal/domain/artifact"
)

// The coordinator reports a refused prepare once, naming the refusing stage,
// and returns the same error class as before.
func TestContextDownloadRefusalNamesPreparationStage(t *testing.T) {
	for fail, want := range map[string]string{"recovery": "recovery", "lookup-key": "key-lookup", "route": "route", "authority": "authority", "plan": "plan", "reserve": "reserve", "source": "source", "continue": "continue"} {
		t.Run(fail, func(t *testing.T) {
			f, s := newDownloadControlFixture(t)
			f.fail = fail
			var reports []string
			s.Refused = func(_ context.Context, operation string, err error) {
				var fixed interface{ FixedStep() string }
				if errors.As(err, &fixed) {
					operation += "/" + fixed.FixedStep()
				}
				reports = append(reports, operation)
			}
			_, err := s.PrepareContextDownload(context.Background(), f, f.a.Scope.ArtifactID, "key")
			if !errors.Is(err, artifact.ErrDownloadUnavailable) || len(reports) != 1 || reports[0] != "prepare/"+want {
				t.Fatalf("%v %q", err, reports)
			}
		})
	}
}
