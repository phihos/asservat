package evidence

import (
	query "asservat.local/asservat/internal/domain/analysis"
	"context"
	"errors"
	"testing"
)

func TestLocalProjectionExecutorRefusesUninstalledComparisonBeforeEffects(t *testing.T) {
	f := newProjectionWorkerFixture(t)
	f.worker.query.Scope.Comparison.Normalization = query.ProfileComparisonRaw
	read, err := f.worker.ExecuteProjection(context.Background(), f.start, f)
	if !errors.Is(err, query.ErrUnavailable) || read != nil || f.opened != 0 || f.keyCalls != 0 || f.reads != 0 {
		t.Fatal("uninstalled local comparison performed work", err)
	}
}
