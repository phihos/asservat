package fleet

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	value "asservat.local/asservat/internal/domain/fleet"
)

func TestOwnerEndpointDiagnosticKeepsClosedStageContextAndPublicClass(t *testing.T) {
	for _, mode := range []string{"live", "canceled", "deadline", "unknown-stage"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			stage, reason := "pod-final-rv", "other"
			switch mode {
			case "canceled":
				cancel()
				reason = "canceled"
			case "deadline":
				var end context.CancelFunc
				ctx, end = context.WithDeadline(ctx, time.Now().Add(-time.Second))
				defer end()
				reason = "deadline"
			case "unknown-stage":
				stage = "private-provider-text-and-identity"
			}
			failure := OwnerEndpointFailure(ctx, stage, value.ErrUnavailable)
			if !errors.Is(failure, value.ErrUnavailable) || errors.Is(failure, context.Canceled) || errors.Is(failure, context.DeadlineExceeded) {
				t.Fatal("diagnostic changed the adapter's original error class", failure)
			}
			if mode == "unknown-stage" {
				stage = "unknown"
			}
			var reports []string
			reportCtx := WithRefusalSteps(ctx, func(s string) { reports = append(reports, s) })
			ownerRouteReadRefusal(reportCtx, "route-read/endpoints/read", failure)
			want := "route-read/endpoints/read/" + stage + "/" + reason + RemainingBucket(ctx, time.Now())
			if !reflect.DeepEqual(reports, []string{want}) {
				t.Fatal("closed context diagnostic missing", reports, want)
			}
		})
	}
}
