package bootstrap

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	executionapp "asservat.local/asservat/internal/application/execution"
	identities "asservat.local/asservat/internal/application/identity"
	capturevalue "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/transport/contextstart"
)

// Actual StartContext and Router, with the existing protected loopback capability
// reader. No SQL/node effect: a held same-capture slot models an unjoined history
// conversation; absent replacement uses the original short caller, not a sleep.
func TestRegionalStartPreservesActualAttachFailure(t *testing.T) {
	for _, mode := range []string{"capacity", "unavailable"} {
		t.Run(mode, func(t *testing.T) {
			f, _, settings := newRegionalObservationFixture(t)
			capability, _, _ := regionalObservationCapability(t, f, settings)
			ctx, cancel := context.WithDeadline(t.Context(), f.now.Add(2*time.Second))
			defer cancel()
			original, _ := ctx.Deadline()
			current, _, err := identities.NewBearerRequest(ctx, f, "synthetic-token", time.Now)
			if err != nil {
				t.Fatal(err)
			}
			router, err := contextstart.NewRouter(contextstart.RouterLimits{Standby: 1, Captures: 1, Clusters: []contextstart.ClusterLimit{{ClusterID: f.work.Target.ClusterID, Standby: 1, Captures: 1}}})
			if err != nil {
				t.Fatal(err)
			}
			defer router.Close()
			if mode == "capacity" {
				resident, end := context.WithCancel(t.Context())
				defer end()
				standby, err := router.RegisterStandby(resident, f.receiver, func(context.Context) (fleet.APIContextReceiver, error) { return f.receiver, nil })
				if err != nil {
					t.Fatal(err)
				}
				held, err := router.Attach(ctx, f.work.Target.ClusterID, f.work.Accepted.CaptureID)
				if err != nil {
					t.Fatal(err)
				}
				defer func() { standby.Finish(); held.Close() }()
			}
			var reports []string
			start := RegionalAPIContextStart{Runner: executionapp.APIContextRunner{Read: f, Prepare: f, Record: f, Capabilities: capability, Recovery: f, Now: time.Now}, Signer: f, Router: router, Now: time.Now, Report: func(s string) { reports = append(reports, s) }}
			err = start.StartContext(ctx, current, f.work.Accepted.CaptureID)
			if !errors.Is(err, capturevalue.ErrAcquisitionNotStarted) || f.preparations != 0 || f.signed.CaptureID != "" {
				t.Fatal("attach refusal reached effects", err, f.preparations)
			}
			if len(reports) != 1 || !strings.HasPrefix(reports[0], "attach ("+mode+") start-left") || !strings.Contains(reports[0], "bound=parent") {
				t.Fatal("actual attach cause/budget lost", reports)
			}
			if end, _ := ctx.Deadline(); !end.Equal(original) {
				t.Fatal("caller deadline renewed")
			}
		})
	}
}
