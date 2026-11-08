package bootstrap

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	access "asservat.local/asservat/internal/application/authorization"
	executionapp "asservat.local/asservat/internal/application/execution"
	identities "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/contracts"
	capturevalue "asservat.local/asservat/internal/domain/capture"
	execution "asservat.local/asservat/internal/domain/execution"
	"asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/transport/contextstart"
)

// lostRegionalStream models a standby exchange that ends during the run's first
// regional operation: the hub sends work, then the operation's send fails.
type lostRegionalStream struct{ *regionalObservationStream }

func (s lostRegionalStream) Send(ctx context.Context, frame contracts.APIContextFrame) error {
	if frame.Kind == contracts.APIContextOperationRequestFrame {
		return execution.ErrUnavailable
	}
	return s.regionalObservationStream.Send(ctx, frame)
}

// Installed CI: an admitted Save whose standby exchange ended during
// ResolveSourceSnapshot stayed Pending with no execution row. The actual
// StartContext and Router now repeat that not-started attempt on the next
// standby within the first attempt's interval; the repeated run reaches the
// one SQL preparation, whose refusal is final (no third attempt).
func TestRegionalStartRepeatsNotStartedAttemptOnNextStandby(t *testing.T) {
	f, _, settings := newRegionalObservationFixture(t)
	capability, _, _ := regionalObservationCapability(t, f, settings)
	ctx, cancel := context.WithDeadline(t.Context(), f.now.Add(5*time.Second))
	defer cancel()
	original, _ := ctx.Deadline()
	current, _, err := identities.NewBearerRequest(ctx, f, "synthetic-token", time.Now)
	if err != nil {
		t.Fatal(err)
	}
	router, err := contextstart.NewRouter(contextstart.RouterLimits{Standby: 2, Captures: 1, Clusters: []contextstart.ClusterLimit{{ClusterID: f.work.Target.ClusterID, Standby: 2, Captures: 1}}})
	if err != nil {
		t.Fatal(err)
	}
	defer router.Close()
	resident, endResident := context.WithCancel(t.Context())
	defer endResident()
	// The newer standby is selected first; it is the one that is lost.
	healthy, lost := f.receiver, f.receiver
	lost.Channel.ExchangeID = regionalObservationID(59)
	var served []chan error
	for _, receiver := range []fleet.APIContextReceiver{healthy, lost} {
		standby, err := router.RegisterStandby(resident, receiver, func(ctx context.Context) (fleet.APIContextReceiver, error) { return receiver, ctx.Err() })
		if err != nil {
			t.Fatal(err)
		}
		stream := &regionalObservationStream{f: f, ctx: resident}
		var serve contextstart.Stream = stream
		if receiver.Channel.ExchangeID == lost.Channel.ExchangeID {
			serve = lostRegionalStream{stream}
		}
		done := make(chan error, 1)
		served = append(served, done)
		go func() { defer standby.Finish(); done <- standby.Serve(serve, time.Now) }()
	}
	var reports []string
	start := RegionalAPIContextStart{Runner: executionapp.APIContextRunner{Read: f, Prepare: f, Record: f, Eligibility: access.Evaluator{Permissions: f, Now: time.Now}, Capabilities: capability, Retention: regionalObservationRetention{f}, Recovery: f, Now: time.Now}, Signer: f, Router: router, Now: time.Now, Report: func(s string) { reports = append(reports, s) }}
	err = start.StartContext(ctx, current, f.work.Accepted.CaptureID)
	endResident()
	for _, done := range served {
		<-done
	}
	t.Log(reports)
	if errors.Is(err, capturevalue.ErrAcquisitionNotStarted) || f.preparations != 1 || f.workReads != 2 {
		t.Fatal("lost standby left the admitted capture unstarted", err, f.preparations, f.workReads)
	}
	if f.signed.Channel.ExchangeID != healthy.Channel.ExchangeID {
		t.Fatal("repeated attempt did not use the next standby")
	}
	retried := false
	for _, r := range reports {
		retried = retried || strings.HasPrefix(r, "retry not-started start-left")
	}
	if !retried {
		t.Fatal("retry not reported", reports)
	}
	if end, _ := ctx.Deadline(); !end.Equal(original) || f.check.ValidUntil.After(original) {
		t.Fatal("caller deadline renewed")
	}
}
