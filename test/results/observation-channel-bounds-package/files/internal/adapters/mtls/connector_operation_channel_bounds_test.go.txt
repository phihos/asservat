package mtls

import (
	"context"
	"sync"
	"testing"
	"time"

	app "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/contracts"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
)

type operationBoundStream struct {
	x   *operationCoordinatorFixture
	t   *testing.T
	end time.Time
}

func (s operationBoundStream) ExchangeConnectorObservationOperation(ctx context.Context, p contracts.ClusterObservationOperationProbe) (contracts.ConnectorObservationOperationReply, error) {
	return s.x.ExchangeConnectorObservationOperation(ctx, p)
}
func (s operationBoundStream) CompleteClusterObservation(ctx context.Context, r contracts.ClusterObservationReceipt) error {
	return s.x.CompleteClusterObservation(ctx, r)
}
func (s operationBoundStream) ExchangeClusterObservation(ctx context.Context, r value.ClusterObservationRequest) (value.ClusterObservationResult, error) {
	out, err := s.x.channel.ObserveCluster(ctx, r)
	if err == nil && out.Interval.FreshUntil.After(s.end) {
		s.t.Error("metadata result lost newly observed owner cutoff")
	}
	return out, err
}

// Actual TLS/process keys and the complete typed conversation; the native and
// SQL ports remain synthetic. These assertions are on the contexts passed to
// actual subsequent port calls, not just the final output's minimum date.
func TestOperationChannelCarriesSelectedOwnerCutoffs(t *testing.T) {
	for _, mode := range []string{"following-candidate", "returned-result"} {
		t.Run(mode, func(t *testing.T) {
			x := newOperationCoordinatorFixture(t, "current")
			before := x.f.clock().Add(2 * time.Second)
			after := before.Add(-200 * time.Millisecond)
			oldRegistry := x.channel.registry
			x.channel.registry = forwardRegistry(func(ctx context.Context, leaf value.OwnerCertificate) (value.OwnerRegistrationObservation, error) {
				r, err := oldRegistry.ReadOwnerRegistration(ctx, leaf)
				if x.channel.read {
					cap := before
					if x.metadata != 0 && mode == "returned-result" {
						cap = after
					}
					r.FreshUntil = identity.Earlier(r.FreshUntil, cap)
				}
				return r, err
			})
			oldCandidates := x.channel.candidates
			postReads := 0
			selected, err := app.NewOwnerObservationCandidateSelection(x.owner.Pool, observationCandidatesFunc(func(ctx context.Context) (value.APIContextOwnerCandidates, error) {
				if x.metadata != 0 {
					postReads++
					end, finite := ctx.Deadline()
					if mode == "following-candidate" && (!finite || end.After(before)) {
						t.Error("post-metadata candidate lost original shorter owner cutoff")
					}
				}
				return oldCandidates.ReadOwnerObservationCandidates(ctx)
			}))
			if err != nil {
				t.Fatal(err)
			}
			x.channel.candidates = selected
			if mode == "returned-result" {
				x.hub.stream = operationBoundStream{x, t, after}
			}
			out, err := x.hub.ObserveClusterOperation(x.ctx, x.request, x.operation)
			if err != nil || postReads == 0 || x.metadata != 1 || x.proofs != 4 || x.receipts != 1 {
				t.Fatal("conversation did not reach required boundary", err, postReads, x.metadata, x.proofs, x.receipts)
			}
			end := before
			if mode == "returned-result" {
				end = after
			}
			if out.Interval.FreshUntil.After(end) {
				t.Fatal("final result renewed owner cutoff")
			}
		})
	}
}

func TestOperationChannelExpiredRetainedCutoffDeniesBeforeAnotherRead(t *testing.T) {
	x := newOperationCoordinatorFixture(t, "current")
	if _, err := x.hub.ObserveClusterOperation(x.ctx, x.request, x.operation); err != nil {
		t.Fatal(err)
	}
	old := x.channel.candidates
	reads := 0
	selected, err := app.NewOwnerObservationCandidateSelection(x.owner.Pool, observationCandidatesFunc(func(ctx context.Context) (value.APIContextOwnerCandidates, error) {
		reads++
		return old.ReadOwnerObservationCandidates(ctx)
	}))
	if err != nil {
		t.Fatal(err)
	}
	x.channel.candidates = selected
	x.f.advance.Store(int64(6 * time.Second))
	if err := x.channel.checkSelectedOwner(x.ctx); err == nil || reads != 0 {
		t.Fatal("expired retained cutoff admitted another candidate read", err, reads)
	}
}

type operationAfterWaitStream struct {
	*operationCoordinatorFixture
	returned chan error
}

func (s operationAfterWaitStream) ExchangeClusterObservation(ctx context.Context, r value.ClusterObservationRequest) (value.ClusterObservationResult, error) {
	out, err := s.channel.ObserveCluster(ctx, r)
	s.returned <- err
	return out, err
}

func TestOperationChannelOriginalSelectedCutoffSurvivesKeyLockWait(t *testing.T) {
	x := newOperationCoordinatorFixture(t, "current")
	old := x.channel.registry
	locked := make(chan time.Time, 1)
	returned := make(chan error, 1)
	var release sync.Once
	withheld := false
	joined := make(chan struct{})
	// This is the existing process key mutex, not a replacement current-key
	// callback. The original shorter SQL observation must govern this wait.
	t.Cleanup(func() {
		x.hub.cancel()
		select {
		case <-locked:
			release.Do(x.regional.mu.Unlock)
		case <-joined:
		}
		x.hub.Close()
		<-joined
	})
	x.channel.registry = forwardRegistry(func(ctx context.Context, leaf value.OwnerCertificate) (value.OwnerRegistrationObservation, error) {
		r, err := old.ReadOwnerRegistration(ctx, leaf)
		if !withheld && x.channel.read && x.metadata == 1 {
			withheld = true
			r.FreshUntil = time.Now().Add(40 * time.Millisecond)
			x.regional.mu.Lock()
			locked <- r.FreshUntil
		}
		return r, err
	})
	x.hub.stream = operationAfterWaitStream{x, returned}
	done := make(chan error, 1)
	go func() {
		defer close(joined)
		_, err := x.hub.ObserveClusterOperation(x.ctx, x.request, x.operation)
		done <- err
	}()
	var until time.Time
	select {
	case until = <-locked:
	case <-time.After(time.Second):
		t.Fatal("post-metadata registry boundary not reached")
	}
	// Retain a cleanup signal after observing the admitted lock, including a
	// test failure before release. The product interval itself stays 40ms.
	locked <- until
	expired, cancel := context.WithDeadline(context.Background(), until)
	defer cancel()
	<-expired.Done()
	release.Do(x.regional.mu.Unlock)
	select {
	case err := <-returned:
		if err == nil {
			t.Error("metadata result survived original cutoff during key lock wait")
		}
	case <-time.After(time.Second):
		t.Fatal("metadata did not join actual key wait")
	}
	select {
	case err := <-done:
		if err == nil || x.receipts != 0 {
			t.Fatal("expired metadata reached final receipt", err, x.receipts)
		}
	case <-time.After(time.Second):
		t.Fatal("coordinator did not join expired operation")
	}
}
