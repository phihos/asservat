package bootstrap

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	app "asservat.local/asservat/internal/application/fleet"
	value "asservat.local/asservat/internal/domain/fleet"
)

type lookupDiagnosticNative struct {
	fail func(context.Context) error
}

func TestDirectHolderConcurrentLookupFailuresChooseStableClosedStage(t *testing.T) {
	c, f, inputs, _, _ := directHolderFixture(t, "joined")
	original := f.base.owner.servers[0]
	stale := original
	stale.PodUID, stale.ProcessEpoch = observationForwardID(9), observationForwardID(29)
	f.base.owner.servers = []value.OwnerBinding{stale, original}
	inputs.addresses = map[string][]string{stale.PodUID: {"10.0.0.7"}, original.PodUID: {"10.0.0.8"}}
	var dials atomic.Int32
	c.dial = func(ctx context.Context, network, address string) (net.Conn, error) {
		dials.Add(1)
		host, _, _ := net.SplitHostPort(address)
		if host == "10.0.0.7" {
			return nil, errors.New("private dial error")
		}
		return (&net.Dialer{}).DialContext(ctx, network, f.server.Listener.Addr().String())
	}
	c.native = lookupDiagnosticNative{fail: func(context.Context) error { return errors.New("private native error") }}
	ctx, cancel := context.WithTimeout(f.base.root, 5*time.Second)
	defer cancel()
	_, err := c.ObserveCluster(ctx, f.base.request())
	// Both original candidates fail at different stages. Selection is by the
	// closed label, not which concurrent failure arrives first.
	if got := regionalOutcome(err); got != "locate/native-begin (unavailable)" {
		t.Fatal("concurrent failures lost deterministic stage", got)
	}
	if dials.Load() != 2 || ctx.Err() != nil || inputs.tokens.Load() != 0 || f.get.Load() != 0 || f.post.Load() != 0 || len(c.sockets) != 0 {
		t.Fatal("failed candidates retried, became absence or leaked resources", dials.Load(), ctx.Err())
	}
}

func (n lookupDiagnosticNative) OpenOwnerObservationOperation(ctx context.Context, _ value.OwnerObservationRequest, _ []value.OwnerBinding) (app.OwnerNativeObservationOperation, error) {
	return nil, n.fail(ctx)
}

type lookupDiagnosticRegistry struct {
	app.OwnerCertificateRegistry
	fail func(context.Context) error
}

func (r lookupDiagnosticRegistry) ReadOwnerRegistration(ctx context.Context, _ value.OwnerCertificate) (value.OwnerRegistrationObservation, error) {
	return value.OwnerRegistrationObservation{}, r.fail(ctx)
}

func TestDirectHolderLookupFailureReportsClosedStageUnderLiveOriginalBound(t *testing.T) {
	for _, stage := range []string{"native-begin", "registration-first"} {
		t.Run(stage, func(t *testing.T) {
			c, f, inputs, _, _ := directHolderFixture(t, "joined")
			ctx, cancel := context.WithTimeout(f.base.root, 5*time.Second)
			defer cancel()
			original, _ := ctx.Deadline()
			calls := 0
			private := errors.New("private provider detail must not reach diagnostics")
			fail := func(call context.Context) error {
				calls++
				until, finite := call.Deadline()
				if !finite || until.After(original) || call.Err() != nil || !time.Now().Before(until) {
					t.Error("failure was not injected under the live original authority bound")
				}
				return private
			}
			if stage == "native-begin" {
				c.native = lookupDiagnosticNative{fail: fail}
			} else {
				c.registry = lookupDiagnosticRegistry{OwnerCertificateRegistry: c.registry, fail: fail}
			}
			_, err := c.ObserveCluster(ctx, f.base.request())
			var step interface{ FixedStep() string }
			if !errors.Is(err, value.ErrUnavailable) || errors.Is(err, errHolderNoStandby) || !errors.As(err, &step) || step.FixedStep() != "locate/"+stage {
				t.Fatal("lookup failure lost its unavailable class or private stage", err)
			}
			if calls != 1 || ctx.Err() != nil || !time.Now().Before(original) {
				t.Fatal("lookup retried or required parent expiry", calls, ctx.Err())
			}
			if got := regionalOutcome(err); got != "locate/"+stage+" (unavailable)" || strings.Contains(got, private.Error()) || errors.Is(err, private) {
				t.Fatal("existing capacity report leaked provider detail or lost fixed stage", got)
			}
			if inputs.tokens.Load() != 0 || f.get.Load() != 0 || f.post.Load() != 0 || len(c.sockets) != 0 {
				t.Fatal("failure advanced to token/locator/claim or leaked socket")
			}
		})
	}
}
