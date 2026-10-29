package mtls

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"sync/atomic"
	"testing"
	"time"

	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/targets"
	"asservat.local/asservat/internal/transport/contextstart"
)

type residencyProbeReader struct {
	io.ReadCloser
	failures chan error
}

func (r residencyProbeReader) Read(p []byte) (int, error) {
	n, e := r.ReadCloser.Read(p)
	if e != nil {
		select {
		case r.failures <- e:
		default:
		}
	}
	return n, e
}

// Test-only actual TLS/H2 witness. Its caller, setup and accepted-connection
// residency intervals match production; all authority adapters remain synthetic.
func TestContextStartOriginalResidencyCanEndSelectedQuery(t *testing.T) {
	setup := newContextStartSetupFixture(t)
	f := setup.f
	f.connector.realClock.Store(true)
	currentSource := f.connector
	setup.begin = func(ctx context.Context) error {
		timer := time.NewTimer(4 * time.Second)
		defer timer.Stop()
		select {
		case <-timer.C:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	var accepted atomic.Pointer[time.Time]
	dial := f.client.dial
	f.client.dial = func(ctx context.Context, network, address string) (net.Conn, error) {
		socket, e := dial(ctx, network, address)
		if e == nil {
			now := time.Now()
			accepted.Store(&now)
		}
		return socket, e
	}
	hubDeadline := make(chan time.Time, 1)
	readFailures := make(chan error, 8)
	f.intercept = func(_ http.ResponseWriter, r *http.Request) bool {
		at := accepted.Load()
		if at == nil {
			t.Error("missing actual dial receipt")
			return true
		}
		until := at.Add(30 * time.Second)
		// The reference harness has no native listener. Preserve its actual H2
		// handler and apply native's accepted+30s parent bound at that boundary.
		ctx, cancel := context.WithDeadline(r.Context(), until)
		t.Cleanup(cancel)
		*r = *r.WithContext(ctx)
		r.Body = residencyProbeReader{r.Body, readFailures}
		hubDeadline <- until
		return false
	}
	regional := &restartRegion{regionalOperationsFixture: &regionalOperationsFixture{t: t, process: f.api}}
	f.targets = regional
	routes := f.owners.Routes
	var hold atomic.Bool
	entered := make(chan struct{})
	f.owners.Routes = forwardRoutes(func(ctx context.Context, b value.OwnerBinding) (value.OwnerRoute, error) {
		if hold.CompareAndSwap(true, false) {
			close(entered)
			<-ctx.Done()
			return value.OwnerRoute{}, ctx.Err()
		}
		return routes.CurrentOwnerRoute(ctx, b)
	})
	owner, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	originalEnd, _ := owner.Deadline()
	opened := time.Now()
	exchange, e := f.client.Open(owner, f.owner)
	if e != nil {
		var diagnostic *contextStartOpeningError
		if errors.As(e, &diagnostic) {
			elapsed, remaining := diagnostic.OpeningTiming()
			t.Fatalf("original five-second setup failed: stage=%s elapsed=%s remaining=%s", diagnostic.FixedStep(), elapsed, remaining)
		}
		t.Fatal("original five-second setup failed: closed diagnostic unavailable")
	}
	defer exchange.Close()
	if setup.setup == nil {
		t.Fatal("opening omitted original setup handle")
	}
	setupEnd, bounded := setup.setup.root.Deadline()
	owned := setup.setup.owned
	if !bounded || owned.ObservedAt.Before(opened) || !owned.ValidUntil.After(owned.ObservedAt) || owned.ValidUntil.After(owned.ObservedAt.Add(5*time.Second)) || owned.ValidUntil.After(setupEnd) {
		t.Fatal("setup did not retain a current original bounded proof")
	}
	until := <-hubDeadline
	response, writer, socket, e := exchange.IO()
	if e != nil {
		t.Fatal(e)
	}
	stream, e := contextstart.NewOutboundStream(exchange.Context(), exchange.Receiver().Channel, exchange.Check, currentSource, f.targets, response, writer, socket, exchange.Close)
	if e != nil {
		t.Fatal(e)
	}
	work, signer, _, _ := f.work(t, exchange.Receiver())
	regional.work = work
	local := contextstart.RegionalLocal{Process: regional, Targets: regional, Local: regional, Starts: regional, Output: regional, Collector: regional, Source: f.connector, Now: time.Now}
	joined := make(chan struct{})
	go func() {
		defer close(joined)
		_ = contextstart.ServeRegionalOperations(exchange.Context(), stream, exchange.Receiver(), signer, local, time.Now)
	}()
	defer func() { _ = stream.Close(); <-joined }()
	t.Logf("opened=%s preDial=%s hubMinusRegional=%s originalRegionEnd=%s actualDialAt=%s hubEnd=%s", time.Since(opened), accepted.Load().Sub(opened), until.Sub(originalEnd), originalEnd.UTC().Format(time.RFC3339Nano), accepted.Load().UTC().Format(time.RFC3339Nano), until.UTC().Format(time.RFC3339Nano))
	// Start before the existing hub idle-retirement cutoff. Keep the caller's
	// real five-second bound past the region's original stop, with 3s hub margin.
	queryEnd := originalEnd.Add(500 * time.Millisecond)
	start := queryEnd.Add(-5 * time.Second)
	timer := time.NewTimer(time.Until(start))
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-t.Context().Done():
		t.Fatal("test ended before query")
	}
	if !until.After(queryEnd.Add(3 * time.Second)) {
		t.Fatal("fixture did not meet existing selection margin")
	}
	query, stop := context.WithDeadline(t.Context(), queryEnd)
	defer stop()
	hold.Store(true)
	event := ""
	hub := contextstart.Targets{Router: f.router, Now: time.Now, Report: func(v, _ string) { event = v }}
	result := make(chan error, 1)
	go func() {
		_, e := hub.ObserveWorkloadRestarts(query, targets.RestartRequest{WorkloadRequest: targets.WorkloadRequest{ClusterID: work.Target.ClusterID, Namespace: "app", Kind: "Deployment", Name: "app"}})
		result <- e
	}()
	select {
	case <-entered:
	case e := <-result:
		if !errors.Is(e, value.ErrUnavailable) || query.Err() != nil || !time.Now().Before(originalEnd) {
			t.Fatal("unavailable original residency did not refuse before caller/remote expiry", event, e)
		}
		t.Log("original regional end excluded standby before source/check dispatch")
		return
	case <-time.After(3 * time.Second):
		t.Fatal("query neither selected nor exhausted its original registration wait")
	}
	e = <-result
	if !errors.Is(e, value.ErrUnavailable) || query.Err() != nil || owner.Err() != context.DeadlineExceeded {
		t.Fatal("query did not fail before its own bound at original regional stop", event, e, query.Err(), owner.Err())
	}
	select {
	case raw := <-readFailures:
		var network net.Error
		_, single := raw.(interface{ Unwrap() error })
		_, as := raw.(interface{ As(any) bool })
		t.Logf("event=%s remaining=%s queryEnd=%s rawDeadline=%t rawEOF=%t rawNetError=%t rawSingleWrap=%t rawAs=%t", event, time.Until(queryEnd), queryEnd.UTC().Format(time.RFC3339Nano), errors.Is(raw, context.DeadlineExceeded) || errors.Is(raw, os.ErrDeadlineExceeded), errors.Is(raw, io.EOF), errors.As(raw, &network), single, as)
	case <-time.After(time.Second):
		t.Fatal("actual H2 body read did not retain a closed shape")
	}
	t.Fatal("hub selected a conversation that closed before its query deadline")
}
