package native_test

import (
	"context"
	"crypto/tls"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
	native "asservat.local/asservat/internal/transport/native"
)

type handoffAdmission struct {
	router *native.HubRouter
	origin evidence.NativeOrigin
	closed *atomic.Bool
}

func (a *handoffAdmission) OpenNative(ctx context.Context, peer *tls.ConnectionState, h contracts.NativeHello) (native.Conversation, error) {
	if peer == nil || !peer.HandshakeComplete || len(peer.VerifiedChains) == 0 || a.closed.Load() {
		return nil, artifact.ErrDownloadUnavailable
	}
	return a.router.Attach(ctx, a.origin, h)
}

// Real two-hop h2/mTLS, product router and worker. SQL/source authority is an
// explicit synthetic port. The before helper uses the unchanged original
// registrar API; after adds the private completion callback to that same API.
func TestNativeJoinedWaitsForExactSQLClosureBeyondIdleDelay(t *testing.T) {
	runNativeHandoff(t, "delayed-close")
}
func TestNativeHandoffRejectsUnacknowledgedClosure(t *testing.T) {
	for _, mode := range []string{"failed-close", "unknown-close", "deadline", "cancel", "concurrent-registration", "lost-final", "known-revocation", "known-shortening"} {
		t.Run(mode, func(t *testing.T) { runNativeHandoff(t, mode) })
	}
}
func runNativeHandoff(t *testing.T, mode string) {
	duration := 8 * time.Second
	if mode == "deadline" {
		duration = 700 * time.Millisecond
	}
	ctx, cancel := context.WithTimeout(context.Background(), duration)
	defer cancel()
	source := flowSourceValue(t)
	origin, _, _ := routerFixture(t)
	router, e := native.NewHubRouter(1)
	if e != nil {
		t.Fatal(e)
	}
	defer router.Close()
	var closed, revoked, shortened atomic.Bool
	entered, release := make(chan struct{}), make(chan struct{})
	unblock := sync.OnceFunc(func() { close(release) })
	defer unblock()
	var once sync.Once
	var closeErr error
	var closeCalls atomic.Int32
	var capturedDeadline time.Time
	complete := func(call context.Context, l value.NativeLease) error {
		once.Do(func() {
			closeCalls.Add(1)
			capturedDeadline, _ = call.Deadline()
			if !l.Operation.Equal(origin.Lease.Operation) || l.Sequence != origin.Lease.Sequence || l.Until.After(origin.Lease.Until) {
				closeErr = artifact.ErrDownloadUnavailable
				close(entered)
				return
			}
			close(entered)
			select {
			case <-release:
			case <-call.Done():
				closeErr = call.Err()
				return
			}
			if call.Err() != nil {
				closeErr = call.Err()
				return
			}
			switch mode {
			case "failed-close":
				closeErr = errors.New("synthetic exact close unavailable")
				return
			case "unknown-close":
				closed.Store(true)
				closeErr = errors.New("synthetic unknown close response")
				return
			}
			closed.Store(true)
		})
		return closeErr
	}
	check := func(call context.Context, _ evidence.NativeOrigin) (value.NativeLease, error) {
		if call.Err() != nil || closed.Load() || revoked.Load() {
			return value.NativeLease{}, artifact.ErrDownloadUnavailable
		}
		l := origin.Lease
		if shortened.Load() {
			l.Until = time.Now().Add(20 * time.Millisecond)
		}
		return l, nil
	}
	pending, e := registerHandoffOperation(ctx, router, evidence.NativeExchangeRegistration{Operation: origin.Lease.Operation, Source: source}, func(context.Context, evidence.NativeOrigin) error { return nil }, check, complete)
	if e != nil {
		t.Fatal(e)
	}
	defer pending.Close()
	upstream := flowServer(t, contracts.NativeOwnerPath, &handoffAdmission{router, origin, &closed})
	connector := &flowAdmission{t: t, owner: ctx, lease: origin.Lease, upstream: upstream, check: func(call context.Context) (value.NativeLease, error) {
		// Real connector origins read the same SQL open/closed state. Only its
		// existing terminal forwarding path can survive positive owner closure.
		return check(call, origin)
	}}
	if mode == "lost-final" {
		connector.wrap = func(s native.Stream) native.Stream { return lostHandoffFinal{s} }
	}
	client := flowServer(t, contracts.NativeWorkerPath, connector)
	now := time.Now()
	target := value.WorkerCredentialTarget{InstallationID: nativeID, SessionID: nativeID, WorkerID: nativeID, PodUID: nativeID, CreatedAt: now, RunUntil: now.Add(time.Minute)}
	reader := &flowSource{}
	result, e := evidence.NewRegionalContextResult(ctx, target, reader, time.Now)
	if e != nil {
		t.Fatal(e)
	}
	defer func() { result.Close(); result.Wait(context.Background()) }()
	done := flowRunWorker(t, ctx, client, target, result)
	exchange, e := pending.Wait(ctx)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = exchange.Prepared(ctx); e != nil {
		t.Fatal(e)
	}
	appDone := make(chan error, 1)
	go func() {
		err := exchange.Commit(ctx)
		// Original application path joins registration and closes the exact owner
		// after Commit. After correction the same cleanup is already acknowledged.
		pending.Close()
		cleanup, stop := context.WithDeadline(ctx, origin.Lease.Until)
		defer stop()
		closeResult := complete(cleanup, origin.Lease)
		if err == nil {
			err = closeResult
		}
		appDone <- err
	}()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("completion was not reached", ctx.Err())
	}
	var premature bool
	var workerErr error
	switch mode {
	case "delayed-close":
		timer := time.NewTimer(1100 * time.Millisecond)
		select {
		case workerErr = <-done:
			premature = true
			<-timer.C
		case <-timer.C:
		}
		if closed.Load() {
			t.Fatal("held SQL close already succeeded")
		}
	case "concurrent-registration":
		_, _, factory := routerFixture(t)
		if p, err := router.Register(ctx, origin.Lease.Operation, factory); err == nil {
			p.Close()
			t.Error("unjoined original released routing capacity")
		}
	case "deadline":
		// Expiry of the actual original caller bound is not cancellation renewal.
		<-ctx.Done()
	case "cancel":
		cancel()
	case "known-revocation":
		revoked.Store(true)
		if _, err := exchange.(*native.HubOperation).Gate().Check(ctx); err == nil {
			t.Fatal("known revocation accepted")
		}
	case "known-shortening":
		shortened.Store(true)
		l, err := exchange.(*native.HubOperation).Gate().Check(ctx)
		if err != nil {
			t.Fatal(err)
		}
		wait, stop := context.WithDeadline(ctx, l.Until)
		<-wait.Done()
		stop()
	}
	unblock()
	if !premature {
		workerErr = <-done
	}
	appErr := <-appDone
	if capturedDeadline.After(origin.Lease.Until) {
		t.Fatal("SQL close renewed original deadline")
	}
	if premature && workerErr == nil {
		t.Fatal("worker Joined while old SQL operation remained routeable beyond one-second backoff")
	}
	positive := mode == "delayed-close" || mode == "concurrent-registration"
	if positive && (workerErr != nil || appErr != nil || !closed.Load()) {
		t.Fatal("acknowledged original close did not finish", workerErr, appErr)
	}
	if !positive && workerErr == nil {
		t.Fatal("unacknowledged closure became Joined", mode)
	}
	if closeCalls.Load() != 1 || reader.reads.Load() != 1 {
		t.Fatal("closure retry or evidence reread", closeCalls.Load(), reader.reads.Load())
	}
	if positive {
		_, _, factory := routerFixture(t)
		replacement, err := router.Register(ctx, origin.Lease.Operation, factory)
		if err != nil {
			t.Fatal("joined registration stayed occupied", err)
		}
		pending.Close() // An old cleanup handle cannot remove the replacement.
		if p, err := router.Register(ctx, origin.Lease.Operation, factory); err == nil {
			p.Close()
			t.Error("old close removed replacement")
		}
		replacement.Close()
	}
}

// Drop the already produced final marker on the real connector receive path.
// Its absence cannot restore the SQL owner or imply worker success.
type lostHandoffFinal struct{ native.Stream }

func (s lostHandoffFinal) Receive(ctx context.Context) (contracts.NativeFrame, error) {
	f, e := s.Stream.Receive(ctx)
	if e == nil && f.Kind == contracts.NativeDoneFrame {
		clear(f.Payload)
		return contracts.NativeFrame{}, contracts.ErrNativeProtocol
	}
	return f, e
}
