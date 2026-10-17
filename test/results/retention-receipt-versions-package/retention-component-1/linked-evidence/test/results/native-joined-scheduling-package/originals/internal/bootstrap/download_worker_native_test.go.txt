package bootstrap

import (
	"context"
	"errors"
	"io"
	"sync/atomic"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
)

type nativeTokenFixture struct {
	reads  int
	values [][]byte
}

func (f *nativeTokenFixture) ReadDownloadPeerToken(context.Context) ([]byte, error) {
	f.reads++
	b := []byte("synthetic-projected-token")
	f.values = append(f.values, b)
	return b, nil
}

type nativeStreamFixture struct {
	ctx        context.Context
	closed     int
	closeError error
}

func (f *nativeStreamFixture) Context() context.Context { return f.ctx }
func (*nativeStreamFixture) Receive(context.Context) (contracts.NativeFrame, error) {
	return contracts.NativeFrame{}, io.EOF
}
func (*nativeStreamFixture) Send(context.Context, contracts.NativeFrame) error { return nil }
func (f *nativeStreamFixture) Close() error                                    { f.closed++; return f.closeError }

func TestWorkerNativeOnlyReentersAfterPositiveDisposition(t *testing.T) {
	for _, mode := range []string{"joined", "idle", "idle-after-setup", "idle-after-setup-expiry", "unknown-open", "unknown-command", "false-joined", "failed-close", "foreign-idle", "expired-idle", "extended-idle", "nil-stream"} {
		t.Run(mode, func(t *testing.T) {
			now := time.Now().UTC()
			id := "11111111-1111-4111-8111-111111111111"
			target := value.WorkerCredentialTarget{InstallationID: id, SessionID: id, WorkerID: id, PodUID: id, CreatedAt: now, RunUntil: now.Add(time.Minute)}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			tokens := &nativeTokenFixture{}
			stream := &nativeStreamFixture{ctx: ctx}
			opens, runs, waits := 0, 0, 0
			var firstNonce string
			loop := workerNativeLoop{target: target, token: tokens, now: func() time.Time { return now }, nonce: workerNativeNonce,
				wait: func(ctx context.Context, d time.Duration) error {
					waits++
					if d != contracts.NativeIdleRetry {
						t.Fatal("idle retry was unbounded")
					}
					return nil
				},
				open: func(ctx context.Context, h contracts.NativeHello) (contracts.NativeStream, error) {
					opens++
					if !contracts.ValidWorkerNonce(h.Nonce) {
						t.Fatal("startup emitted a nonce rejected by the native wire contract")
					}
					if h.Reference.InstallationID != id || h.Reference.WorkerID != id || h.Reference.SessionID != id || h.Reference.OperationID != "" || h.Reference.Fence != 0 || len(h.WorkerLeaf) != 0 {
						t.Fatal("worker selected command or foreign identity")
					}
					if opens > 1 {
						if h.Nonce == firstNonce {
							t.Fatal("nonce replay")
						}
						return nil, io.ErrUnexpectedEOF
					}
					firstNonce = h.Nonce
					switch mode {
					case "unknown-open":
						return nil, io.ErrUnexpectedEOF
					case "nil-stream":
						return nil, nil
					case "idle", "idle-after-setup", "idle-after-setup-expiry", "foreign-idle", "expired-idle", "extended-idle":
						x := &contracts.NativeNoCommand{Reference: h.Reference, Nonce: h.Nonce, Until: now.Add(time.Second)}
						if mode == "idle-after-setup" {
							now = now.Add(100 * time.Millisecond)
							x.Until = now.Add(5 * time.Second)
						}
						if mode == "idle-after-setup-expiry" {
							now = now.Add(6 * time.Second)
							x.Until = now.Add(time.Second)
						}
						if mode == "foreign-idle" {
							x.Nonce = workerNativeNonce()
						}
						if mode == "expired-idle" {
							x.Until = now
						}
						if mode == "extended-idle" {
							x.Until = now.Add(6 * time.Second)
						}
						return nil, x
					}
					return stream, nil
				},
				run: func(context.Context, contracts.NativeStream, contracts.NativeHello) (contracts.NativeConversationResult, error) {
					runs++
					if mode == "unknown-command" {
						return contracts.NativeConversationResult{State: contracts.NativeUncertain}, io.ErrUnexpectedEOF
					}
					if mode == "false-joined" {
						return contracts.NativeConversationResult{State: contracts.NativeUncertain}, nil
					}
					if mode == "failed-close" {
						stream.closeError = io.ErrClosedPipe
					}
					return contracts.NativeConversationResult{State: contracts.NativeJoined}, nil
				},
			}
			if err := loop.Run(ctx); err == nil {
				t.Fatal("failure reported as success")
			}
			want := 1
			if mode == "joined" || mode == "idle" || mode == "idle-after-setup" {
				want = 2
			}
			if opens != want || tokens.reads != want {
				t.Fatalf("unexpected replay: opens=%d token reads=%d", opens, tokens.reads)
			}
			allowed := mode == "idle" || mode == "joined" || mode == "idle-after-setup"
			if allowed && waits != 1 || !allowed && waits != 0 {
				t.Fatal("missing backoff or unjustified retry")
			}
			if runs > 0 && stream.closed != 1 {
				t.Fatal("stream cleanup missing")
			}
			for _, b := range tokens.values {
				for _, v := range b {
					if v != 0 {
						t.Fatal("projected token retained after conversation")
					}
				}
			}
		})
	}
}

func TestWorkerNativeSupervisionJoinsBothChildren(t *testing.T) {
	for _, fails := range []string{"credentials", "work", "parent"} {
		t.Run(fails, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			ready := make(chan value.KeyPeer, 1)
			started := make(chan struct{})
			cleanup := make(chan struct{})
			release := make(chan struct{})
			done := make(chan error, 1)
			failure := errors.New("synthetic child failure")
			go func() {
				done <- runWorkerNativePair(ctx, ready, func(ctx context.Context) error {
					ready <- value.KeyPeer{}
					<-started
					if fails == "credentials" {
						return failure
					}
					<-ctx.Done()
					close(cleanup)
					<-release
					return ctx.Err()
				}, func(ctx context.Context) error {
					close(started)
					if fails == "work" {
						return failure
					}
					<-ctx.Done()
					if fails == "credentials" {
						close(cleanup)
						<-release
					}
					return ctx.Err()
				})
			}()
			<-started
			if fails == "parent" {
				cancel()
			}
			<-cleanup
			select {
			case <-done:
				t.Fatal("supervisor returned before child cleanup joined")
			default:
			}
			close(release)
			if err := <-done; err == nil {
				t.Fatal("supervisor hid failed lifetime")
			}
		})
	}
}

func TestWorkerNativeNeverStartsBeforeCredentialReadiness(t *testing.T) {
	ready := make(chan value.KeyPeer, 1)
	var called atomic.Bool
	err := runWorkerNativePair(t.Context(), ready, func(context.Context) error { return artifact.ErrDownloadUnavailable }, func(context.Context) error { called.Store(true); return nil })
	if err == nil || called.Load() {
		t.Fatal("native work started without credentials")
	}
}

func TestWorkerNativeIdleKeepsOriginalWorkerDeadline(t *testing.T) {
	now := time.Now().UTC()
	id := "11111111-1111-4111-8111-111111111111"
	target := value.WorkerCredentialTarget{InstallationID: id, SessionID: id, WorkerID: id, PodUID: id, CreatedAt: now, RunUntil: now.Add(time.Second)}
	reads := &nativeTokenFixture{}
	opens := 0
	loop := workerNativeLoop{target: target, token: reads, now: func() time.Time { return now }, nonce: workerNativeNonce,
		open: func(ctx context.Context, h contracts.NativeHello) (contracts.NativeStream, error) {
			opens++
			if d, ok := ctx.Deadline(); !ok || !d.Equal(target.RunUntil) {
				t.Fatal("worker lifetime changed")
			}
			return nil, &contracts.NativeNoCommand{Reference: h.Reference, Nonce: h.Nonce, Until: target.RunUntil}
		},
		wait: func(context.Context, time.Duration) error { now = target.RunUntil; return nil },
		run: func(context.Context, contracts.NativeStream, contracts.NativeHello) (contracts.NativeConversationResult, error) {
			t.Fatal("idle lookup ran a command")
			return contracts.NativeConversationResult{}, nil
		},
	}
	if err := loop.Run(t.Context()); !errors.Is(err, artifact.ErrDownloadExpired) || opens != 1 {
		t.Fatalf("idle extended worker: opens=%d err=%v", opens, err)
	}
}
