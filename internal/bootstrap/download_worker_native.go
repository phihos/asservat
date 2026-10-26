package bootstrap

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"asservat.local/asservat/internal/adapters/mtls"
	"asservat.local/asservat/internal/adapters/objectstore"
	auditapp "asservat.local/asservat/internal/application/audit"
	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/transport/native"
	"github.com/aws/aws-sdk-go-v2/aws"
)

// Only a positively authenticated NoCommand or positively joined conversation
// permits another connection. A timeout/lost acknowledgement cannot turn into
// a retry of a spent operation. These callbacks are private runtime composition,
// not public extension points or substitutes for the transport's authority.
type workerNativeLoop struct {
	target value.WorkerCredentialTarget
	token  evidence.DownloadPeerToken
	open   func(context.Context, contracts.NativeHello) (contracts.NativeStream, error)
	run    func(context.Context, contracts.NativeStream, contracts.NativeHello) (contracts.NativeConversationResult, error)
	now    func() time.Time
	wait   func(context.Context, time.Duration) error
	nonce  func() string
}

// workerNativeStep is the loop's refusal: always ErrDownloadUnavailable for
// every caller decision, labelled with its closed stage and any nested fixed
// stage of the cause (never its text) for the worker's stop report.
func workerNativeStep(stage string, cause error) error {
	var inner interface{ FixedStep() string }
	if errors.As(cause, &inner) {
		return &fixedStepError{stage, &nativeLoopCause{inner}}
	}
	return &fixedStepError{stage, artifact.ErrDownloadUnavailable}
}

type nativeLoopCause struct {
	inner interface{ FixedStep() string }
}

func (e *nativeLoopCause) Error() string     { return artifact.ErrDownloadUnavailable.Error() }
func (e *nativeLoopCause) Unwrap() error     { return artifact.ErrDownloadUnavailable }
func (e *nativeLoopCause) FixedStep() string { return e.inner.FixedStep() }

func workerNativeNonce() string {
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(nonce[:])
}

func (l workerNativeLoop) Run(parent context.Context) error {
	if parent == nil || !l.target.Valid() || l.token == nil || l.open == nil || l.run == nil || l.now == nil || l.wait == nil || l.nonce == nil {
		return artifact.ErrInvalid
	}
	ctx, cancel := context.WithDeadline(parent, l.target.RunUntil)
	defer cancel()
	for i := 0; i < contracts.NativeMaximumConversations; i++ {
		if ctx.Err() != nil || !l.now().Before(l.target.RunUntil) {
			return artifact.ErrDownloadExpired
		}
		token, err := l.token.ReadDownloadPeerToken(ctx)
		if err != nil {
			clear(token)
			return workerNativeStep("token", err)
		}
		h := contracts.NativeHello{Format: contracts.NativeExchangeFormat, Reference: contracts.NativeReference{InstallationID: l.target.InstallationID, SessionID: l.target.SessionID, QueryID: l.target.QueryID, WorkerID: l.target.WorkerID}, Nonce: l.nonce(), WorkerToken: token}
		if !contracts.ValidWorkerNonce(h.Nonce) || !contracts.ValidWorkerToken(token) {
			clear(token)
			return artifact.ErrInvalid
		}
		openedAt := l.now()
		stream, err := l.open(ctx, h)
		if err != nil {
			clear(token)
			if stream != nil {
				stream.Close()
				return workerNativeStep("open", err)
			}
			var idle *contracts.NativeNoCommand
			receivedAt := l.now()
			// The server's current observation starts after connection setup.
			// Check its remaining freshness at receipt, independently of the
			// original setup budget. Neither interval extends the worker lifetime.
			if !errors.As(err, &idle) || idle == nil {
				return workerNativeStep("open", err)
			}
			if idle.Reference != h.Reference || idle.Nonce != h.Nonce || !receivedAt.Before(openedAt.Add(5*time.Second)) || !receivedAt.Before(idle.Until) || idle.Until.After(receivedAt.Add(5*time.Second)) || idle.Until.After(l.target.RunUntil) {
				return workerNativeStep("idle", nil)
			}
			// At most one idle lookup per NativeIdleRetry. A hub that parked the
			// request until shortly before its reply already spent that interval,
			// so the next lookup follows at once instead of leaving a gap.
			if d := contracts.NativeIdleRetry - receivedAt.Sub(openedAt); d > 0 {
				if err := l.wait(ctx, d); err != nil {
					return err
				}
			}
			continue
		}
		if stream == nil {
			clear(token)
			return workerNativeStep("open", nil)
		}
		outcome, err := l.run(ctx, stream, h)
		// The actual conversation joins its reader/buffers/stream before return.
		// Close again is idempotent and covers a failed precondition before Run.
		closeErr := stream.Close()
		clear(token)
		if err != nil || closeErr != nil || outcome.State != contracts.NativeJoined {
			return workerNativeStep("conversation", err)
		}
		if err := l.wait(ctx, contracts.NativeIdleRetry); err != nil {
			return err
		}
	}
	return artifact.ErrDownloadUnavailable
}

// Both child lifetimes are joined even if the initiating context is already
// cancelled. Native work starts only after credential readiness; readiness is
// not reported as a successful download. A failed child cancels the other.
func runWorkerNativePair(ctx context.Context, ready <-chan value.KeyPeer, credentials, work func(context.Context) error) error {
	if ctx == nil || ready == nil || credentials == nil || work == nil {
		return artifact.ErrInvalid
	}
	joined, cancel := context.WithCancel(ctx)
	defer cancel()
	credentialDone := make(chan error, 1)
	go func() { credentialDone <- credentials(joined) }()
	select {
	case err := <-credentialDone:
		if err == nil {
			return artifact.ErrDownloadUnavailable
		}
		return err
	case <-ctx.Done():
		cancel()
		<-credentialDone
		return ctx.Err()
	case <-ready:
	}
	if joined.Err() != nil {
		cancel()
		<-credentialDone
		return joined.Err()
	}
	workDone := make(chan error, 1)
	go func() { workDone <- work(joined) }()
	var err error
	select {
	case err = <-credentialDone:
		cancel()
		<-workDone
	case err = <-workDone:
		cancel()
		<-credentialDone
	case <-ctx.Done():
		err = ctx.Err()
		cancel()
		<-credentialDone
		<-workDone
	}
	if err == nil {
		return artifact.ErrDownloadUnavailable
	}
	return err
}

func runWorkerNative(ctx context.Context, input WorkerStartup, trust *mtls.WorkerNativeTrust, credentials *mtls.WorkerCredentials, private contracts.WorkerStoreCredentials) error {
	if ctx == nil || trust == nil || credentials == nil || !input.Target.Valid() {
		return artifact.ErrInvalid
	}
	exchangeRoots, storeRoots, keyRoots, err := trust.Roots(time.Now())
	if err != nil {
		return err
	}
	key, err := credentials.PublicKeyDigest()
	if err != nil {
		return err
	}
	if err = workerStoreCredentialLifetime(private, time.Now(), input.Target.RunUntil); err != nil {
		return err
	}
	pins := trust.Settings()
	provider := aws.CredentialsProviderFunc(func(ctx context.Context) (aws.Credentials, error) {
		if ctx.Err() != nil {
			return aws.Credentials{}, ctx.Err()
		}
		if err := workerStoreCredentialLifetime(private, time.Now(), input.Target.RunUntil); err != nil {
			return aws.Credentials{}, err
		}
		c := aws.Credentials{AccessKeyID: private.AccessKeyID, SecretAccessKey: private.SecretAccessKey, SessionToken: private.SessionToken, Source: "protected worker projection"}
		if private.ExpiresAt != "" {
			c.CanExpire = true
			c.Expires, _ = time.Parse(time.RFC3339Nano, private.ExpiresAt)
		}
		return c, nil
	})
	storeHTTP := workerNativeHTTP(storeRoots, nil)
	defer storeHTTP.CloseIdleConnections()
	store, err := objectstore.New(pins.StoreEndpoint, pins.StoreRegion, pins.StoreBucket, provider, storeHTTP)
	if err != nil {
		return err
	}
	defer store.Close()
	bound, err := store.ForCustody(pins.StoreID)
	if err != nil {
		return err
	}
	keyHTTP := workerNativeHTTP(keyRoots, credentials)
	defer keyHTTP.CloseIdleConnections()
	reader, err := objectstore.NewNativeContextReader(bound, pins.KeyScope, pins.KeyEndpoint, keyHTTP)
	if err != nil {
		return err
	}
	var result *evidence.RegionalContextResult
	switch input.Target.Parent().Purpose {
	case value.AcquisitionDownload:
		result, err = evidence.NewRegionalContextResult(ctx, input.Target, reader, time.Now)
	case value.AcquisitionProjection:
		result, err = evidence.NewRegionalApprovedResult(ctx, input.Target, reader, time.Now)
	default:
		return artifact.ErrInvalid
	}
	if err != nil {
		return err
	}
	defer func() { result.Close(); _ = result.Wait(context.Background()) }()
	client, err := mtls.NewNativeClientVia(pins.ExchangeEndpoint, pins.ExchangeAddress, &tls.Config{RootCAs: exchangeRoots, GetClientCertificate: credentials.GetClientCertificate, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13})
	if err != nil {
		return err
	}
	loop := workerNativeLoop{target: input.Target, token: mtls.NewProjectedWorkerToken(), now: time.Now, wait: waitWorker, nonce: workerNativeNonce,
		open: func(ctx context.Context, h contracts.NativeHello) (contracts.NativeStream, error) {
			s, err := client.Open(ctx, h)
			if err != nil {
				return nil, err
			}
			return s, nil
		},
		run: func(ctx context.Context, s contracts.NativeStream, h contracts.NativeHello) (contracts.NativeConversationResult, error) {
			ctx, steps := auditapp.WithStepTimes(ctx)
			out, err := native.RunWorkerConversation(ctx, s, h, input.Target, key, result)
			reportNativeRead(os.Stderr, steps.String(), err)
			return out, err
		},
	}
	return loop.Run(ctx)
}

// reportNativeRead writes one approved read's worker-side step timing (key
// unwraps, object read and decryption, parsing, result frames) with its outcome.
// Only fixed step names, buckets and the closed stop stage are written.
func reportNativeRead(out io.Writer, steps string, err error) {
	if steps == "" {
		return
	}
	outcome := "joined"
	if err != nil {
		outcome = "stopped"
		var fixed interface{ FixedStep() string }
		if errors.As(err, &fixed) {
			outcome += " at " + fixed.FixedStep()
		}
	}
	fmt.Fprintf(out, "native read: %s, %s\n", steps, outcome)
}
