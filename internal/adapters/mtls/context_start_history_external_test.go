package mtls_test

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	mtls "asservat.local/asservat/internal/adapters/mtls"
	app "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/bootstrap"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/fleet"
)

type historyTimedSigner struct {
	app.HistoryWorkSigner
	elapsed time.Duration
	calls   int
}

func (s *historyTimedSigner) SignHistoryWork(ctx context.Context, w app.HistoryWork) ([]byte, error) {
	began := time.Now()
	defer func() { s.elapsed += time.Since(began); s.calls++ }()
	return s.HistoryWorkSigner.SignHistoryWork(ctx, w)
}

// Actual dispatch, process-owned TLS/H2, handler/router, source frames and
// signatures. Current authority, SQL claim and object effects are synthetic.
func TestHistoryDispatchTLSOriginalBoundAndSourceReads(t *testing.T) {
	for _, mode := range []string{"write", "read", "write-delayed", "read-short-authority", "source-change", "closed-attachment", "canceled", "expired"} {
		t.Run(mode, func(t *testing.T) {
			delay := time.Duration(0)
			budget := 3 * time.Second
			if mode == "write-delayed" {
				delay = 200 * time.Millisecond
				budget = 500 * time.Millisecond
			}
			if mode == "expired" {
				budget = 100 * time.Millisecond
			}
			f := mtls.NewHistoryTLSHarness(t, delay)
			signer := &historyTimedSigner{HistoryWorkSigner: f.Signer}
			var exchangeBudget, peerBudget string
			dispatch := bootstrap.RegionalHistoryDispatch{Router: f.Router, Signer: signer, Now: time.Now, Report: func(stage, details string) {
				if stage == "exchange/failed" {
					exchangeBudget = details
				}
				if stage == "exchange-peer/failed" {
					peerBudget = details
				}
				t.Log("dispatch", stage, details)
			}}
			ctx, cancel := context.WithTimeout(t.Context(), budget)
			defer cancel()
			now := time.Now().UTC().Truncate(time.Microsecond)
			const id = "55000000-0000-4000-8000-000000000001"
			begun := time.Now()
			session, err := dispatch.PrepareHistory(ctx, f.Receiver.Channel.Connector.Binding.ClusterID, id)
			if err != nil {
				t.Fatal("prepare", err)
			}
			defer session.Close()
			prepared := time.Since(begun)
			e := capture.HistoryExpectation{RootID: f.RootID, CaptureID: id, Registration: artifact.Registration{Location: artifact.Location{ClusterID: f.Receiver.Channel.Connector.Binding.ClusterID, ArtifactID: id, AttemptID: id}, StoreID: id, AllocationID: id, PoolRevision: 1, AllocationRevision: 1, NativeLimit: capture.MaxHistoryParameters, AnchorAt: now, WriteUntil: now.Add(time.Minute), ExpiresAt: now.Add(time.Hour), DeleteBy: now.Add(2 * time.Hour)}, SelectorKey: artifact.Digest{1}, SettingsKey: artifact.Digest{2}, MACVersion: "v1", OriginalExecutionDigest: artifact.Digest{3}}
			authority := capture.HistoryOperationAuthority{Expectation: e, Operation: "write", RequestID: id, ExecutorEpoch: session.ExecutorEpoch(), StartedAt: now, NotAfter: session.NotAfter()}
			authority.BundleDigest, _ = capture.HistoryCiphertextsDigest(f.Bundle)
			if mode == "read" || mode == "read-short-authority" {
				authority.Operation = "read"
				authority.BundleDigest = artifact.Digest{}
				authority.CopiesDigest = capture.HistoryCopiesDigest(f.Copies)
			}
			switch mode {
			case "source-change":
				f.ChangeSource()
			case "closed-attachment":
				session.Close()
			case "canceled":
				cancel()
			case "expired":
				<-ctx.Done()
			}
			if mode == "read-short-authority" {
				// A real effect starts, then its original signed bound expires
				// while caller/session still have time. No longer bound is granted.
				f.DelayEffects(600 * time.Millisecond)
				authority.NotAfter = time.Now().UTC().Truncate(time.Microsecond).Add(300 * time.Millisecond)
			}
			reply, err := session.ExecuteHistory(ctx, authority, f.Bundle, f.Copies)
			if err == nil {
				if reply.Copies != f.Copies {
					t.Error("history receipts changed")
				}
				if mode == "read" {
					for i := range f.Bundle {
						if !bytes.Equal(reply.Bundle[i], f.Bundle[i]) {
							t.Error("history ciphertext changed", i)
						}
					}
				}
			}
			reply.Bundle.Clear()
			t.Logf("mode=%s prepare=%s sign=%s executeOther=%s total=%s sourceReads=%d signCalls=%d effects=%d", mode, prepared, signer.elapsed, time.Since(begun)-prepared-signer.elapsed, time.Since(begun), f.Sources(), signer.calls, f.Effects())
			if mode == "read-short-authority" {
				if err == nil || ctx.Err() != nil || time.Now().Before(authority.NotAfter) || f.Effects() != 1 || signer.calls != 1 || !strings.Contains(exchangeBudget, " expired") || !strings.Contains(peerBudget, " expired") {
					t.Fatal("history reported session budget instead of expired original work/peer bound", err, ctx.Err(), f.Effects(), exchangeBudget, peerBudget)
				}
				if duplicate, duplicateErr := f.Router.Attach(ctx, f.Receiver.Channel.Connector.Binding.ClusterID, id); duplicate != nil || duplicateErr != fleet.ErrCapacity {
					t.Fatal("uncertain effect released its original attachment before joined Close", duplicateErr)
				}
				// Even another valid signed bound cannot rearm this consumed
				// attachment after its effect/reply became uncertain.
				authority.NotAfter = session.NotAfter()
				again, retryErr := session.ExecuteHistory(ctx, authority, f.Bundle, f.Copies)
				again.Bundle.Clear()
				if retryErr == nil || f.Effects() != 1 {
					t.Fatal("uncertain history effect was rearmed", retryErr, f.Effects())
				}
				return
			}
			if mode == "source-change" || mode == "closed-attachment" || mode == "canceled" || mode == "expired" {
				if err == nil || f.Effects() != 0 {
					t.Fatal("dead history authority reached effects", err, f.Effects())
				}
				return
			}
			if err != nil || signer.calls != 1 || f.Effects() != 1 || f.Sources() != 2 {
				t.Fatal("history exhausted original bound or repeated source read", err, signer.calls, f.Effects(), f.Sources())
			}
		})
	}
}
