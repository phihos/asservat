package native_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/transport/browser"
)

func TestNativeTwoHopPacedSinkStopsAtRevocationAndOriginalDeadline(t *testing.T) {
	for _, mode := range []string{"revocation", "original-deadline", "token-expiry"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
			defer cancel()
			source := pcapngSourceValue(t)
			body := syntheticPCAPNG(t, int(artifact.RemoteNativeLimit)-(256<<10))
			now := time.Now()
			target := value.WorkerCredentialTarget{InstallationID: nativeID, SessionID: nativeID, WorkerID: nativeID, PodUID: nativeID, CreatedAt: now, RunUntil: now.Add(time.Minute)}
			reader := &pcapngReader{source: source, body: body}
			result, err := evidence.NewRegionalContextResult(ctx, target, reader, time.Now)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { result.Close(); result.Wait(context.Background()) }()
			prepare, client, _ := flowOperation(t, ctx, source, value.NativePrepare, 1, artifact.DownloadDeliveryLease{})
			done := flowRunWorker(t, ctx, client, target, result)
			metadata, err := prepare.Prepared(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if err = prepare.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			if err = <-done; err != nil {
				t.Fatal(err)
			}
			prepare.Close()
			request := ctx
			if mode == "original-deadline" {
				var stop context.CancelFunc
				request, stop = context.WithTimeout(ctx, 3500*time.Millisecond)
				defer stop()
			}
			now = time.Now()
			a := artifact.DownloadAuthority{Scope: artifact.DownloadScope{RootID: nativeID, ArtifactID: nativeID, CaptureID: nativeID, ClusterID: nativeID, NamespaceUID: nativeID, WorkloadUID: nativeID, PodUID: nativeID, Version: evidence.ContextCopiesDigest(source.Copies), Principal: identity.Principal{Issuer: "https://id.invalid", Subject: "dev", ClientID: "browser", Kind: identity.Human}}, PermissionEpoch: nativeID, PermissionSequence: 1, ProjectionDigest: artifact.Digest{1}, DecisionDigest: artifact.Digest{2}, IdentityRevision: identity.Revision{UID: "policy", Generation: 1, Digest: [32]byte{3}}, CheckedAt: now, ValidUntil: now.Add(4 * time.Second), AccessUntil: source.Expectation.Registration.ExpiresAt, DeleteBy: source.Expectation.Registration.DeleteBy}
			lease := artifact.DownloadDeliveryLease{ResponseID: nativeID, WindowID: nativeID, OwnerID: nativeID, Generation: 1, Sequence: 1, Length: metadata.Size, StartedAt: now, Until: a.ValidUntil, Authority: a}
			var sequence, writes atomic.Int64
			sequence.Store(1)
			var revoked atomic.Bool
			tokenEnd := time.Now().Add(time.Second)
			observe := func(l value.NativeLease) value.NativeLease {
				if revoked.Load() {
					return value.NativeLease{}
				}
				l.Sequence = sequence.Load()
				l.ObservedAt = time.Now()
				l.Until = identity.Earlier(l.Operation.Until, l.ObservedAt.Add(4*time.Second))
				if mode == "token-expiry" {
					l.Until = identity.Earlier(l.Until, tokenEnd)
				}
				return l
			}
			response, client, _ := flowOperationWithConnector(t, request, source, value.NativeResponse, 2, lease, nil, observe)
			defer response.Close()
			worker := flowRunWorker(t, request, client, target, result)
			outcome := make(chan error, 1)
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				outcome <- func() error {
					paced := &pacedNativeSink{ResponseWriter: w, ctx: r.Context(), delay: 750 * time.Millisecond, afterWrite: func() {
						if writes.Add(1) == 7 && mode == "revocation" {
							revoked.Store(true)
						}
					}}
					if mode == "token-expiry" {
						paced.delay = 1500 * time.Millisecond
					}
					factory := browser.HTTPDownloadResponseFactory{Writer: paced, Request: r}
					plan := artifact.DownloadResponse{ID: nativeID, SessionID: nativeID, OwnerID: nativeID, Generation: 1, Plan: artifact.DownloadResponsePlan{Version: 1, Selection: artifact.DownloadSelection{Length: metadata.Size}, WholeFile: true, WindowReadLimit: evidence.NativeWindowReadWork(source.Expectation.Type())}, StartedAt: now, Until: target.RunUntil}
					sink, err := factory.OpenDownloadResponse(request, metadata, plan)
					if err != nil {
						return err
					}
					defer sink.Close()
					for at := int64(0); at < metadata.Size; {
						if time.Now().Add(2 * time.Second).After(lease.Until) {
							n := time.Now()
							a.CheckedAt = n
							a.ValidUntil = n.Add(4 * time.Second)
							lease.Authority = a
							lease.StartedAt = n
							lease.Until = a.ValidUntil
							lease.Sequence = sequence.Add(1)
						}
						n := min(artifact.DeliveryBytes, metadata.Size-at)
						piece, stop := context.WithDeadline(request, lease.Until)
						chunk, err := response.ReadChunk(piece, lease, at, n)
						if err == nil {
							bounded, stopBound := context.WithDeadline(piece, chunk.NativeUntil)
							_, err = sink.WriteChunk(bounded, lease, at, chunk.Bytes)
							if err == nil {
								err = response.AcknowledgeNativeChunk(bounded, lease, at, n)
							}
							stopBound()
						}
						clear(chunk.Bytes)
						stop()
						if err != nil {
							return err
						}
						at += n
					}
					return sink.Finish(request)
				}()
			}))
			defer server.Close()
			reply, err := server.Client().Get(server.URL)
			var got []byte
			if err == nil {
				got, _ = io.ReadAll(reply.Body)
				reply.Body.Close()
			}
			sinkErr, workerErr := <-outcome, <-worker
			if sinkErr == nil || workerErr == nil || len(got) == len(body) {
				t.Fatal("paced transfer outlived authority", mode, len(got), sinkErr, workerErr)
			}
			if mode == "revocation" && !revoked.Load() {
				t.Fatal("fixture did not revoke")
			}
			if mode == "token-expiry" && (writes.Load() != 0 || len(got) != 0) {
				t.Fatal("blocked write disclosed after native token expiry", writes.Load(), len(got))
			}
			if mode == "original-deadline" && request.Err() == nil {
				t.Fatal("fixture did not reach original deadline")
			}
			t.Logf("%s: wrote%d/%d bytes; writes=%d; original request unchanged", mode, len(got), len(body), writes.Load())
		})
	}
}
