package integration

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/postgres"
	authapp "asservat.local/asservat/internal/application/authorization"
	app "asservat.local/asservat/internal/application/capture"
	identities "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/targets"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Target/process provenance, login and processing coverage are explicitly
// synthetic. Storage, its actual Ledger transaction, passive preview, replay,
// permission/retention guards and admission use their real SQL adapters. This
// exercises the formerly separate reader and Request tests together; it does
// not qualify a worker refresh, protected source producer or installed capture.
type storageRequestTarget struct{ target targets.PodResolution }

func (s storageRequestTarget) ResolveWorkload(c context.Context, _ targets.WorkloadRequest) (targets.PodResolution, error) {
	return s.ResolvePod(c, s.target.Request)
}
func (s storageRequestTarget) ResolvePod(c context.Context, r targets.Request) (targets.PodResolution, error) {
	if r != s.target.Request {
		return targets.PodResolution{}, targets.ErrChanged
	}
	v := s.target
	v.ObservedAt = time.Now().UTC().Truncate(time.Microsecond)
	v.FreshUntil = v.ObservedAt.Add(5 * time.Second)
	return v, c.Err()
}

type storageRequestProcessing struct{}

func (storageRequestProcessing) ContextProcessingCoverage(c context.Context, r value.ProcessingCoverageRequest, _ artifact.RecoveryProof) (value.ProcessingCoverage, error) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	return value.ProcessingCoverage{Request: r, ObservedAt: now, FreshUntil: now.Add(5 * time.Second)}, c.Err()
}

type storageRequestRefresh struct {
	run func(context.Context, targets.Request) error
}

func (s storageRequestRefresh) DemandCapacityRefresh(c context.Context, r targets.Request) error {
	return s.run(c, r)
}

func qualifyContextStorageRequest(t *testing.T, ctx context.Context, admin *pgxpool.Pool, poolFor func(string, string) *pgxpool.Pool, create func(*testing.T, int64) captureAdmissionScenario) {
	t.Run("storage-expiry-request-composition", func(t *testing.T) {
		for _, mode := range []string{"fresh-after-demand", "fresh-after-failed-demand", "failed-demand", "short-tail"} {
			t.Run(mode, func(t *testing.T) {
				s := create(t, 1)
				previewsPool := poolFor("context_preview_runtime", "synthetic-context-preview")
				defer previewsPool.Close()
				readPool := poolFor("context_storage_read_runtime", "synthetic-context-storage-read")
				defer readPool.Close()
				previews, err := postgres.NewContextPreviews(ctx, previewsPool, s.a.RootID)
				if err != nil {
					t.Fatal(err)
				}
				storage, err := postgres.NewContextStorageReader(ctx, readPool, s.a.RootID)
				if err != nil {
					t.Fatal(err)
				}
				demands, err := postgres.NewCapacityRefreshDemands(ctx, previewsPool, s.a.RootID)
				if err != nil {
					t.Fatal(err)
				}
				service := app.ContextInvestigation{RootID: s.a.RootID, InstallationID: s.recovery.installation, Previews: previews, Replay: s.s, Admission: s.s, Targets: storageRequestTarget{s.a.Plan.Input.Target}, Eligibility: authapp.Evaluator{Permissions: s.p, Now: time.Now}, Capabilities: nativeAPICapability{s.a.Plan.Input.Capability}, Retention: nativeAPIRetention{s.retention}, Storage: storage, Processing: storageRequestProcessing{}, Recovery: s.recovery.reader, Lifetime: 30 * time.Second, Now: time.Now, NewID: custodyID}
				human := s.a.Eligibility.VerifiedIdentity
				human.VerifiedAt = time.Now().UTC().Truncate(time.Microsecond)
				human.ValidUntil = human.VerifiedAt.Add(5 * time.Second)
				source, _, err := identities.NewBearerRequest(ctx, nativeAPIIdentity{human}, "synthetic-storage-request", time.Now)
				if err != nil {
					t.Fatal(err)
				}
				target := s.a.Plan.Input.Target.Request
				preview, err := service.Preview(ctx, source, value.ContextIntent{Target: targets.WorkloadRequest{ClusterID: target.ClusterID, Namespace: target.Namespace.Name, Kind: target.Workload.Kind, Name: target.Workload.Name}, Diagnostic: value.ContextDiagnosticName})
				if err != nil {
					t.Fatal("actual Request fixture preview failed", err)
				}
				// An expired actual SQL row supplies non-authoritative original selection.
				// These administrator-authored times are fixture facts, not a runtime
				// refresh or authority qualification. Do not change scope/revisions.
				publish := func(c context.Context, expired bool) error {
					at := time.Now().UTC().Truncate(time.Microsecond)
					until := at.Add(30 * time.Second)
					if expired {
						at = at.Add(-31 * time.Second)
						until = at.Add(30 * time.Second)
					}
					tag, e := admin.Exec(c, `UPDATE context_storage_binding SET observed_at=$3,fresh_until=$4 WHERE root_id=$1 AND allocation_id=$2`, s.a.RootID, s.a.Registration.AllocationID, at, until)
					if e == nil && tag.RowsAffected() != 1 {
						return errors.New("fixture source update missing")
					}
					return e
				}
				if err := publish(ctx, true); err != nil {
					t.Fatal(err)
				}
				expired, err := storage.ContextStorage(ctx, s.a.Eligibility.Target)
				if !errors.Is(err, value.ErrStorageBindingExpired) || expired.Selection != preview.Preview.Storage {
					t.Fatal("actual SQL expired source lost its original preview selection", err)
				}
				var submitted atomic.Int32
				var waitLeft atomic.Int64
				service.Refresh = storageRequestRefresh{run: func(c context.Context, r targets.Request) error {
					submitted.Add(1)
					if d, ok := c.Deadline(); ok {
						waitLeft.Store(int64(time.Until(d)))
					}
					if err := demands.DemandCapacityRefresh(c, r); err != nil {
						return err
					}
					if mode == "fresh-after-demand" || mode == "fresh-after-failed-demand" {
						if err := publish(c, false); err != nil {
							return err
						}
					}
					// An uncertain/failed wakeup is not authority. A later independent
					// current SELECT must still be accepted before that failure gate.
					if mode == "failed-demand" || mode == "fresh-after-failed-demand" {
						return value.ErrUnavailable
					}
					return nil
				}}
				var reason string
				service.ReportPreviewFailure = func(stage string) { reason = stage }
				call := ctx
				end := func() {}
				if mode == "short-tail" {
					call, end = context.WithTimeout(ctx, 750*time.Millisecond)
				}
				defer end()
				began := time.Now()
				accepted, err := service.Request(call, source, preview.Preview.ID, "storage-request-composed")
				elapsed := time.Since(began)
				var captures int
				if e := admin.QueryRow(ctx, `SELECT count(*) FROM context_capture WHERE root_id=$1`, s.a.RootID).Scan(&captures); e != nil {
					t.Fatal(e)
				}
				if mode == "fresh-after-demand" || mode == "fresh-after-failed-demand" {
					if err != nil || accepted.CaptureID != preview.Preview.CaptureID || captures != 1 || submitted.Load() != 1 {
						t.Fatal("actual reader/request/admission failed independent fresh source", mode, err, captures, submitted.Load(), reason)
					}
					// Accepted idempotency must precede the now-expired source; no rearm.
					if err := publish(ctx, true); err != nil {
						t.Fatal(err)
					}
					replay, e := service.Request(ctx, source, preview.Preview.ID, "storage-request-composed")
					if e != nil || !replay.Replay || replay.CaptureID != accepted.CaptureID || submitted.Load() != 1 {
						t.Fatal("accepted replay refreshed storage or lost original capture", e, submitted.Load())
					}
				} else {
					want := "request/facts/storage/expired/demand-failed"
					count := int32(1)
					if mode == "short-tail" {
						want = "request/facts/storage/expired/readiness-tail"
						count = 0
					}
					if !errors.Is(err, value.ErrStorageBindingExpired) || captures != 0 || submitted.Load() != count || reason != want {
						t.Fatal("actual expired read lost its bounded readiness refusal", err, captures, submitted.Load(), reason)
					}
				}
				t.Logf("actual SQL Reader→Request mode=%s request=%s original wait-left-at-demand=%s demands=%d captures=%d refusal=%q; source/target/processing provenance remains synthetic", mode, elapsed, time.Duration(waitLeft.Load()), submitted.Load(), captures, reason)
			})
		}
	})
}

var _ app.ContextStorageReader = (*postgres.ContextStorageReader)(nil)
