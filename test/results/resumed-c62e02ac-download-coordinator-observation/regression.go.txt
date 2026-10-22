package evidence

import (
	"context"
	"testing"
	"time"

	identities "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/domain/artifact"
)

// The actual coordinator, runtime and dispatcher share one public request.
// Synthetic port latency exposes duplicate full-authority construction; it is
// not a measurement of provider cost or attribution of the native56 refusal.
func TestContextDownloadRequestUsesOneObservationThroughPending(t *testing.T) {
	for _, cost := range []time.Duration{0, 1600 * time.Millisecond} {
		t.Run(cost.String(), func(t *testing.T) {
			f, c, coordinator, _ := newPreflightPreparation(t, "normal")
			c.plan.HardUntil = c.now.Add(10 * time.Second)
			original := c.a
			calls := 0
			gate := workerCurrentGateFunc(func(ctx context.Context, current identities.CurrentIdentity, scope artifact.DownloadScope) (artifact.DownloadAuthority, error) {
				calls++
				f.advance(cost)
				c.now = f.f.now
				return c.CheckDownloadCurrent(ctx, current, scope)
			})
			coordinator.Authority, f.r.config.Authority = gate, gate
			out, err := coordinator.PrepareContextDownload(t.Context(), c, c.a.Scope.ArtifactID, "one-observation")
			if err != nil || !out.ContinuePreparation || out.Session.State != artifact.DownloadPreparing {
				t.Fatalf("one original request lost acknowledged Pending: full checks=%d launch=%v error=%v", calls, f.launch.calls, err)
			}
			if calls != 1 || f.launch.count("record-job") != 1 || f.launch.count("observe-job") != 1 || countDownloadCalls(c, "observe") != 1 {
				t.Fatalf("duplicate reconstruction or missing current observations: full=%d launch=%v control=%v", calls, f.launch.calls, c.calls)
			}
			if !original.Valid(c.now) || out.ValidUntil.After(original.ValidUntil) || c.a != original {
				t.Fatal("request reused or extended an expired original observation")
			}
		})
	}
}

func TestContextDownloadRequestObservationKeepsFinalFences(t *testing.T) {
	for _, which := range []string{"sql-refusal", "groups", "scopes", "policy", "cancel", "original-expiry", "unknown-job"} {
		t.Run(which, func(t *testing.T) {
			f, c, coordinator, _ := newPreflightPreparation(t, "normal")
			call, cancel := context.WithCancel(t.Context())
			defer cancel()
			if which == "unknown-job" {
				f.jobs.err = artifact.ErrDownloadUnavailable
			} else if which == "sql-refusal" {
				c.fail = "observe"
			} else {
				c.after = func(step string) {
					if step != "observe" {
						return
					}
					switch which {
					case "groups":
						c.i.Groups = []string{"changed"}
					case "scopes":
						c.i.Scopes = []string{"evidence:read"}
					case "policy":
						c.i.Policy.Generation++
					case "cancel":
						cancel()
					case "original-expiry":
						f.advance(5 * time.Second)
						c.now = f.f.now
					}
				}
			}
			out, err := coordinator.PrepareContextDownload(call, c, c.a.Scope.ArtifactID, "final-fences")
			if err == nil || out.ContinuePreparation || out.Session.ID != "" || f.launch.count("record-job") != 1 {
				t.Fatal("a refused or uncertain result became acknowledged Pending", which, out, f.launch.calls, err)
			}
		})
	}
}

func TestContextDownloadRequestReadyReplayUsesFreshSingleObservation(t *testing.T) {
	f, sql, runtime, metadata := warmContextRuntimeFixture(t)
	f.s.RequestDigest = ContextDownloadRequestDigest(f.a.Scope.ArtifactID)
	c, coordinator := newDownloadControlFixture(t)
	c.now, c.a, c.i, c.session, c.found = f.now, f.a, f.identity, f.s, true
	c.prepared = artifact.PreparedDownload{Preparation: *sql.value.Preparation, Scope: f.s.Scope, Native: metadata}
	coordinator.RootID, coordinator.InstallationID = c.a.Scope.RootID, c.a.Environment.InstallationID
	coordinator.Runtime = runtime
	calls := 0
	gate := workerCurrentGateFunc(func(ctx context.Context, current identities.CurrentIdentity, scope artifact.DownloadScope) (artifact.DownloadAuthority, error) {
		calls++
		return c.CheckDownloadCurrent(ctx, current, scope)
	})
	coordinator.Authority, runtime.config.Authority = gate, gate
	for request := 1; request <= 2; request++ {
		out, err := coordinator.PrepareContextDownload(t.Context(), c, c.a.Scope.ArtifactID, "ready-original-key")
		if err != nil || out.Metadata == nil || *out.Metadata != metadata || out.ContinuePreparation {
			t.Fatal("exact committed metadata unavailable", request, out, err)
		}
		if calls != request || sql.reads != 2*request || countDownloadCalls(c, "observe") != 2*request {
			t.Fatal("request did not obtain one fresh authority with current SQL checks", request, calls, sql.reads, c.calls)
		}
	}
	c.fail = "authority"
	if out, err := coordinator.PrepareContextDownload(t.Context(), c, c.a.Scope.ArtifactID, "ready-original-key"); err == nil || out.Metadata != nil || sql.reads != 4 {
		t.Fatal("another request reused previous authority", calls, sql.reads, err)
	}
}
