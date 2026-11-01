package integration

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strings"
	"testing"
	"time"
)

// Four cumulative sessions cover the control, paced whole, two ranges sharing
// one session, and stale If-Range. No uncertain preparation or body is retried.
func qualifyInstalledNativePacing(t *testing.T, ctx context.Context, m *nativePacingMeasurement, transport *http.Transport, identity *installedIdentity, origin, artifactID string, control installedJourneyDownload, native []byte, invoke func(string, any) (installedJourneyEnvelope, string), read func(string, any, any), diagnose func()) {
	t.Helper()
	if control.ETag == "" || strings.HasPrefix(control.ETag, "W/") || sha256.Sum256(native) != m.Bodies["unpaced"].SHA256 {
		t.Fatal("authenticated control lacks strong immutable metadata")
	}
	client, closeClient := nativePacingClient(transport)
	defer closeClient()
	seenSessions := map[string]bool{control.DownloadID: true}
	phase := func(name string) func() {
		t.Helper()
		end, err := m.begin(ctx, name)
		if err != nil {
			t.Fatal(name, err)
		}
		return func() {
			t.Helper()
			if err := end(); err != nil {
				t.Fatal(name, err)
			}
		}
	}
	prepare := func(name string) installedJourneyDownload {
		t.Helper()
		end := phase("prepare-" + name)
		input := map[string]string{"artifact_id": artifactID, "idempotency_key": "installed-native-" + name}
		var d installedJourneyDownload
		create := func() {
			t.Helper()
			reply, code := invoke("prepare_artifact_download", input)
			if code != "" || reply.Status != "ok" || json.Unmarshal(reply.Data, &d) != nil {
				diagnose()
				t.Fatal("native preparation failed without retry", name, code)
			}
		}
		create()
		id, deadline := d.DownloadID, d.ExpiresAt
		until := time.Now().Add(60 * time.Second)
		for d.State == "Preparing" && time.Now().Before(until) {
			if err := installedJourneyPause(ctx, time.Second); err != nil {
				t.Fatal(err)
			}
			if d.ContinuePreparation {
				create()
			} else {
				read("get_artifact_download", map[string]string{"download_id": id}, &d)
			}
			if d.DownloadID != id || !d.ExpiresAt.Equal(deadline) {
				t.Fatal("native preparation changed original session or expiry")
			}
		}
		if d.State != "Ready" || d.SizeBytes == nil || *d.SizeBytes != int64(len(native)) || d.SHA256 != control.SHA256 || d.ETag != control.ETag || d.ContentPath == "" || !time.Now().Before(deadline) {
			diagnose()
			t.Fatal("native preparation did not retain exact artifact metadata", name, d.State)
		}
		if d.DownloadID == "" || seenSessions[d.DownloadID] {
			t.Fatal("native preparation reused another comparison session")
		}
		seenSessions[d.DownloadID] = true
		end()
		return d
	}
	consume := func(name string, d installedJourneyDownload, offset, length int64, partial bool, headers map[string]string, interval time.Duration, writer io.Writer, owner bool) nativePacingResult {
		t.Helper()
		end := phase(name)
		bodyCtx, cancel := context.WithDeadline(ctx, minTime(d.ExpiresAt, time.Now().Add(25*time.Second)))
		defer cancel()
		var observer *nativePacingOwnerObserver
		var err error
		if owner {
			observer, err = newNativePacingOwnerObserver(bodyCtx, m.admin, m.root, d.DownloadID, writer)
			if err != nil {
				t.Fatal(err)
			}
			writer = observer
		}
		response := installedJourneyContent(t, bodyCtx, client, strings.TrimSuffix(origin, "/")+d.ContentPath, identity.downloadToken(), headers)
		_, disposition, err := mime.ParseMediaType(response.Header.Get("Content-Disposition"))
		if err != nil || disposition["filename"] != "artifact-"+artifactID+".pcapng" {
			response.Body.Close()
			t.Fatal("paced native filename mismatch")
		}
		selection := nativePacingSelection{Offset: offset, Length: length, Total: int64(len(native)), ETag: control.ETag, SHA256: sha256.Sum256(native[offset : offset+length]), Partial: partial}
		result, err := nativePacingConsume(bodyCtx, response, selection, writer, interval)
		if err != nil {
			diagnose()
			t.Fatal("exact native transfer", name, err)
		}
		m.Bodies[name] = result
		if owner {
			// Completion is observed through the public operation; only then
			// inspect the pinned SQL acknowledgement once, without retrying it.
			var finished installedJourneyDownload
			until := time.Now().Add(5 * time.Second)
			for time.Now().Before(until) {
				read("get_artifact_download", map[string]string{"download_id": d.DownloadID}, &finished)
				if finished.State == "Completed" {
					break
				}
				if err := installedJourneyPause(ctx, 100*time.Millisecond); err != nil {
					t.Fatal(err)
				}
			}
			if finished.DownloadID != d.DownloadID || finished.State != "Completed" || !finished.ExpiresAt.Equal(d.ExpiresAt) {
				t.Fatal("paced native response lacks public completion")
			}
			m.Owner, err = observer.Finish(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if result.Elapsed <= 5*time.Second {
				t.Fatal("paced response did not cross old five-second observation")
			}
		}
		end()
		return result
	}
	// Keep comparison data bounded by the already authenticated 8 MiB native
	// file. Only the control is retained as PCAPNG; other bodies stream to hashes.
	paced := prepare("paced")
	consume("paced", paced, 0, int64(len(native)), false, nil, nativePacingInterval, io.Discard, true)
	pacedPhase := m.Phases[len(m.Phases)-1]
	if pacedPhase.Name != "paced" {
		t.Fatal("paced measurement phase missing")
	}
	idleEnd := phase("idle-baseline")
	if err := installedJourneyPause(ctx, pacedPhase.FinishedAt.Sub(pacedPhase.StartedAt)); err != nil {
		t.Fatal(err)
	}
	idleEnd()
	ranges := prepare("range")
	half := int64(len(native)) / 2
	joined := sha256.New()
	consume("range-first", ranges, 0, half, true, map[string]string{"Range": fmt.Sprintf("bytes=0-%d", half-1), "If-Range": control.ETag}, 0, joined, false)
	consume("range-resume", ranges, half, int64(len(native))-half, true, map[string]string{"Range": fmt.Sprintf("bytes=%d-", half), "If-Range": control.ETag}, 0, joined, false)
	m.RangeSessionReused = true
	if hex.EncodeToString(joined.Sum(nil)) != control.SHA256 {
		t.Fatal("native resumed ranges changed full artifact hash")
	}
	stale := prepare("stale")
	consume("stale-ifrange", stale, 0, int64(len(native)), false, map[string]string{"Range": "bytes=0-1023", "If-Range": "\"fixture-stale-version\""}, 0, io.Discard, false)
	if len(m.Bodies) != 5 || m.Bodies["unpaced"].SHA256 != m.Bodies["paced"].SHA256 {
		t.Fatal("native comparison set incomplete")
	}
	m.DistinctSessionCount = len(seenSessions)
	if m.DistinctSessionCount != 4 {
		t.Fatal("native comparison session set incomplete")
	}
	// PCAPNG/tshark validation in the parent must still pass before Complete
	// becomes true. Revocation/cancellation/concurrency are separate open gates.
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}
