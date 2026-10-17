package postgres

import (
	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	"bytes"
	"encoding/json"
	"testing"
	"time"
)

func TestCurrentBatchReceiptRequiresVersionButHistoryKeepsBytes(t *testing.T) {
	w := versionWorkerFixture(t)
	a := w.Intent.Authority
	n := w.Intent.CreatedAt
	i := audit.DownloadIntent{SessionID: w.Intent.SessionID, Batch: artifact.DownloadBatch{ID: w.Intent.ID, Purpose: artifact.DownloadMetadata, Generation: 1, ReadBytes: 4096, StartedAt: n, LeaseUntil: n.Add(time.Second), Authority: a}}
	raw, err := json.Marshal(i)
	if err != nil || !i.Valid() {
		t.Fatal("fixture", err)
	}
	row := custodydb.DownloadBatch{ID: id(i.Batch.ID), SessionID: id(i.SessionID), Generation: i.Batch.Generation, IntentJson: raw, LeaseUntil: ts(i.Batch.LeaseUntil), AuditAcknowledgedAt: ts(n)}
	for _, version := range []string{"original", "", "null"} {
		name := version
		if name == "" {
			name = "empty"
		}
		t.Run(name, func(t *testing.T) {
			r := audit.Receipt{Key: audit.DownloadAuditKey(a.Scope.RootID, i.SessionID, i.Batch.ID, "intent"), Version: version, ETag: "original", Bytes: 17, SHA256: artifact.Digest{8}}
			candidate := row
			candidate.AuditReceiptJson, _ = json.Marshal(r)
			before := bytes.Clone(candidate.AuditReceiptJson)
			_, err := decodeDownloadIntent(candidate)
			if version == "original" && err != nil || version != "original" && err == nil {
				t.Fatal("current batch receipt version", err)
			}
			got, err := decodeHistoricalDownloadIntent(candidate)
			if err != nil || !got.Equal(i) {
				t.Fatal("historical accounting blocked", err)
			}
			if !bytes.Equal(before, candidate.AuditReceiptJson) {
				t.Fatal("decoder rewrote history")
			}
		})
	}
}

func versionWindowFixture(t *testing.T) audit.DownloadWindowIntent {
	t.Helper()
	worker := versionWorkerFixture(t)
	now := worker.Intent.CreatedAt
	key := worker.Intent.ID
	r := artifact.DownloadResponse{ID: key, SessionID: key, OwnerID: key, Generation: 2, Plan: artifact.DownloadResponsePlan{Version: 1, Selection: artifact.DownloadSelection{Length: 100}, WholeFile: true, WindowReadLimit: 1024}, StartedAt: now, Until: now.Add(time.Minute), WindowCount: 1, ActiveWindowID: key}
	w := artifact.DownloadWindow{ID: key, ResponseID: key, SessionID: key, OwnerID: key, AuditStoreID: key, Generation: 2, Ordinal: 1, Length: 100, ReadLimit: 1024, StartedAt: now, WriteUntil: now.Add(2 * time.Minute), Authority: worker.Intent.Authority}
	i := audit.DownloadWindowIntent{Response: r, Window: w}
	if !i.Valid() {
		t.Fatal("window fixture")
	}
	return i
}
func TestCurrentWindowReceiptsRequireVersionsButHistoryKeepsBytes(t *testing.T) {
	i := versionWindowFixture(t)
	encode := func(v any) []byte {
		b, e := json.Marshal(v)
		if e != nil {
			t.Fatal(e)
		}
		return b
	}
	good := func(phase string) audit.Receipt {
		return audit.Receipt{Key: audit.DownloadWindowAuditKey(i.Window.Authority.Scope.RootID, i.Response.ID, i.Window.ID, phase), Version: "original", ETag: "original", Bytes: 17, SHA256: artifact.Digest{9}}
	}
	row := custodydb.DownloadWindow{ID: id(i.Window.ID), ResponseID: id(i.Response.ID), SessionID: id(i.Window.SessionID), Ordinal: 1, IntentJson: encode(i), IntentReceipt: encode(good("intent")), OutcomeJson: encode(artifact.DownloadWindowOutcome{EmittedBytes: 100, Success: true, VerifiedFinal: true, RecordedAt: i.Window.StartedAt.Add(time.Second)}), OutcomeReceipt: encode(good("outcome"))}
	if _, _, err := decodeWindow(row); err != nil {
		t.Fatal("original row", err)
	}
	for _, phase := range []string{"intent", "outcome"} {
		for _, version := range []string{"", "null"} {
			name := version
			if name == "" {
				name = "empty"
			}
			t.Run(phase+"-"+name, func(t *testing.T) {
				candidate := row
				r := good(phase)
				r.Version = version
				if phase == "intent" {
					candidate.IntentReceipt = encode(r)
				} else {
					candidate.OutcomeReceipt = encode(r)
				}
				before := encode(candidate)
				if _, _, err := decodeWindow(candidate); err == nil {
					t.Fatal("historical window became current")
				}
				if _, _, err := decodeHistoricalWindow(candidate); err != nil {
					t.Fatal("historical byte accounting blocked", err)
				}
				if !bytes.Equal(before, encode(candidate)) {
					t.Fatal("decoder rewrote historical row")
				}
			})
		}
	}
}
