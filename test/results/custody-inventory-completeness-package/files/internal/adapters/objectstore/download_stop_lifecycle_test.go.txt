package objectstore

import (
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/audit"
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"sync/atomic"
	"testing"
	"time"
)

func stopObjectBinding(now time.Time) value.DownloadStopLifecycleBinding {
	p := value.DownloadStopLifecyclePolicy{RootID: operationTestID, InstallationID: operationTestID, StoreID: operationTestID, PolicyID: operationTestID, BackupProfileID: operationTestID, QualificationID: operationTestID, PolicyDigest: artifact.Digest{1}, BackupProfileDigest: artifact.Digest{2}, QualificationDigest: artifact.Digest{3}, Layout: value.DownloadStopHistoryLayout, CleanupBudgetSeconds: 60, ProofWindowSeconds: 60, MaximumRowFootprintBytes: 128 << 10, MaximumTransitionWALBytes: 128 << 10, BackupCopies: 1, WALCopies: 1, MaxPurgeLeases: 4}
	d := now.Add(time.Hour)
	return value.DownloadStopLifecycleBinding{Protocol: value.DownloadStopWriterProtocol, RootID: operationTestID, DownloadID: operationTestID, AllocationID: operationTestID, IssuerEpoch: operationTestID, Policy: p, ReservedAt: now, TransferUntil: now.Add(time.Minute), HardDeleteBy: d, OriginalPurgeAt: d.Add(-4 * time.Minute), CertificatePurgeAt: d.Add(-2 * time.Minute), LiveRetireBy: d.Add(-time.Minute), HistoryReleaseAt: d.Add(-time.Minute), HistoryDeleteBy: d}
}
func TestClosedDownloadStopWriterRequiresPositivePUTAndExactJoinedVerification(t *testing.T) {
	for _, mode := range []string{"success", "exists", "unknown-put", "wrong-etag", "wrong-version", "wrong-bytes", "bad-verification", "canceled-at-verification"} {
		t.Run(mode, func(t *testing.T) {
			var puts, gets atomic.Int32
			b := []byte("synthetic ciphertext only")
			store := auditObjectStore(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == "PUT" {
					puts.Add(1)
					if r.Header.Get("If-None-Match") != "*" {
						t.Error("not conditional")
					}
					got, _ := io.ReadAll(r.Body)
					if !bytes.Equal(got, b) {
						t.Error("body changed")
					}
					if mode == "exists" {
						w.WriteHeader(412)
						fmt.Fprint(w, "<Error><Code>PreconditionFailed</Code></Error>")
						return
					}
					if mode == "unknown-put" {
						w.WriteHeader(503)
						fmt.Fprint(w, "<Error><Code>SlowDown</Code></Error>")
						return
					}
					w.Header().Set("ETag", "\"known\"")
					w.Header().Set("x-amz-version-id", "v1")
					return
				}
				if r.Method != "GET" {
					t.Error("unexpected I/O", r.Method)
					w.WriteHeader(400)
					return
				}
				gets.Add(1)
				w.Header().Set("ETag", "\"known\"")
				w.Header().Set("x-amz-version-id", "v1")
				if mode == "wrong-etag" {
					w.Header().Set("ETag", "\"changed\"")
				}
				if mode == "wrong-version" {
					w.Header().Set("x-amz-version-id", "v2")
				}
				if mode == "wrong-bytes" {
					w.Write([]byte("changed"))
				} else {
					w.Write(b)
				}
			}))
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			now := time.Now().UTC().Truncate(time.Microsecond)
			p := &ClosedDownloadStopObjects{store: store, storeID: operationTestID}
			c, e := p.write(ctx, stopObjectBinding(now), "decision", now, now.Add(5*time.Second), struct{ Synthetic bool }{true}, func(context.Context) ([]byte, error) { return bytes.Clone(b), nil }, func(context.Context, []byte) error {
				if mode == "bad-verification" {
					return artifact.ErrDownloadUnavailable
				}
				if mode == "canceled-at-verification" {
					cancel()
				}
				return nil
			})
			if mode == "success" {
				if e != nil || !c.Valid(stopObjectBinding(now), "decision", now, now.Add(5*time.Second)) {
					t.Fatal("missing positive completion", e, c)
				}
			} else if e == nil || c != (value.DownloadStopWriteCompletion{}) {
				t.Fatal("unknown or incomplete writer emitted closure", e, c)
			}
			if puts.Load() != 1 || (mode == "exists" || mode == "unknown-put") && gets.Load() != 0 {
				t.Fatal("write automatically retried or existence reconstructed completion", puts.Load(), gets.Load())
			}
		})
	}
}
func TestClosedDownloadStopWriterDoesNotReturnBeforeOwnedVerificationJoins(t *testing.T) {
	b := []byte("synthetic")
	store := auditObjectStore(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", "\"known\"")
		if r.Method == "PUT" {
			io.Copy(io.Discard, r.Body)
		} else {
			w.Write(b)
		}
	}))
	now := time.Now().UTC().Truncate(time.Microsecond)
	entered, release := make(chan struct{}), make(chan struct{})
	done := make(chan error, 1)
	p := &ClosedDownloadStopObjects{store: store, storeID: operationTestID}
	go func() {
		_, e := p.write(context.Background(), stopObjectBinding(now), "decision", now, now.Add(5*time.Second), true, func(context.Context) ([]byte, error) { return bytes.Clone(b), nil }, func(context.Context, []byte) error { close(entered); <-release; return nil })
		done <- e
	}()
	<-entered
	select {
	case e := <-done:
		t.Fatal("completion escaped active verifier", e)
	default:
	}
	close(release)
	if e := <-done; e != nil {
		t.Fatal(e)
	}
}
func TestDownloadStopPurgeConfinesAllVersionsAndTerminalSlot(t *testing.T) {
	for _, mode := range []string{"original", "terminal", "overdue", "overdue-unexpected-certificate", "unexpected-certificate", "unexpected-key", "truncated", "retained-marker"} {
		t.Run(mode, func(t *testing.T) {
			now := time.Now().UTC().Truncate(time.Microsecond)
			l := value.DownloadStopPurgeLease{RootID: operationTestID, DownloadID: operationTestID, StoreID: operationTestID, InstallationID: operationTestID, IssuerEpoch: operationTestID, Phase: "original", BindingDigest: artifact.Digest{3}, ObjectsDigest: artifact.Digest{1}, WritersDigest: artifact.Digest{2}, Fence: 1, StartedAt: now, Until: now.Add(5 * time.Second)}
			phase := "decision"
			if mode == "overdue" || mode == "overdue-unexpected-certificate" {
				l.Phase = "overdue"
			}
			if mode == "terminal" {
				l.Phase = "terminal"
				phase = "deletion-certificate"
			}
			if mode == "unexpected-certificate" || mode == "overdue-unexpected-certificate" {
				phase = "deletion-certificate"
			}
			if mode == "unexpected-key" {
				phase = "unknown"
			}
			key := artifact.DownloadStopKey(l.RootID, l.DownloadID)
			if phase != "decision" {
				key += "/" + phase
			}
			var deletes atomic.Int32
			store := auditObjectStore(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/xml")
				q := r.URL.Query()
				if r.Method == "DELETE" {
					deletes.Add(1)
					if q.Get("versionId") != "v1" {
						t.Error("unqualified deletion")
					}
					w.WriteHeader(204)
					return
				}
				if q.Get("prefix") != artifact.DownloadStopKey(l.RootID, l.DownloadID) {
					t.Error("prefix escaped")
				}
				switch {
				case q.Has("versions"):
					fmt.Fprint(w, "<ListVersionsResult>")
					if mode == "truncated" {
						fmt.Fprint(w, "<IsTruncated>true</IsTruncated>")
					} else {
						fmt.Fprint(w, "<IsTruncated>false</IsTruncated>")
					}
					if deletes.Load() == 0 || mode == "retained-marker" {
						fmt.Fprintf(w, "<Version><Key>%s</Key><VersionId>v1</VersionId></Version>", key)
					}
					fmt.Fprint(w, "</ListVersionsResult>")
				case q.Has("uploads"):
					fmt.Fprint(w, "<ListMultipartUploadsResult><IsTruncated>false</IsTruncated></ListMultipartUploadsResult>")
				case q.Has("list-type"):
					fmt.Fprint(w, "<ListBucketResult><IsTruncated>false</IsTruncated></ListBucketResult>")
				default:
					t.Error("unexpected request")
				}
			}))
			p := &DownloadStopCleanupObjects{producer: &ClosedDownloadStopObjects{store: store, storeID: operationTestID}}
			e := p.PurgeDownloadStopObjects(context.Background(), l)
			if mode == "original" || mode == "terminal" || mode == "overdue" {
				if e != nil || deletes.Load() != 1 {
					t.Fatal("qualified registered purge failed", e, deletes.Load())
				}
			} else if e == nil || (mode != "retained-marker" && deletes.Load() != 0) {
				t.Fatal("incomplete/foreign inventory erased or released", e, deletes.Load())
			}
		})
	}
}
