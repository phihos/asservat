package objectstore

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	"github.com/aws/aws-sdk-go-v2/credentials"
)

// The backend deliberately moves latest immediately after the acknowledged PUT.
// Identical valid ciphertext at a new version must not change the receipt.
func TestOwnerAuditCreatePreservesAcknowledgedVersion(t *testing.T) {
	for _, mode := range []string{"original", "substituted", "exists", "unknown", "semantic-mismatch"} {
		t.Run(mode, func(t *testing.T) {
			var mu sync.Mutex
			puts, gets, verified := 0, 0, 0
			want := []byte("synthetic original ciphertext")
			existing := []byte("different ciphertext for the same synthetic record")
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				defer mu.Unlock()
				w.Header().Set("ETag", `"original"`)
				w.Header().Set("X-Amz-Version-Id", "original")
				if r.Method == http.MethodPut {
					puts++
					body, err := io.ReadAll(r.Body)
					if err != nil || !bytes.Equal(body, want) || r.Header.Get("If-None-Match") != "*" {
						t.Error("conditional write changed")
					}
					if mode == "exists" || mode == "semantic-mismatch" {
						w.WriteHeader(http.StatusPreconditionFailed)
					}
					if mode == "unknown" {
						w.WriteHeader(http.StatusServiceUnavailable)
					}
					return
				}
				gets++
				if r.Method != http.MethodGet {
					t.Error("unexpected method")
					w.WriteHeader(400)
					return
				}
				out := want
				if mode == "exists" || mode == "semantic-mismatch" {
					if r.URL.Query().Has("versionId") || r.Header.Get("If-Match") != "" {
						t.Error("conflict invented a successful PUT receipt")
					}
					out = existing
					w.Header().Set("ETag", `"existing"`)
					w.Header().Set("X-Amz-Version-Id", "existing")
				} else if r.URL.Query().Get("versionId") != "original" || r.Header.Get("If-Match") != `"original"` || mode == "substituted" {
					w.Header().Set("X-Amz-Version-Id", "replacement")
				}
				w.Header().Set("Content-Length", fmt.Sprint(len(out)))
				_, _ = w.Write(out)
			}))
			defer server.Close()
			store, err := NewVersionedAudit(server.URL, "test", "audit", credentials.NewStaticCredentialsProvider("synthetic", "synthetic", ""), server.Client())
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			writer := OwnerEnrollmentAuditObjects{Store: store}
			receipt, err := writer.write(context.Background(), "synthetic-audit", want, func(b []byte) error {
				verified++
				expected := want
				if mode == "exists" {
					expected = existing
				}
				if !bytes.Equal(b, expected) {
					return artifact.ErrIntegrity
				}
				return nil
			})
			switch mode {
			case "original":
				if err != nil || receipt.Version != "original" {
					t.Fatal("OWNER_PUT_RECEIPT_REPLACED", err, receipt.Version)
				}
			case "exists":
				if err != nil || receipt.Version != "existing" || verified != 1 {
					t.Fatal("semantic conflict reconciliation lost", err, receipt.Version, verified)
				}
			default:
				if err == nil || receipt != (audit.Receipt{}) {
					t.Fatal("OWNER_PUT_SUBSTITUTION_ACCEPTED", mode, receipt.Version)
				}
			}
			mu.Lock()
			defer mu.Unlock()
			if puts != 1 || mode == "unknown" && (gets != 0 || verified != 0) || mode != "unknown" && gets != 1 {
				t.Fatal("unknown write retried/reconciled", puts, gets, verified)
			}
			if mode == "substituted" && verified != 0 {
				t.Fatal("replacement reached semantic verification")
			}
		})
	}
}

func TestDownloadWindowReadUsesPositiveVersionAndFindStaysReadOnly(t *testing.T) {
	var mu sync.Mutex
	var body []byte
	var methods []string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		methods = append(methods, r.Method)
		w.Header().Set("ETag", `"original"`)
		w.Header().Set("X-Amz-Version-Id", "original")
		if r.Method == http.MethodPut {
			body, _ = io.ReadAll(r.Body)
			return
		}
		if r.Method != http.MethodGet {
			t.Error("unexpected method")
			w.WriteHeader(400)
			return
		}
		if len(methods) == 2 && (r.URL.Query().Get("versionId") != "original" || r.Header.Get("If-Match") != `"original"`) {
			w.Header().Set("X-Amz-Version-Id", "replacement")
		}
		if len(methods) == 3 && (r.URL.Query().Has("versionId") || r.Header.Get("If-Match") != "") {
			t.Error("Find fabricated a prior receipt")
		}
		w.Header().Set("Content-Length", fmt.Sprint(len(body)))
		_, _ = w.Write(body)
	}))
	defer server.Close()
	store, err := NewVersionedAudit(server.URL, "test", "audit", credentials.NewStaticCredentialsProvider("synthetic", "synthetic", ""), server.Client())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	intent := windowAuditFixture()
	writer, err := NewDownloadWindowAuditObjects(store, intent.Window.AuditStoreID, windowTestKeys{}, windowTestKeys{})
	if err != nil {
		t.Fatal(err)
	}
	result, err := writer.CreateDownloadWindowIntent(context.Background(), intent)
	if err != nil || result.Completion == nil || result.Receipt.Version != "original" {
		t.Fatal("WINDOW_POSITIVE_VERSION_NOT_SELECTED", err)
	}
	receipt, err := writer.FindDownloadWindowIntent(context.Background(), intent)
	if err != nil || receipt != result.Receipt {
		t.Fatal("read-only reconciliation changed", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if fmt.Sprint(methods) != "[PUT GET GET]" {
		t.Fatal("find wrote or retried", methods)
	}
}

func TestControlAuditRejectsOversizedInputBeforeWrite(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("invalid input performed I/O")
		w.WriteHeader(500)
	}))
	defer server.Close()
	store, err := NewVersionedAudit(server.URL, "test", "audit", credentials.NewStaticCredentialsProvider("synthetic", "synthetic", ""), server.Client())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	for _, maximum := range []int64{0, 2, MaxSmallObject + 1} {
		if _, _, err := store.putControlAudit(context.Background(), "synthetic", []byte("four"), maximum); err == nil {
			t.Fatal("invalid size accepted", maximum)
		}
	}
}
