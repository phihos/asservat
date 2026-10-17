package objectstore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	"asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	"github.com/aws/aws-sdk-go-v2/credentials"
)

func TestAcknowledgedAuditReadPinsOriginalVersionWithoutFallback(t *testing.T) {
	for _, mode := range []string{"latest-replaced", "missing-original", "wrong-version", "null-version", "missing-version", "wrong-etag", "wrong-length", "wrong-body", "canceled"} {
		t.Run(mode, func(t *testing.T) {
			body := []byte("synthetic original ciphertext")
			expected := Object{Key: "audit-record", VersionID: "original", ETag: `"original"`, Bytes: int64(len(body)), SHA256: artifact.Digest(sha256.Sum256(body))}
			var calls atomic.Int32
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if r.Method != http.MethodGet || r.URL.Query().Get("versionId") != "original" || r.Header.Get("If-Match") != expected.ETag || r.Header.Get("Range") != "" {
					t.Error("ACKNOWLEDGED_VERSION_NOT_SELECTED")
					w.WriteHeader(http.StatusPreconditionFailed)
					return
				}
				if mode == "missing-original" {
					w.WriteHeader(http.StatusNotFound)
					return
				}
				w.Header().Set("ETag", expected.ETag)
				w.Header().Set("X-Amz-Version-Id", "original")
				out := bytes.Clone(body)
				switch mode {
				case "wrong-version":
					w.Header().Set("X-Amz-Version-Id", "latest")
				case "null-version":
					w.Header().Set("X-Amz-Version-Id", "null")
				case "missing-version":
					w.Header().Del("X-Amz-Version-Id")
				case "wrong-etag":
					w.Header().Set("ETag", `"replacement"`)
				case "wrong-length":
					out = append(out, '!')
				case "wrong-body":
					out[0] ^= 1
				case "canceled":
					cancel()
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
			got, content, err := store.readAcknowledgedControlAudit(ctx, expected, 1024)
			if mode == "latest-replaced" {
				if err != nil || got != expected || !bytes.Equal(content, body) {
					t.Fatal("ORIGINAL_AUDIT_VERSION_UNAVAILABLE", err)
				}
			} else if err == nil || got != (Object{}) || content != nil {
				t.Fatal("substituted or canceled original read accepted")
			}
			if calls.Load() != 1 {
				t.Fatal("read retried or selected latest after failure", calls.Load())
			}
		})
	}
}

func TestInitialAuditAcknowledgesTheSuccessfulPUTVersion(t *testing.T) {
	for _, mode := range []string{"original", "substituted-response", "unknown-put"} {
		t.Run(mode, func(t *testing.T) {
			var mu sync.Mutex
			var stored []byte
			var puts, gets int
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				mu.Lock()
				defer mu.Unlock()
				w.Header().Set("ETag", `"original"`)
				w.Header().Set("X-Amz-Version-Id", "original")
				if req.Method == http.MethodPut {
					puts++
					if req.Header.Get("If-None-Match") != "*" {
						t.Error("conditional creation lost")
					}
					stored, _ = io.ReadAll(req.Body)
					if mode == "unknown-put" {
						w.WriteHeader(http.StatusServiceUnavailable)
					}
					return
				}
				gets++
				if req.Method != http.MethodGet {
					t.Error("unexpected method", req.Method)
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				if req.URL.Query().Get("versionId") != "original" || mode == "substituted-response" {
					// A new latest version can contain the same valid envelope. The
					// original positive PUT still selects only the original version.
					w.Header().Set("X-Amz-Version-Id", "replacement")
				}
				w.Header().Set("Content-Length", fmt.Sprint(len(stored)))
				_, _ = w.Write(stored)
			}))
			defer server.Close()
			store, err := NewVersionedAudit(server.URL, "test", "audit", credentials.NewStaticCredentialsProvider("synthetic", "synthetic", ""), server.Client())
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			id := "10000000-0000-4000-8000-000000000031"
			now := time.Now().UTC().Truncate(time.Microsecond)
			r := audit.InitialInstallation{Scope: fleet.InstallationWitnessScope{InstallationID: id, IssuerEpoch: id, ClusterID: id, Namespace: "control", NamespaceUID: id, Name: "witness", UID: id, WriterAccount: "installer", WriterAccountUID: id}, Claim: fleet.InitialActivationClaim{ID: id, Database: fleet.DatabaseIncarnation{StartedAt: now.Add(-time.Minute), DatabaseOID: 10, SchemaVersion: 32}, FleetSource: identity.Revision{UID: "fleet", Generation: 1, Digest: artifact.Digest{1}}, PlanDigest: artifact.Digest{2}, NotBefore: now, NotAfter: now.Add(time.Minute)}}
			writer := InitialInstallationObjects{Store: store, Seal: windowTestKeys{}, Open: windowTestKeys{}}
			receipt, err := writer.WriteInitialInstallation(context.Background(), r)
			if mode == "original" {
				if err != nil || receipt.Version != "original" {
					t.Fatal("INITIAL_PUT_RECEIPT_WAS_NOT_PRESERVED", err, receipt.Version)
				}
			} else if err == nil || receipt != (audit.Receipt{}) {
				t.Fatal("INITIAL_PUT_VERSION_SUBSTITUTED", receipt.Version)
			}
			mu.Lock()
			defer mu.Unlock()
			if puts != 1 || mode == "unknown-put" && gets != 0 || mode != "unknown-put" && gets != 1 {
				t.Fatal("unknown effect retried or reconciled", puts, gets)
			}
		})
	}
}
