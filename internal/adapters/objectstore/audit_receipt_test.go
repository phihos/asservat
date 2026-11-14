package objectstore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"asservat.local/asservat/internal/domain/artifact"
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
