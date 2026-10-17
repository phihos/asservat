package objectstore

import (
	auditapp "asservat.local/asservat/internal/application/audit"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	"asservat.local/asservat/internal/domain/identity"
	"context"
	"encoding/base64"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"
)

func windowAuditFixture() audit.DownloadWindowIntent {
	now := time.Now().UTC().Truncate(time.Microsecond)
	id := "11111111-1111-4111-8111-111111111111"
	scope := artifact.DownloadScope{RootID: id, ArtifactID: id, CaptureID: id, ClusterID: id, NamespaceUID: "ns", WorkloadUID: "app", PodUID: "pod", Version: artifact.Digest{1}, Principal: identity.Principal{Issuer: "https://id.invalid", Subject: "dev", ClientID: "browser", Kind: identity.Human}}
	a := artifact.DownloadAuthority{Scope: scope, PermissionEpoch: id, PermissionSequence: 1, ProjectionDigest: artifact.Digest{2}, DecisionDigest: artifact.Digest{3}, IdentityRevision: identity.Revision{UID: "policy", Generation: 1, Digest: [32]byte{4}}, CheckedAt: now, ValidUntil: now.Add(5 * time.Second), AccessUntil: now.Add(time.Minute)}
	r := artifact.DownloadResponse{ID: id, SessionID: id, OwnerID: id, Generation: 2, Plan: artifact.DownloadResponsePlan{Version: 1, Selection: artifact.DownloadSelection{Length: 100}, WholeFile: true, WindowReadLimit: 1024}, StartedAt: now, Until: now.Add(time.Minute), WindowCount: 1, ActiveWindowID: id}
	w := artifact.DownloadWindow{ID: id, ResponseID: id, SessionID: id, OwnerID: id, AuditStoreID: id, Generation: 2, Ordinal: 1, Length: 100, ReadLimit: 1024, StartedAt: now, WriteUntil: now.Add(2 * time.Minute), Authority: a}
	return audit.DownloadWindowIntent{Response: r, Window: w}
}

type windowTestKeys struct{ contextWriterTestKeys }

func (windowTestKeys) Open(_ context.Context, k artifact.SealedKey, _ []byte) ([]byte, error) {
	return base64.StdEncoding.DecodeString(k.Ciphertext)
}
func TestDownloadWindowWriterRequiresFirstPutExactReadAndNoUnknownRetry(t *testing.T) {
	for _, mode := range []string{"ok", "exists", "uncertain", "changed", "corrupt", "missing"} {
		t.Run(mode, func(t *testing.T) {
			var mu sync.Mutex
			var body []byte
			puts, gets := 0, 0
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				defer mu.Unlock()
				w.Header().Set("ETag", `"pinned"`)
				w.Header().Set("X-Amz-Version-Id", "v1")
				if r.Method == http.MethodPut {
					puts++
					if r.Header.Get("If-None-Match") != "*" {
						t.Error("nonconditional PUT")
					}
					body, _ = io.ReadAll(r.Body)
					if mode == "exists" {
						w.WriteHeader(412)
					} else if mode == "uncertain" {
						w.WriteHeader(503)
					}
					return
				}
				gets++
				if mode == "missing" {
					w.WriteHeader(404)
					return
				}
				if mode == "changed" {
					w.Header().Set("ETag", `"other"`)
				}
				b := append([]byte(nil), body...)
				if mode == "corrupt" {
					b[len(b)-1] ^= 1
				}
				w.Header().Set("Content-Length", strconv.Itoa(len(b)))
				w.Write(b)
			}))
			defer srv.Close()
			store, e := New(srv.URL, "us-east-1", "fixture", credentials.NewStaticCredentialsProvider("synthetic", "synthetic", ""), srv.Client())
			if e != nil {
				t.Fatal(e)
			}
			i := windowAuditFixture()
			objects, e := NewDownloadWindowAuditObjects(store, i.Window.AuditStoreID, windowTestKeys{}, windowTestKeys{})
			if e != nil {
				t.Fatal(e)
			}
			result, e := objects.CreateDownloadWindowIntent(context.Background(), i)
			if mode == "ok" {
				if e != nil || result.Completion == nil || !result.Completion.Valid(i, nil) {
					t.Fatal("first write did not close", e)
				}
				bad := *result.Completion
				bad.RecordDigest[0]++
				if auditapp.ValidDownloadWindowCompletion(bad, i, nil) {
					t.Fatal("changed record digest accepted")
				}
				receipt, e := objects.FindDownloadWindowIntent(context.Background(), i)
				if e != nil || receipt != result.Receipt {
					t.Fatal("read-only receipt", e)
				}
			} else if e == nil || result.Completion != nil {
				t.Fatal("unknown or wrong writer closed", e)
			}
			mu.Lock()
			defer mu.Unlock()
			if puts != 1 {
				t.Fatal("automatic conditional write retry", puts)
			}
			if (mode == "exists" || mode == "uncertain") && gets != 0 {
				t.Fatal("failed PUT adopted through GET")
			}
		})
	}
}
