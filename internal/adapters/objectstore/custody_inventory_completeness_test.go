package objectstore

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"asservat.local/asservat/internal/domain/artifact"
	"github.com/aws/aws-sdk-go-v2/credentials"
)

// Exercise the real TLS transport and AWS XML decoder: an omitted Boolean must
// not become false and thereby certify deletion. The initial scan contains both
// a version and an upload; the independent final scan follows their exact removal.
func TestPurgeRejectsOmittedInventoryCompleteness(t *testing.T) {
	location := artifact.Location{ClusterID: "10000000-0000-4000-8000-000000000001", ArtifactID: "10000000-0000-4000-8000-000000000002", AttemptID: "10000000-0000-4000-8000-000000000003"}
	for _, phase := range []string{"initial", "final"} {
		for index, api := range []string{"versions", "uploads", "current"} {
			t.Run(phase+"/"+api, func(t *testing.T) {
				var mu sync.Mutex
				scans, lists, deletes, aborts := 0, 0, 0, 0
				key, uploadKey := location.Prefix()+"data", location.Prefix()+"manifest"
				server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					mu.Lock()
					defer mu.Unlock()
					w.Header().Set("Content-Type", "application/xml")
					q := r.URL.Query()
					if r.Method == http.MethodDelete {
						switch {
						case q.Get("uploadId") == "pending" && !q.Has("versionId") && strings.HasSuffix(r.URL.Path, "/"+uploadKey):
							aborts++
						case q.Get("versionId") == "v1" && !q.Has("uploadId") && strings.HasSuffix(r.URL.Path, "/"+key):
							deletes++
						default:
							t.Error("unexpected or unqualified mutation")
							w.WriteHeader(http.StatusBadRequest)
							return
						}
						w.WriteHeader(http.StatusNoContent)
						return
					}
					if r.Method != http.MethodGet || q.Get("prefix") != location.Prefix() {
						t.Error("inventory escaped original request/prefix")
						w.WriteHeader(http.StatusBadRequest)
						return
					}
					var name, root string
					switch {
					case q.Has("versions"):
						scans++
						name, root = "versions", "ListVersionsResult"
					case q.Has("uploads"):
						name, root = "uploads", "ListMultipartUploadsResult"
					case q.Get("list-type") == "2":
						name, root = "current", "ListBucketResult"
					default:
						t.Error("unexpected LIST API")
						w.WriteHeader(http.StatusBadRequest)
						return
					}
					lists++
					fmt.Fprintf(w, "<%s>", root)
					malformed := name == api && ((phase == "initial" && scans == 1) || (phase == "final" && scans == 2))
					if !malformed {
						fmt.Fprint(w, "<IsTruncated>false</IsTruncated>")
					}
					switch {
					case name == "versions" && deletes == 0:
						fmt.Fprintf(w, "<Version><Key>%s</Key><VersionId>v1</VersionId></Version>", key)
					case name == "uploads" && aborts == 0:
						fmt.Fprintf(w, "<Upload><Key>%s</Key><UploadId>pending</UploadId></Upload>", uploadKey)
					case name == "current" && deletes == 0:
						fmt.Fprintf(w, "<Contents><Key>%s</Key><Size>1</Size></Contents>", key)
					}
					fmt.Fprintf(w, "</%s>", root)
				}))
				defer server.Close()
				store, err := New(server.URL, "us-east-1", "fixture", credentials.NewStaticCredentialsProvider("synthetic", "synthetic", ""), server.Client())
				if err != nil {
					t.Fatal(err)
				}
				err = store.PurgeAttempt(context.Background(), location)
				mu.Lock()
				gotLists, gotDeletes, gotAborts := lists, deletes, aborts
				mu.Unlock()
				if !errors.Is(err, artifact.ErrIntegrity) {
					t.Fatalf("omitted IsTruncated certified absence or wrong failure: phase=%s api=%s err=%v deletes=%d aborts=%d", phase, api, err, gotDeletes, gotAborts)
				}
				wantLists, wantEffects := index+1, 0
				if phase == "final" {
					wantLists += 3
					wantEffects = 1
				}
				if gotLists != wantLists || gotDeletes != wantEffects || gotAborts != wantEffects {
					t.Fatalf("continued after malformed inventory: lists=%d want=%d deletes=%d aborts=%d want-each=%d", gotLists, wantLists, gotDeletes, gotAborts, wantEffects)
				}
			})
		}
	}
}
