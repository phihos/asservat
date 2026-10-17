package objectstore

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"asservat.local/asservat/internal/domain/artifact"
	"github.com/aws/aws-sdk-go-v2/credentials"
)

func TestPurgeRequiresCompleteConfinedInventory(t *testing.T) {
	loc := artifact.Location{ClusterID: "10000000-0000-4000-8000-000000000001", ArtifactID: "10000000-0000-4000-8000-000000000002", AttemptID: "10000000-0000-4000-8000-000000000003"}
	for _, mode := range []string{"denied", "delete-failed", "retained-marker", "foreign-key", "truncated", "oversized", "null-version"} {
		t.Run(mode, func(t *testing.T) {
			deletes, versionLists := 0, 0
			s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				q := r.URL.Query()
				w.Header().Set("Content-Type", "application/xml")
				if r.Method == http.MethodDelete {
					deletes++
					if mode == "delete-failed" {
						w.WriteHeader(503)
						fmt.Fprint(w, "<Error><Code>SlowDown</Code></Error>")
						return
					}
					if !q.Has("versionId") {
						t.Error("unversioned deletion creates marker")
					}
					if mode == "null-version" && q.Get("versionId") != "null" {
						t.Error("null version not pinned")
					}
					w.WriteHeader(204)
					return
				}
				if mode == "denied" {
					w.WriteHeader(403)
					fmt.Fprint(w, "<Error><Code>AccessDenied</Code></Error>")
					return
				}
				if q.Get("prefix") != loc.Prefix() {
					t.Error("wrong inventory scope")
				}
				if q.Has("versions") {
					versionLists++
					if mode == "oversized" {
						fmt.Fprint(w, "<ListVersionsResult><Prefix>"+strings.Repeat("x", 3<<20)+"</Prefix></ListVersionsResult>")
						return
					}
					fmt.Fprint(w, "<ListVersionsResult>")
					if mode == "truncated" {
						fmt.Fprint(w, "<IsTruncated>true</IsTruncated>")
					} else {
						fmt.Fprint(w, "<IsTruncated>false</IsTruncated>")
					}
					if mode == "retained-marker" || mode == "delete-failed" || mode == "foreign-key" {
						key := loc.Prefix() + "data"
						if mode == "foreign-key" {
							key = "v1/another-attempt/data"
						}
						fmt.Fprintf(w, "<DeleteMarker><Key>%s</Key><VersionId>marker</VersionId></DeleteMarker>", key)
					}
					fmt.Fprint(w, "</ListVersionsResult>")
					return
				}
				if q.Has("uploads") {
					fmt.Fprint(w, "<ListMultipartUploadsResult><IsTruncated>false</IsTruncated></ListMultipartUploadsResult>")
					return
				}
				if q.Has("list-type") {
					fmt.Fprint(w, "<ListBucketResult><IsTruncated>false</IsTruncated>")
					if mode == "null-version" && deletes == 0 {
						fmt.Fprintf(w, "<Contents><Key>%sdata</Key><Size>1</Size></Contents>", loc.Prefix())
					}
					fmt.Fprint(w, "</ListBucketResult>")
					return
				}
				t.Error("unexpected storage operation")
			}))
			defer s.Close()
			store, err := New(s.URL, "us-east-1", "fixture", credentials.NewStaticCredentialsProvider("synthetic", "synthetic", ""), s.Client())
			if err != nil {
				t.Fatal(err)
			}
			err = store.PurgeAttempt(context.Background(), loc)
			if mode == "null-version" {
				if err != nil || deletes != 1 || versionLists != 2 {
					t.Fatalf("exact null deletion: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("uncertain inventory certified deleted")
			}
			if mode == "foreign-key" && (!errors.Is(err, artifact.ErrIntegrity) || deletes != 0) {
				t.Fatal("foreign key reached deletion")
			}
			if mode == "retained-marker" && !errors.Is(err, artifact.ErrLimit) {
				t.Fatal(err)
			}
		})
	}
}
