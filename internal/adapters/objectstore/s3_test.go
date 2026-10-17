package objectstore

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"asservat.local/asservat/internal/domain/artifact"
	"github.com/aws/aws-sdk-go-v2/credentials"
)

func TestPinnedRangeRejectsChangedOrUnboundedResponse(t *testing.T) {
	for _, mode := range []string{"ok", "changed-etag", "ignored-range", "wrong-size", "wrong-version"} {
		t.Run(mode, func(t *testing.T) {
			s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Range") != "bytes=1-2" || r.Header.Get("If-Match") != `"pinned"` || r.URL.Query().Get("versionId") != "version-1" {
					t.Error("missing immutable read constraints")
				}
				w.Header().Set("ETag", `"pinned"`)
				w.Header().Set("X-Amz-Version-Id", "version-1")
				w.Header().Set("Content-Range", "bytes 1-2/4")
				if mode == "changed-etag" {
					w.Header().Set("ETag", `"other"`)
				}
				if mode == "ignored-range" {
					w.Header().Del("Content-Range")
				}
				if mode == "wrong-version" {
					w.Header().Set("X-Amz-Version-Id", "version-2")
				}
				if mode == "wrong-size" {
					w.Header().Set("Content-Length", "3")
					w.WriteHeader(206)
					w.Write([]byte("bcd"))
					return
				}
				w.Header().Set("Content-Length", "2")
				w.WriteHeader(206)
				w.Write([]byte("bc"))
			}))
			defer s.Close()
			store, err := New(s.URL, "us-east-1", "fixture", credentials.NewStaticCredentialsProvider("synthetic", "synthetic", ""), s.Client())
			if err != nil {
				t.Fatal(err)
			}
			p, err := store.Pin(Object{Key: "object", VersionID: "version-1", ETag: `"pinned"`, Bytes: 4})
			if err != nil {
				t.Fatal(err)
			}
			b, err := p.ReadRange(context.Background(), 1, 2)
			if mode == "ok" {
				if err != nil || string(b) != "bc" {
					t.Fatalf("exact range: %v", err)
				}
				return
			}
			if !errors.Is(err, artifact.ErrIntegrity) || len(b) != 0 {
				t.Fatalf("accepted changed response: %v", err)
			}
		})
	}
}
