package objectstore

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"

	"asservat.local/asservat/internal/application/evidence"
	value "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
	"github.com/aws/aws-sdk-go-v2/credentials"
)

type projectionTestOpener struct{ calls int }

func (k *projectionTestOpener) Open(_ context.Context, s artifact.SealedKey, _ []byte) ([]byte, error) {
	k.calls++
	return base64.StdEncoding.DecodeString(s.Ciphertext)
}

// Actual product framing/manifest/crypto are exercised against an owned TLS
// object fixture. Synthetic key wrapping and HTTP receipts are not native S3,
// query authority or private worker qualification.
func TestProjectionReaderVerifiesEntirePinnedSourceBeforeTypedOutput(t *testing.T) {
	var mu sync.Mutex
	objects := map[string][]byte{}
	changed := ""
	requests := 0
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if r.Method == http.MethodPut {
			b, err := io.ReadAll(r.Body)
			if err != nil {
				t.Error(err)
				w.WriteHeader(500)
				return
			}
			objects[r.URL.Path] = b
			w.Header().Set("ETag", `"pinned"`)
			w.WriteHeader(200)
			return
		}
		requests++
		b, ok := objects[r.URL.Path]
		if r.Method != http.MethodGet || !ok {
			w.WriteHeader(404)
			return
		}
		var from, to int
		if _, err := fmt.Sscanf(r.Header.Get("Range"), "bytes=%d-%d", &from, &to); err != nil || from < 0 || to < from || to >= len(b) || r.Header.Get("If-Match") != `"pinned"` {
			t.Error("unpinned read")
			w.WriteHeader(400)
			return
		}
		out := bytes.Clone(b[from : to+1])
		defer clear(out)
		if r.URL.Path == changed {
			out[0] ^= 1
		}
		w.Header().Set("ETag", `"pinned"`)
		w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", from, to, len(b)))
		w.Header().Set("Content-Length", strconv.Itoa(len(out)))
		w.WriteHeader(206)
		_, _ = w.Write(out)
	})
	handle, e, native := writerFixture(t, handler)
	var doc struct{ ObservedAt time.Time }
	if err := json.Unmarshal(native, &doc); err != nil {
		t.Fatal(err)
	}
	now := doc.ObservedAt
	copies, err := handle.StoreContext(context.Background(), native, now, now)
	if err != nil {
		t.Fatal("prepare stored source", err)
	}
	if _, err = handle.CompleteStored(); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(handler)
	defer server.Close()
	store, err := New(server.URL, "us-east-1", "fixture", credentials.NewStaticCredentialsProvider("synthetic", "synthetic", ""), server.Client())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	bound, err := store.ForCustody(e.Registration.StoreID)
	if err != nil {
		t.Fatal(err)
	}
	reader, err := NewContextProjectionReader(bound)
	if err != nil {
		t.Fatal(err)
	}
	source := evidence.NativeContextSource{Expectation: e, Copies: copies}
	scope := testProjectionScope()
	scope.CaseID, scope.CaptureID = e.CaseID, e.CaptureUID
	scope.ArtifactID, scope.ClusterID = e.Registration.Location.ArtifactID, e.Registration.Location.ClusterID
	scope.NamespaceUID, scope.WorkloadUID, scope.PodUID = e.NamespaceUID, e.WorkloadUID, e.PodUID
	scope.Version = evidence.ContextCopiesDigest(copies)
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	until, _ := ctx.Deadline()
	keys := &projectionTestOpener{}
	p, err := reader.ReadProjectionNative(ctx, source, scope, keys, until)
	if err != nil || !p.Valid() || p.PodUID != e.PodUID || p.ResourceVersion != "1" || keys.calls != 3 {
		t.Fatal("full verified projection", p, err, keys.calls)
	}
	for role := 0; role < 4; role++ {
		t.Run(artifact.Role(role), func(t *testing.T) {
			mu.Lock()
			changed = "/fixture/" + e.Registration.Location.Prefix() + artifact.Role(role)
			mu.Unlock()
			p, err := reader.ReadProjectionNative(ctx, source, scope, &projectionTestOpener{}, until)
			if err == nil || p != (value.PodStatusProjection{}) {
				t.Fatal("tampered pinned source released projection")
			}
		})
	}
	mu.Lock()
	changed = ""
	before := requests
	mu.Unlock()
	for _, mutate := range []func(*evidence.NativeContextSource, *value.ContextProjectionScope){
		func(s *evidence.NativeContextSource, _ *value.ContextProjectionScope) {
			s.Expectation.CaseID = scope.RootID
		},
		func(_ *evidence.NativeContextSource, s *value.ContextProjectionScope) { s.Version[0]++ },
		func(s *evidence.NativeContextSource, _ *value.ContextProjectionScope) {
			s.Expectation.Registration.NativeLimit++
		},
	} {
		s, c := source, scope
		mutate(&s, &c)
		if _, err := reader.ReadProjectionNative(ctx, s, c, keys, until); err == nil {
			t.Fatal("source swap accepted")
		}
	}
	mu.Lock()
	after := requests
	mu.Unlock()
	if after != before {
		t.Fatal("invalid source performed object I/O")
	}
	if _, err = reader.ReadProjectionNative(context.Background(), source, scope, keys, until); err == nil {
		t.Fatal("unbounded read accepted")
	}
}
