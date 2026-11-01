package objectstore

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
)

// This uses the actual regional adapter's admission logic. Constructor-only
// TLS input is synthetic; no key request is made and no key authority is claimed.
func TestNativeResponseReaderSeparatesShortOpeningFromConversation(t *testing.T) {
	_, expectation, _ := writerFixture(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Error("unexpected storage I/O during opener admission")
		w.WriteHeader(http.StatusInternalServerError)
	}))
	var copies artifact.Copies
	for i := range copies {
		copies[i] = artifact.CopyReceipt{ETag: "synthetic", Bytes: 128, SHA256: artifact.Digest{byte(i + 1)}}
	}
	source := evidence.NativeContextSource{Expectation: expectation, Copies: copies}
	id := expectation.Registration.Location.ClusterID
	scope := value.KeyScope{InstallationID: id, Purpose: "artifact", KeyID: "synthetic"}
	reader := &NativeContextReader{scope: scope, endpoint: "https://keys.invalid", client: &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{Certificates: []tls.Certificate{{}}}}}}
	now := time.Now()
	operation := value.NativeOperation{Reference: value.NativeReference{InstallationID: id, SessionID: id, WorkerID: id, OperationID: id, Fence: 1}, Kind: value.NativeResponse, HubPodUID: id, HubProcessEpoch: id, WorkerPodUID: id, WorkerPublicKey: artifact.Digest{1}, SourceVersion: evidence.ContextCopiesDigest(copies), ParentID: id, Generation: 1, StartedAt: now, Until: now.Add(20 * time.Second)}
	owner, cancel := context.WithDeadline(t.Context(), operation.Until)
	defer cancel()
	before := time.Now()
	end, opener, err := reader.opener(owner, source, operation, id, operation.Until)
	if err != nil {
		t.Fatal("valid fixed response conversation rejected before key I/O", err)
	}
	opener.Close()
	if end.After(before.Add(5*time.Second+time.Millisecond)) || !end.Before(operation.Until) {
		t.Fatal("opening phase inherited response lifetime", end, operation.Until)
	}
	operation.Kind = value.NativePrepare
	operation.Until = now.Add(4 * time.Second)
	if _, opener, err = reader.opener(owner, source, operation, "", operation.Until); err == nil {
		opener.Close()
		t.Fatal("preparation opening accepted response lifetime")
	}
}

// Actual framed encryption/pinned HTTP object reads, synthetic key wrapping.
// The initial key phase is short; canceling it cannot kill the retained cursor.
type responseOpeningKeys struct {
	t     *testing.T
	until time.Time
	opens int
}

func (k *responseOpeningKeys) Open(ctx context.Context, s artifact.SealedKey, _ []byte) ([]byte, error) {
	k.opens++
	if d, ok := ctx.Deadline(); !ok || d.After(k.until) || ctx.Err() != nil {
		k.t.Error("key opening escaped original short phase")
	}
	return base64.StdEncoding.DecodeString(s.Ciphertext)
}
func TestNativeFramedCursorOutlivesJoinedShortOpening(t *testing.T) {
	for _, cause := range []string{"owner", "caller"} {
		t.Run(cause, func(t *testing.T) { nativeFramedCursorCancellation(t, cause) })
	}
}

func nativeFramedCursorCancellation(t *testing.T, cause string) {
	t.Helper()
	var blockNext atomic.Bool
	releaseRead := make(chan struct{})
	var mu sync.Mutex
	objects := map[string][]byte{}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && blockNext.CompareAndSwap(true, false) {
			<-releaseRead
		}
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
		b, ok := objects[r.URL.Path]
		var from, to int
		if r.Method != http.MethodGet || !ok {
			w.WriteHeader(404)
			return
		}
		if _, err := fmt.Sscanf(r.Header.Get("Range"), "bytes=%d-%d", &from, &to); err != nil || from < 0 || to < from || to >= len(b) || r.Header.Get("If-Match") != `"pinned"` {
			w.WriteHeader(400)
			return
		}
		w.Header().Set("ETag", `"pinned"`)
		w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", from, to, len(b)))
		w.Header().Set("Content-Length", strconv.Itoa(to-from+1))
		w.WriteHeader(206)
		_, _ = w.Write(b[from : to+1])
	})
	handle, e, native := writerFixture(t, handler)
	var doc struct{ ObservedAt time.Time }
	if err := json.Unmarshal(native, &doc); err != nil {
		t.Fatal(err)
	}
	copies, err := handle.StoreContext(t.Context(), native, doc.ObservedAt, doc.ObservedAt)
	if err != nil {
		t.Fatal(err)
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
	owner, cancelOwner := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancelOwner()
	opening, cancelOpening := context.WithTimeout(owner, 5*time.Second)
	until, _ := owner.Deadline()
	keyUntil, _ := opening.Deadline()
	keys := &responseOpeningKeys{t: t, until: keyUntil}
	verifier, err := NewContextVerifier(bound, keys)
	if err != nil {
		t.Fatal(err)
	}
	cursor, err := verifier.openNative(owner, opening, e, copies, until)
	if err != nil {
		t.Fatal(err)
	}
	defer cursor.Close()
	cancelOpening()
	// Loading an authenticated frame belongs to the original owner. A short
	// observation can expire while the object read blocks; delivery must then
	// acquire a fresh lease, rather than reopening keys or discarding the cursor.
	piece, cancelPiece := context.WithTimeout(owner, 100*time.Millisecond)
	defer cancelPiece()
	blockNext.Store(true)
	go func() {
		<-piece.Done()
		close(releaseRead)
	}()
	got, final, err := cursor.ReadNext(piece, 0, 1)
	defer clear(got)
	if err != nil || !final || !bytes.Equal(got, native[:1]) || keys.opens != 3 || piece.Err() != context.DeadlineExceeded || blockNext.Load() {
		t.Fatal("owned frame load lost cursor at short observation expiry", err, final, keys.opens, piece.Err())
	}
	// A live owner can read the next contiguous byte from the authenticated
	// carry. Cancellation must refuse that same otherwise-valid operation.
	next, _, err := cursor.ReadNext(owner, 1, 1)
	defer clear(next)
	if err != nil || !bytes.Equal(next, native[1:2]) {
		t.Fatal("live contiguous read refused", err)
	}
	checked := owner
	if cause == "owner" {
		cancelOwner()
	} else {
		var cancelCall context.CancelFunc
		checked, cancelCall = context.WithCancel(owner)
		cancelCall()
	}
	if leaked, _, err := cursor.ReadNext(checked, 2, 1); err == nil {
		clear(leaked)
		t.Fatal("cursor escaped explicit cancellation", cause)
	}
	if !cursor.closed || len(cursor.carry) != 0 || keys.opens != 3 {
		t.Fatal("canceled cursor retained plaintext or reopened keys", cause)
	}
}
