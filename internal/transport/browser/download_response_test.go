package browser

import (
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/identity"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func responseDeliveryFixture(size int64, selection artifact.DownloadSelection) (artifact.DownloadResponse, artifact.DownloadDeliveryLease) {
	now := time.Now().UTC()
	id := "11111111-1111-4111-8111-111111111111"
	scope := artifact.DownloadScope{RootID: id, ArtifactID: id, CaptureID: id, ClusterID: id, NamespaceUID: "ns", WorkloadUID: "app", PodUID: "pod", Version: artifact.Digest{1}, Principal: identity.Principal{Issuer: "https://id.invalid", Subject: "dev", ClientID: "browser", Kind: identity.Human}}
	a := artifact.DownloadAuthority{Scope: scope, PermissionEpoch: id, PermissionSequence: 1, ProjectionDigest: artifact.Digest{2}, DecisionDigest: artifact.Digest{3}, IdentityRevision: identity.Revision{UID: "policy", Generation: 1, Digest: [32]byte{4}}, CheckedAt: now, ValidUntil: now.Add(4 * time.Second), AccessUntil: now.Add(time.Minute)}
	r := artifact.DownloadResponse{ID: id, SessionID: id, OwnerID: id, Generation: 2, Plan: artifact.DownloadResponsePlan{Version: 1, Selection: selection, WholeFile: selection.Offset == 0 && selection.Length == size, WindowReadLimit: artifact.DownloadWindowBytes}, StartedAt: now, Until: now.Add(time.Minute)}
	l := artifact.DownloadDeliveryLease{ResponseID: id, WindowID: id, OwnerID: id, Generation: 2, Sequence: 1, Offset: selection.Offset, Length: selection.Length, StartedAt: now, Until: a.ValidUntil, Authority: a}
	return r, l
}
func TestNativeHTTPResponseMultipleChunksExactWholeHeaders(t *testing.T) {
	body := bytes.Repeat([]byte("synthetic!"), 250000)
	m := artifact.NativeDownloadMetadata{Filename: "native.core", ETag: `"version1"`, Size: int64(len(body)), SHA256: sha256.Sum256(body)}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		sel, e := ResolveDownloadSelection(m.Size, m.ETag, req.Header)
		if e != nil {
			http.Error(w, "invalid", DownloadConditionStatus(e))
			return
		}
		r, l := responseDeliveryFixture(m.Size, sel)
		sink, e := NewHTTPDownloadResponse(w, req, m, r)
		if e != nil {
			t.Error(e)
			return
		}
		defer sink.Close()
		ctx, cancel := context.WithDeadline(req.Context(), l.Until)
		defer cancel()
		for at := sel.Offset; at < sel.Offset+sel.Length; {
			n := min(artifact.DeliveryBytes, sel.Offset+sel.Length-at)
			if emitted, e := sink.WriteChunk(ctx, l, at, body[at:at+n]); e != nil || emitted != n {
				t.Errorf("chunk %d %v", emitted, e)
				return
			}
			at += n
		}
		if e = sink.Finish(ctx); e != nil {
			t.Error(e)
		}
	}))
	defer server.Close()
	for _, rangeHeader := range []string{"", "bytes=100-2100000"} {
		req, _ := http.NewRequest(http.MethodGet, server.URL, nil)
		req.Header.Set("If-Match", m.ETag)
		if rangeHeader != "" {
			req.Header.Set("Range", rangeHeader)
		}
		resp, e := server.Client().Do(req)
		if e != nil {
			t.Fatal(e)
		}
		got, e := io.ReadAll(resp.Body)
		resp.Body.Close()
		if e != nil {
			t.Fatal(e)
		}
		expected := body
		status := 200
		if rangeHeader != "" {
			expected = body[100:2100001]
			status = 206
			if resp.Header.Get("Content-Range") != "bytes 100-2100000/2500000" {
				t.Fatal(resp.Header)
			}
		}
		if resp.StatusCode != status || !bytes.Equal(got, expected) || resp.ContentLength != int64(len(expected)) || resp.Header.Get("ETag") != m.ETag || resp.Header.Get("Cache-Control") != "no-store, private" {
			t.Fatal("wrong whole response", resp.StatusCode, resp.Header, len(got))
		}
	}
}
func TestNativeHTTPResponseRejectsForeignLeaseAndIncompleteFinish(t *testing.T) {
	request := httptest.NewRequest("GET", "https://console.invalid/content", nil)
	request.TLS = &tls.ConnectionState{}
	writer := &responseDeadlineRecorder{ResponseRecorder: httptest.NewRecorder()}
	r, l := responseDeliveryFixture(3, artifact.DownloadSelection{Length: 3})
	m := artifact.NativeDownloadMetadata{Filename: "a.bin", ETag: `"v1"`, Size: 3}
	sink, e := NewHTTPDownloadResponse(writer, request, m, r)
	if e != nil {
		t.Fatal(e)
	}
	defer sink.Close()
	ctx, cancel := context.WithDeadline(request.Context(), l.Until)
	defer cancel()
	bad := l
	bad.Generation++
	if _, e = sink.WriteChunk(ctx, bad, 0, []byte("abc")); e == nil || sink.HeadersSent() {
		t.Fatal("foreign generation exposed metadata")
	}
	if _, e = sink.WriteChunk(ctx, l, 1, []byte("ab")); e == nil {
		t.Fatal("gap accepted")
	}
	if _, e = sink.WriteChunk(ctx, l, 0, []byte("a")); e != nil {
		t.Fatal(e)
	}
	if sink.Finish(ctx) == nil {
		t.Fatal("incomplete response finished")
	}
	if _, e = sink.WriteChunk(ctx, l, 0, []byte("a")); e == nil {
		t.Fatal("duplicate bytes accepted")
	}
	if _, e = sink.WriteChunk(ctx, l, 1, []byte("bc")); e != nil {
		t.Fatal(e)
	}
	if e = sink.Finish(ctx); e != nil {
		t.Fatal(e)
	}
	if _, e = sink.WriteChunk(ctx, l, 3, nil); e == nil {
		t.Fatal("finished response reopened")
	}
}

type responseDeadlineRecorder struct{ *httptest.ResponseRecorder }

func (*responseDeadlineRecorder) SetWriteDeadline(time.Time) error { return nil }
func TestNativeHTTPResponseJoinsCancellationDeadlineBeforeReturn(t *testing.T) {
	owner, cancel := context.WithCancel(context.Background())
	defer cancel()
	req := httptest.NewRequest("GET", "https://console.invalid/content", nil).WithContext(owner)
	req.TLS = &tls.ConnectionState{}
	writer := &blockedDownloadDeadlineWriter{ResponseRecorder: httptest.NewRecorder(), cancel: cancel, entered: make(chan struct{}), release: make(chan struct{})}
	r, l := responseDeliveryFixture(3, artifact.DownloadSelection{Length: 3})
	sink, e := NewHTTPDownloadResponse(writer, req, artifact.NativeDownloadMetadata{Filename: "x", ETag: `"v1"`, Size: 3}, r)
	if e != nil {
		t.Fatal(e)
	}
	ctx, stop := context.WithDeadline(owner, l.Until)
	defer stop()
	done := make(chan error, 1)
	go func() { _, e := sink.WriteChunk(ctx, l, 0, []byte("abc")); done <- e }()
	select {
	case <-writer.entered:
	case <-time.After(time.Second):
		t.Fatal("cancellation callback absent")
	}
	select {
	case <-done:
		t.Fatal("returned before deadline callback joined")
	case <-time.After(20 * time.Millisecond):
	}
	close(writer.release)
	select {
	case e := <-done:
		if e == nil {
			t.Fatal("cancelled write succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("callback join stuck")
	}
	sink.Close()
}
