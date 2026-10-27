package native_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"io"
	"mime"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/transport/browser"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

// syntheticPCAPNG writes a deterministic synthetic PCAPNG of at least size
// bytes: one Ethernet interface (128-byte snapshot) and 96-byte pseudo-random
// header records. No real traffic.
func syntheticPCAPNG(t *testing.T, size int) []byte {
	t.Helper()
	var b bytes.Buffer
	w, err := pcapgo.NewNgWriterInterface(&b, pcapgo.NgInterface{Name: "pod", LinkType: layers.LinkTypeEthernet, SnapLength: 128}, pcapgo.DefaultNgWriterOptions)
	if err != nil {
		t.Fatal(err)
	}
	record := make([]byte, 96)
	at := time.Unix(1_700_000_000, 0)
	for i := uint32(1); b.Len() < size; i++ {
		for j := range record {
			record[j] = byte(i*31 + uint32(j)*7)
		}
		if err = w.WritePacket(gopacket.CaptureInfo{Timestamp: at.Add(time.Duration(i) * time.Millisecond), CaptureLength: len(record), Length: len(record)}, record); err != nil {
			t.Fatal(err)
		}
		if i%1024 == 0 {
			_ = w.Flush()
		}
	}
	if err = w.Flush(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

// pcapngSourceValue is a synthetic stored PCAPNG ongoing save (ADR-244) within
// the installed download bound (ADR-248: one 8 MiB frame).
func pcapngSourceValue(t *testing.T) evidence.NativeContextSource {
	s := flowSourceValue(t)
	e := &s.Expectation
	now := e.TriggeredAt
	e.ExecutionClass = artifact.ContextNodeExecution
	e.NativeType = artifact.PCAPNGArtifact
	e.NodeUID, e.NodeBootID = "synthetic-node-uid", nativeID
	e.ActionID = "a0123456789abcdef01234567"
	e.Registration.NativeLimit = artifact.RemoteNativeLimit
	e.TriggeredAt = now.Add(-20 * time.Second)
	e.Lifecycle = &artifact.OngoingLifecycle{TriggerKind: "policy", SourceSessionID: nativeID, SourceStartedAt: now.Add(-2 * time.Minute), SnapshotID: nativeID, RequestedBefore: 30 * time.Second, After: 10 * time.Second, HistoryCoverage: "full", GapReasons: []string{}, WindowCoverage: "full"}
	if err := e.Validate(); err != nil {
		t.Fatal("synthetic pcapng expectation", err)
	}
	if !s.Valid(evidence.ContextCopiesDigest(s.Copies)) {
		t.Fatal("invalid pcapng source")
	}
	return s
}

func pcapngMetadata(s evidence.NativeContextSource, body []byte) artifact.NativeDownloadMetadata {
	e := s.Expectation
	ty := e.Type()
	return artifact.NativeDownloadMetadata{Filename: ty.Filename(e.Registration.Location.ArtifactID), Format: ty.Format, ETag: evidence.NativeETag(evidence.ContextCopiesDigest(s.Copies)), Coverage: ty.CoverageFor(e.Lifecycle), Size: int64(len(body)), SHA256: sha256.Sum256(body), ReadUntil: e.Registration.ExpiresAt, DeleteBy: e.Registration.DeleteBy}
}

// pcapngReader stands in for the regional object reader: it serves the stored
// bytes through the framed-source port and refuses the pod-status port.
type pcapngReader struct {
	source evidence.NativeContextSource
	body   []byte
	opens  atomic.Int32
	reads  atomic.Int32
}

func (r *pcapngReader) ReadNativeContext(context.Context, evidence.NativeContextSource, value.NativeOperation, string, time.Time) ([]byte, error) {
	return nil, artifact.ErrInvalid
}
func (r *pcapngReader) OpenNativeArtifact(ctx context.Context, s evidence.NativeContextSource, o value.NativeOperation, window string, until time.Time) (evidence.NativeArtifactSource, error) {
	if ctx.Err() != nil || s.Expectation.NativeType != artifact.PCAPNGArtifact || o.Kind == value.NativeResponse && !value.UUID(window) {
		return nil, artifact.ErrInvalid
	}
	r.opens.Add(1)
	return &pcapngArtifact{r: r, m: pcapngMetadata(r.source, r.body), next: -1}, nil
}

type pcapngArtifact struct {
	r    *pcapngReader
	m    artifact.NativeDownloadMetadata
	next int64
}

func (a *pcapngArtifact) Metadata() artifact.NativeDownloadMetadata { return a.m }
func (a *pcapngArtifact) ReadNext(ctx context.Context, offset, length int64) ([]byte, bool, error) {
	if ctx.Err() != nil || a.next >= 0 && offset != a.next || length < 1 || length > artifact.DeliveryBytes || offset+length > a.m.Size {
		return nil, false, artifact.ErrDownloadUnavailable
	}
	a.r.reads.Add(1)
	a.next = offset + length
	return append([]byte(nil), a.r.body[offset:offset+length]...), true, nil
}
func (a *pcapngArtifact) Close() {}

// A stored PCAPNG of several delivery chunks is prepared, observed and
// downloaded over the real two-hop h2/mTLS exchange into the real HTTPS sink:
// one conversation and one key opening per window, one data frame and one
// final-sink acknowledgement per chunk. Whole-file and If-Range resumed
// downloads return the stored bytes and headers of the pcapng type.
func TestNativeTwoHopPCAPNGWindowChunksAndResume(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	source := pcapngSourceValue(t)
	body := syntheticPCAPNG(t, 2*int(artifact.DeliveryBytes)+300_000) // three chunks
	sum := sha256.Sum256(body)
	now := time.Now()
	target := value.WorkerCredentialTarget{InstallationID: nativeID, SessionID: nativeID, WorkerID: nativeID, PodUID: nativeID, CreatedAt: now, RunUntil: now.Add(time.Minute)}
	reader := &pcapngReader{source: source, body: body}
	result, e := evidence.NewRegionalContextResult(ctx, target, reader, time.Now)
	if e != nil {
		t.Fatal(e)
	}
	defer func() { result.Close(); result.Wait(context.Background()) }()

	preparation, client, _ := flowOperation(t, ctx, source, value.NativePrepare, 1, artifact.DownloadDeliveryLease{})
	done := flowRunWorker(t, ctx, client, target, result)
	m, e := preparation.Prepared(ctx)
	if e != nil {
		t.Fatal("prepare", e)
	}
	if m != pcapngMetadata(source, body) || m.Filename != "artifact-"+nativeID+".pcapng" || m.Format != "pcapng" || m.SHA256 != sum {
		t.Fatalf("pcapng metadata %+v", m)
	}
	if e = preparation.Commit(ctx); e != nil {
		t.Fatal("commit", e)
	}
	if e = <-done; e != nil {
		t.Fatal("worker prepare", e)
	}
	preparation.Close()

	fence := int64(2)
	// download serves one request through one remote window covering the
	// selection resolved from its Range/If-Range against the verified
	// metadata, chunk by chunk with final-sink acknowledgements.
	download := func(t *testing.T, header http.Header) (*http.Response, []byte) {
		t.Helper()
		selection, e := browser.ResolveDownloadSelection(m.Size, m.ETag, header)
		if e != nil {
			t.Fatal(e)
		}
		now := time.Now()
		a := artifact.DownloadAuthority{Scope: artifact.DownloadScope{RootID: nativeID, ArtifactID: nativeID, CaptureID: nativeID, ClusterID: nativeID, NamespaceUID: nativeID, WorkloadUID: nativeID, PodUID: nativeID, Version: evidence.ContextCopiesDigest(source.Copies), Principal: identity.Principal{Issuer: "https://id.invalid", Subject: "dev", ClientID: "browser", Kind: identity.Human}}, PermissionEpoch: nativeID, PermissionSequence: 1, ProjectionDigest: artifact.Digest{1}, DecisionDigest: artifact.Digest{2}, IdentityRevision: identity.Revision{UID: "policy", Generation: 1, Digest: [32]byte{3}}, CheckedAt: now, ValidUntil: now.Add(4 * time.Second), AccessUntil: source.Expectation.Registration.ExpiresAt, DeleteBy: source.Expectation.Registration.DeleteBy}
		lease := artifact.DownloadDeliveryLease{ResponseID: nativeID, WindowID: nativeID, OwnerID: nativeID, Generation: 1, Sequence: 1, Offset: selection.Offset, Length: selection.Length, StartedAt: now, Until: a.ValidUntil, Authority: a}
		fence++
		response, client, _ := flowOperation(t, ctx, source, value.NativeResponse, fence, lease)
		defer response.Close()
		worker := flowRunWorker(t, ctx, client, target, result)
		readWork := evidence.NativeWindowReadWork(source.Expectation.Type())
		outcome := make(chan error, 1)
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			outcome <- func() error {
				factory := browser.HTTPDownloadResponseFactory{Writer: w, Request: r}
				if got, e := factory.SelectDownloadResponse(m); e != nil || got != selection {
					return artifact.ErrIntegrity
				}
				work, stop := context.WithDeadline(r.Context(), lease.Until)
				defer stop()
				plan := artifact.DownloadResponse{ID: nativeID, SessionID: nativeID, OwnerID: nativeID, Generation: 1, Plan: artifact.DownloadResponsePlan{Version: 1, Selection: selection, WholeFile: selection.Offset == 0 && selection.Length == m.Size, WindowReadLimit: readWork}, StartedAt: now, Until: target.RunUntil}
				sink, e := factory.OpenDownloadResponse(work, m, plan)
				if e != nil {
					return e
				}
				defer sink.Close()
				// A chunk out of order is refused before any data moves.
				if _, e := response.ReadChunk(work, lease, lease.Offset+1, min(artifact.DeliveryBytes, lease.Length-1)); e == nil {
					return artifact.ErrIntegrity
				}
				for offset, end := lease.Offset, lease.Offset+lease.Length; offset < end; {
					n := min(artifact.DeliveryBytes, end-offset)
					chunk, e := response.ReadChunk(work, lease, offset, n)
					if e != nil {
						return e
					}
					// The window's read work is reported once, with its first chunk.
					want := int64(0)
					if offset == lease.Offset {
						want = readWork
					}
					if chunk.ReadWork != want || !chunk.FinalVerified {
						clear(chunk.Bytes)
						return artifact.ErrIntegrity
					}
					written, e := sink.WriteChunk(work, lease, offset, chunk.Bytes)
					clear(chunk.Bytes)
					if e != nil {
						return e
					}
					if written != n {
						return artifact.ErrIntegrity
					}
					if e = response.AcknowledgeNativeChunk(work, lease, offset, n); e != nil {
						return e
					}
					offset += n
				}
				return sink.Finish(work)
			}()
		}))
		defer server.Close()
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, server.URL, nil)
		for k, v := range header {
			req.Header[k] = v
		}
		httpClient := server.Client()
		httpClient.Transport.(*http.Transport).DisableCompression = true
		reply, e := httpClient.Do(req)
		if e != nil {
			t.Fatal(e)
		}
		got, e := io.ReadAll(reply.Body)
		reply.Body.Close()
		if e != nil {
			t.Fatal(e)
		}
		outcomeErr, workerErr := <-outcome, <-worker
		if outcomeErr != nil || workerErr != nil {
			t.Fatal("remote window", outcomeErr, "worker", workerErr)
		}
		return reply, got
	}

	whole, got := download(t, nil)
	if whole.StatusCode != http.StatusOK || !bytes.Equal(got, body) || sha256.Sum256(got) != sum {
		t.Fatal("whole-file pcapng download differs", whole.StatusCode, len(got), len(body))
	}
	if ct := whole.Header.Get("Content-Type"); ct != "application/octet-stream" {
		t.Fatal("content type", ct)
	}
	if _, params, e := mime.ParseMediaType(whole.Header.Get("Content-Disposition")); e != nil || params["filename"] != "artifact-"+nativeID+".pcapng" {
		t.Fatal("content disposition", whole.Header.Get("Content-Disposition"), e)
	}
	if whole.Header.Get("ETag") != m.ETag {
		t.Fatal("etag", whole.Header.Get("ETag"))
	}
	// Resume after an interruption past the first chunk with If-Range.
	from := int64(artifact.DeliveryBytes + 4321)
	resumed, got := download(t, http.Header{"Range": {"bytes=" + strconv.FormatInt(from, 10) + "-"}, "If-Range": {m.ETag}})
	if resumed.StatusCode != http.StatusPartialContent || !bytes.Equal(got, body[from:]) {
		t.Fatal("resumed pcapng range differs", resumed.StatusCode, len(got))
	}
	// A changed validator falls back to the whole file.
	stale, got := download(t, http.Header{"Range": {"bytes=" + strconv.FormatInt(from, 10) + "-"}, "If-Range": {`"v1-0000"`}})
	if stale.StatusCode != http.StatusOK || !bytes.Equal(got, body) {
		t.Fatal("stale If-Range did not return the whole file", stale.StatusCode, len(got))
	}
	// Preparation plus one key opening per window, never one per chunk.
	if reader.opens.Load() != 4 {
		t.Fatal("framed source openings", reader.opens.Load())
	}
}
