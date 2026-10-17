package browser

import (
	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/domain/artifact"
	"context"
	"errors"
	"mime"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// HTTPDownloadResponse owns one whole selected response, with bounded writes
// under short current leases. It is a sink, not authentication or authorization.
// Native contents/identity must come from the protected application coordinator.
type HTTPDownloadResponse struct {
	mu                     sync.Mutex
	writer                 http.ResponseWriter
	owner                  context.Context
	cancel                 context.CancelFunc
	metadata               artifact.NativeDownloadMetadata
	response               artifact.DownloadResponse
	selection              artifact.DownloadSelection
	until                  time.Time
	emitted                int64
	sent, failed, finished bool
}

func NewHTTPDownloadResponse(w http.ResponseWriter, r *http.Request, m artifact.NativeDownloadMetadata, response artifact.DownloadResponse) (*HTTPDownloadResponse, error) {
	now := time.Now()
	selection, until := response.Plan.Selection, response.Until
	if !response.Valid() || w == nil || r == nil || r.Method != http.MethodGet || r.TLS == nil || r.Context().Err() != nil || !until.After(now) || until.After(now.Add(8*time.Hour)) || m.Size < 0 || m.Size > artifact.MaxNativeBytes || !strongETag(m.ETag) || !safeDownloadFilename(m.Filename) || selection.Offset < 0 || selection.Length < 0 || selection.Offset > m.Size || selection.Length > m.Size-selection.Offset || selection.Partial && selection.Length == 0 || !selection.Partial && (selection.Offset != 0 || selection.Length != m.Size) || w.Header().Get("Content-Encoding") != "" {
		return nil, artifact.ErrInvalid
	}
	owner, cancel := context.WithDeadline(r.Context(), until)
	return &HTTPDownloadResponse{writer: w, owner: owner, cancel: cancel, metadata: m, response: response, selection: selection, until: until}, nil
}
func (s *HTTPDownloadResponse) HeadersSent() bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sent
}
func (s *HTTPDownloadResponse) headers() {
	h := s.writer.Header()
	m, r := s.metadata, s.selection
	h.Set("Content-Type", "application/octet-stream")
	h.Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": m.Filename}))
	h.Set("Content-Length", strconv.FormatInt(r.Length, 10))
	h.Set("Cache-Control", "no-store, private")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("ETag", m.ETag)
	h.Set("Accept-Ranges", "bytes")
	h.Del("Content-Range")
	status := http.StatusOK
	if r.Partial {
		status = http.StatusPartialContent
		h.Set("Content-Range", "bytes "+strconv.FormatInt(r.Offset, 10)+"-"+strconv.FormatInt(r.Offset+r.Length-1, 10)+"/"+strconv.FormatInt(m.Size, 10))
	}
	s.sent = true
	s.writer.WriteHeader(status)
}
func (s *HTTPDownloadResponse) WriteChunk(ctx context.Context, lease artifact.DownloadDeliveryLease, offset int64, p []byte) (int64, error) {
	if s == nil || ctx == nil || !s.mu.TryLock() {
		return 0, artifact.ErrDownloadConflict
	}
	defer s.mu.Unlock()
	now := time.Now()
	length := int64(len(p))
	if lease.ResponseID != s.response.ID || lease.OwnerID != s.response.OwnerID || lease.Generation != s.response.Generation || s.failed || s.finished || ctx.Err() != nil || s.owner.Err() != nil || !now.Before(s.until) || !lease.Allows(offset, length, now) || offset != s.selection.Offset+s.emitted || length > s.selection.Length-s.emitted || length == 0 && s.selection.Length != 0 {
		return 0, artifact.ErrDownloadExpired
	}
	deadline, ok := ctx.Deadline()
	if !ok || deadline.After(lease.Until) || !now.Before(deadline) {
		return 0, artifact.ErrDownloadExpired
	}
	control := http.NewResponseController(s.writer)
	if err := control.SetWriteDeadline(deadline); err != nil {
		s.failed = true
		return 0, err
	}
	call, cancel := context.WithDeadline(s.owner, deadline)
	inputJoined := make(chan struct{})
	stopInput := context.AfterFunc(ctx, func() { cancel(); close(inputJoined) })
	interrupted := make(chan struct{})
	stopWrite := context.AfterFunc(call, func() { _ = control.SetWriteDeadline(time.Now()); close(interrupted) })
	// Both callback sources join before any deadline reset or caller reuse.
	join := func() {
		if !stopInput() {
			<-inputJoined
		}
		if !stopWrite() {
			<-interrupted
		}
	}
	if call.Err() != nil || ctx.Err() != nil {
		join()
		cancel()
		s.failed = true
		return 0, artifact.ErrDownloadExpired
	}
	if !s.sent {
		s.headers()
	}
	n, err := s.writer.Write(p)
	if err == nil && n != len(p) {
		err = errors.New("incomplete native transfer")
	}
	if err == nil {
		err = control.Flush()
	}
	join()
	if err == nil && (call.Err() != nil || ctx.Err() != nil || !time.Now().Before(deadline)) {
		err = artifact.ErrDownloadExpired
	}
	// An exceeded write deadline cannot be reset into a renewed write. Only a
	// completed still-current flush moves to the original response idle bound.
	if err == nil {
		err = control.SetWriteDeadline(s.until)
	}
	cancel()
	if n < 0 || n > len(p) {
		s.failed = true
		return 0, artifact.ErrIntegrity
	}
	s.emitted += int64(n)
	if err != nil {
		s.failed = true
	}
	return int64(n), err
}
func (s *HTTPDownloadResponse) Finish(ctx context.Context) error {
	if s == nil || ctx == nil || !s.mu.TryLock() {
		return artifact.ErrDownloadConflict
	}
	defer s.mu.Unlock()
	if s.failed || s.finished || !s.sent || ctx.Err() != nil || s.owner.Err() != nil || s.emitted != s.selection.Length {
		return artifact.ErrDownloadUnavailable
	}
	s.finished = true
	return nil
}
func (s *HTTPDownloadResponse) Close() {
	if s == nil {
		return
	}
	s.cancel()
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.finished {
		s.failed = true
	}
}

// HTTPDownloadResponseFactory retains the authenticated original HTTP request.
// No route is installed by this helper; the application authorizes its source.
type HTTPDownloadResponseFactory struct {
	Writer  http.ResponseWriter
	Request *http.Request
}

func (f HTTPDownloadResponseFactory) SelectDownloadResponse(m artifact.NativeDownloadMetadata) (artifact.DownloadSelection, error) {
	if f.Request == nil {
		return artifact.DownloadSelection{}, artifact.ErrInvalid
	}
	return ResolveDownloadSelection(m.Size, m.ETag, f.Request.Header)
}
func (f HTTPDownloadResponseFactory) OpenDownloadResponse(ctx context.Context, m artifact.NativeDownloadMetadata, r artifact.DownloadResponse) (evidence.DownloadResponseSink, error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, artifact.ErrDownloadExpired
	}
	return NewHTTPDownloadResponse(f.Writer, f.Request, m, r)
}

var _ evidence.DownloadResponseSink = (*HTTPDownloadResponse)(nil)
var _ evidence.DownloadResponseSinkFactory = HTTPDownloadResponseFactory{}
