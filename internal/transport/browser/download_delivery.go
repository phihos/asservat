package browser

import (
	"asservat.local/asservat/internal/domain/artifact"
	"context"
	"errors"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// HTTPDownloadDestination is an authenticated route's final bounded sink, not
// an HTTP handler or authorization middleware. It has no SQL or unwrap keys.
// Bootstrap must place it after current browser/OAuth authority and use the
// acquisition worker/relay to supply verified metadata and native bytes.
type HTTPDownloadDestination struct {
	Writer      http.ResponseWriter
	Request     *http.Request
	headersSent bool
}

// ResolveDownloadSelection uses verified native metadata, never a client size
// or checksum. Admission must charge its returned length, including full-file
// fallback. This function still confers no authority and does not write headers.
func ResolveDownloadSelection(size int64, etag string, h http.Header) (artifact.DownloadSelection, error) {
	if size < 0 || size > artifact.MaxNativeBytes || !strongETag(etag) {
		return artifact.DownloadSelection{}, errConditional
	}
	if values, exists := h["If-Match"]; exists {
		matched, err := matchETagList(strings.Join(values, ","), etag, false)
		if err != nil {
			return artifact.DownloadSelection{}, err
		}
		if !matched {
			return artifact.DownloadSelection{}, errPrecondition
		}
	}
	if values, exists := h["If-None-Match"]; exists {
		matched, err := matchETagList(strings.Join(values, ","), etag, true)
		if err != nil {
			return artifact.DownloadSelection{}, err
		}
		if matched {
			return artifact.DownloadSelection{}, errNotModified
		}
	}
	if len(h.Values("If-Range")) > 1 {
		return artifact.DownloadSelection{}, errConditional
	}
	rangeHeader := strings.Join(h.Values("Range"), ",")
	if len(rangeHeader) > 128 {
		return artifact.DownloadSelection{}, errRange
	}
	r, err := selectNativeRange(size, etag, rangeHeader, strings.Join(h.Values("If-Match"), ","), h.Get("If-Range"))
	return artifact.DownloadSelection{Offset: r.Offset, Length: r.Length, Partial: r.Partial}, err
}
func DownloadConditionStatus(err error) int {
	switch {
	case errors.Is(err, errNotModified):
		return http.StatusNotModified
	case errors.Is(err, errPrecondition):
		return http.StatusPreconditionFailed
	case errors.Is(err, errRange):
		return http.StatusRequestedRangeNotSatisfiable
	case errors.Is(err, errConditional):
		return http.StatusBadRequest
	default:
		return http.StatusInternalServerError
	}
}

func (s *HTTPDownloadDestination) HeadersSent() bool { return s != nil && s.headersSent }

// An error after HeadersSent requires aborting the response/stream. Never append
// a JSON problem or HTML login page to a partly emitted native evidence file.
func (s *HTTPDownloadDestination) Send(ctx context.Context, m artifact.NativeDownloadMetadata, r artifact.DownloadSelection, p []byte) (int64, error) {
	if s == nil || s.Writer == nil || s.Request == nil || s.Request.Method != http.MethodGet || s.Request.TLS == nil || s.headersSent {
		return 0, artifact.ErrInvalid
	}
	deadline, ok := ctx.Deadline()
	if !ok || !time.Now().Before(deadline) || deadline.After(time.Now().Add(5*time.Second)) || ctx.Err() != nil {
		return 0, artifact.ErrDownloadExpired
	}
	if m.Size < 0 || m.Size > artifact.MaxNativeBytes || !strongETag(m.ETag) || !safeDownloadFilename(m.Filename) || r.Offset < 0 || r.Length < 0 || r.Offset > m.Size || r.Length > m.Size-r.Offset || r.Length != int64(len(p)) || r.Length > artifact.DeliveryBytes || !r.Partial && (r.Offset != 0 || r.Length != m.Size) || r.Partial && r.Length == 0 {
		return 0, artifact.ErrInvalid
	}
	// Transparent compression would change the representation and invalidate
	// its range offsets, native checksum and known Content-Length.
	if s.Writer.Header().Get("Content-Encoding") != "" {
		return 0, artifact.ErrInvalid
	}
	control := http.NewResponseController(s.Writer)
	if err := control.SetWriteDeadline(deadline); err != nil {
		return 0, artifact.ErrDownloadUnavailable
	}
	interrupted := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		_ = control.SetWriteDeadline(time.Now())
		close(interrupted)
	})
	defer func() {
		// stop does not join an already-running callback. Finish its socket
		// mutation before the response or connection can be reused.
		if !stop() {
			<-interrupted
		}
	}()
	if ctx.Err() != nil {
		return 0, artifact.ErrDownloadExpired
	}
	h := s.Writer.Header()
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
	s.headersSent = true
	s.Writer.WriteHeader(status)
	n, err := s.Writer.Write(p)
	if err == nil && n != len(p) {
		err = errors.New("incomplete native transfer")
	}
	if err == nil {
		err = control.Flush()
	}
	return int64(n), err
}
func safeDownloadFilename(s string) bool {
	if len(s) < 1 || len(s) > 128 || s == "." || s == ".." || strings.HasPrefix(s, ".") {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.') {
			return false
		}
	}
	return true
}
