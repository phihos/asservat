package presentation

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"time"

	"asservat.local/asservat/internal/domain/identity"
)

// WriteOperationResponse retains the original delivery deadline through a
// bounded write and flush. sent forbids appending an error after partial output.
// The caller owns/join-closes its reply after this function and serialization
// finish; no download permit, key slot or acquisition authority is reused here.
func WriteOperationResponse(ctx context.Context, w http.ResponseWriter, status int, body []byte, until time.Time, check func(context.Context) error) (sent bool, err error) {
	if ctx == nil || w == nil || check == nil || ctx.Err() != nil || len(body) > 64<<10 || until.IsZero() || !time.Now().Before(until) {
		return false, ErrOperationDelivery
	}
	deadline, ok := ctx.Deadline()
	if !ok || until.After(deadline) || until.After(time.Now().Add(identity.EvidenceReadRequestWindow)) {
		return false, ErrOperationDelivery
	}
	call, cancel := context.WithDeadline(ctx, until)
	defer cancel()
	control := http.NewResponseController(w)
	if control.SetWriteDeadline(until) != nil {
		return false, ErrOperationDelivery
	}
	joined := make(chan struct{})
	stop := context.AfterFunc(call, func() { _ = control.SetWriteDeadline(time.Now()); close(joined) })
	defer func() {
		if !stop() {
			<-joined
		}
	}()
	if check(call) != nil || call.Err() != nil || !time.Now().Before(until) {
		return false, ErrOperationDelivery
	}
	w.WriteHeader(status)
	n, err := w.Write(body)
	if err != nil || n != len(body) {
		return true, ErrOperationDelivery
	}
	if control.Flush() != nil || call.Err() != nil || !time.Now().Before(until) {
		return true, ErrOperationDelivery
	}
	return true, nil
}

// WriteOperationReplyResponse preserves the private owner through browser/MCP
// serialization. Unowned output retains the existing fixed 64KiB writer.
func WriteOperationReplyResponse(ctx context.Context, w http.ResponseWriter, status int, body []byte, reply OperationReply, until time.Time, check func(context.Context) error) (bool, error) {
	if w == nil {
		return false, ErrOperationDelivery
	}
	if reply.owner == nil {
		return WriteOperationResponse(ctx, w, status, body, until, check)
	}
	if len(body) == 0 {
		return false, ErrOperationDelivery
	}
	// No payload or trailers may be appended in the framing-only interval.
	for key := range w.Header() {
		if strings.EqualFold(key, "Trailer") || strings.HasPrefix(key, http.TrailerPrefix) {
			return false, ErrOperationDelivery
		}
	}
	previous, present := w.Header()["Content-Length"]
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	sent, err := WriteOperationResponse(ctx, w, status, body, until, check)
	if err != nil {
		if !sent {
			if present {
				w.Header()["Content-Length"] = previous
			} else {
				w.Header().Del("Content-Length")
			}
		}
		return sent, err
	}
	// The payload callback has joined. Only HTTP completion may now use the
	// original finite cleanup/request interval while synchronous Close joins.
	o := reply.owner
	o.mu.Lock()
	defer o.mu.Unlock()
	end, ok := o.ctx.Deadline()
	end = identity.Earlier(end, o.cleanupUntil)
	if !ok || ctx.Err() != nil || !time.Now().Before(until) || o.ctx.Err() != nil || o.closed || !o.acknowledged || !time.Now().Before(end) {
		return sent, ErrOperationDelivery
	}
	if !until.Before(end) {
		return sent, nil
	}
	if http.NewResponseController(w).SetWriteDeadline(end) != nil {
		return sent, ErrOperationDelivery
	}
	return sent, nil
}
