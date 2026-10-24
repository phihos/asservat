package presentation

import (
	"context"
	"net/http"
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
