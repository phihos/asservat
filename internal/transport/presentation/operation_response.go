package presentation

import (
	"context"
	"net/http"
	"time"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/identity"
)

// WriteOperationResponse retains the original delivery deadline through a
// bounded write and flush. sent forbids appending an error after partial output.
// The caller owns/join-closes its reply after this function and serialization
// finish; no download permit, key slot or acquisition authority is reused here.
func WriteOperationResponse(ctx context.Context, w http.ResponseWriter, status int, body []byte, until time.Time, check func(context.Context) error) (sent bool, err error) {
	return writeOperationResponse(ctx, w, status, body, until, check, 64<<10)
}

// The original general/MCP writer keeps its 64KiB cap. Only an authenticated
// browser settings reply gets the fixed larger budget, never a caller number.
func WriteBrowserOperationResponse(ctx context.Context, w http.ResponseWriter, status int, name string, reply OperationReply, until time.Time) (bool, error) {
	limit := 64 << 10
	if browserSettingsView(ctx, name) && reply.browserSettings {
		limit = contracts.InvestigationBrowserSettingsOutputLimit
	}
	return writeOperationResponse(ctx, w, status, reply.Body, until, reply.CheckDisclosure, limit)
}
func writeOperationResponse(ctx context.Context, w http.ResponseWriter, status int, body []byte, until time.Time, check func(context.Context) error, limit int) (sent bool, err error) {
	if ctx == nil || w == nil || check == nil || ctx.Err() != nil || len(body) > limit || until.IsZero() || !time.Now().Before(until) {
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
