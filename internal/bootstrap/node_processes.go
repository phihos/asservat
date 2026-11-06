package bootstrap

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"asservat.local/asservat/internal/domain/collector"
	"asservat.local/asservat/internal/transport/node"
)

// Process discovery shares the original finite-acquisition map, budget lock,
// spent IDs, join and native working reservation with endpoint profiles.
func (n *nodeProfiles) startProcesses(ctx context.Context, epoch string, w collector.Work) collector.Receipt {
	r := collector.Decide(w, n.now())
	if r.Reason == collector.ReasonWorkUnknown || r.Reason == collector.ReasonWorkExpired {
		return r
	}
	if ctx == nil || ctx.Err() != nil || w.Processes == nil || n.processes == nil || n.uploadProcesses == nil {
		return r
	}
	p := *w.Processes
	id := n.identity()
	if id.Epoch != epoch || p.CollectorEpoch != epoch || p.Request.NodeUID != id.NodeUID || p.Request.NodeBootID != id.BootID || p.Request.Pin.NodeName != id.NodeName {
		r.Reason = collector.ReasonWorkUnknown
		return r
	}
	n.budgetMu.Lock()
	if n.running == nil {
		n.running = map[string]runningProfile{}
	}
	if n.spent == nil {
		n.spent = map[string]time.Time{}
	}
	now := n.now()
	for key, until := range n.spent {
		if !now.Before(until) {
			delete(n.spent, key)
		}
	}
	_, replay := n.spent[p.CaptureID]
	_, busy := n.running[p.Request.Pin.UID]
	if replay || busy || len(n.running) >= collector.MaxQueuedWork || len(n.spent) >= collector.MaxQueuedWork || n.budget().ReserveFrozen(p.Request.NativeLimit) != nil {
		n.budgetMu.Unlock()
		r.Reason = collector.ReasonCaptureBusy
		return r
	}
	call, cancel := context.WithDeadline(ctx, p.Request.Deadline)
	n.running[p.Request.Pin.UID] = runningProfile{captureID: p.CaptureID, workID: w.ID, cancel: cancel}
	n.spent[p.CaptureID] = p.Request.Deadline.Add(30 * time.Second)
	n.wg.Add(1)
	n.budgetMu.Unlock()
	go func() {
		defer n.wg.Done()
		defer cancel()
		defer func() {
			n.budgetMu.Lock()
			delete(n.running, p.Request.Pin.UID)
			n.budget().ReleaseFrozen(p.Request.NativeLimit)
			n.budgetMu.Unlock()
		}()
		started := n.now().UTC()
		value, e := n.processes(call, p)
		var raw []byte
		if e == nil && value.Valid() && call.Err() == nil {
			raw, e = json.Marshal(value)
		}
		result := collector.ProcessResult{WorkID: w.ID, CaptureID: p.CaptureID, PodUID: p.Request.Pin.UID, NodeUID: id.NodeUID, NodeBootID: id.BootID, ExpectationDigest: p.ExpectationDigest, StartedAt: started, CompletedAt: n.now().UTC(), NativeBytes: int64(len(raw))}
		if e != nil || !value.Valid() || call.Err() != nil || int64(len(raw)) > p.Request.NativeLimit {
			clear(raw)
			raw = nil
			result.NativeBytes = 0
			result.Failure = collector.ReasonCaptureFailed
		}
		defer clear(raw)
		upload, stop := context.WithDeadline(ctx, p.Request.Deadline.Add(30*time.Second))
		defer stop()
		n.budgetMu.Lock()
		running := n.running[p.Request.Pin.UID]
		if running.stopRequested {
			clear(raw)
			raw = nil
			result.NativeBytes = 0
			result.Failure = collector.ReasonCaptureFailed
		}
		if len(raw) > 0 {
			running.cancelUpload = stop
			n.running[p.Request.Pin.UID] = running
		}
		n.budgetMu.Unlock()
		_ = n.uploadProcesses(upload, epoch, result, bytes.NewReader(raw))
	}()
	r.Outcome, r.Reason = collector.OutcomeAccepted, ""
	return r
}

// loggedProcessUploader retains the original upload/result unchanged. Diagnostic
// output is one content-free line per task, never an error string or source ID.
func loggedProcessUploader(upload func(context.Context, string, collector.ProcessResult, io.Reader) error, log io.Writer) func(context.Context, string, collector.ProcessResult, io.Reader) error {
	return func(ctx context.Context, epoch string, result collector.ProcessResult, body io.Reader) error {
		err := upload(ctx, epoch, result, body)
		acquisition, outcome := "native-ready", "ok"
		if result.Failure != "" {
			acquisition = "source-failed"
		}
		if err != nil {
			switch {
			case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded), ctx.Err() != nil:
				outcome = "canceled"
			case errors.Is(err, node.ErrRefused):
				outcome = "refused"
			case errors.Is(err, node.ErrUnauthenticated):
				outcome = "unauthenticated"
			default:
				outcome = "unavailable"
			}
		}
		if log != nil {
			_, _ = fmt.Fprintf(log, "node processes: acquisition=%s upload=%s\n", acquisition, outcome)
		}
		return err
	}
}
