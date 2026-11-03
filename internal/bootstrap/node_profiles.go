package bootstrap

import (
	"bytes"
	"context"
	"errors"
	"io"
	"sync"
	"time"

	"asservat.local/asservat/internal/adapters/diagnostics"
	"asservat.local/asservat/internal/adapters/gadget"
	executionapp "asservat.local/asservat/internal/application/execution"
	"asservat.local/asservat/internal/domain/collector"
	"asservat.local/asservat/internal/domain/execution"
)

type profileAcquirer func(context.Context, collector.ProfileCapture, io.Writer) (execution.GoProfileOutcome, error)
type profileUploader func(context.Context, string, collector.ProfileResult, io.Reader) error

type nodeProfiles struct {
	identity func() collector.Identity
	acquire  profileAcquirer
	upload   profileUploader
	now      func() time.Time
	budget   func() *collector.Budget
	budgetMu *sync.Mutex
	running  map[string]runningProfile // one conservative runtime slot per whole Pod
	spent    map[string]time.Time
	wg       sync.WaitGroup
}
type runningProfile struct {
	captureID, workID string
	cancel            context.CancelFunc
	uncertainUntil    time.Time
}

func (n *nodeProfiles) start(ctx context.Context, epoch string, w collector.Work) collector.Receipt {
	reply := collector.Decide(w, n.now())
	if reply.Reason == collector.ReasonWorkUnknown || reply.Reason == collector.ReasonWorkExpired {
		return reply
	}
	if w.Profile == nil || n.acquire == nil || n.upload == nil || ctx == nil || ctx.Err() != nil {
		reply.Reason = collector.ReasonEngineUnavailable
		return reply
	}
	p := *w.Profile
	id := n.identity()
	if id.Epoch != epoch || epoch != p.CollectorEpoch || id.NodeUID != p.Request.NodeUID || id.NodeName != p.Request.Pin.NodeName || id.BootID != p.Request.NodeBootID {
		reply.Reason = collector.ReasonWorkUnknown
		return reply
	}
	n.budgetMu.Lock()
	if n.running == nil {
		n.running = map[string]runningProfile{}
	}
	if n.spent == nil {
		n.spent = map[string]time.Time{}
	}
	now := n.now()
	for pod, r := range n.running {
		if !r.uncertainUntil.IsZero() && !now.Before(r.uncertainUntil) {
			delete(n.running, pod)
		}
	}
	for capture, until := range n.spent {
		if !now.Before(until) {
			delete(n.spent, capture)
		}
	}
	_, busy := n.running[p.Request.Pin.UID]
	_, replay := n.spent[p.CaptureID]
	if busy || replay || len(n.running) >= collector.MaxQueuedWork || len(n.spent) >= collector.MaxQueuedWork || !now.Before(w.NotAfter) || n.budget().ReserveFrozen(p.Request.NativeLimit) != nil {
		// A newly refused admitted attempt still returns a typed terminal
		// outcome. Replayed work never creates another upload or runtime slot.
		if !replay && len(n.spent) < collector.MaxQueuedWork && now.Before(w.NotAfter) {
			n.spent[p.CaptureID] = w.NotAfter
			n.wg.Add(1)
			go n.refuse(ctx, epoch, w, p, collector.ReasonCaptureBusy)
		}
		n.budgetMu.Unlock()
		reply.Reason = collector.ReasonCaptureBusy
		return reply
	}
	action, cancel := context.WithDeadline(ctx, p.Request.Deadline)
	n.running[p.Request.Pin.UID] = runningProfile{captureID: p.CaptureID, workID: w.ID, cancel: cancel}
	n.spent[p.CaptureID] = w.NotAfter
	n.wg.Add(1)
	n.budgetMu.Unlock()
	go n.run(ctx, action, cancel, epoch, w, p)
	reply.Outcome, reply.Reason = collector.OutcomeAccepted, ""
	return reply
}

func (n *nodeProfiles) run(parent, action context.Context, cancel context.CancelFunc, epoch string, w collector.Work, p collector.ProfileCapture) {
	defer n.wg.Done()
	defer cancel()
	uncertain := false
	defer func() {
		n.budgetMu.Lock()
		defer n.budgetMu.Unlock()
		if uncertain && n.now().Before(p.Request.Deadline) {
			r := n.running[p.Request.Pin.UID]
			r.uncertainUntil = p.Request.Deadline
			n.running[p.Request.Pin.UID] = r
		} else {
			delete(n.running, p.Request.Pin.UID)
		}
		n.budget().ReleaseFrozen(p.Request.NativeLimit)
	}()
	buffer := &profileNativeBuffer{data: make([]byte, 0, p.Request.NativeLimit), ctx: action, limit: p.Request.NativeLimit}
	outcome, err := n.acquire(action, p, buffer)
	uncertain = outcome.MayHaveStarted && (!outcome.ResponseComplete || err != nil)
	result := collector.ProfileResult{WorkID: w.ID, CaptureID: p.CaptureID, ExpectationDigest: p.ExpectationDigest, EndpointDigest: p.Request.EndpointDigest, Outcome: outcome}
	data := buffer.Bytes()
	defer clear(data)
	if err != nil || !outcome.ResponseComplete || outcome.NativeBytes != int64(len(data)) {
		result.Failure = collector.ReasonCaptureFailed
		if errors.Is(err, execution.ErrProfilerBusy) {
			result.Failure = collector.ReasonCaptureBusy
		}
		result.Outcome.ResponseComplete = false
		result.Outcome.Format = p.Request.Parameters.Format()
		result.Outcome.CompletedAt = n.now().UTC()
		result.Outcome.NativeBytes = 0
		data = nil
	}
	// Upload ownership is bounded separately by the original action deadline
	// plus the existing transport margin; an action cancellation never renews it.
	upload, cancelUpload := context.WithDeadline(parent, p.Request.Deadline.Add(30*time.Second))
	defer cancelUpload()
	if len(data) == 0 {
		_ = n.upload(upload, epoch, result, bytes.NewReader(nil))
		return
	}
	_ = n.upload(upload, epoch, result, &profileUploadReader{owner: n, ctx: upload, source: bytes.NewReader(data)})
}

func (n *nodeProfiles) stop(w collector.Work) collector.Receipt {
	reply := collector.Decide(w, n.now())
	if reply.Reason == collector.ReasonWorkUnknown || reply.Reason == collector.ReasonWorkExpired {
		return reply
	}
	if w.CancelProfile == nil {
		return reply
	}
	n.budgetMu.Lock()
	defer n.budgetMu.Unlock()
	for _, r := range n.running {
		if r.captureID == w.CancelProfile.CaptureID && r.workID == w.CancelProfile.WorkID {
			r.cancel()
			reply.Outcome, reply.Reason = collector.OutcomeAccepted, ""
			return reply
		}
	}
	reply.Reason = collector.ReasonCaptureFailed
	return reply
}

type profileNativeBuffer struct {
	data  []byte
	ctx   context.Context
	limit int64
}

func (b *profileNativeBuffer) Write(p []byte) (int, error) {
	if b.ctx.Err() != nil {
		return 0, b.ctx.Err()
	}
	if int64(len(b.data)+len(p)) > b.limit {
		return 0, execution.ErrProfileLimit
	}
	b.data = append(b.data, p...)
	return len(p), nil
}

type nodeProfileMechanism struct {
	identity func() collector.Identity
	p        collector.ProfileCapture
	now      func() time.Time
}

func (m nodeProfileMechanism) DialGoProfile(ctx context.Context, r execution.GoProfileRequest) (executionapp.GoProfileChannel, error) {
	if r != m.p.Request {
		return executionapp.GoProfileChannel{}, execution.ErrDenied
	}
	connection, err := gadget.DialProfile(ctx, r.Pin.UID, m.p.Address, m.p.Port)
	return executionapp.GoProfileChannel{Connection: connection, Host: m.p.Host, ValidUntil: r.Deadline}, err
}
func (m nodeProfileMechanism) ObserveGoProfile(ctx context.Context, r execution.GoProfileRequest) (execution.GoProfileCurrent, error) {
	id := m.identity()
	now := m.now()
	if ctx.Err() != nil || r != m.p.Request || id.Epoch != m.p.CollectorEpoch || id.NodeUID != r.NodeUID || id.BootID != r.NodeBootID || r.Validate(now) != nil {
		return execution.GoProfileCurrent{}, execution.ErrDenied
	}
	until := now.Add(5 * time.Second)
	if r.Deadline.Before(until) {
		until = r.Deadline
	}
	return execution.GoProfileCurrent{CheckedAt: now, ValidUntil: until}, nil
}
func acquireNodeProfile(identity func() collector.Identity, now func() time.Time) profileAcquirer {
	return func(ctx context.Context, p collector.ProfileCapture, destination io.Writer) (execution.GoProfileOutcome, error) {
		mechanism := nodeProfileMechanism{identity, p, now}
		collector, err := diagnostics.NewGoProfileCollector(mechanism, mechanism, now)
		if err != nil {
			return execution.GoProfileOutcome{}, err
		}
		return collector.CollectGoProfileNative(ctx, p.Request, destination)
	}
}

func (b *profileNativeBuffer) Bytes() []byte { return b.data }

type profileUploadReader struct {
	owner  *nodeProfiles
	ctx    context.Context
	source *bytes.Reader
}

func (r *profileUploadReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	n := min(len(p), 64<<10, r.source.Len())
	if n == 0 {
		return 0, io.EOF
	}
	for {
		r.owner.budgetMu.Lock()
		wait, err := r.owner.budget().TakeUpload(r.owner.now(), int64(n))
		r.owner.budgetMu.Unlock()
		if err != nil {
			return 0, err
		}
		if wait == 0 {
			break
		}
		if err := nodeSleep(r.ctx, wait, nil); err != nil {
			return 0, err
		}
	}
	if r.ctx.Err() != nil {
		return 0, r.ctx.Err()
	}
	return r.source.Read(p[:n])
}

func (n *nodeProfiles) refuse(parent context.Context, epoch string, w collector.Work, p collector.ProfileCapture, reason collector.Reason) {
	defer n.wg.Done()
	ctx, cancel := context.WithDeadline(parent, p.Request.Deadline.Add(30*time.Second))
	defer cancel()
	result := collector.ProfileResult{WorkID: w.ID, CaptureID: p.CaptureID, ExpectationDigest: p.ExpectationDigest, EndpointDigest: p.Request.EndpointDigest, Failure: reason, Outcome: execution.GoProfileOutcome{Format: p.Request.Parameters.Format(), CompletedAt: n.now().UTC()}}
	_ = n.upload(ctx, epoch, result, bytes.NewReader(nil))
}
