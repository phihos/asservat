package delivery

import (
	"asservat.local/asservat/internal/domain/collector"
	"context"
	"crypto/rand"
	"encoding/hex"
	"io"
	"time"
)

type ProcessSink interface {
	DeliverProcesses(context.Context, collector.Identity, collector.ProcessResult, io.Reader) error
}

func (c *NodeChannel) SetProcessSink(s ProcessSink) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.processSink = s
}

func (c *NodeChannel) EnqueueProcesses(ctx context.Context, p collector.ProcessCapture, startBy time.Time) (collector.Work, error) {
	if ctx == nil || ctx.Err() != nil || !p.Valid() {
		return collector.Work{}, ErrNodeInvalid
	}
	var raw [16]byte
	if _, e := rand.Read(raw[:]); e != nil {
		return collector.Work{}, ErrNodeUnavailable
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	e := c.nodes[p.Request.NodeUID]
	if e == nil || e.id.NodeName != p.Request.Pin.NodeName || e.id.Epoch != p.CollectorEpoch || e.id.BootID != p.Request.NodeBootID || !c.view(e, now).RecorderAvailable(collector.MechanismProcesses) || !now.Before(startBy) || startBy.After(p.Request.Deadline) || ctx.Err() != nil {
		return collector.Work{}, ErrNodeUnavailable
	}
	for id, p := range e.captures {
		if !now.Before(p.until) {
			delete(e.captures, id)
		}
	}
	if len(e.work) >= collector.MaxQueuedWork || len(e.captures) >= collector.MaxQueuedWork || e.nextSeq == ^uint64(0) {
		return collector.Work{}, ErrNodeLimit
	}
	for _, pending := range e.captures {
		if pending.captureID == p.CaptureID {
			return collector.Work{}, ErrNodeConflict
		}
	}
	e.nextSeq++
	h := hex.EncodeToString(raw[:])
	copy := p
	w := collector.Work{ID: h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:], Sequence: e.nextSeq, Kind: collector.WorkProcesses, NotAfter: startBy, Processes: &copy}
	e.captures[w.ID] = pendingCapture{captureID: p.CaptureID, until: p.Request.Deadline.Add(PacketUploadMargin), processes: &copy}
	e.work = append(e.work, w)
	close(e.wake)
	e.wake = make(chan struct{})
	return w, nil
}

func (c *NodeChannel) DeliverProcesses(ctx context.Context, peer NodePeer, epoch string, r collector.ProcessResult, body io.Reader) error {
	if ctx == nil || ctx.Err() != nil || body == nil || !r.Valid() {
		return ErrNodeInvalid
	}
	c.mu.Lock()
	e, err := c.current(peer, epoch)
	if err != nil {
		c.mu.Unlock()
		return err
	}
	pending, ok := e.captures[r.WorkID]
	if !ok || pending.processes == nil || pending.cancelOnly || pending.captureID != r.CaptureID || !c.now().Before(pending.until) || c.processSink == nil {
		c.mu.Unlock()
		return ErrNodeConflict
	}
	p := pending.processes
	if r.ExpectationDigest != p.ExpectationDigest || r.PodUID != p.Request.Pin.UID || r.NodeUID != e.id.NodeUID || r.NodeBootID != e.id.BootID || r.NativeBytes > p.Request.NativeLimit || r.StartedAt.Before(p.Request.NotBefore) || r.Failure == "" && r.CompletedAt.After(p.Request.Deadline) || r.CompletedAt.After(c.now()) {
		c.mu.Unlock()
		return ErrNodeConflict
	}
	pending.cancelOnly = true
	e.captures[r.WorkID] = pending
	id, sink := e.id, c.processSink
	c.mu.Unlock()
	defer func() { c.mu.Lock(); delete(e.captures, r.WorkID); c.mu.Unlock() }()
	if e := sink.DeliverProcesses(ctx, id, r, io.LimitReader(body, r.NativeBytes)); e != nil {
		return ErrNodeUnavailable
	}
	return nil
}

func (c *NodeChannel) EnqueueProcessCancel(ctx context.Context, nodeUID, captureID, workID string, until time.Time) (collector.Work, error) {
	cancel := collector.PacketCancel{CaptureID: captureID, WorkID: workID}
	if ctx == nil || ctx.Err() != nil || !cancel.Valid() {
		return collector.Work{}, ErrNodeInvalid
	}
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return collector.Work{}, ErrNodeUnavailable
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	e := c.nodes[nodeUID]
	if e == nil || ctx.Err() != nil || !now.Before(until) || until.After(now.Add(5*time.Second)) {
		return collector.Work{}, ErrNodeUnavailable
	}
	if end, ok := ctx.Deadline(); !ok || until.After(end) {
		return collector.Work{}, ErrNodeUnavailable
	}
	pending, ok := e.captures[workID]
	if !ok || pending.processes == nil || pending.captureID != captureID || !now.Before(pending.until) {
		return collector.Work{}, ErrNodeUnavailable
	}
	if len(e.work) >= collector.MaxQueuedWork || e.nextSeq == ^uint64(0) {
		return collector.Work{}, ErrNodeLimit
	}
	e.nextSeq++
	h := hex.EncodeToString(raw[:])
	w := collector.Work{ID: h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:], Sequence: e.nextSeq, Kind: collector.WorkCancelProcesses, NotAfter: until, CancelProcesses: &cancel}
	e.work = append(e.work, w)
	close(e.wake)
	e.wake = make(chan struct{})
	return w, nil
}
