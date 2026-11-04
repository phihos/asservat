package delivery

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"io"
	"time"

	"asservat.local/asservat/internal/domain/collector"
)

// ProfileSink encrypts and stores exactly one completed profile received from
// its original node process. Failure remains charged and cannot be redelivered.
type ProfileSink interface {
	DeliverProfile(context.Context, collector.Identity, collector.ProfileResult, io.Reader) error
}

func (c *NodeChannel) SetProfileSink(s ProfileSink) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.profileSink = s
}

// ProfileTLSAvailable requires an explicit current implementation capability;
// the older goProfile advertisement establishes HTTP support only.
func (v NodeView) ProfileTLSAvailable() bool {
	if !v.RecorderAvailable(collector.MechanismProfile) {
		return false
	}
	for _, m := range v.Report.Mechanisms {
		if m.Mechanism == collector.MechanismProfile {
			return m.ProfileTLS
		}
	}
	return false
}

func (v NodeView) ProfileAuthorizationAvailable() bool {
	if !v.ProfileTLSAvailable() {
		return false
	}
	for _, m := range v.Report.Mechanisms {
		if m.Mechanism == collector.MechanismProfile {
			return m.ProfileAuthorization
		}
	}
	return false
}

func (c *NodeChannel) EnqueueProfile(ctx context.Context, p collector.ProfileCapture, startBy time.Time) (collector.Work, error) {
	if ctx == nil || ctx.Err() != nil || !p.Valid() {
		return collector.Work{}, ErrNodeInvalid
	}
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return collector.Work{}, ErrNodeUnavailable
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	e := c.nodes[p.Request.NodeUID]
	if e == nil || e.id.NodeName != p.Request.Pin.NodeName || e.id.Epoch != p.CollectorEpoch || e.id.BootID != p.Request.NodeBootID || !c.view(e, now).RecorderAvailable(collector.MechanismProfile) || (!p.TLS.IsZero() && !c.view(e, now).ProfileTLSAvailable()) || (p.AuthorizationRequired && !c.view(e, now).ProfileAuthorizationAvailable()) || !now.Before(startBy) || startBy.After(p.Request.Deadline.Add(-p.Request.Parameters.Duration-2*time.Second)) || ctx.Err() != nil {
		return collector.Work{}, ErrNodeUnavailable
	}
	for id, pending := range e.captures {
		if !now.Before(pending.until) {
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
	w := collector.Work{ID: h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:], Sequence: e.nextSeq, Kind: collector.WorkProfileCapture, NotAfter: startBy, Profile: &copy}
	e.captures[w.ID] = pendingCapture{captureID: p.CaptureID, until: p.Request.Deadline.Add(PacketUploadMargin), profile: &copy}
	e.work = append(e.work, w)
	close(e.wake)
	e.wake = make(chan struct{})
	return w, nil
}

func (c *NodeChannel) DeliverProfile(ctx context.Context, peer NodePeer, epoch string, r collector.ProfileResult, body io.Reader) error {
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
	if !ok || pending.profile == nil || pending.cancelOnly || pending.captureID != r.CaptureID || !c.now().Before(pending.until) || c.profileSink == nil {
		c.mu.Unlock()
		return ErrNodeConflict
	}
	p := pending.profile
	o := r.Outcome
	if r.ExpectationDigest != p.ExpectationDigest || r.EndpointDigest != p.Request.EndpointDigest || o.Format != p.Request.Parameters.Format() || o.NativeBytes > p.Request.NativeLimit || (!o.StartedAt.IsZero() && o.StartedAt.Before(p.Request.NotBefore)) || (r.Failure == "" && o.CompletedAt.After(p.Request.Deadline)) || o.CompletedAt.After(c.now()) {
		c.mu.Unlock()
		return ErrNodeConflict
	}
	// Fence duplicate result delivery before handing off any bytes. Retain only
	// this original cancellation identity while the sink owns the active upload.
	pending.cancelOnly = true
	e.captures[r.WorkID] = pending
	id, sink := e.id, c.profileSink
	c.mu.Unlock()
	defer func() { c.mu.Lock(); delete(e.captures, r.WorkID); c.mu.Unlock() }()
	if err := sink.DeliverProfile(ctx, id, r, io.LimitReader(body, o.NativeBytes)); err != nil {
		return ErrNodeUnavailable
	}
	return nil
}

// EnqueueProfileCancel stops only this queued profile; it does not create a
// new attempt or extend the original result delivery deadline.
func (c *NodeChannel) EnqueueProfileCancel(ctx context.Context, nodeUID, captureID, workID string, until time.Time) (collector.Work, error) {
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
	if !ok || pending.profile == nil || pending.captureID != captureID || !now.Before(pending.until) {
		return collector.Work{}, ErrNodeUnavailable
	}
	if len(e.work) >= collector.MaxQueuedWork || e.nextSeq == ^uint64(0) {
		return collector.Work{}, ErrNodeLimit
	}
	e.nextSeq++
	h := hex.EncodeToString(raw[:])
	w := collector.Work{ID: h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:], Sequence: e.nextSeq, Kind: collector.WorkCancelProfileCapture, NotAfter: until, CancelProfile: &cancel}
	e.work = append(e.work, w)
	close(e.wake)
	e.wake = make(chan struct{})
	return w, nil
}
