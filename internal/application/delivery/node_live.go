package delivery

import (
	"asservat.local/asservat/internal/domain/collector"
	v "asservat.local/asservat/internal/domain/live"
	"context"
	"crypto/rand"
	"encoding/hex"
	"time"
)

type pendingLive struct {
	request collector.LiveRead
	until   time.Time
	reply   chan v.NodeReply
}

// ReadLive uses the existing node work channel. Pending state lasts only for
// this original caller, is removed on every return and cannot authorize capture.
func (c *NodeChannel) ReadLive(ctx context.Context, r collector.LiveRead) (v.NodeReply, error) {
	if ctx == nil || ctx.Err() != nil || !r.Valid() {
		return v.NodeReply{}, ErrNodeInvalid
	}
	if r.Manual != nil {
		m := *r.Manual
		r.Manual = &m
	}
	until, ok := ctx.Deadline()
	if !ok {
		return v.NodeReply{}, ErrNodeInvalid
	}
	now := c.now()
	if !now.Before(until) || until.After(now.Add(5*time.Second)) {
		return v.NodeReply{}, ErrNodeInvalid
	}
	var raw [16]byte
	if _, e := rand.Read(raw[:]); e != nil {
		return v.NodeReply{}, ErrNodeUnavailable
	}
	h := hex.EncodeToString(raw[:])
	id := h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
	c.mu.Lock()
	entry := c.nodes[r.Node()]
	mechanism := collector.MechanismPacket
	if r.Projection == v.Syscall {
		mechanism = collector.MechanismSyscall
	}
	if entry == nil || entry.id.Epoch != r.Epoch() || entry.id.BootID != r.Boot() || entry.id.PodUID != r.CollectorPod() || !c.view(entry, now).RecorderAvailable(mechanism) || !c.view(entry, now).LiveAvailable(r.Projection) {
		c.mu.Unlock()
		return v.NodeReply{}, ErrNodeUnavailable
	}
	if len(entry.live) >= v.MaxSources || len(entry.work) >= collector.MaxQueuedWork || entry.nextSeq == ^uint64(0) {
		c.mu.Unlock()
		return v.NodeReply{}, ErrNodeLimit
	}
	if entry.live == nil {
		entry.live = map[string]*pendingLive{}
	}
	pending := &pendingLive{r, until, make(chan v.NodeReply, 1)}
	entry.live[id] = pending
	entry.nextSeq++
	entry.work = append(entry.work, collector.Work{ID: id, Sequence: entry.nextSeq, Kind: collector.WorkLiveRead, NotAfter: until, Live: &r})
	close(entry.wake)
	entry.wake = make(chan struct{})
	c.mu.Unlock()
	defer func() {
		// A cancellation racing a successful upload must not leave an abandoned
		// approved batch retained in this caller's single-item delivery channel.
		select {
		case abandoned := <-pending.reply:
			clear(abandoned.Rows)
		default:
		}
		c.mu.Lock()
		defer c.mu.Unlock()
		delete(entry.live, id)
		for n, w := range entry.work {
			if w.ID == id {
				entry.work = append(entry.work[:n], entry.work[n+1:]...)
				break
			}
		}
	}()
	select {
	case <-ctx.Done():
		return v.NodeReply{}, ctx.Err()
	case out := <-pending.reply:
		c.mu.Lock()
		same := c.nodes[r.Node()] == entry && c.now().Before(until) && ctx.Err() == nil
		c.mu.Unlock()
		if !same {
			return v.NodeReply{}, ErrNodeConflict
		}
		return out, nil
	}
}

// DeliverLive accepts exactly one reply from the currently authenticated node.
// It stores no rows beyond the still-waiting bounded caller and never logs them.
func (c *NodeChannel) DeliverLive(ctx context.Context, peer NodePeer, epoch string, out v.NodeReply) error {
	if ctx == nil || ctx.Err() != nil {
		return ErrNodeInvalid
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, e := c.current(peer, epoch)
	if e != nil {
		return e
	}
	p := entry.live[out.WorkID]
	if p == nil || !c.now().Before(p.until) || out.SourceID != p.request.SourceID() || out.Fence != p.request.Fence() || out.BootID != p.request.Boot() || out.Sample <= 0 || out.Clock != "monotonic" && out.Clock != "boottime" || len(out.Rows) > p.request.Limit || p.request.Head && len(out.Rows) != 0 || out.Dropped < 0 || out.Dropped > 100 || out.Examined < 0 || out.Examined > 4096 || out.Bytes < 0 || out.Bytes > 1<<20 || !out.Position.Follows(v.Position{Sequence: p.request.AfterSequence, Lost: p.request.AfterLost, ClockLost: p.request.AfterClockLost, Unsupported: p.request.AfterUnsupported, SensorLost: p.request.AfterSensorLost}) {
		return ErrNodeConflict
	}
	bound, err := v.BindManualLiveReply(p.request, out)
	if err != nil {
		return ErrNodeConflict
	}
	out = bound
	for _, row := range out.Rows {
		if row.Nanos <= 0 || row.Nanos > out.Sample || row.Clock != out.Clock || row.Row.SourceID != out.SourceID || row.Row.PodUID != p.request.Pod() || row.Row.Projection != p.request.Projection || row.Row.Sequence <= p.request.AfterSequence || row.Row.Sequence > out.Position.Sequence || !row.Row.Valid(row.Row.ReceivedAt) {
			return ErrNodeConflict
		}
	}
	select {
	case p.reply <- out:
		delete(entry.live, out.WorkID)
		return nil
	default:
		return ErrNodeConflict
	}
}

func (v NodeView) LiveAvailable(projection string) bool {
	if !v.Current || v.Report == nil {
		return false
	}
	for _, m := range v.Report.Mechanisms {
		if m.Adapter == collector.AdapterAvailable && m.Prerequisites {
			for _, p := range m.LiveProjections {
				if p == projection {
					return true
				}
			}
		}
	}
	return false
}
