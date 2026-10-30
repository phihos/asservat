package delivery

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"

	"asservat.local/asservat/internal/domain/collector"
	"asservat.local/asservat/internal/domain/targets"
)

// EnqueueSourceExpected carries a committed ordinary source-purpose permit to
// exactly the current authenticated collector process. A successful enqueue is
// neither an attach ACK nor evidence of continuously observed history.
func (c *NodeChannel) EnqueueSourceExpected(ctx context.Context, expected targets.PacketSourceObservation, source collector.PacketSource) (collector.Work, error) {
	if !source.Valid() || SourceResourcesDigest(source.Resources) != source.Permit.Binding.ResourceDigest {
		return collector.Work{}, ErrNodeInvalid
	}
	copy := source
	copy.Program = append(copy.Program[:0:0], source.Program...)
	until := source.Permit.DispatchUntil
	if ctx != nil {
		if end, ok := ctx.Deadline(); ok && end.Before(until) {
			until = end
		}
	}
	if expected.FreshUntil.Before(until) {
		until = expected.FreshUntil
	}
	return c.enqueueSource(ctx, &expected, &copy, nil, nil, until)
}

// EnqueueSourceStop only narrows the exact named incarnation. It needs no
// fresh workload observation: deletion or lost recorder capability must not
// prevent an authenticated exact-process stop from being delivered.
func (c *NodeChannel) EnqueueSourceStop(ctx context.Context, binding collector.SourceBinding, notAfter time.Time) (collector.Work, error) {
	if !binding.Valid() {
		return collector.Work{}, ErrNodeInvalid
	}
	return c.enqueueSource(ctx, nil, nil, &binding, nil, notAfter)
}

func (c *NodeChannel) enqueueSource(ctx context.Context, expected *targets.PacketSourceObservation, source *collector.PacketSource, stop *collector.SourceBinding, snapshot *collector.SourceSnapshot, until time.Time) (collector.Work, error) {
	if ctx == nil || ctx.Err() != nil {
		return collector.Work{}, ErrNodeInvalid
	}
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return collector.Work{}, ErrNodeUnavailable
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	b := stop
	if snapshot != nil {
		b = &snapshot.Binding
	}
	if source != nil {
		b = &source.Permit.Binding
	}
	if b == nil {
		return collector.Work{}, ErrNodeInvalid
	}
	now := c.now()
	e := c.nodes[b.NodeUID]
	if ctx.Err() != nil || e == nil || !now.Before(until) || until.After(now.Add(5*time.Second)) {
		return collector.Work{}, ErrNodeUnavailable
	}
	if deadline, ok := ctx.Deadline(); !ok || until.After(deadline) {
		return collector.Work{}, ErrNodeUnavailable
	}
	if source != nil {
		if expected == nil || !expected.Valid(now) || b.PodUID != expected.PodUID || b.NodeUID != expected.NodeUID || b.BootID != expected.BootID || b.CollectorPodUID != expected.CollectorPodUID || b.CollectorEpoch != expected.CollectorEpoch || !c.view(e, now).PacketRecorderAvailable() || !source.Permit.Dispatchable(now) {
			return collector.Work{}, ErrNodeUnavailable
		}
		// Same-process certificate renewal preserves the source incarnation;
		// each leaf must still fit a currently accepted certificate's expiry.
		covered := false
		for _, end := range e.certs {
			if !source.Permit.LeafUntil.After(end) {
				covered = true
				break
			}
		}
		if !covered {
			return collector.Work{}, ErrNodeUnavailable
		}
	}
	if b.NodeUID != e.id.NodeUID || b.BootID != e.id.BootID || b.CollectorPodUID != e.id.PodUID || b.CollectorEpoch != e.id.Epoch {
		return collector.Work{}, ErrNodeUnavailable
	}
	if snapshot != nil {
		for key, pending := range e.captures {
			if !now.Before(pending.until) {
				delete(e.captures, key)
			}
		}
		if len(e.captures) >= collector.MaxQueuedWork {
			return collector.Work{}, ErrNodeLimit
		}
	}
	if len(e.work) >= collector.MaxQueuedWork || e.nextSeq == ^uint64(0) {
		return collector.Work{}, ErrNodeLimit
	}
	e.nextSeq++
	h := hex.EncodeToString(raw[:])
	kind := collector.WorkPacketSource
	if snapshot != nil {
		kind = collector.WorkPacketSourceSnapshot
	}
	if stop != nil {
		kind = collector.WorkStopPacketSource
	}
	w := collector.Work{ID: h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:], Sequence: e.nextSeq, Kind: kind, NotAfter: until, Source: source, StopSource: stop, Snapshot: snapshot}
	if snapshot != nil {
		owned := *snapshot
		e.captures[w.ID] = pendingCapture{captureID: snapshot.CaptureID, until: snapshot.Request.ProcessingUntil, snapshot: &owned}
	}
	e.work = append(e.work, w)
	close(e.wake)
	e.wake = make(chan struct{})
	return w, nil
}

// SourceResourcesDigest binds the exact protected policy and typed lowerings.
// Canonical encoding/hashing stays at the application boundary; domain values
// retain their existing structural-only role and dependency constraints.
func SourceResourcesDigest(r collector.SourceResources) [32]byte {
	limits := struct {
		Node     collector.PolicyLimits
		Workload collector.SourceLimits
	}{r.Node, r.Workload}
	b, _ := json.Marshal(struct {
		PolicyUID string
		Limits    any
	}{r.PolicyUID, limits})
	return sha256.Sum256(b)
}

// SourceBindingDigest binds a saved window to its exact original source purpose.
func SourceBindingDigest(b collector.SourceBinding) [32]byte {
	encoded, _ := json.Marshal(b)
	return sha256.Sum256(encoded)
}

// EnqueueSourceSnapshot queues a committed save for the exact existing source.
func (c *NodeChannel) EnqueueSourceSnapshot(ctx context.Context, snapshot collector.SourceSnapshot) (collector.Work, error) {
	if !snapshot.Valid() || SourceBindingDigest(snapshot.Binding) != [32]byte(snapshot.Request.SourceBindingDigest) {
		return collector.Work{}, ErrNodeInvalid
	}
	until := snapshot.Request.StartBy
	if ctx != nil {
		if end, ok := ctx.Deadline(); ok && end.Before(until) {
			until = end
		}
	}
	return c.enqueueSource(ctx, nil, nil, nil, &snapshot, until)
}

// NodeByUID reads the exact attested incarnation without resolving a Pod name.
func (c *NodeChannel) NodeByUID(uid string) (NodeView, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e := c.nodes[uid]
	if e == nil {
		return NodeView{}, false
	}
	return c.view(e, c.now()), true
}
