package bootstrap

import (
	"asservat.local/asservat/internal/application/delivery"
	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/collector"
	"asservat.local/asservat/internal/domain/identity"
	v "asservat.local/asservat/internal/domain/live"
	"asservat.local/asservat/internal/domain/targets"
	"context"
	"os"
	"sync"
	"time"
)

// manualHolderLocked checks original accepted provenance and the live regional
// holder without manufacturing policy/source authority. It never prepares,
// starts, collects, cancels or replaces a recording. Call with holder.mu held.
func (h *ConnectorRecordings) manualHolderLocked(t targets.ManualLiveTarget) (*heldRecording, bool) {
	p := h.held[t.CaptureID]
	if p == nil || p.cancelRequested || p.cancelOnly || p.storing || p.resultArrived || p.resultJoined || p.workID == "" || p.outcome.State != evidence.RecordingPending || !h.now().Before(t.WriteUntil) {
		return nil, false
	}
	e := p.expectation
	if e.Recording == nil || e.Snapshot != nil || e.CaptureUID != t.CaptureID || e.ActionID != t.ActionID || e.Registration.Location.AttemptID != t.AttemptID || e.PlanDigest != t.Scope || p.digest != t.ExpectationDigest || e.Registration.Location.ClusterID != t.Target.ClusterID || e.NamespaceUID != t.Target.NamespaceUID || e.WorkloadUID != t.Target.WorkloadUID || e.PodUID != t.Target.PodUID || !e.Registration.WriteUntil.Equal(t.WriteUntil) {
		return nil, false
	}
	projection := "packetMetadata"
	if e.Recording.Kind == "syscallTrace" {
		projection = "syscallMetadata"
	} else if e.Recording.Profile == "httpHeaders" {
		projection = "httpHeaders"
	}
	if t.Projection != projection || t.Executor.ImageDigest != e.CollectorImageDigest {
		return nil, false
	}
	expectedKind := ""
	if e.Recording.Arguments != nil {
		expectedKind = "arguments"
	} else if e.NativeType == artifact.RawPCAPNGArtifact || e.NativeType == artifact.HTTPHeadersArtifact {
		expectedKind = "packet"
	}
	if t.ObservationKind != expectedKind {
		return nil, false
	}
	return p, true
}

// ResolveManualLive obtains the actual node holder's original start/end. The
// accepted SQL preparation deadline is deliberately absent from this API.
func (t reportedTargets) ResolveManualLive(ctx context.Context, in []targets.ManualLiveTarget) ([]targets.ManualLiveResolution, error) {
	if ctx == nil || ctx.Err() != nil || t.recordings == nil || len(in) < 1 || len(in) > 16 {
		return nil, targets.ErrInvalid
	}
	h := t.recordings
	registry, ok := h.nodes.(interface {
		NodeByUID(string) (delivery.NodeView, bool)
	})
	if !ok {
		return nil, targets.ErrUnsupported
	}
	reader, ok := h.nodes.(liveNodeReader)
	if !ok {
		return nil, targets.ErrUnsupported
	}
	deadline, ok := ctx.Deadline()
	if !ok {
		return nil, targets.ErrInvalid
	}
	out := make([]targets.ManualLiveResolution, len(in))
	var wg sync.WaitGroup
	for n, original := range in {
		if !original.Valid() {
			return nil, targets.ErrInvalid
		}
		wg.Add(1)
		go func(n int, original targets.ManualLiveTarget) {
			defer wg.Done()
			at := h.now()
			until := identity.Earlier(identity.Earlier(at.Add(5*time.Second), deadline), original.WriteUntil)
			unavailable := targets.ManualLiveResolution{Original: original, Unavailable: true, ObservedAt: at, FreshUntil: until}
			out[n] = unavailable
			reason := "holder"
			defer func() {
				if out[n].Unavailable {
					manualLiveRefused(reason)
				}
			}()
			h.mu.Lock()
			p, valid := h.manualHolderLocked(original)
			var nodeUID, workID string
			var queued time.Time
			var duration time.Duration
			if valid {
				nodeUID, workID = p.nodeUID, p.workID
				queued = p.queued
				duration = time.Duration(p.expectation.Recording.DurationMillis) * time.Millisecond
			}
			h.mu.Unlock()
			if !valid {
				return
			}
			view, valid := registry.NodeByUID(nodeUID)
			reason = "node"
			if !valid || !view.Current || !view.LiveAvailable(original.Projection) {
				return
			}
			id := view.Identity
			m := collector.ManualLiveSource{RootID: original.RootID, CaptureID: original.CaptureID, AttemptID: original.AttemptID, ActionID: original.ActionID, WorkID: workID, PodUID: original.Target.PodUID, NodeUID: id.NodeUID, BootID: id.BootID, CollectorPodUID: id.PodUID, CollectorEpoch: id.Epoch, ExecutorPodUID: original.Executor.PodUID, ExecutorEpoch: original.Executor.ProcessEpoch, Scope: [32]byte(original.Scope), ExpectationDigest: [32]byte(original.ExpectationDigest), ObservationKind: original.ObservationKind, ObservationSessionID: original.ObservationSessionID, ObservationFence: original.ObservationFence}
			r := collector.LiveRead{Manual: &m, Inspect: true, ClusterID: original.Target.ClusterID, NamespaceUID: original.Target.NamespaceUID, WorkloadUID: original.Target.WorkloadUID, Projection: original.Projection, PrivacyUntil: original.WriteUntil, Head: true, Limit: 1, ReplyBytes: 2048}
			reason = "request"
			if !r.Valid() {
				return
			}
			reply, e := reader.ReadLive(ctx, r)
			if e == nil {
				reply, e = v.BindManualLiveReply(r, reply)
			}
			reason = "inspect"
			if e != nil {
				reason = "inspect-error"
			}
			if e != nil || reply.Manual == nil || reply.SourceID != m.CaptureID || reply.Fence != m.WorkID || reply.BootID != m.BootID || len(reply.Rows) != 0 || !reply.Manual.SameBinding(m) {
				return
			}
			reason = "window"
			if reply.Manual.StartedAt.Before(queued) || reply.Manual.HardUntil.Sub(reply.Manual.StartedAt) > duration {
				return
			}
			until = identity.Earlier(until, reply.Manual.HardUntil)
			current := targets.ManualLiveResolution{Original: original, Source: *reply.Manual, ObservedAt: at, FreshUntil: until}
			reason = "holder-changed"
			h.mu.Lock()
			again, live := h.manualHolderLocked(original)
			same := live && again == p && again.workID == workID && again.nodeUID == nodeUID
			h.mu.Unlock()
			if !same || ctx.Err() != nil || !current.Valid(h.now()) {
				return
			}
			out[n] = current
		}(n, original)
	}
	wg.Wait()
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	return out, nil
}

func (h *ConnectorRecordings) manualReadHolderLocked(r collector.LiveRead) (*heldRecording, bool) {
	if r.Manual == nil || !r.Manual.Valid() || r.Inspect {
		return nil, false
	}
	m := *r.Manual
	p := h.held[m.CaptureID]
	if p == nil || p.cancelRequested || p.cancelOnly || p.storing || p.resultArrived || p.resultJoined || p.outcome.State != evidence.RecordingPending || p.workID != m.WorkID || p.nodeUID != m.NodeUID {
		return nil, false
	}
	e := p.expectation
	if e.Recording == nil || e.Snapshot != nil || e.CaptureUID != m.CaptureID || e.ActionID != m.ActionID || e.Registration.Location.AttemptID != m.AttemptID || e.PlanDigest != artifact.Digest(m.Scope) || p.digest != artifact.Digest(m.ExpectationDigest) || e.Registration.Location.ClusterID != r.ClusterID || e.NamespaceUID != r.NamespaceUID || e.WorkloadUID != r.WorkloadUID || e.PodUID != m.PodUID || manualProjection(e) != r.Projection || m.StartedAt.Before(p.queued) || m.HardUntil.Sub(m.StartedAt) > time.Duration(e.Recording.DurationMillis)*time.Millisecond || m.HardUntil.After(e.Registration.WriteUntil) || r.PrivacyUntil.After(e.Registration.WriteUntil) || !h.now().Before(m.HardUntil) {
		return nil, false
	}
	return p, true
}

// manualLiveRefused reports why a manual live source resolved unavailable;
// fixed stage words only, on the stable doubling sequence.
var manualLiveRefused = eventLog(os.Stderr, "regional manual live unavailable")
