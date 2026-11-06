package bootstrap

import (
	app "asservat.local/asservat/internal/application/live"
	"asservat.local/asservat/internal/domain/collector"
	v "asservat.local/asservat/internal/domain/live"
	"context"
	"slices"
	"time"
)

// liveNodeReader is implemented by existing authenticated regional routing.
// No endpoint/address override or raw/native acquisition port is available.
type liveNodeReader interface {
	ReadLive(context.Context, collector.LiveRead) (v.NodeReply, error)
}
type liveRegionalReader interface {
	ReadLiveBatch(context.Context, []collector.LiveRead) ([]v.NodeReply, error)
}
type liveProjectionReader struct {
	remote liveRegionalReader
	now    func() time.Time
}
type liveNodeAnswer struct {
	value      v.NodeReply
	start, end time.Time
	err        error
}

func (r liveProjectionReader) fetch(ctx context.Context, sources []v.Source, projection string, positions []v.Position, limit int, head bool, waitMS int) ([]liveNodeAnswer, error) {
	if ctx == nil || ctx.Err() != nil || r.remote == nil || r.now == nil || len(sources) < 1 || len(sources) > v.MaxSources || len(positions) != len(sources) || limit < 1 || limit > v.MaxRows || !v.Projection(projection) || waitMS < 0 || waitMS > 5000 {
		return nil, v.ErrInvalid
	}
	deadline, ok := ctx.Deadline()
	if !ok {
		return nil, v.ErrInvalid
	}

	results := make([]liveNodeAnswer, len(sources))
	requests := make([]collector.LiveRead, len(sources))
	first := sources[0]
	for n, source := range sources {
		if !source.Valid(r.now()) || !slices.Contains(source.Projections, projection) || source.Target.ClusterID != first.Target.ClusterID || source.Root() != first.Root() || deadline.After(r.now().Add(5*time.Second)) {
			return nil, v.ErrUnavailable
		}
		requests[n] = collector.LiveRead{Binding: source.Binding, ClusterID: source.Target.ClusterID, NamespaceUID: source.Target.NamespaceUID, WorkloadUID: source.Target.WorkloadUID, Projection: projection, PrivacyUntil: source.PrivacyUntil, Generation: source.Generation, AfterSequence: positions[n].Sequence, AfterLost: positions[n].Lost, AfterClockLost: positions[n].ClockLost, AfterUnsupported: positions[n].Unsupported, AfterSensorLost: positions[n].SensorLost, Head: head, Limit: (limit + len(sources) - 1) / len(sources), WaitMS: waitMS, ReplyBytes: min(24<<10, (28<<10)/len(sources))}
		if source.Manual != nil {
			m := *source.Manual
			requests[n].Manual = &m
		}
	}
	// One regional query avoids multiplying work across the cluster's two
	// existing standbys. Its region fans out at most sixteen finite node reads.
	started := r.now()
	values, e := r.remote.ReadLiveBatch(ctx, requests)
	received := r.now()
	if e != nil || len(values) != len(sources) || ctx.Err() != nil {
		return nil, v.ErrUnavailable
	}
	for n, value := range values {
		if sources[n].Manual != nil {
			if value.Manual == nil || !value.Manual.SameBinding(*sources[n].Manual) || !value.Manual.StartedAt.Equal(sources[n].Manual.StartedAt) || !value.Manual.HardUntil.Equal(sources[n].Manual.HardUntil) {
				return nil, v.ErrUnavailable
			}
		} else if value.Manual != nil {
			return nil, v.ErrUnavailable
		}
		results[n] = liveNodeAnswer{value: value, start: started, end: received}
	}

	return results, nil
}
func (r liveProjectionReader) Head(ctx context.Context, sources []v.Source, projection string) ([]v.Position, error) {
	answers, e := r.fetch(ctx, sources, projection, make([]v.Position, len(sources)), v.MaxRows, true, 0)
	if e != nil {
		return nil, e
	}
	out := make([]v.Position, len(sources))
	for n, a := range answers {
		if a.err != nil || a.value.SourceID != sources[n].ID() || a.value.Fence != sources[n].Fence() || a.value.BootID != sources[n].Boot() || len(a.value.Rows) != 0 {
			return nil, v.ErrUnavailable
		}
		out[n] = a.value.Position
	}
	return out, nil
}
func (r liveProjectionReader) Read(ctx context.Context, sources []v.Source, projection string, positions []v.Position, limit, scan, waitMS int) (app.Projection, error) {
	out := app.Projection{Rows: []v.Row{}, Sources: []v.SourceStatus{}, Gaps: []v.Gap{}, Positions: append([]v.Position(nil), positions...)}
	if scan < 1 || scan > 4096 {
		return out, v.ErrInvalid
	}
	answers, e := r.fetch(ctx, sources, projection, positions, limit, false, waitMS)
	if e != nil {
		return app.Projection{}, e
	}
	until, _ := ctx.Deadline()
	for n, a := range answers {
		source := sources[n]
		id := source.ID()
		if a.err != nil {
			return app.Projection{}, v.ErrUnavailable
		}
		p := a.value
		if p.SourceID != id || p.Fence != source.Fence() || p.BootID != source.Boot() || p.Dropped < 0 || p.Dropped > v.MaxRows || p.Examined < 0 || p.Examined > scan-out.Examined || p.Bytes < 0 || p.Bytes > (1<<20)-out.Bytes || !p.Position.Follows(positions[n]) {
			return app.Projection{}, v.ErrUnavailable
		}
		out.Positions[n] = p.Position
		out.Examined += p.Examined
		out.Bytes += p.Bytes
		proof := v.ClockProof{SourceID: id, BootID: source.Boot(), Clock: p.Clock, RemoteNanos: p.Sample, StartedAt: a.start, ReceivedAt: a.end}
		status := v.SourceStatus{ID: id, State: source.State, Generation: source.Generation, Coverage: "observed"}
		lost := p.Position.Lost - positions[n].Lost
		for _, reason := range []struct {
			name  string
			value uint64
		}{{"clockUncertain", p.Position.ClockLost - positions[n].ClockLost}, {"unsupportedProtocol", p.Position.Unsupported - positions[n].Unsupported}, {"sensorLoss", p.Position.SensorLost - positions[n].SensorLost}} {
			if reason.value > 0 {
				count := int(min(uint64(1000000000), reason.value))
				out.Gaps = append(out.Gaps, v.Gap{SourceID: &id, Reason: reason.name, Count: &count, From: a.start, Until: a.end})
				status.Coverage = "partial"
				lost -= min(lost, reason.value)
			}
		}
		if lost > 0 {
			count := int(min(uint64(1000000000), lost))
			out.Gaps = append(out.Gaps, v.Gap{SourceID: &id, Reason: "projectionSampled", Count: &count, From: a.start, Until: a.end})
			status.Coverage = "partial"
		}
		if p.Dropped > 0 {
			count := p.Dropped
			out.Gaps = append(out.Gaps, v.Gap{SourceID: &id, Reason: "subscriberOverflow", Count: &count, From: a.start, Until: a.end})
			status.Coverage = "partial"
		}
		last := positions[n].Sequence
		for _, pending := range p.Rows {
			row := pending.Row
			if row.SourceID != id || row.PodUID != source.Pod() || row.Projection != projection || row.Sequence <= last || row.Sequence > p.Position.Sequence {
				return app.Projection{}, v.ErrUnavailable
			}
			last = row.Sequence
			at, end, uncertainty, ok := proof.Place(pending.Nanos, id, source.Boot(), pending.Clock, source.PrivacyUntil, source.HardUntil, until)
			if !ok {
				status.Coverage = "unknown"
				continue
			}
			row.ObservedAt = at
			row.ReceivedAt = a.end
			row.ExpiresAt = end
			row.ClockUncertainty = uncertainty
			if !row.Valid(r.now()) {
				status.Coverage = "unknown"
				continue
			}
			if len(out.Rows) >= limit {
				status.Coverage = "partial"
				continue
			}
			out.Rows = append(out.Rows, row.Clone())
			t := at
			status.LastObserved = &t
		}
		if status.Coverage == "unknown" {
			out.Gaps = append(out.Gaps, v.Gap{SourceID: &id, Reason: "clockUncertain", From: a.start, Until: a.end})
		}
		if status.Coverage == "partial" && len(p.Rows) > 0 && len(out.Rows) >= limit {
			out.Gaps = append(out.Gaps, v.Gap{SourceID: &id, Reason: "subscriberOverflow", From: a.start, Until: a.end})
		}
		if len(out.Gaps) > 32 {
			out.Gaps = out.Gaps[:31]
			out.Gaps = append(out.Gaps, v.Gap{Reason: "subscriberOverflow", From: a.start, Until: a.end})
		}
		out.Sources = append(out.Sources, status)
	}
	return out, nil
}
