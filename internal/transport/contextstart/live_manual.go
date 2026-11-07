package contextstart

import (
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/domain/targets"
	"asservat.local/asservat/internal/transport/node"
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

const queryManualLive = "inspect-manual-live"

// Response repeats only the positional capture identity, not the whole accepted
// target. The trusted caller independently restores/compares its original tuple.
type manualLiveWire struct {
	CaptureID              string
	Source                 *contracts.NodeManualLiveSource
	Unavailable            bool
	ObservedAt, FreshUntil time.Time
}

type manualLiveTargets interface {
	ResolveManualLive(context.Context, []targets.ManualLiveTarget) ([]targets.ManualLiveResolution, error)
}

func executorForManual(t targets.ManualLiveTarget) fleet.APIContextExecutor {
	p := t.Executor
	return fleet.APIContextExecutor{NamespaceUID: p.NamespaceUID, AccountUID: p.AccountUID, PodUID: p.PodUID, ProcessEpoch: p.ProcessEpoch, StartupDigest: p.StartupDigest, ImageDigest: p.ImageDigest}
}
func validManualTargets(in []targets.ManualLiveTarget) bool {
	if len(in) < 1 || len(in) > 16 {
		return false
	}
	seen := map[string]bool{}
	for _, t := range in {
		if !t.Valid() || seen[t.CaptureID] {
			return false
		}
		seen[t.CaptureID] = true
	}
	return true
}

// ResolveManualLive uses only original already-started executor holders. One
// query per distinct regional process (<=16), joined under the same original
// caller deadline; it never retries another holder or starts collection.
func (t Targets) ResolveManualLive(ctx context.Context, in []targets.ManualLiveTarget) ([]targets.ManualLiveResolution, error) {
	if ctx == nil || ctx.Err() != nil || t.Router == nil || t.Now == nil || !validManualTargets(in) {
		return nil, targets.ErrInvalid
	}
	call, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	type group struct {
		indices []int
		values  []targets.ManualLiveTarget
	}
	groups := map[[3]string]*group{}
	for n, v := range in {
		k := [3]string{v.Target.ClusterID, v.Executor.PodUID, v.Executor.ProcessEpoch}
		g := groups[k]
		if g == nil {
			g = &group{}
			groups[k] = g
		}
		g.indices = append(g.indices, n)
		g.values = append(g.values, v)
	}
	out := make([]targets.ManualLiveResolution, len(in))
	errs := make(chan error, len(groups))
	var wg sync.WaitGroup
	for _, g := range groups {
		wg.Add(1)
		go func(g *group) {
			defer wg.Done()
			var reply []manualLiveWire
			first := g.values[0]
			until, e := t.Router.QueryProcess(call, first.Target.ClusterID, queryManualLive, g.values, &reply, first.Executor.PodUID, first.Executor.ProcessEpoch)
			if e != nil || len(reply) != len(g.values) || call.Err() != nil || !t.Now().Before(until) {
				errs <- fmt.Errorf("%w: manual-query (%v, replies %d of %d)", targets.ErrUnavailable, e, len(reply), len(g.values))
				return
			}
			for n, w := range reply {
				if w.CaptureID != g.values[n].CaptureID || (w.Source == nil) != w.Unavailable {
					errs <- fmt.Errorf("%w: manual-reply-shape", targets.ErrUnavailable)
					return
				}
				v := targets.ManualLiveResolution{Original: g.values[n], Unavailable: w.Unavailable, ObservedAt: w.ObservedAt, FreshUntil: w.FreshUntil}
				if w.Source != nil {
					var ok bool
					v.Source, ok = node.DomainManualLive(*w.Source)
					if !ok {
						errs <- fmt.Errorf("%w: manual-reply-source", targets.ErrUnavailable)
						return
					}
				}
				if !v.Valid(t.Now()) || v.FreshUntil.After(until) {
					errs <- fmt.Errorf("%w: manual-reply-fresh", targets.ErrUnavailable)
					return
				}
				out[g.indices[n]] = v
			}
		}(g)
	}
	wg.Wait()
	close(errs)
	if len(errs) > 0 {
		return nil, <-errs
	}
	if call.Err() != nil {
		return nil, fmt.Errorf("%w: manual-deadline", targets.ErrUnavailable)
	}
	return out, nil
}
func (s *frameStream) answerManualLive(ctx context.Context, raw json.RawMessage) (any, error) {
	var in []targets.ManualLiveTarget
	if decodeOperationBody(raw, &in) != nil || !validManualTargets(in) {
		return nil, contracts.ErrAPIContextProtocol
	}
	until, _ := ctx.Deadline()
	for _, t := range in {
		if t.RootID != s.channel.RootID || t.Target.ClusterID != s.channel.Connector.Binding.ClusterID || executorForManual(t) != s.channel.Executor || t.Executor.InstallationID != s.channel.Connector.Binding.InstallationID || t.Executor.IssuerEpoch != s.channel.Connector.Binding.IssuerEpoch {
			return nil, contracts.ErrAPIContextProtocol
		}
	}
	resolver, ok := s.targets.(manualLiveTargets)
	if !ok {
		return nil, targets.ErrUnsupported
	}
	values, e := resolver.ResolveManualLive(ctx, in)
	if e != nil || len(values) != len(in) {
		return nil, targets.ErrUnavailable
	}
	wire := make([]manualLiveWire, len(values))
	for n, v := range values {
		if v.Original != in[n] || !v.Valid(time.Now()) {
			return nil, targets.ErrUnavailable
		}
		wire[n] = manualLiveWire{CaptureID: v.Original.CaptureID, Unavailable: v.Unavailable, ObservedAt: v.ObservedAt, FreshUntil: identity.Earlier(v.FreshUntil, until)}
		if !v.Unavailable {
			m := node.WireManualLive(v.Source)
			wire[n].Source = &m
		}
	}
	return wire, nil
}
