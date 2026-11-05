package processes

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"time"

	query "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
)

// Query validates the complete native source before returning a bounded page.
// Neither a cursor nor a reached row bound can bypass the tail/authentication
// checks owned by the surrounding native reader.
func Query(ctx context.Context, r io.Reader, e artifact.ContextExpectation, from, until time.Time, w query.TargetDiscoveryWindow, version artifact.Digest) (query.ProjectionResult, error) {
	var zero query.ProjectionResult
	if ctx == nil || ctx.Err() != nil || r == nil || !w.Valid() || e.NativeType != artifact.ProcessesArtifact || e.DataClass != "metadata" || !e.Processes.Valid() || version == (artifact.Digest{}) {
		return zero, query.ErrUnavailable
	}
	raw, err := io.ReadAll(io.LimitReader(r, e.Registration.NativeLimit+1))
	if err != nil || int64(len(raw)) > e.Registration.NativeLimit {
		return zero, query.ErrUnavailable
	}
	defer clear(raw)
	native, err := DecodeProcesses(raw)
	if err != nil || native.PodUID != e.PodUID || native.Mode != e.Processes.Mode || native.StartedAt.Before(from) || native.CompletedAt.After(until) || ctx.Err() != nil {
		return zero, query.ErrUnavailable
	}
	if !w.Matches(e.CaptureUID, e.Registration.Location.ArtifactID, version) || w.Start > len(native.Processes) || w.Start == len(native.Processes) && w.Start != 0 {
		return query.ProjectionResult{InvalidCursor: true}, nil
	}
	p := query.TargetDiscoveryPage{CaptureID: e.CaptureUID, ArtifactID: e.Registration.Location.ArtifactID, PodUID: e.PodUID, Section: w.Section, Version: version, StartedAt: native.StartedAt, EndedAt: native.CompletedAt, RetainedBytes: int64(len(raw)), InventoryComplete: native.Mode == artifact.ProcessAll, Start: w.Start, Total: len(native.Processes), Processes: []query.TargetDiscoveryProcess{}, Gaps: append([]string{}, native.Gaps...), StopReason: "completed"}
	for _, o := range native.Origins {
		if o.Outcome == "observed" {
			p.CoveredPods = 1
		} else {
			p.InventoryComplete = false
			p.StopReason = "capabilityGap"
		}
	}
	if p.CoveredPods == 0 {
		p.StopReason = "capabilityGap"
		p.InventoryComplete = false
	}
	for _, g := range native.Gaps {
		if g != "socketOwnersUnsupported" {
			p.InventoryComplete = false
			if g == "processLimit" || g == "containerLimit" || g == "cgroupLimit" {
				p.StopReason = "outputLimit"
			} else if p.StopReason != "outputLimit" {
				p.StopReason = "capabilityGap"
			}
		}
	}
	if w.Section == "summary" {
		if !p.Valid(w) {
			return zero, query.ErrUnavailable
		}
		return query.ProjectionResult{TargetDiscovery: &p}, nil
	}
	main := map[string]artifact.ProcessRecord{}
	for _, r := range native.Processes {
		if r.Main {
			main[r.Identity.RuntimeID] = r
		}
	}
	for n := w.Start; n < len(native.Processes) && len(p.Processes) < w.Limit; n++ {
		r := native.Processes[n]
		row := query.TargetDiscoveryProcess{ProcessRef: processRef(e, version, r.Identity), PodUID: r.Identity.PodUID, DisplayPID: r.NamespacePID, ExecutablePath: r.ExecutablePath, RSSBytes: r.RSSBytes, ObservedAt: r.ObservedAt}
		// Only the runtime-identified main is independently pinned across
		// this member's read. Other raw PPIDs do not establish a stable parent.
		if parent, ok := main[r.Identity.RuntimeID]; ok && !r.Main && r.ParentPID == parent.Identity.HostPID {
			row.ParentRef = processRef(e, version, parent.Identity)
		}
		p.Processes = append(p.Processes, row)
		if p.EncodedSize() > query.TargetDiscoveryPageBytes {
			p.Processes = p.Processes[:len(p.Processes)-1]
			if len(p.Processes) == 0 {
				return query.ProjectionResult{TooLarge: true}, nil
			}
			break
		}
	}
	if ctx.Err() != nil || !p.Valid(w) {
		return zero, query.ErrUnavailable
	}
	return query.ProjectionResult{TargetDiscovery: &p}, nil
}

func processRef(e artifact.ContextExpectation, version artifact.Digest, i artifact.ProcessIdentity) string {
	b, _ := json.Marshal(i)
	h := sha256.New()
	h.Write([]byte("process-ref/v1\x00" + e.CaptureUID + e.Registration.Location.ArtifactID))
	h.Write(version[:])
	h.Write(b)
	return hex.EncodeToString(h.Sum(nil))
}
