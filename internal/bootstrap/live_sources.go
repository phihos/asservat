package bootstrap

import (
	"context"
	"fmt"
	"slices"
	"time"

	authapp "asservat.local/asservat/internal/application/authorization"
	captureapp "asservat.local/asservat/internal/application/capture"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/domain/live"
	"asservat.local/asservat/internal/domain/targets"
)

type liveCandidateReader interface {
	captureapp.RecordingCandidates
	LiveSourceTarget(context.Context, string) (authorization.Target, error)
}
type livePolicyReader interface {
	SourcePolicy(context.Context, string, string) (captureapp.RecordingPolicy, error)
}
type liveSourceStatusReader interface {
	ResolveSourceSnapshots(context.Context, []targets.SourceSnapshotTarget) ([]targets.SourceSnapshotResolution, error)
}

// liveSourceCatalog reuses protected accepted source rows and authenticated
// reports. It has no arm, renew, snapshot, raw read or Pod replacement port.
type liveSourceCatalog struct {
	root       string
	candidates liveCandidateReader
	policies   livePolicyReader
	status     liveSourceStatusReader
	now        func() time.Time
}

func (s liveSourceCatalog) configured() bool {
	return authorization.UUID(s.root) && s.candidates != nil && s.policies != nil && s.status != nil && s.now != nil
}
func (s liveSourceCatalog) LiveSourceTarget(ctx context.Context, id, kind string) (authorization.Target, error) {
	if !s.configured() || kind != "policy" {
		return authorization.Target{}, fmt.Errorf("%w: live_sources:43", live.ErrUnavailable)
	}
	return s.candidates.LiveSourceTarget(ctx, id)
}
func (s liveSourceCatalog) ReadLiveSource(ctx context.Context, expected live.Source) (authapp.LiveSourceRecord, error) {
	return s.ReadLiveSourceID(ctx, expected.Target, expected.ID(), expected.OwnerKind)
}
func (s liveSourceCatalog) ReadLiveSourceID(ctx context.Context, target authorization.Target, id, kind string) (authapp.LiveSourceRecord, error) {
	if !s.configured() || kind != "policy" || !target.Valid() || !authorization.UUID(id) {
		return authapp.LiveSourceRecord{}, fmt.Errorf("%w: live_sources:52", live.ErrUnavailable)
	}
	w := authorization.WorkloadTarget{ClusterID: target.ClusterID, NamespaceUID: target.NamespaceUID, WorkloadUID: target.WorkloadUID}
	rows, e := s.candidates.RecordingSources(ctx, w, []string{id})
	if e != nil || len(rows) != 1 || rows[0].Source.Binding.SourceID != id || rows[0].Source.Target == nil || rows[0].Source.Target.Target() != target {
		return authapp.LiveSourceRecord{}, fmt.Errorf("%w: live_sources:57", live.ErrUnavailable)
	}
	out, e := s.records(ctx, rows)
	if e != nil || len(out) != 1 {
		return authapp.LiveSourceRecord{}, fmt.Errorf("%w: live_sources:61", live.ErrUnavailable)
	}
	return out[0], nil
}
func (s liveSourceCatalog) ListLiveSources(ctx context.Context, target authorization.WorkloadTarget, cursor string, limit int) ([]authapp.LiveSourceRecord, string, error) {
	if !s.configured() || ctx == nil || ctx.Err() != nil || !target.Valid() || limit < 1 || limit > 100 || cursor != "" && !authorization.UUID(cursor) {
		return nil, "", fmt.Errorf("%w: live_sources:67", live.ErrInvalid)
	}
	page, e := s.candidates.RecordingCandidates(ctx, target, captureapp.RecordingCandidateQuery{AfterSourceID: cursor})
	if e != nil || len(page.Rows) > 100 {
		return nil, "", fmt.Errorf("%w: live_sources:71", live.ErrUnavailable)
	}
	next := ""
	rows := page.Rows
	if len(rows) > limit {
		rows = rows[:limit]
		next = rows[len(rows)-1].Source.Binding.SourceID
	} else if page.More {
		next = page.AfterSourceID
	}
	for _, row := range rows {
		if row.Source.ClusterID != target.ClusterID || row.Source.NamespaceUID != target.NamespaceUID || row.Source.WorkloadUID != target.WorkloadUID {
			return nil, "", fmt.Errorf("%w: live_sources:83", live.ErrUnavailable)
		}
	}
	out, e := s.records(ctx, rows)
	if e != nil {
		return nil, "", e
	}
	return out, next, nil
}
func (s liveSourceCatalog) records(ctx context.Context, rows []captureapp.RecordingCandidate) ([]authapp.LiveSourceRecord, error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, fmt.Errorf("%w: live_sources:94", live.ErrUnavailable)
	}
	observed := s.now()
	policies := map[string]captureapp.RecordingPolicy{}
	refused := map[string]bool{}
	out := make([]authapp.LiveSourceRecord, 0, len(rows))
	originals := make([]targets.SourceSnapshotTarget, 0, len(rows))
	expected := make([]string, 0, len(rows))
	for _, candidate := range rows {
		state := candidate.Source
		b := state.Binding
		if b.RootID != s.root || !b.Valid() || state.Target == nil || !state.Target.Valid() || state.Target.SourceID != b.SourceID || state.Target.Fence != b.Fence {
			return nil, fmt.Errorf("%w: live_sources:106", live.ErrUnavailable)
		}
		p, ok := policies[b.PolicyUID]
		if !ok && !refused[b.PolicyUID] {
			var e error
			p, e = s.policies.SourcePolicy(ctx, candidate.PolicyName, b.PolicyUID)
			if e != nil {
				refused[b.PolicyUID] = true
				continue
			}
			policies[b.PolicyUID] = p
		}
		if refused[b.PolicyUID] {
			continue
		}
		a := p.Accepted.Authority
		rec := p.Policy.RecorderFor(b.ActionID)
		if rec == nil || rec.Action.ExecutionMode != "ongoing" || a.PolicyUID != b.PolicyUID || [32]byte(a.ScopeDigest) != b.Scope || rec.Digest != artifact.Digest(b.ExpectationDigest) || a.ClusterID != state.ClusterID || a.NamespaceUID != state.NamespaceUID || a.WorkloadUID != state.WorkloadUID {
			continue
		}
		projection := ""
		switch {
		case rec.Action.Kind == "packetCapture" && rec.Action.PacketProfile == "networkHeaders":
			projection = live.Packet
		case rec.Action.Kind == "packetCapture" && rec.Action.PacketProfile == "httpHeaders" && rec.HTTP.Valid():
			projection = live.HTTP
		case rec.Action.Kind == "syscallTrace" && rec.Action.SyscallMode == "metadata":
			projection = live.Syscall
		}
		if projection == "" {
			continue
		}
		save := "unavailable"
		if p.Policy.RecordingSaves {
			save = "recordingSave"
		}
		source := live.Source{Binding: b, Target: state.Target.Target(), OwnerKind: "policy", OwnerID: b.PolicyUID, State: "Unavailable", SaveVia: save, Projections: []string{}, Blockers: []string{"SourceUnavailable"}, LeaseUntil: state.InitialLeafUntil, HardUntil: state.HardUntil, PrivacyUntil: state.HardUntil}
		if !source.ReferenceValid() {
			return nil, fmt.Errorf("%w: live_sources:144", live.ErrUnavailable)
		}
		out = append(out, authapp.LiveSourceRecord{Source: source, Audience: append([]artifact.AudienceAssignment(nil), state.Audience...), Executor: a.Executor, ObservedAt: observed, ValidUntil: identity.Earlier(observed.Add(5*time.Second), p.Accepted.FreshUntil)})
		originals = append(originals, *state.Target)
		expected = append(expected, projection)
	}
	// Existing status batching is eight per frame, at most sixteen per call.
	// An unavailable chunk remains explicit; never retry it as independent calls.
	for first := 0; first < len(out); first += 16 {
		end := min(first+16, len(out))
		values, e := s.status.ResolveSourceSnapshots(ctx, originals[first:end])
		if e != nil {
			if ctx.Err() != nil {
				return nil, fmt.Errorf("%w: live_sources:157", live.ErrUnavailable)
			}
			continue
		}
		if len(values) != end-first {
			return nil, fmt.Errorf("%w: live_sources:162", live.ErrUnavailable)
		}
		for n, value := range values {
			index := first + n
			source := &out[index].Source
			if value.Original != originals[index] || !value.Valid(s.now()) {
				return nil, fmt.Errorf("%w: live_sources:168", live.ErrUnavailable)
			}
			source.LeaseUntil = identity.Earlier(value.State.LeafUntil, source.HardUntil)
			out[index].ValidUntil = identity.Earlier(out[index].ValidUntil, value.FreshUntil)
			source.Blockers = []string{}
			source.State = "Ready"
			if value.State.Stopped {
				source.State = "Stopped"
				source.Blockers = append(source.Blockers, "SourceStopped")
			}
			if value.State.InputUnknown && !value.State.Stopped {
				source.State = "Degraded"
				source.Blockers = append(source.Blockers, "SourceInputUnknown")
			}
			if slices.Contains(value.LiveProjections, expected[index]) {
				source.Projections = []string{expected[index]}
			} else {
				source.State = "Unavailable"
				source.Blockers = append(source.Blockers, "ProjectionUnavailable")
			}
		}
	}
	if ctx.Err() != nil {
		return nil, fmt.Errorf("%w: live_sources:191", live.ErrUnavailable)
	}
	return out, nil
}

// ReadLiveSourceRecords performs one protected exact-ID scan per authorization
// phase after C3 has checked current Pod rights for the complete selection.
func (s liveSourceCatalog) ReadLiveSourceRecords(ctx context.Context, refs []live.SourceReference) ([]authapp.LiveSourceRecord, error) {
	if !s.configured() || len(refs) < 1 || len(refs) > live.MaxSources {
		return nil, fmt.Errorf("%w: live_sources:200", live.ErrInvalid)
	}
	first := refs[0].Target
	target := authorization.WorkloadTarget{ClusterID: first.ClusterID, NamespaceUID: first.NamespaceUID, WorkloadUID: first.WorkloadUID}
	ids := make([]string, len(refs))
	seen := map[string]bool{}
	for n, ref := range refs {
		if !ref.Target.Valid() || ref.Kind != "policy" || ref.Target.ClusterID != first.ClusterID || ref.Target.NamespaceUID != first.NamespaceUID || ref.Target.WorkloadUID != first.WorkloadUID || !authorization.UUID(ref.ID) || seen[ref.ID] {
			return nil, fmt.Errorf("%w: live_sources:208", live.ErrDenied)
		}
		seen[ref.ID] = true
		ids[n] = ref.ID
	}
	rows, e := s.candidates.RecordingSources(ctx, target, ids)
	if e != nil || len(rows) != len(refs) {
		return nil, fmt.Errorf("%w: live_sources:215", live.ErrUnavailable)
	}
	records, e := s.records(ctx, rows)
	if e != nil || len(records) != len(refs) {
		return nil, fmt.Errorf("%w: live_sources:219", live.ErrUnavailable)
	}
	indexed := map[string]authapp.LiveSourceRecord{}
	for _, record := range records {
		id := record.Source.ID()
		if _, ok := indexed[id]; ok || !seen[id] {
			return nil, fmt.Errorf("%w: live_sources:225", live.ErrUnavailable)
		}
		indexed[id] = record
	}
	out := make([]authapp.LiveSourceRecord, len(refs))
	for n, ref := range refs {
		record, ok := indexed[ref.ID]
		if !ok || record.Source.Target != ref.Target {
			return nil, fmt.Errorf("%w: live_sources:233", live.ErrUnavailable)
		}
		out[n] = record
	}
	return out, nil
}
