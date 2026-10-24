package privacy

import (
	configuration "asservat.local/asservat/internal/application/configuration"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	value "asservat.local/asservat/internal/domain/privacy"
	"context"
	"crypto/sha256"
	"encoding/json"
	"slices"
	"time"
)

type RetentionSelectorReader interface {
	ProtectedRetentionSelectors(context.Context, authorization.Target, []string, []string) (value.SelectorFacts, error)
}

// AcceptedRetentionReader composes C-01's complete accepted source topology and
// protected selector observations. It never promotes a raw API read to authority.
type AcceptedRetentionReader struct {
	Topology  configuration.RetentionTopologyReader
	Sources   configuration.RetentionSourceReader
	Selectors RetentionSelectorReader
	Now       func() time.Time
}

var _ RetentionReader = AcceptedRetentionReader{}
var _ RetainedPolicyReader = AcceptedRetentionReader{}

func (r AcceptedRetentionReader) RetentionPolicies(ctx context.Context, t authorization.Target) (value.PolicySet, error) {
	return r.read(ctx, t, nil)
}
func (r AcceptedRetentionReader) RetainedRetentionPolicies(ctx context.Context, t authorization.Target, origins []artifact.RetentionRule) (value.PolicySet, error) {
	if !value.ValidPolicyOrigins(origins) {
		return value.PolicySet{}, value.ErrInvalid
	}
	return r.read(ctx, t, slices.Clone(origins))
}
func stableDigest(v any) artifact.Digest { b, _ := json.Marshal(v); return sha256.Sum256(b) }
func (r AcceptedRetentionReader) read(ctx context.Context, t authorization.Target, origins []artifact.RetentionRule) (value.PolicySet, error) {
	var out value.PolicySet
	if !t.Valid() {
		return out, value.ErrInvalid
	}
	if r.Topology == nil || r.Sources == nil || r.Now == nil || ctx.Err() != nil {
		return out, value.ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	topology, err := r.Topology.RetentionTopology(ctx, t.ClusterID)
	if err != nil || !topology.Valid(r.Now()) || topology.TargetClusterID != t.ClusterID {
		return out, readStep("topology")
	}
	topology.Sources = slices.Clone(topology.Sources)
	// Stable order is independent of the configuration's source array order.
	slices.SortFunc(topology.Sources, func(a, b value.PolicySourceRef) int {
		if a.Hub != b.Hub {
			if a.Hub {
				return -1
			}
			return 1
		}
		return 0
	})
	type checkpoint struct {
		Source               value.PolicySourceRef
		Epoch                string `json:"-"` // runtime fence; not a policy-definition revision
		Acceptance, Snapshot identity.Revision
	}
	points := make([]checkpoint, 0, len(topology.Sources))
	snapshots := make([]value.PolicySnapshot, 0, len(topology.Sources))
	observed, until := topology.ObservedAt, topology.FreshUntil
	source := func(ref value.PolicySourceRef) (value.AcceptedSource, error) {
		s, err := r.Sources.AcceptedRetentionSource(ctx, topology.RootID, ref)
		if err != nil || !s.Valid(r.Now()) || s.RootID != topology.RootID || s.Snapshot.SourceClusterID != ref.ClusterID || s.Snapshot.ControlNamespaceUID != ref.ControlNamespaceUID || s.Snapshot.Hub != ref.Hub || s.ProtectionDigest != ref.ProtectionDigest || configuration.RetentionSnapshotDigest(s.Snapshot) != artifact.Digest(s.Snapshot.Revision.Digest) {
			return value.AcceptedSource{}, value.ErrUnavailable
		}
		return s, nil
	}
	namespaceKeys, workloadKeys := []string{}, []string{}
	for _, ref := range topology.Sources {
		s, err := source(ref)
		if err != nil {
			if ref.Hub {
				return out, readStep("source-hub")
			}
			return out, readStep("source-region")
		}
		observed = identity.Earlier(observed, identity.Earlier(s.ObservedAt, s.Snapshot.ObservedAt))
		until = identity.Earlier(until, identity.Earlier(s.FreshUntil, s.Snapshot.FreshUntil))
		points = append(points, checkpoint{ref, s.Epoch, s.Acceptance, s.Snapshot.Revision})
		snapshots = append(snapshots, s.Snapshot)
		for _, p := range s.Snapshot.Policies {
			if slices.ContainsFunc(origins, func(o artifact.RetentionRule) bool { return o.UID == p.Policy.Revision.UID }) {
				continue
			}
			if len(p.Scope.ClusterIDs) > 0 && !slices.Contains(p.Scope.ClusterIDs, t.ClusterID) {
				continue
			}
			for k := range p.Scope.NamespaceLabels {
				namespaceKeys = append(namespaceKeys, k)
			}
			for k := range p.Scope.WorkloadLabels {
				workloadKeys = append(workloadKeys, k)
			}
		}
	}
	slices.Sort(namespaceKeys)
	namespaceKeys = slices.Compact(namespaceKeys)
	slices.Sort(workloadKeys)
	workloadKeys = slices.Compact(workloadKeys)
	if len(namespaceKeys) > 64 || len(workloadKeys) > 64 {
		return out, readStep("selector-limit")
	}
	facts := value.SelectorFacts{Target: t, Revision: identity.Revision{UID: topology.Revision.UID, Generation: topology.Revision.Generation, Digest: stableDigest(t)}, ObservedAt: observed, FreshUntil: until}
	if len(namespaceKeys)+len(workloadKeys) > 0 {
		if r.Selectors == nil {
			return out, readStep("selectors-absent")
		}
		facts, err = r.Selectors.ProtectedRetentionSelectors(ctx, t, slices.Clone(namespaceKeys), slices.Clone(workloadKeys))
		if err != nil || !facts.Valid(r.Now()) || facts.Target != t {
			return out, readStep("selectors")
		}
	}
	sourceUntil := until
	var policies []value.Policy
	if len(origins) > 0 {
		policies, until, err = value.MatchRetainedPolicies(snapshots, facts, origins, r.Now())
	} else {
		policies, until, err = value.MatchPolicies(snapshots, facts, r.Now())
	}
	if err != nil {
		return out, err
	}
	until = identity.Earlier(until, sourceUntil)
	observed = identity.Earlier(observed, facts.ObservedAt)
	// Re-read after metadata I/O; a new source acceptance/guard/topology revision
	// cannot be combined with policies from an older read. Never freshen old input.
	final, err := r.Topology.RetentionTopology(ctx, t.ClusterID)
	if err != nil || !final.Valid(r.Now()) || final.RootID != topology.RootID || final.TargetClusterID != topology.TargetClusterID || final.Revision != topology.Revision {
		return out, readStep("final-topology")
	}
	final.Sources = slices.Clone(final.Sources)
	slices.SortFunc(final.Sources, func(a, b value.PolicySourceRef) int {
		if a.Hub != b.Hub {
			if a.Hub {
				return -1
			}
			return 1
		}
		return 0
	})
	if !slices.Equal(final.Sources, topology.Sources) {
		return out, readStep("final-sources")
	}
	until = identity.Earlier(until, final.FreshUntil)
	for _, p := range points {
		s, err := source(p.Source)
		if err != nil || s.Epoch != p.Epoch || s.Acceptance != p.Acceptance || s.Snapshot.Revision != p.Snapshot {
			return out, readStep("final-source")
		}
		until = identity.Earlier(until, identity.Earlier(s.FreshUntil, s.Snapshot.FreshUntil))
	}
	if ctx.Err() != nil || !identity.Fresh(observed, until, r.Now(), value.RetentionSourceInterval) {
		return out, readStep("fresh")
	}
	slices.SortFunc(origins, func(a, b artifact.RetentionRule) int {
		if a.UID < b.UID {
			return -1
		}
		if a.UID > b.UID {
			return 1
		}
		return 0
	})
	digest := stableDigest(struct {
		Topology  identity.Revision
		Sources   []checkpoint
		Target    authorization.Target
		Selectors identity.Revision
		Origins   []artifact.RetentionRule
	}{topology.Revision, points, t, facts.Revision, origins})
	revision := identity.Revision{UID: topology.Revision.UID, Generation: topology.Revision.Generation, Digest: digest}
	proof := artifact.RetentionProof{RootID: topology.RootID, ClusterID: t.ClusterID, NamespaceUID: t.NamespaceUID, WorkloadUID: t.WorkloadUID, PodUID: t.PodUID, Topology: topology.Revision, Policy: revision, Selectors: facts.Revision, SourceCount: len(points), ObservedAt: observed, ValidUntil: until}
	for i, p := range points {
		proof.Sources[i] = artifact.RetentionSourceVersion{ClusterID: p.Source.ClusterID, ControlNamespaceUID: p.Source.ControlNamespaceUID, Epoch: p.Epoch, Hub: p.Source.Hub, ProtectionDigest: p.Source.ProtectionDigest, SnapshotDigest: p.Snapshot.Digest, Acceptance: p.Acceptance}
	}
	if !proof.Valid(r.Now()) {
		return value.PolicySet{}, value.ErrUnavailable
	}
	return value.PolicySet{Target: t, Revision: revision, ObservedAt: observed, FreshUntil: until, Complete: true, Policies: policies, Proof: proof}, nil
}

// readStepError is ErrUnavailable with the closed step where an accepted
// policy read stopped, for diagnostics only.
type readStepError struct{ step string }

func readStep(step string) error              { return readStepError{step} }
func (e readStepError) Error() string         { return value.ErrUnavailable.Error() }
func (e readStepError) Unwrap() error         { return value.ErrUnavailable }
func (e readStepError) RetentionStep() string { return e.step }
