package capture

import (
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/domain/planning"
	"asservat.local/asservat/internal/domain/targets"
	"bytes"
	"encoding/json"
	"slices"
)

// HistoryAuthored is supplied by an accepted automatic source, independently
// from its selected execution Pod. Public callers cannot author this field.
// It preserves control configuration and source versions, never grants.
type HistoryAuthored struct {
	Target        targets.WorkloadRequest
	TargetJSON    json.RawMessage
	Selector      HistorySelector
	Selection     string
	PolicyOrigins []HistoryPolicyOrigin
}
type HistoryPolicyOrigin struct {
	UID                       string
	Generation, IntentVersion int64
	CollectionDigest          artifact.Digest
}

func (p HistoryPolicyOrigin) Valid() bool {
	return identity.Text(p.UID, 64) && p.Generation > 0 && p.IntentVersion > 0 && p.CollectionDigest != (artifact.Digest{})
}

func (h HistoryAuthored) Valid() bool {
	if !h.Target.Valid() || !json.Valid(h.TargetJSON) || len(h.TargetJSON) > 16<<10 || !h.Selector.Valid() || h.Selector.ClusterID != h.Target.ClusterID || len(h.PolicyOrigins) > 16 {
		return false
	}
	if h.Selection != "triggeringPod" && h.Selection != "allWithinLimit" && h.Selection != "explicitPod" {
		return false
	}
	for _, p := range h.PolicyOrigins {
		if !identity.Text(p.UID, 64) || p.Generation < 1 || p.IntentVersion < 1 || p.CollectionDigest == (artifact.Digest{}) {
			return false
		}
	}
	return true
}
func (h *HistoryAuthored) Clone() *HistoryAuthored {
	if h == nil {
		return nil
	}
	out := *h
	out.TargetJSON = bytes.Clone(h.TargetJSON)
	out.PolicyOrigins = slices.Clone(h.PolicyOrigins)
	if h.Selector.MatchLabels != nil {
		out.Selector.MatchLabels = make(map[string]string, len(h.Selector.MatchLabels))
		for k, v := range h.Selector.MatchLabels {
			out.Selector.MatchLabels[k] = v
		}
	}
	return &out
}

type HistoryRepeatEdits struct {
	Target           *targets.WorkloadRequest
	Composition      *planning.ProfileComposition
	RequestedSeconds int64
	Selection        string
}
