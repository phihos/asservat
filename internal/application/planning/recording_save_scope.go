package planning

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"slices"
	"strconv"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	value "asservat.local/asservat/internal/domain/planning"
	"asservat.local/asservat/internal/domain/targets"
)

// RecordingSaveScopeInput is independently resolved application input, never a
// browser/MCP DTO. The executor comes from accepted policy authority.
type RecordingSaveScopeInput struct {
	CaptureID                      string
	Requester                      identity.Principal
	Authority                      authorization.AcceptedPolicyAuthority
	Sources                        []RecordingSaveScopeSource
	IncidentPodLimit               int
	FinalizeTimeout                time.Duration
	CeilingDigest, RetentionDigest artifact.Digest
}
type RecordingSaveScopeSource struct {
	PolicyUID                        string
	ExecutionDigest                  artifact.Digest
	Original                         targets.SourceSnapshotTarget
	ActionID, Kind                   string
	DefinitionDigest, AudienceDigest artifact.Digest
	CeilingDigest, RetentionDigest   artifact.Digest
	ApprovedBefore, Before           time.Duration
	MaxBytes                         int64
}

type recordingSavePolicyRef struct {
	ClusterID       string `json:"clusterID"`
	NamespaceUID    string `json:"namespaceUID"`
	PolicyUID       string `json:"policyUID"`
	ExecutionDigest string `json:"executionDigest"`
}
type recordingSaveScopeSource struct {
	SourceID         string `json:"sourceSessionID"`
	PodUID           string `json:"podUID"`
	NodeUID          string `json:"nodeUID"`
	BootID           string `json:"nodeBootID"`
	ActionID         string `json:"actionID"`
	Kind             string `json:"kind"`
	DefinitionDigest string `json:"sourceDefinitionDigest"`
	AudienceDigest   string `json:"retainedAudienceDigest"`
	CeilingDigest    string `json:"collectionCeilingDigest,omitempty"`
	RetentionDigest  string `json:"retentionDigest,omitempty"`
	Before           string `json:"before"`
	After            string `json:"after"`
	MaxBytes         int64  `json:"maxBytes"`
}
type recordingSaveScope struct {
	Version          string                     `json:"schemaVersion"`
	Operation        string                     `json:"operation"`
	CaptureID        string                     `json:"captureID"`
	Requester        principal                  `json:"requester"`
	Executor         principal                  `json:"executor"`
	Policy           recordingSavePolicyRef     `json:"policy"`
	WorkloadUID      string                     `json:"workloadUID"`
	Sources          []recordingSaveScopeSource `json:"sources"`
	IncidentPodLimit int                        `json:"incidentPodLimit"`
	FinalizeTimeout  string                     `json:"finalizeTimeout"`
	Dependencies     []dependency               `json:"dependencies"`
}

func scopeDuration(d time.Duration) (string, bool) {
	if d <= 0 || d%time.Millisecond != 0 {
		return "", false
	}
	for _, unit := range []struct {
		duration time.Duration
		name     string
	}{{time.Hour, "h"}, {time.Minute, "m"}, {time.Second, "s"}, {time.Millisecond, "ms"}} {
		if d%unit.duration == 0 {
			return strconv.FormatInt(int64(d/unit.duration), 10) + unit.name, true
		}
	}
	return "", false
}

// CompileRecordingSaveScope freezes exactly the existing-source manual save
// contract. It performs no acquisition, lease renewal or authority effect.
// The schema ceiling of16 does not override an accepted incident pod cap.
func CompileRecordingSaveScope(in RecordingSaveScopeInput, now time.Time) ([]byte, artifact.Digest, error) {
	bad := func() ([]byte, artifact.Digest, error) { return nil, artifact.Digest{}, value.ErrInvalid }
	a := in.Authority
	timeout, validTimeout := scopeDuration(in.FinalizeTimeout)
	if !authorization.UUID(in.CaptureID) || !in.Requester.Valid() || !a.Valid(now) || !validTimeout || in.IncidentPodLimit < 1 || in.IncidentPodLimit > 100 || len(in.Sources) < 1 || len(in.Sources) > 16 || in.CeilingDigest == (artifact.Digest{}) || in.RetentionDigest == (artifact.Digest{}) {
		return bad()
	}
	sourceRows := make([]recordingSaveScopeSource, 0, len(in.Sources))
	seenSource, pods := map[string]bool{}, map[string]bool{}
	seenAction := map[string]bool{}
	for _, source := range in.Sources {
		original := source.Original
		before, validBefore := scopeDuration(source.Before)
		if source.PolicyUID != a.PolicyUID || source.ExecutionDigest != a.ScopeDigest || !original.Valid() || original.Request.ClusterID != a.ClusterID || original.Request.Namespace.UID != a.NamespaceUID || original.Request.Workload.UID != a.WorkloadUID || !identity.Text(source.ActionID, 63) || !slices.Contains(a.Actions, source.Kind) || source.Kind != "packetCapture" && source.Kind != "syscallTrace" || source.DefinitionDigest == (artifact.Digest{}) || source.AudienceDigest == (artifact.Digest{}) || !validBefore || source.Before > source.ApprovedBefore || source.ApprovedBefore > artifact.MaxLifecycleWindow || source.MaxBytes < 1 || source.MaxBytes > artifact.RecordingNativeLimit || seenSource[original.SourceID] || seenAction[original.Request.PodUID+"\x00"+source.ActionID] {
			return bad()
		}
		seenSource[original.SourceID] = true
		seenAction[original.Request.PodUID+"\x00"+source.ActionID] = true
		pods[original.Request.PodUID] = true
		row := recordingSaveScopeSource{SourceID: original.SourceID, PodUID: original.Request.PodUID, NodeUID: original.NodeUID, BootID: original.BootID, ActionID: source.ActionID, Kind: source.Kind, DefinitionDigest: hexDigest(source.DefinitionDigest), AudienceDigest: hexDigest(source.AudienceDigest), Before: before, After: "0s", MaxBytes: source.MaxBytes}
		if len(in.Sources) > 1 {
			ceiling, retention := source.CeilingDigest, source.RetentionDigest
			if ceiling == (artifact.Digest{}) {
				ceiling = in.CeilingDigest
			}
			if retention == (artifact.Digest{}) {
				retention = in.RetentionDigest
			}
			row.CeilingDigest, row.RetentionDigest = hexDigest(ceiling), hexDigest(retention)
		} else if source.CeilingDigest != (artifact.Digest{}) && source.CeilingDigest != in.CeilingDigest || source.RetentionDigest != (artifact.Digest{}) && source.RetentionDigest != in.RetentionDigest {
			return bad()
		}
		sourceRows = append(sourceRows, row)
	}
	if len(pods) > in.IncidentPodLimit {
		return bad()
	}
	slices.SortFunc(sourceRows, func(a, b recordingSaveScopeSource) int {
		if a.SourceID < b.SourceID {
			return -1
		}
		if a.SourceID > b.SourceID {
			return 1
		}
		return 0
	})
	if len(sourceRows) > 1 {
		in.CeilingDigest, in.RetentionDigest = recordingSaveGroupDependencyDigests(sourceRows)
	}
	requester, executor := in.Requester, a.Executor
	scope := recordingSaveScope{Version: "recording-save/v1", Operation: "recordingSave", CaptureID: in.CaptureID, Requester: principal{requester.Issuer, requester.Subject, requester.ClientID, string(requester.Kind)}, Executor: principal{executor.Issuer, executor.Subject, executor.ClientID, string(executor.Kind)}, Policy: recordingSavePolicyRef{a.ClusterID, a.NamespaceUID, a.PolicyUID, hexDigest(a.ScopeDigest)}, WorkloadUID: a.WorkloadUID, Sources: sourceRows, IncidentPodLimit: in.IncidentPodLimit, FinalizeTimeout: timeout, Dependencies: []dependency{{"collectionCeiling", hexDigest(in.CeilingDigest)}, {"retention", hexDigest(in.RetentionDigest)}}}
	raw, err := json.Marshal(scope)
	if err != nil {
		return bad()
	}
	raw, digest, err := canonical(raw)
	if err != nil || len(raw) > 65536 {
		return bad()
	}
	return raw, digest, nil
}

func readRecordingSaveScopeIdentity(raw []byte, want artifact.Digest) (ContextScopeIdentity, error) {
	var s recordingSaveScope
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&s) != nil {
		return ContextScopeIdentity{}, value.ErrInvalid
	}
	encoded, err := json.Marshal(s)
	if err != nil {
		return ContextScopeIdentity{}, value.ErrInvalid
	}
	encoded, digest, err := canonical(encoded)
	requester := identity.Principal{Issuer: s.Requester.Issuer, Subject: s.Requester.Subject, ClientID: s.Requester.ClientID, Kind: identity.Kind(s.Requester.Kind)}
	executor := identity.Principal{Issuer: s.Executor.Issuer, Subject: s.Executor.Subject, ClientID: s.Executor.ClientID, Kind: identity.Kind(s.Executor.Kind)}
	_, policy, isPolicy := authorization.PolicyExecutor(executor)
	if err != nil || digest != want || !bytes.Equal(encoded, raw) || s.Version != "recording-save/v1" || s.Operation != "recordingSave" || !authorization.UUID(s.CaptureID) || !requester.Valid() || !isPolicy || policy != s.Policy.PolicyUID || len(s.Sources) < 1 || len(s.Sources) > 16 {
		return ContextScopeIdentity{}, value.ErrInvalid
	}
	if s.IncidentPodLimit < 1 || s.IncidentPodLimit > 100 || len(s.Dependencies) != 2 || s.Dependencies[0].Role != "collectionCeiling" || s.Dependencies[1].Role != "retention" || !saveScopeHash(s.Policy.ExecutionDigest) || !saveScopeHash(s.Dependencies[0].Digest) || !saveScopeHash(s.Dependencies[1].Digest) {
		return ContextScopeIdentity{}, value.ErrInvalid
	}
	timeout, timeoutErr := time.ParseDuration(s.FinalizeTimeout)
	canonicalTimeout, timeoutValid := scopeDuration(timeout)
	if timeoutErr != nil || !timeoutValid || canonicalTimeout != s.FinalizeTimeout {
		return ContextScopeIdentity{}, value.ErrInvalid
	}
	targets := make([]authorization.Target, 0, len(s.Sources))
	seenAction, pods := map[string]bool{}, map[string]bool{}
	for index, source := range s.Sources {
		if len(s.Sources) > 1 && (!saveScopeHash(source.CeilingDigest) || !saveScopeHash(source.RetentionDigest)) || len(s.Sources) == 1 && (source.CeilingDigest != "" || source.RetentionDigest != "") {
			return ContextScopeIdentity{}, value.ErrInvalid
		}
		before, beforeErr := time.ParseDuration(source.Before)
		canonicalBefore, beforeValid := scopeDuration(before)
		if !authorization.UUID(source.SourceID) || !identity.Text(source.PodUID, 64) || !identity.Text(source.NodeUID, 128) || !authorization.UUID(source.BootID) || !identity.Text(source.ActionID, 63) || source.Kind != "packetCapture" && source.Kind != "syscallTrace" || source.After != "0s" || beforeErr != nil || !beforeValid || canonicalBefore != source.Before || before > artifact.MaxLifecycleWindow || source.MaxBytes < 1 || source.MaxBytes > artifact.RecordingNativeLimit || !saveScopeHash(source.DefinitionDigest) || !saveScopeHash(source.AudienceDigest) || index > 0 && s.Sources[index-1].SourceID >= source.SourceID || seenAction[source.PodUID+"\x00"+source.ActionID] {
			return ContextScopeIdentity{}, value.ErrInvalid
		}
		target := authorization.Target{ClusterID: s.Policy.ClusterID, NamespaceUID: s.Policy.NamespaceUID, WorkloadUID: s.WorkloadUID, PodUID: source.PodUID}
		if !target.Valid() {
			return ContextScopeIdentity{}, value.ErrInvalid
		}
		targets = append(targets, target)
		seenAction[source.PodUID+"\x00"+source.ActionID] = true
		pods[source.PodUID] = true
	}
	if len(s.Sources) > 1 {
		ceiling, retention := recordingSaveGroupDependencyDigests(s.Sources)
		if s.Dependencies[0].Digest != hexDigest(ceiling) || s.Dependencies[1].Digest != hexDigest(retention) {
			return ContextScopeIdentity{}, value.ErrInvalid
		}
	}
	if len(pods) > s.IncidentPodLimit {
		return ContextScopeIdentity{}, value.ErrInvalid
	}
	target := targets[0]
	out := ContextScopeIdentity{Actor: executor, Requester: &requester, Target: target, CaptureID: s.CaptureID, ExecutionClass: artifact.ContextAPIExecution, ApprovedAcceptance: true}
	if len(targets) > 1 {
		out.Target.PodUID = ""
		out.Targets = targets
	}
	return out, nil
}

func saveScopeHash(s string) bool {
	if len(s) != 64 {
		return false
	}
	raw, err := hex.DecodeString(s)
	if err != nil || len(raw) != 32 {
		return false
	}
	for _, b := range raw {
		if b != 0 {
			return true
		}
	}
	return false
}

// recordingSaveContextMatches joins the reviewed manual scope to independent
// current compilation input. An opaque passive scope alone cannot choose work.
func recordingSaveContextMatches(raw []byte, digest artifact.Digest, in value.ContextInput) bool {
	saved := in.Snapshot
	if saved == nil || saved.SourceTarget == nil {
		return false
	}
	var identity ContextScopeIdentity
	var err error
	index := 0
	if saved.Group != nil {
		identity, err = ReadRecordingSaveChildScopeIdentity(raw, digest, *saved.Group, in.CaptureID)
		index = saved.Group.ChildIndex
	} else {
		identity, err = readRecordingSaveScopeIdentity(raw, digest)
	}
	if err != nil || identity.Actor != in.Executor || identity.Target != in.Target.Target() || identity.CaptureID != in.CaptureID {
		return false
	}
	var s recordingSaveScope
	if json.Unmarshal(raw, &s) != nil || saved.Group == nil && len(s.Sources) != 1 {
		return false
	}
	source := s.Sources[index]
	before, _ := scopeDuration(saved.Request.Before)
	original := saved.SourceTarget
	ceiling, retention := s.Dependencies[0].Digest, s.Dependencies[1].Digest
	if saved.Group != nil && len(s.Sources) > 1 {
		ceiling, retention = source.CeilingDigest, source.RetentionDigest
	}
	return s.Policy.PolicyUID == saved.PolicyUID && s.Policy.ExecutionDigest == hexDigest(saved.ExecutionDigest) && source.SourceID == saved.Request.SourceID && source.PodUID == in.Target.Request.PodUID && source.NodeUID == original.NodeUID && source.BootID == original.BootID && source.ActionID == saved.ActionID && source.Kind == "packetCapture" && source.Before == before && source.After == "0s" && saved.Request.After == 0 && source.MaxBytes == saved.Request.MaxBytes && source.DefinitionDigest == hexDigest(saved.SourceDefinitionDigest) && source.AudienceDigest == hexDigest(saved.SourceAudienceDigest) && ceiling == hexDigest(artifact.Digest(in.Capability.Revision.Digest)) && retention == hexDigest(artifact.Digest(in.Retention.PolicyRevision.Digest))
}

// RecordingSaveFinalizeTimeout reads authored limits from the exact canonical
// manual scope. It is a limit only, never a new processing/source permit.
func RecordingSaveFinalizeTimeout(raw []byte, digest artifact.Digest) (time.Duration, error) {
	if _, err := readRecordingSaveScopeIdentity(raw, digest); err != nil {
		return 0, err
	}
	var scope recordingSaveScope
	if json.Unmarshal(raw, &scope) != nil {
		return 0, value.ErrInvalid
	}
	return time.ParseDuration(scope.FinalizeTimeout)
}
