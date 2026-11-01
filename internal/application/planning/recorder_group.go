package planning

import (
	"bytes"
	"encoding/hex"
	"encoding/json"

	"asservat.local/asservat/internal/domain/identity"

	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/planning"
)

// RecorderGroupVersion is the parent scope of a manual composition group
// (ADR-276): one review over the children's exact scope digests.
const RecorderGroupVersion = "recorder-group/v1"

type recorderGroupChild struct {
	CaptureID    string `json:"captureID"`
	ActionID     string `json:"actionID"`
	Kind         string `json:"kind"`
	EvidenceType string `json:"evidenceType"`
	ScopeDigest  string `json:"scopeDigest"`
}

type recorderGroupScope struct {
	Version   string               `json:"schemaVersion"`
	CaptureID string               `json:"captureID"`
	Executor  principal            `json:"executor"`
	Target    recorderTarget       `json:"target"`
	Source    source               `json:"source"`
	Approval  bool                 `json:"approvalRequired"`
	Children  []recorderGroupChild `json:"children"`
}

// CompileRecorderGroup binds already compiled single-action child plans of
// one Pod into the canonical parent scope. Children must share executor,
// target and the approval requirement; each keeps its own scope and digest.
func CompileRecorderGroup(captureID string, children []value.RecorderPlan) ([]byte, artifact.Digest, error) {
	bad := func() ([]byte, artifact.Digest, error) { return nil, artifact.Digest{}, value.ErrInvalid }
	if len(children) < 2 || len(children) > 16 {
		return bad()
	}
	var out recorderGroupScope
	for i, p := range children {
		var s recorderScope
		if len(p.Actions) != 1 || strict(p.CanonicalScope, &s) != nil || s.Version != value.RecorderPlanVersion {
			return bad()
		}
		if i == 0 {
			out = recorderGroupScope{Version: RecorderGroupVersion, CaptureID: captureID, Executor: s.Executor, Target: s.Target, Source: source{s.Source.ClusterID, s.Source.NamespaceUID, captureID}, Approval: s.Approval != nil}
		} else if s.Executor != out.Executor || s.Target != out.Target || s.Source.ClusterID != out.Source.ClusterID || s.Source.NamespaceUID != out.Source.NamespaceUID || (s.Approval != nil) != out.Approval {
			return bad()
		}
		a := p.Actions[0]
		out.Children = append(out.Children, recorderGroupChild{CaptureID: s.Source.ResourceUID, ActionID: a.ID, Kind: a.Kind, EvidenceType: a.EvidenceType, ScopeDigest: hexDigest(p.ScopeDigest)})
	}
	b, err := json.Marshal(out)
	if err != nil {
		return bad()
	}
	b, d, err := canonical(b)
	if err != nil || len(b) > 64<<10 {
		return bad()
	}
	return b, d, nil
}

// RecorderGroupScope is the read view of a recorder-group/v1 parent scope.
type RecorderGroupScope struct {
	CaptureID    string
	Executor     identity.Principal
	ChildCapture []string
	ChildScope   []artifact.Digest
}

// ReadRecorderGroupScope strictly reads a canonical parent scope whose
// digest is d.
func ReadRecorderGroupScope(scope []byte, d artifact.Digest) (RecorderGroupScope, error) {
	var out RecorderGroupScope
	var s recorderGroupScope
	if c, digest, err := canonical(scope); err != nil || digest != d || !bytes.Equal(c, scope) || strict(scope, &s) != nil || s.Version != RecorderGroupVersion || len(s.Children) < 2 || len(s.Children) > 16 {
		return out, value.ErrInvalid
	}
	out = RecorderGroupScope{CaptureID: s.CaptureID, Executor: identity.Principal{Issuer: s.Executor.Issuer, Subject: s.Executor.Subject, ClientID: s.Executor.ClientID, Kind: identity.Kind(s.Executor.Kind)}}
	for _, c := range s.Children {
		b, err := hex.DecodeString(c.ScopeDigest)
		if err != nil || len(b) != len(artifact.Digest{}) {
			return RecorderGroupScope{}, value.ErrInvalid
		}
		out.ChildCapture = append(out.ChildCapture, c.CaptureID)
		out.ChildScope = append(out.ChildScope, artifact.Digest(b))
	}
	return out, nil
}
