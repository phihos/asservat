package presentation

import (
	"crypto/sha256"
	"encoding/json"
	"encoding/json/jsontext"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/capture"
)

type RecordingSavePolicyRef struct {
	ClusterID       string `json:"clusterID"`
	NamespaceUID    string `json:"namespaceUID"`
	PolicyUID       string `json:"policyUID"`
	ExecutionDigest string `json:"executionDigest"`
}
type RecordingSavePreference struct {
	ActionID string `json:"actionID"`
	Before   string `json:"before"`
}
type RecordingSaveSettings struct {
	Target  json.RawMessage           `json:"target"`
	Policy  RecordingSavePolicyRef    `json:"policy"`
	Windows []RecordingSavePreference `json:"action_windows"`
}
type RecordingSaveSettingsRecord struct {
	Kind            string                `json:"kind"`
	Operation       string                `json:"operation"`
	CaptureID       string                `json:"capture_id"`
	ClusterID       string                `json:"cluster_id"`
	NamespaceUID    string                `json:"namespace_uid"`
	AcceptedAt      time.Time             `json:"accepted_at"`
	ExpiresAt       time.Time             `json:"expires_at"`
	SettingsDigest  string                `json:"settings_digest"`
	ExecutionDigest string                `json:"original_execution_digest"`
	Settings        RecordingSaveSettings `json:"settings"`
	NavigationURI   string                `json:"navigation_uri"`
}

func (s *ContextOperations) recordingSaveSettings(settings value.CaptureSettings) (any, *string, time.Time, error) {
	saved := settings.RecordingSave
	if !saved.Valid() {
		return nil, nil, time.Time{}, value.ErrUnavailable
	}
	view := RecordingSaveSettings{Target: append(json.RawMessage(nil), settings.TargetJSON...), Policy: RecordingSavePolicyRef{settings.ClusterID, settings.NamespaceUID, saved.PolicyUID, hash(saved.PolicyExecutionDigest)}, Windows: make([]RecordingSavePreference, 0, len(saved.Windows))}
	for _, w := range saved.Windows {
		view.Windows = append(view.Windows, RecordingSavePreference{w.ActionID, artifact.LifecycleDuration(w.Before)})
	}
	raw, err := json.Marshal(view)
	if err != nil {
		return nil, nil, time.Time{}, value.ErrUnavailable
	}
	canonical := jsontext.Value(raw)
	if canonical.Canonicalize() != nil {
		return nil, nil, time.Time{}, value.ErrUnavailable
	}
	digest := artifact.Digest(sha256.Sum256(canonical))
	if settings.SettingsKey != (artifact.Digest{}) {
		digest = settings.SettingsKey
	}
	return RecordingSaveSettingsRecord{Kind: "recordingSaveSettings", Operation: "recordingSave", CaptureID: settings.CaptureID, ClusterID: settings.ClusterID, NamespaceUID: settings.NamespaceUID, AcceptedAt: settings.AcceptedAt.UTC(), ExpiresAt: settings.ExpiresAt.UTC(), SettingsDigest: hash(digest), ExecutionDigest: hash(settings.ExecutionDigest), Settings: view, NavigationURI: s.config.PublicOrigin + "/captures/new"}, nil, settings.ValidUntil, nil
}
func recordingSelectionFailure(origin string) any {
	return struct {
		OperationFailure
		NavigationURI string `json:"navigation_uri"`
	}{OperationFailure{"RecordingSelectionRequired", "Choose current recordings to repeat this saved window. Previous sources and grants are not reused.", false}, origin + "/captures/new"}
}
