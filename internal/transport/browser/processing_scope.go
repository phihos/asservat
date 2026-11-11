package browser

import (
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/privacy"
	"bytes"
	"encoding/json"
	"encoding/json/jsontext"
	"time"
)

// These DTOs are the browser contract only. Stored immutable scope JSON keeps
// the domain's original field names and digest representation.
type processingLocationWire struct {
	ClusterID  string `json:"clusterID"`
	ArtifactID string `json:"artifactID"`
	AttemptID  string `json:"attemptID"`
}
type processingScopeWire struct {
	Kind          string                  `json:"kind"`
	Location      *processingLocationWire `json:"location,omitempty"`
	ClusterID     string                  `json:"clusterID,omitempty"`
	NamespaceUID  string                  `json:"namespaceUID,omitempty"`
	WorkloadUID   string                  `json:"workloadUID,omitempty"`
	AcquiredFrom  *time.Time              `json:"acquiredFrom,omitempty"`
	AcquiredUntil *time.Time              `json:"acquiredUntil,omitempty"`
}

func (s processingScopeWire) domain() value.ProcessingScope {
	out := value.ProcessingScope{Kind: s.Kind, ClusterID: s.ClusterID, NamespaceUID: s.NamespaceUID, WorkloadUID: s.WorkloadUID}
	if s.Location != nil {
		out.Location = artifact.Location{ClusterID: s.Location.ClusterID, ArtifactID: s.Location.ArtifactID, AttemptID: s.Location.AttemptID}
	}
	if s.AcquiredFrom != nil {
		out.AcquiredFrom = *s.AcquiredFrom
	}
	if s.AcquiredUntil != nil {
		out.AcquiredUntil = *s.AcquiredUntil
	}
	return out
}
func processingScopeReply(s value.ProcessingScope) processingScopeWire {
	out := processingScopeWire{Kind: s.Kind, ClusterID: s.ClusterID, NamespaceUID: s.NamespaceUID, WorkloadUID: s.WorkloadUID}
	if s.Kind == "artifact" {
		out.Location = &processingLocationWire{s.Location.ClusterID, s.Location.ArtifactID, s.Location.AttemptID}
	}
	if !s.AcquiredFrom.IsZero() {
		out.AcquiredFrom = &s.AcquiredFrom
	}
	if !s.AcquiredUntil.IsZero() {
		out.AcquiredUntil = &s.AcquiredUntil
	}
	return out
}

// Keep the accepted browser spelling and action-specific shape exact; the
// standard struct decoder alone also accepts case-insensitive field aliases.
func processingExactFields(raw []byte, names ...string) bool {
	var object map[string]json.RawMessage
	if json.Unmarshal(raw, &object) != nil || len(object) != len(names) {
		return false
	}
	for _, name := range names {
		if raw, ok := object[name]; !ok || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			return false
		}
	}
	return true
}
func processingChangeShape(raw []byte, in processingChangeInput) bool {
	switch in.Action {
	case "initialize_processing":
		return processingExactFields(raw, "action")
	case value.RequestEarlyErasure:
		return jsontext.Value(raw).IsValid() && processingExactFields(raw, "action", "artifactID")
	}
	var object map[string]json.RawMessage
	if json.Unmarshal(raw, &object) != nil {
		return false
	}
	if in.ArtifactID != "" {
		return processingExactFields(raw, "action", "ruleID", "expectedRevision", "artifactID")
	}
	if in.Scope == nil || !processingExactFields(raw, "action", "ruleID", "expectedRevision", "scope") {
		return false
	}
	scope := object["scope"]
	switch in.Scope.Kind {
	case "artifact":
		if !processingExactFields(scope, "kind", "location") {
			return false
		}
		var fields map[string]json.RawMessage
		if json.Unmarshal(scope, &fields) != nil {
			return false
		}
		return processingExactFields(fields["location"], "clusterID", "artifactID", "attemptID")
	case "workloadInterval":
		return processingExactFields(scope, "kind", "clusterID", "namespaceUID", "workloadUID", "acquiredFrom", "acquiredUntil")
	}
	return false
}
