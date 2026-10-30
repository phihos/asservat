package audit

import (
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	"slices"
	"time"
)

const OperationCipherLimit = 64 << 10
const OperationOutputLimit = 24 << 10

// Sixteen source assessments retain up to64 policy digests per source.
// Only this passive preview may prepare the bounded larger metadata result.
const OperationRecordingSavePreviewOutputLimit = 128 << 10

// Only the authenticated browser settings view has this larger prepared-byte
// maximum. Audit stores the HMAC/count/refs, never the parameter response body.
const OperationCaptureSettingsOutputLimit = 160 << 10

func operationOutputLimit(name string) int64 {
	if name == "preview_recording_save" {
		return OperationRecordingSavePreviewOutputLimit
	}
	if name == "get_capture_settings" {
		return OperationCaptureSettingsOutputLimit
	}
	return OperationOutputLimit
}

// Lane is server-selected from the fixed operation, never supplied by a caller.
func OperationLane(name string) string {
	switch name {
	case "persist_capture_intent":
		return "capture"
	case "connector_client_certificate", "connector_server_certificate", "connector_process_enrollment", "connector_backing_acceptance", "connector_retirement":
		return "identity"
	case "initialize_processing", "restrict_processing":
		return "normal"
	case "release_processing":
		return "processing"
	case "resolve_capture_request":
		return "resolution"
	case "cancel_capture", "list_recordings", "preview_recording_save", "list_diagnostics", "preview_capture", "request_capture", "get_capture", "get_case", "prepare_artifact_download", "get_artifact_download", "download_artifact_content", "invalid_operation", "get_file_excerpt", "get_query_result", "activate_policy", "get_policy_status", "deactivate_policy", "create_share", "list_shares", "revoke_share", "explain_access", "list_capture_history", "get_capture_settings", "preview_access_change", "transfer_share", "stop_future_sharing", "preview_retention_change", "get_grant", "list_reviews", "decide_review", "revoke_grant", "request_policy_grant":
		return "normal"
	default:
		return ""
	}
}

// OperationRequestWindow is the maximum request interval of an operation:
// identity.EvidenceReadRequestWindow for evidence reads, five seconds otherwise.
func OperationRequestWindow(name string) time.Duration {
	switch name {
	case "get_file_excerpt", "get_query_result", "prepare_artifact_download", "get_artifact_download":
		return identity.EvidenceReadRequestWindow
	default:
		return 5 * time.Second
	}
}

// OperationIntent contains only bounded audit facts. It is not a permit, and
// persisted identity/deadline fields never become current caller authority.
type OperationIntent struct {
	ReasonEnvelope                                                     *CaptureReasonEnvelope `json:",omitempty"`
	ID, RootID, TraceID, Name, InputFormat, MACVersion, AccountVersion string
	Actor                                                              identity.Principal              `json:",omitzero"`
	Peer                                                               *OperationPeerActor             `json:",omitempty"`
	Process                                                            *OperationConnectorProcessActor `json:",omitempty"`
	ConnectorReservations                                              *ConnectorRetirementSet         `json:",omitempty"`
	RetirementOrigin                                                   *ConnectorRetirementOrigin      `json:",omitempty"`
	PrincipalDigest, InputDigest                                       artifact.Digest
	CreatedAt, RequestUntil, WriteUntil, RetainUntil                   time.Time
	Lifecycle                                                          *OperationLifecycleBinding `json:",omitempty"`
	Capture                                                            *CaptureIntent             `json:",omitempty"`
}

func (r OperationIntent) Valid() bool {
	for _, t := range []time.Time{r.CreatedAt, r.RequestUntil, r.WriteUntil, r.RetainUntil} {
		if t.IsZero() || t.Nanosecond()%1000 != 0 {
			return false
		}
	}
	return (r.Lifecycle == nil || r.Lifecycle.Valid(r)) && authorization.UUID(r.ID) && authorization.UUID(r.RootID) && authorization.UUID(r.TraceID) && OperationLane(r.Name) != "" &&
		r.actorValid() && r.connectorReservationsValid() && r.capturePayloadValid() && identity.Text(r.MACVersion, 64) && identity.Text(r.AccountVersion, 64) &&
		r.PrincipalDigest != (artifact.Digest{}) && r.InputDigest != (artifact.Digest{}) &&
		identity.Fresh(r.CreatedAt, r.RequestUntil, r.CreatedAt, OperationRequestWindow(r.Name)) && r.WriteUntil.After(r.CreatedAt) && !r.WriteUntil.After(r.CreatedAt.Add(30*time.Second)) &&
		!r.RequestUntil.After(r.WriteUntil) && r.RetainUntil.After(r.WriteUntil) && !r.RetainUntil.After(r.CreatedAt.Add(3660*24*time.Hour))
}

// Outcome describes prepared bytes, never client receipt. References may only
// come from an already authorized successful result, never echoed input IDs.
type OperationOutcome struct {
	Intent                                OperationIntent
	Status, Reason, Effect, ClientReceipt string
	CaseIDs, ArtifactIDs, CaptureIDs      []string
	OutputDigest                          artifact.Digest
	OutputBytes                           int64
	MetadataUntil, RecordedAt             time.Time
	Credential                            *OperationCredentialOutcome `json:",omitempty"`
}

func (r OperationOutcome) Valid() bool {
	if !r.Intent.Valid() || !slices.Contains([]string{"success", "denied", "invalid", "unavailable", "interrupted"}, r.Status) ||
		!slices.Contains([]string{"prepared", "not_available", "invalid_input", "authority_unavailable", "interrupted"}, r.Reason) ||
		!slices.Contains([]string{"none", "accepted", "unknown"}, r.Effect) || r.ClientReceipt != "unknown" || r.OutputBytes < 0 || r.OutputBytes > operationOutputLimit(r.Intent.Name) ||
		r.OutputDigest == (artifact.Digest{}) || r.RecordedAt.Before(r.Intent.CreatedAt) || !r.RecordedAt.Before(r.Intent.WriteUntil) ||
		r.MetadataUntil.Before(r.Intent.CreatedAt) || r.MetadataUntil.After(r.Intent.RequestUntil) {
		return false
	}
	if !r.credentialValid() || !r.captureOutcomeValid() {
		return false
	}
	if r.Effect != "none" && !r.Intent.connectorOperation() && !r.Intent.processingOperation() && r.Intent.Name != "persist_capture_intent" && r.Intent.Name != "cancel_capture" && r.Intent.Name != "request_capture" && r.Intent.Name != "resolve_capture_request" && r.Intent.Name != "prepare_artifact_download" && r.Intent.Name != "get_file_excerpt" && r.Intent.Name != "get_query_result" && r.Intent.Name != "activate_policy" && r.Intent.Name != "deactivate_policy" && r.Intent.Name != "create_share" && r.Intent.Name != "revoke_share" && r.Intent.Name != "transfer_share" && r.Intent.Name != "stop_future_sharing" && r.Intent.Name != "decide_review" && r.Intent.Name != "revoke_grant" && r.Intent.Name != "request_policy_grant" {
		return false
	}
	if r.Status != "success" && (len(r.CaseIDs) > 0 || len(r.ArtifactIDs) > 0 || len(r.CaptureIDs) > 0) {
		return false
	}
	for _, ids := range [][]string{r.CaseIDs, r.ArtifactIDs, r.CaptureIDs} {
		if len(ids) > 100 {
			return false
		}
		seen := map[string]bool{}
		for _, id := range ids {
			if !authorization.UUID(id) || seen[id] {
				return false
			}
			seen[id] = true
		}
	}
	return true
}
func OperationAuditKey(root, id, phase string) string {
	return "operation-audit/v1/" + root + "/" + id + "/" + phase
}
func (r Receipt) ValidOperation(root, id, phase string) bool {
	return authorization.UUID(root) && authorization.UUID(id) && (phase == "intent" || phase == "outcome") && r.Key == OperationAuditKey(root, id, phase) &&
		(r.Version == "" || identity.Text(r.Version, 1024)) && identity.Text(r.ETag, 256) && r.Bytes > 0 && r.Bytes <= OperationCipherLimit && r.SHA256 != (artifact.Digest{})
}

// Snapshot is private audit-journal state. None of its fields grants access or
// permits redispatch of the business operation.
type OperationSnapshot struct {
	Intent                        OperationIntent
	IntentStarted, OutcomeStarted bool
	IntentReceipt, OutcomeReceipt *Receipt
	Outcome                       *OperationOutcome
}
