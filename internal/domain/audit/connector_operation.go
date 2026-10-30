package audit

import (
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	"time"
)

// OperationPeerActor records the exact independently authenticated connector.
// It is not a credential or a current identity observation. New private records
// contain this branch instead of a fabricated human/workload OIDC principal.
type OperationPeerActor struct {
	Binding           fleet.PeerBinding
	CertificateDigest artifact.Digest
}

func (p OperationPeerActor) Valid() bool {
	return p.Binding.Valid() && p.Binding.Role == fleet.ConnectorPeer && p.CertificateDigest != (artifact.Digest{})
}
func (r OperationIntent) connectorOperation() bool {
	return r.Name == "connector_client_certificate" || r.Name == "connector_server_certificate" || r.Name == "connector_process_enrollment" || r.Name == "connector_backing_acceptance" || r.Name == "connector_retirement"
}
func (r OperationIntent) actorValid() bool {
	if r.Name == "connector_retirement" {
		return r.Actor == (identity.Principal{}) && r.Peer == nil && r.Process == nil && r.RetirementOrigin != nil && r.RetirementOrigin.ValidFor(r) && r.InputFormat == "connector-retirement/v1"
	}
	if r.RetirementOrigin != nil {
		return false
	}

	if r.Name == "connector_backing_acceptance" {
		return r.Actor == (identity.Principal{}) && r.Peer == nil && r.Process != nil && r.Process.Valid() && r.InputFormat == "connector-backing/v1"
	}
	if r.Name == "connector_process_enrollment" {
		return r.Actor == (identity.Principal{}) && r.Peer == nil && r.Process != nil && r.Process.Valid() && r.InputFormat == "connector-process/v1"
	}
	if r.connectorOperation() {
		return r.Actor == (identity.Principal{}) && ((r.Process == nil && r.Peer != nil && r.Peer.Valid()) || (r.Peer == nil && r.Process != nil && r.Process.Valid())) && r.InputFormat == "connector-credential/v1"
	}
	return r.Process == nil && r.Peer == nil && r.Actor.Valid() && humanOperationInputValid(r.Name, r.InputFormat)
}

// OperationCredentialOutcome is public certificate identity metadata, never a
// CSR, certificate body, private key or bootstrap secret. The exact leaf and its
// original expiry remain independently verified by the business ledger.
type OperationCredentialOutcome struct {
	OperationID, Usage string
	CertificateDigest  artifact.Digest
	NotAfter           time.Time
}

func (r OperationOutcome) credentialValid() bool {
	if !r.Intent.connectorOperation() {
		return r.Credential == nil
	}
	if len(r.CaseIDs)+len(r.ArtifactIDs)+len(r.CaptureIDs) != 0 {
		return false
	}
	if r.Status != "success" {
		return r.Credential == nil && r.Effect != "accepted"
	}
	if r.Intent.Name == "connector_process_enrollment" || r.Intent.Name == "connector_backing_acceptance" || r.Intent.Name == "connector_retirement" {
		return r.Credential == nil && r.Effect == "accepted"
	}
	c := r.Credential
	usage := "client"
	if r.Intent.Name == "connector_server_certificate" {
		usage = "server"
	}
	return c != nil && authorization.UUID(c.OperationID) && c.OperationID == r.Intent.ID && c.Usage == usage && c.CertificateDigest != (artifact.Digest{}) && microTime(c.NotAfter) && c.NotAfter.After(r.RecordedAt) && !c.NotAfter.After(r.Intent.CreatedAt.Add(time.Hour)) && r.Effect == "accepted"
}

// Closed internal classification, separate from public tool discovery. Keeping
// this branch explicit prevents a private peer operation accepting human data.
func humanOperationInputValid(name, format string) bool {
	switch name {
	case "get_file_excerpt", "get_query_result":
		return format == "context-query-input/v1"
	case "download_artifact_content":
		return format == "native-content-input/v1"
	case "persist_capture_intent":
		return format == CaptureOperationInputFormat
	case "initialize_processing", "restrict_processing", "release_processing":
		return format == "processing-input/v1"
	case "cancel_capture", "list_recordings", "preview_recording_save", "list_diagnostics", "preview_capture", "request_capture", "get_capture", "get_case", "prepare_artifact_download", "get_artifact_download", "resolve_capture_request", "invalid_operation", "activate_policy", "get_policy_status", "deactivate_policy", "create_share", "list_shares", "revoke_share", "explain_access", "list_capture_history", "get_capture_settings", "preview_access_change", "transfer_share", "stop_future_sharing", "preview_retention_change", "get_grant", "list_reviews", "decide_review", "revoke_grant", "request_policy_grant":
		return format == "context-input/v1" || format == "invalid-input/v1"
	default:
		return false
	}
}

// OperationConnectorProcessActor records independently reviewed Pod/controller
// facts for initial automatic enrollment. It is never a TLS or human identity,
// and contains no token, token digest, private key, certificate body or CSR.
type OperationConnectorProcessActor struct {
	Process                          fleet.ConnectorProcessIdentity
	Deployment                       fleet.ConnectorDeployment
	ClientKeyDigest, ServerKeyDigest artifact.Digest
}

func (p OperationConnectorProcessActor) Valid() bool {
	return p.Process.Valid() && p.Deployment.Valid() && p.ClientKeyDigest != (artifact.Digest{}) && p.ServerKeyDigest != (artifact.Digest{}) && p.ClientKeyDigest != p.ServerKeyDigest
}

// CompatibleConnectorPolicy compares the fixed private resources, not current
// admission authority. Different original revisions are usable only when the
// exact intent already exists in the purpose-specific SQL business journal.
func CompatibleConnectorPolicy(a, b OperationLifecyclePolicy) bool {
	if !a.CertificateVerificationBacked() || !b.CertificateVerificationBacked() || a.Lane != "identity" || b.Lane != "identity" || a.History == nil || b.History == nil || !connectorHistoryLayout(a.History.Layout) || !connectorHistoryLayout(b.History.Layout) || *a.History != *b.History {
		return false
	}
	a.History = nil
	b.History = nil
	a.PolicyID = b.PolicyID
	a.PolicyDigest = b.PolicyDigest
	a.BackingRevision = b.BackingRevision
	a.ValidUntil = b.ValidUntil
	return a == b
}
