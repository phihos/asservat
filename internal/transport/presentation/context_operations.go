package presentation

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"slices"
	"time"

	app "asservat.local/asservat/internal/application/capture"
	identities "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/domain/targets"
)

// ContextUseCase is the shared C-09 service. A transport never supplies target
// authority, accepted rows, identities or observations in an input body.
type ContextUseCase interface {
	CheckDiagnostic(context.Context, identities.CurrentIdentity, targets.WorkloadRequest) (time.Time, error)
	Preview(context.Context, identities.CurrentIdentity, value.ContextIntent) (app.ContextPreviewResult, error)
	Request(context.Context, identities.CurrentIdentity, string, string) (value.Accepted, error)
	ResolveContextRequest(context.Context, identities.CurrentIdentity, string, string) (value.ContextRequestDisposition, error)
}

// ContextContinuation is implemented only by the concrete accepted-start composition.
// An admission-only service cannot fall back to admitting on this explicit path.
type ContextContinuation interface {
	Continue(context.Context, identities.CurrentIdentity, string, string) (value.Accepted, error)
}
type ContextProgressUseCase interface {
	Get(context.Context, identities.CurrentIdentity, string) (value.ContextProgress, error)
}

// CollectionEnabled is an installation/client runtime switch, not permission.
// Bootstrap must leave it false until the full execution/publication workflow
// is composed and qualified. A successful preview cannot set this switch.
type ContextOperationsConfig struct {
	PublicOrigin      string
	CollectionEnabled bool
	Now               func() time.Time
	NewID             func() string
}

type ContextOperations struct {
	config    ContextOperationsConfig
	captures  ContextUseCase
	progress  ContextProgressUseCase
	contracts *contracts.InvestigationContracts
}

func (s *ContextOperations) PublicOrigin() string {
	if s == nil {
		return ""
	}
	return s.config.PublicOrigin
}

var ErrOperationsConfiguration = errors.New("invalid context operations configuration")

func NewContextOperations(c ContextOperationsConfig, capture ContextUseCase, progress ContextProgressUseCase) (*ContextOperations, error) {
	u, err := url.Parse(c.PublicOrigin)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" || len(c.PublicOrigin) > 1800 || capture == nil || progress == nil || c.Now == nil || c.NewID == nil {
		return nil, ErrOperationsConfiguration
	}
	wire, err := contracts.NewInvestigationContracts()
	if err != nil {
		return nil, err
	}
	return &ContextOperations{config: c, captures: capture, progress: progress, contracts: wire}, nil
}

func (s *ContextOperations) ToolNames() []string {
	out := []string{"list_diagnostics", "preview_capture", "get_capture", "resolve_capture_request"}
	if s != nil && s.config.CollectionEnabled {
		out = append(out, "request_capture")
	}
	return out
}
func (s *ContextOperations) Tool(name string) (contracts.InvestigationTool, bool) {
	if s == nil || !slices.Contains(s.ToolNames(), name) {
		return contracts.InvestigationTool{}, false
	}
	return s.contracts.Tool(name)
}

type WorkloadReference struct {
	ClusterID string `json:"cluster_id"`
	Namespace string `json:"namespace"`
	Kind      string `json:"kind"`
	Name      string `json:"name"`
}

func (r WorkloadReference) target() targets.WorkloadRequest {
	return targets.WorkloadRequest{ClusterID: r.ClusterID, Namespace: r.Namespace, Kind: r.Kind, Name: r.Name}
}

type PresetReference struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}
type ContextOperationInput struct {
	Target              WorkloadReference `json:"target_ref"`
	Preset              PresetReference   `json:"preset_ref"`
	RequestedSeconds    int64             `json:"requested_retention_seconds"`
	PreviewID           string            `json:"preview_id"`
	IdempotencyKey      string            `json:"idempotency_key"`
	CaptureID           string            `json:"capture_id"`
	ContinueAcquisition bool              `json:"continue_acquisition,omitempty"`
}
type OperationBlocker struct {
	Code            string `json:"code"`
	Message         string `json:"message"`
	ResponsibleRole string `json:"responsible_role"`
	Retryable       bool   `json:"retryable"`
}
type OperationFailure struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	Retryable bool   `json:"retryable"`
}
type OperationEnvelope struct {
	SchemaVersion string   `json:"schema_version"`
	RequestID     string   `json:"request_id"`
	DataClass     string   `json:"data_class"`
	Status        string   `json:"status"`
	Data          any      `json:"data"`
	Truncated     bool     `json:"truncated"`
	NextCursor    *string  `json:"next_cursor"`
	NarrowingHint *string  `json:"narrowing_hint"`
	Warnings      []string `json:"warnings"`
	Provenance    []any    `json:"provenance"`
}
type DiagnosticRow struct {
	Name             string             `json:"name"`
	Version          string             `json:"version"`
	Description      string             `json:"description"`
	ApprovalRequired bool               `json:"approval_required"`
	Available        bool               `json:"available"`
	Blockers         []OperationBlocker `json:"blockers"`
	Preset           PresetReference    `json:"preset_ref"`
}
type SelectedWorkload struct {
	Kind string `json:"kind"`
	Name string `json:"name"`
	UID  string `json:"uid"`
}
type SelectedPod struct {
	ClusterID string           `json:"cluster_id"`
	Namespace string           `json:"namespace"`
	Name      string           `json:"name"`
	UID       string           `json:"uid"`
	Workload  SelectedWorkload `json:"workload"`
}
type ContextPreviewData struct {
	PreviewID        string             `json:"preview_id"`
	ExpiresAt        time.Time          `json:"expires_at"`
	ExecutionDigest  string             `json:"execution_digest"`
	PodCount         int                `json:"pod_count"`
	MaxBytes         int64              `json:"max_bytes"`
	MaxProcessStarts int                `json:"max_process_starts"`
	ApprovalRequired bool               `json:"approval_required"`
	CaptureEnabled   bool               `json:"capture_enabled"`
	Blockers         []OperationBlocker `json:"blockers"`
	Warnings         []string           `json:"warnings"`
	NavigationURI    string             `json:"navigation_uri"`
	Lifecycle        LifecyclePlan      `json:"lifecycle_plan"`
	Assessment       CaptureAssessment  `json:"capture_assessment"`
	Preset           PresetReference    `json:"preset_ref"`
	Target           WorkloadReference  `json:"target_ref"`
	SelectedPods     []SelectedPod      `json:"selected_pods"`
	PodSelection     string             `json:"pod_selection"`
}
type ContextAcceptedData struct {
	CaptureID     string `json:"capture_id"`
	Phase         string `json:"phase"`
	NavigationURI string `json:"navigation_uri"`
	Operation     string `json:"operation"`
}
type ContextResolutionData struct {
	State string `json:"state"`
	*ContextAcceptedData
}

type ContextActionData struct {
	ActionID   string `json:"action_id"`
	Phase      string `json:"phase"`
	ReasonCode string `json:"reason_code,omitempty"`
}
type ContextProgressData struct {
	CaptureID         string              `json:"capture_id"`
	Revision          int64               `json:"revision"`
	Phase             string              `json:"phase"`
	Actions           []ContextActionData `json:"actions"`
	CaseID            string              `json:"case_id,omitempty"`
	NavigationURI     string              `json:"navigation_uri"`
	RetryAfterSeconds int                 `json:"retry_after_seconds,omitempty"`
	CanCancel         bool                `json:"can_cancel"`
	Blockers          []OperationBlocker  `json:"blockers"`
	Operation         string              `json:"operation"`
}

func collectionBlockers(enabled bool) []OperationBlocker {
	if enabled {
		return []OperationBlocker{}
	}
	return []OperationBlocker{{Code: "CollectionDisabled", Message: "Collection is not enabled for this service. The preview has not started a capture.", ResponsibleRole: "administrator", Retryable: false}}
}
func publicCaptureFailure(err error, request bool) OperationFailure {
	switch {
	case errors.Is(err, value.ErrPreparationUncertain):
		return OperationFailure{"AcquisitionUncertain", "Collection may already be in progress, or this attempt may no longer be usable. Check its status before starting a new investigation. The original may still produce a result.", false}
	case errors.Is(err, value.ErrAcquisitionClosed):
		return OperationFailure{"AcquisitionClosed", "The original collection interval has ended. Check its status for any recorded result. To collect again, start a new investigation explicitly.", false}
	case errors.Is(err, value.ErrConflict):
		return OperationFailure{"Conflict", "This submission conflicts with existing request or admission state. Keep the original preview and request key; do not assume an earlier attempt failed.", false}
	case errors.Is(err, value.ErrPreviewExpired):
		return OperationFailure{"PreviewExpired", "This preview is no longer valid for a new capture. An earlier attempt may still have been accepted. Keep the original preview and request key while resolving its outcome.", false}
	case errors.Is(err, value.ErrChanged) && !request:
		// A preview has no earlier review to resolve: an observation that
		// changed or lapsed while it was assembled is a retryable unavailability
		// (installed native 63/69), not ReviewChanged.
		return OperationFailure{"NotAvailable", "The operation is unavailable. Check your access or retry when the service is available.", true}
	case errors.Is(err, value.ErrChanged):
		return OperationFailure{"ReviewChanged", "The reviewed scope or current conditions changed. An earlier attempt may still have been accepted. Resolve the original request before reviewing a replacement.", false}
	case errors.Is(err, value.ErrProcessingCoverage):
		if request {
			return OperationFailure{"ProcessingCoverageUnavailable", "Evidence cannot currently be kept for the selected duration. Check the original request's status before trying again; an earlier attempt may have been accepted.", false}
		}
		return OperationFailure{"ProcessingCoverageUnavailable", "Evidence cannot currently be kept for the selected duration. Ask an administrator to review the retention limits and available capacity.", false}
	case errors.Is(err, value.ErrCapacity):
		return OperationFailure{"CapacityUnavailable", "Capacity is unavailable. Retry the same request after capacity becomes available.", true}
	case !request && (errors.Is(err, value.ErrDenied) || errors.Is(err, identity.ErrDenied) || errors.Is(err, targets.ErrDenied)):
		// Target reads resolve the named workload before authorizing it, so an
		// absent target fails as unavailable. A denied existing one must project
		// identically, or the reply becomes an existence oracle (specs/mcp.md:
		// uniform not-found/not-authorized projection).
		return OperationFailure{"NotAvailable", "The operation is unavailable. Check your access or retry when the service is available.", true}
	case errors.Is(err, value.ErrDenied), errors.Is(err, identity.ErrDenied), errors.Is(err, targets.ErrDenied):
		return OperationFailure{"NotAvailable", "This operation is not available with your current access.", false}
	case errors.Is(err, value.ErrInvalid), errors.Is(err, value.ErrDiagnosticUnavailable):
		return OperationFailure{"UnsupportedRequest", "This runtime supports the pod-status preset and submission of its reviewed previews.", false}
	}
	// Resolution happens before target eligibility. Never relay API object names,
	// not-found/unsupported-owner distinctions, SQL errors or provider details.
	if request {
		return OperationFailure{"OutcomeUnknown", "The submission outcome could not be confirmed. Retry with the same preview and request key; do not automatically create another capture.", true}
	}
	return OperationFailure{"NotAvailable", "The operation is unavailable. Check your access or retry when the service is available.", true}
}

// OperationReply retains the earliest original metadata authority through final
// transport checks and socket writes. ValidUntil is private, never a wire field.
type OperationReply struct {
	Body       []byte
	ValidUntil time.Time

	// These closed private facts preserve decisions through the intentionally
	// nondisclosing public error projection. They are never JSON fields and do
	// not establish the disposition of an earlier same-key request.
	auditDecision   operationAuditDecision
	auditNoDispatch bool
	auditEffect     operationAuditEffect
	owner           *operationReplyOwner
}

type operationAuditDecision uint8

const (
	operationAuditUnspecified operationAuditDecision = iota
	operationAuditDenied
	operationAuditInvalid
)

func captureAuditDecision(err error) operationAuditDecision {
	switch {
	case errors.Is(err, value.ErrDenied), errors.Is(err, identity.ErrDenied), errors.Is(err, targets.ErrDenied):
		return operationAuditDenied
	case errors.Is(err, value.ErrInvalid), errors.Is(err, value.ErrDiagnosticUnavailable):
		return operationAuditInvalid
	default:
		return operationAuditUnspecified
	}
}

// Call is shared by browser and MCP after their respective authentication. Its
// inputs are strictly the implemented canonical subset. No optional unsupported
// reason, sharing, history, raw-access or composition field is silently ignored.
func (s *ContextOperations) Call(ctx context.Context, current identities.CurrentIdentity, name string, raw json.RawMessage) (OperationReply, error) {
	if s == nil {
		return OperationReply{}, ErrOperationsConfiguration
	}
	return s.CallWithContext(ctx, current, OperationCall{requestID: s.config.NewID()}, name, raw)
}

func (s *ContextOperations) CallWithContext(ctx context.Context, current identities.CurrentIdentity, call OperationCall, name string, raw json.RawMessage) (OperationReply, error) {
	if s == nil || ctx == nil || current == nil {
		return OperationReply{}, value.ErrUnavailable
	}
	if err := s.contracts.ValidateInput(name, raw); err != nil {
		return OperationReply{}, err
	}
	var in ContextOperationInput
	if json.Unmarshal(raw, &in) != nil {
		return OperationReply{}, contracts.ErrInvestigationWire
	}
	i, err := current.ResolveIdentity(ctx)
	if err != nil || !i.Valid(s.config.Now()) || !slices.Contains(i.Scopes, "evidence:read") {
		return OperationReply{}, identity.ErrDenied
	}
	requestID := call.requestID
	if !authorization.UUID(requestID) {
		return OperationReply{}, value.ErrUnavailable
	}
	out := OperationEnvelope{SchemaVersion: "mcp-result/v1", RequestID: requestID, DataClass: "metadata", Status: "ok", Warnings: []string{}, Provenance: []any{}}
	until := i.ValidUntil
	var operationErr error
	auditNoDispatch := false
	switch name {
	case "list_diagnostics":
		var observed time.Time
		observed, operationErr = s.captures.CheckDiagnostic(ctx, current, in.Target.target())
		if operationErr == nil {
			until = identity.Earlier(until, observed)
		}
		if operationErr == nil {
			out.Data = struct {
				Diagnostics []DiagnosticRow `json:"diagnostics"`
			}{[]DiagnosticRow{{Name: "Pod status", Version: "v1", Description: "One whole-pod Kubernetes status snapshot, up to 4096 native bytes. This does not collect logs, processes or network traffic.", Available: s.config.CollectionEnabled, Blockers: collectionBlockers(s.config.CollectionEnabled), Preset: PresetReference{"pod-status", "v1"}}}}
		}
	case "preview_capture":
		var result app.ContextPreviewResult
		result, operationErr = s.captures.Preview(ctx, current, value.ContextIntent{Target: in.Target.target(), Diagnostic: value.ContextDiagnosticName, RequestedSeconds: in.RequestedSeconds})
		if operationErr == nil {
			until = identity.Earlier(until, identity.Earlier(result.ValidUntil, result.Assessment.ValidUntil))
			p := result.Preview
			selection := "lexicalEligiblePod"
			if in.Target.Kind == "Pod" {
				selection = "explicitPod"
			}
			out.Data = ContextPreviewData{PreviewID: p.ID, ExpiresAt: p.Deadline, ExecutionDigest: hash(p.ScopeDigest), PodCount: 1, MaxBytes: result.Assessment.OutputLimit, CaptureEnabled: s.config.CollectionEnabled, Blockers: collectionBlockers(s.config.CollectionEnabled), Warnings: []string{}, NavigationURI: s.config.PublicOrigin + "/captures/new", Lifecycle: ContextLifecycle(), Assessment: ContextAssessment(result.Assessment), Preset: PresetReference{"pod-status", "v1"}, Target: in.Target, SelectedPods: []SelectedPod{{ClusterID: p.Target.ClusterID, Namespace: p.Target.Namespace.Name, Name: p.Target.PodName, UID: p.Target.PodUID, Workload: SelectedWorkload{Kind: p.Target.Workload.Kind, Name: p.Target.Workload.Name, UID: p.Target.Workload.UID}}}, PodSelection: selection}
		}
	case "request_capture":
		if !s.config.CollectionEnabled {
			auditNoDispatch = true
			out.Status, out.Data = "error", OperationFailure{"CollectionDisabled", "New collection is disabled for this service. An earlier attempt may still have been accepted. Keep its preview and request key until its outcome can be checked.", false}
		} else if !slices.Contains(i.Scopes, "evidence:capture") {
			auditNoDispatch = true
			operationErr = value.ErrDenied
		} else {
			var accepted value.Accepted
			if in.ContinueAcquisition {
				if continuation, ok := s.captures.(ContextContinuation); ok {
					accepted, operationErr = continuation.Continue(ctx, current, in.PreviewID, in.IdempotencyKey)
				} else {
					auditNoDispatch = true
					operationErr = value.ErrUnavailable
				}
			} else {
				accepted, operationErr = s.captures.Request(ctx, current, in.PreviewID, in.IdempotencyKey)
			}
			if operationErr == nil {
				until = identity.Earlier(until, accepted.MetadataValidUntil)
				out.Data = ContextAcceptedData{CaptureID: accepted.CaptureID, Phase: "Accepted", NavigationURI: s.config.PublicOrigin + "/captures/" + accepted.CaptureID, Operation: "collect"}
			}
		}
	case "resolve_capture_request":
		var disposition value.ContextRequestDisposition
		disposition, operationErr = s.captures.ResolveContextRequest(ctx, current, in.PreviewID, in.IdempotencyKey)
		if operationErr == nil {
			until = identity.Earlier(until, disposition.ValidUntil)
			switch disposition.State {
			case value.RequestAccepted:
				if disposition.Accepted == nil {
					return OperationReply{}, value.ErrUnavailable
				}
				out.Data = ContextResolutionData{State: "accepted", ContextAcceptedData: &ContextAcceptedData{CaptureID: disposition.Accepted.CaptureID, Phase: "Accepted", NavigationURI: s.config.PublicOrigin + "/captures/" + disposition.Accepted.CaptureID, Operation: "collect"}}
			case value.RequestClosed:
				if disposition.Accepted != nil {
					return OperationReply{}, value.ErrUnavailable
				}
				out.Data = ContextResolutionData{State: "closed"}
			default:
				return OperationReply{}, value.ErrUnavailable
			}
		}
	case "get_capture":
		var progress value.ContextProgress
		progress, operationErr = s.progress.Get(ctx, current, in.CaptureID)
		if operationErr == nil {
			until = identity.Earlier(until, progress.ValidUntil)
			out.Data = ContextProgressData{CaptureID: progress.CaptureID, Revision: progress.Revision, Phase: progress.Phase, Actions: []ContextActionData{{ActionID: "pod-status", Phase: progress.ActionPhase, ReasonCode: progress.ReasonCode}}, CaseID: progress.CaseID, NavigationURI: s.config.PublicOrigin + "/captures/" + progress.CaptureID, RetryAfterSeconds: progress.RetryAfterSeconds, CanCancel: progress.CanCancel, Blockers: []OperationBlocker{}, Operation: "collect"}
		}
	default:
		return OperationReply{}, contracts.ErrInvestigationWire
	}
	if operationErr != nil {
		out.Status, out.Data = "error", publicCaptureFailure(operationErr, name == "request_capture" || name == "resolve_capture_request")
	}
	finalIdentity, err := current.ResolveIdentity(ctx)
	if err != nil || ctx.Err() != nil || !i.Valid(s.config.Now()) || !finalIdentity.Valid(s.config.Now()) || finalIdentity.Principal != i.Principal {
		return OperationReply{}, identity.ErrDenied
	}
	until = identity.Earlier(until, finalIdentity.ValidUntil)
	b, err := json.Marshal(out)
	if err != nil || s.contracts.ValidateOutput(name, b) != nil {
		return OperationReply{}, value.ErrUnavailable
	}
	if !s.config.Now().Before(until) || ctx.Err() != nil {
		clear(b)
		return OperationReply{}, value.ErrUnavailable
	}
	return OperationReply{Body: b, ValidUntil: until, auditDecision: captureAuditDecision(operationErr), auditNoDispatch: auditNoDispatch}, nil
}
