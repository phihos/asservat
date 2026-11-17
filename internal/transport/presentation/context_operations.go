package presentation

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"encoding/json/jsontext"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	app "asservat.local/asservat/internal/application/capture"
	identities "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/domain/planning"
	"asservat.local/asservat/internal/domain/targets"
)

// ContextUseCase is the shared C-09 service. A transport never supplies target
// authority, accepted rows, identities or observations in an input body.
type ContextUseCase interface {
	CheckDiagnostic(context.Context, identities.CurrentIdentity, targets.WorkloadRequest) (time.Time, error)
	Preview(context.Context, identities.CurrentIdentity, value.ContextIntent) (app.ContextPreviewResult, error)
	Request(context.Context, identities.CurrentIdentity, app.CaptureRequest) (value.Accepted, error)
}
type ContextProgressUseCase interface {
	Get(context.Context, identities.CurrentIdentity, string) (value.ContextProgress, error)
}

// CollectionEnabled is an installation/client runtime switch, not permission.
// Bootstrap must leave it false until the full execution/publication workflow
// is composed and qualified. A successful preview cannot set this switch.
type ContextOperationsConfig struct {
	HistoryRootID     string
	HistoryCursorKeys app.HistoryKeys
	PublicOrigin      string
	CollectionEnabled bool
	Now               func() time.Time
	NewID             func() string
	// Clusters resolves the cluster names of public inputs (ADR-335 D4).
	Clusters ClusterNames
}

// ContextHistoryUseCase is the ADR-236 history service. It is optional: an
// installation without it serves no history tools and no repeat branch.
type ContextHistoryUseCase interface {
	List(context.Context, identities.CurrentIdentity, targets.WorkloadRequest, []value.HistoryOrigin, *value.HistoryCursor, int) (value.HistoryPage, error)
	Settings(context.Context, identities.CurrentIdentity, string) (value.CaptureSettings, error)
	PreviewRepeat(context.Context, identities.CurrentIdentity, string, *value.ContextSharing) (app.ContextPreviewResult, value.CaptureSettings, error)
}

type ContextOperations struct {
	recordingSaveCancellationEnabled bool
	recordingSaveCollection          bool
	config                           ContextOperationsConfig
	captures                         ContextUseCase
	progress                         ContextProgressUseCase
	history                          ContextHistoryUseCase
	// recordingSaves recomputes a recording-save preview on request_capture.
	recordingSaves RecordingSaveUseCase
	contracts      *contracts.InvestigationContracts
}

func (s *ContextOperations) PublicOrigin() string {
	if s == nil {
		return ""
	}
	return s.config.PublicOrigin
}

var ErrOperationsConfiguration = errors.New("invalid context operations configuration")

func NewContextOperations(c ContextOperationsConfig, capture ContextUseCase, progress ContextProgressUseCase) (*ContextOperations, error) {
	return NewContextOperationsWithHistory(c, capture, progress, nil)
}

// NewContextOperationsWithHistory also serves list_capture_history,
// get_capture view=settings and the preview_capture history branch (ADR-236).
func NewContextOperationsWithHistory(c ContextOperationsConfig, capture ContextUseCase, progress ContextProgressUseCase, history ContextHistoryUseCase) (*ContextOperations, error) {
	u, err := url.Parse(c.PublicOrigin)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" || len(c.PublicOrigin) > 1800 || capture == nil || progress == nil || c.Now == nil || c.NewID == nil {
		return nil, ErrOperationsConfiguration
	}
	wire, err := contracts.NewInvestigationContracts()
	if err != nil {
		return nil, err
	}
	return &ContextOperations{config: c, captures: capture, progress: progress, history: history, contracts: wire}, nil
}

func (s *ContextOperations) ToolNames() []string {
	out := []string{"list_diagnostics", "preview_capture", "get_capture"}
	if s != nil && s.config.CollectionEnabled {
		out = append(out, "request_capture")
	}
	if s != nil && s.history != nil {
		out = append(out, "list_capture_history")
	}
	if s != nil {
		if _, ok := s.captures.(ContextProfiles); ok {
			out = append(out, "get_capture_profile")
		}
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

// TargetRef is the canonical target_ref input: a cluster name, never an ID.
type TargetRef struct {
	Cluster   string `json:"cluster"`
	Namespace string `json:"namespace"`
	Kind      string `json:"kind"`
	Name      string `json:"name"`
}

func targetOutput(t targets.WorkloadRequest) WorkloadReference {
	return WorkloadReference{t.ClusterID, t.Namespace, t.Kind, t.Name}
}

// errUnknownCluster is a public cluster name that no configured cluster has.
var errUnknownCluster = errors.New("unknown cluster name")

// workload resolves a target_ref cluster name.
func (s *ContextOperations) workload(r TargetRef) (targets.WorkloadRequest, error) {
	id, ok := s.config.Clusters.ID(r.Cluster)
	if !ok {
		return targets.WorkloadRequest{}, errUnknownCluster
	}
	return targets.WorkloadRequest{ClusterID: id, Namespace: r.Namespace, Kind: r.Kind, Name: r.Name}, nil
}

// HistoryTarget is the canonical target selector of list_capture_history and
// the explicit request_capture shape. Only a named workload is served.
type HistoryTarget struct {
	Namespace   string `json:"namespace"`
	WorkloadRef *struct {
		Kind string `json:"kind"`
		Name string `json:"name"`
		UID  string `json:"uid"`
	} `json:"workloadRef"`
	PodSelector json.RawMessage `json:"podSelector"`
	MaxPods     *int            `json:"maxPods"`
	Selection   string          `json:"selection"`
	Ordinals    json.RawMessage `json:"ordinals"`
	Adoption    string          `json:"adoption"`
}

func (s *ContextOperations) selector(cluster string, t *HistoryTarget) (targets.WorkloadRequest, error) {
	switch {
	case t.WorkloadRef == nil || t.PodSelector != nil:
		return targets.WorkloadRequest{}, capabilityError("target podSelector")
	case t.WorkloadRef.UID != "" || t.Adoption == "pinUID":
		return targets.WorkloadRequest{}, capabilityError("target uid pinning")
	case t.MaxPods != nil && *t.MaxPods != 1 || t.Selection != "" || t.Ordinals != nil:
		return targets.WorkloadRequest{}, capabilityError("target pod selection")
	}
	return s.workload(TargetRef{cluster, t.Namespace, t.WorkloadRef.Kind, t.WorkloadRef.Name})
}

// capabilityError names a canonical input this runtime cannot serve yet.
type capabilityError string

func (e capabilityError) Error() string { return string(e) + " is unavailable in this runtime" }

type PresetReference struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}
type ContextOperationInput struct {
	Target           TargetRef         `json:"target_ref"`
	TargetHandle     string            `json:"target_handle,omitempty"`
	DiagnosticHandle string            `json:"diagnostic_handle,omitempty"`
	Preset           PresetReference   `json:"preset_ref"`
	RequestedSeconds int64             `json:"requested_retention_seconds"`
	IdempotencyKey   string            `json:"idempotency_key"`
	CaptureID        string            `json:"capture_id"`
	// ADR-330 D9: request_capture submits the reviewed preview request and
	// the plan digest its preview returned.
	Preview            *ContextOperationInput `json:"preview,omitempty"`
	ExpectedPlanDigest string                 `json:"expected_plan_digest,omitempty"`
	// A save of existing recordings (REQ-SAV-004).
	RecordingHandles []string `json:"recording_handles,omitempty"`
	Before           string   `json:"before,omitempty"`
	Reason           *string  `json:"reason,omitempty"`
	// Sharing is the optional capture-time share of the result (ADR-235).
	Sharing *ContextSharingInput `json:"sharing,omitempty"`
	// ADR-236: the preview_capture history branch and list_capture_history.
	HistoryCaptureID      string `json:"history_capture_id,omitempty"`
	RepeatedFromCaptureID string `json:"repeated_from_capture_id,omitempty"`
	HistorySelection      string `json:"history_selection,omitempty"`
	// ADR-243: one builtin packet or syscall capture profile with typed edits.
	Composition *CompositionInput `json:"profile_composition,omitempty"`
	Origin      string            `json:"origin,omitempty"`
	// REQ-CPR-001: list_diagnostics catalog filter and get_capture_profile.
	Catalog    string          `json:"catalog,omitempty"`
	ProfileRef *ProfileRefData `json:"profile_ref,omitempty"`
	Cursor     string          `json:"cursor,omitempty"`
	Limit      int             `json:"limit,omitempty"`
	// ADR-249: the same-human result access of a reviewed recorder plan.
	ResultAccess *ResultAccessInput `json:"result_access,omitempty"`
	// get_capture view; after_revision waits belong to the shared wrapper.
	View string `json:"view,omitempty"`
	// list_diagnostics filters and the recommendation inputs.
	Kind                string          `json:"kind,omitempty"`
	Goal                string          `json:"goal,omitempty"`
	DiscoveryCaptureIDs json.RawMessage `json:"discovery_capture_ids,omitempty"`
	Preferences         json.RawMessage `json:"preferences,omitempty"`
	Focus               json.RawMessage `json:"focus,omitempty"`
	// The explicit request_capture shape and the list_capture_history selector.
	Cluster      string         `json:"cluster,omitempty"`
	Selector     *HistoryTarget `json:"target,omitempty"`
	Recipe       string         `json:"recipe,omitempty"`
	RecipeDigest string         `json:"recipe_digest,omitempty"`
}

// ContextSharingInput is the canonical capture sharing request. Output
// selection, team management and a sharing reason are refused as unavailable.
type ContextSharingInput struct {
	Recipients      []shareRecipientInput `json:"recipients"`
	NotAfter        *time.Time            `json:"notAfter,omitempty"`
	OutputSelection json.RawMessage       `json:"outputSelection,omitempty"`
	Management      json.RawMessage       `json:"management,omitempty"`
	Reason          string                `json:"reason,omitempty"`
}

func (in *ContextSharingInput) unsupported() error {
	switch {
	case in == nil:
		return nil
	case in.OutputSelection != nil:
		return capabilityError("sharing outputSelection")
	case in.Management != nil:
		return capabilityError("sharing management")
	case in.Reason != "":
		return capabilityError("sharing reason")
	}
	return nil
}

func (in *ContextSharingInput) intent() *value.ContextSharing {
	if in == nil {
		return nil
	}
	out := &value.ContextSharing{}
	for _, r := range in.Recipients {
		out.Recipients = append(out.Recipients, authorization.ShareRecipient{Kind: r.Kind, Issuer: r.Issuer, ID: r.ID})
	}
	if in.NotAfter != nil {
		out.NotAfter = in.NotAfter.UTC().Truncate(time.Microsecond)
	}
	return out
}

// ContextSharingData is get_capture's sharing status, separate from capture
// progress (ADR-235).
type ContextSharingData struct {
	State   string `json:"state"`
	ShareID string `json:"share_id,omitempty"`
}

func sharingWarning(s *value.ContextSharing) []string {
	if s == nil {
		return []string{}
	}
	until := "24 hours after it is published"
	if !s.NotAfter.IsZero() {
		until = s.NotAfter.UTC().Format(time.RFC3339)
	}
	return []string{fmt.Sprintf("When this capture is published, its result will be shared with %d recipient(s) until %s (never past the evidence's access end). Recipients can read and download only that result.", len(s.Recipients), until)}
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
	Kind             string             `json:"kind"`
	Name             string             `json:"name"`
	Version          string             `json:"version"`
	Description      string             `json:"description"`
	DisplayName      string             `json:"display_name,omitempty"`
	ApprovalRequired bool               `json:"approval_required"`
	Available        bool               `json:"available"`
	Deprecated       bool               `json:"deprecated,omitempty"`
	Blockers         []OperationBlocker `json:"blockers"`
	ExecutionModes   []string           `json:"execution_modes"`
	Preset           *PresetReference   `json:"preset_ref,omitempty"`
	Profile          *ProfileRefData    `json:"profile_ref,omitempty"`
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
	PlanDigest       string             `json:"plan_digest"`
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
	Preset           *PresetReference   `json:"preset_ref,omitempty"`
	Target           *WorkloadReference `json:"target_ref,omitempty"`
	SelectedPods     []SelectedPod      `json:"selected_pods,omitempty"`
	PodSelection     string             `json:"pod_selection,omitempty"`
	RepeatedFrom     string             `json:"repeated_from_capture_id,omitempty"`
}
type ContextAcceptedData struct {
	RepeatedFrom  string `json:"repeated_from_capture_id,omitempty"`
	HistoryState  string `json:"history_state,omitempty"`
	CaptureID     string `json:"capture_id"`
	Phase         string `json:"phase"`
	NavigationURI string `json:"navigation_uri"`
	Operation     string `json:"operation"`
}

type ContextActionData struct {
	InstanceID string `json:"action_instance_id,omitempty"`
	PodUID     string `json:"pod_uid,omitempty"`
	PodName    string `json:"pod_name,omitempty"`
	ActionID   string `json:"action_id"`
	Phase      string `json:"phase"`
	ReasonCode string `json:"reason_code,omitempty"`
}
type ContextProgressData struct {
	Reason                *string             `json:"reason,omitempty"`
	ReasonState           string              `json:"reason_state,omitempty"`
	RepeatedFrom          string              `json:"repeated_from_capture_id,omitempty"`
	HistoryState          string              `json:"history_state,omitempty"`
	CaptureID             string              `json:"capture_id"`
	Revision              int64               `json:"revision"`
	Phase                 string              `json:"phase"`
	Actions               []ContextActionData `json:"actions"`
	CaseID                string              `json:"case_id,omitempty"`
	NavigationURI         string              `json:"navigation_uri"`
	CanCancel             bool                `json:"can_cancel"`
	CancellationRequested bool                `json:"cancellation_requested,omitempty"`
	Blockers              []OperationBlocker  `json:"blockers"`
	Operation             string              `json:"operation"`
	Sharing               *ContextSharingData `json:"sharing,omitempty"`
}

func collectionBlockers(enabled bool) []OperationBlocker {
	if enabled {
		return []OperationBlocker{}
	}
	return []OperationBlocker{{Code: "CollectionDisabled", Message: "Collection is not enabled for this service. The preview has not started a capture.", ResponsibleRole: "administrator", Retryable: false}}
}
func publicCaptureFailure(err error, request bool) OperationFailure {
	// ADR-243: composition refusals are reported only after current target
	// eligibility and name the authored field and a remedy, never target state.
	var refusal planning.CompositionError
	if errors.As(err, &refusal) {
		return OperationFailure{refusal.Code, boundedText(refusal.Path+": "+refusal.Reason, 1024), false}
	}
	if errors.Is(err, errUnknownCluster) {
		return OperationFailure{"UnknownCluster", "No cluster of this installation has this name. Use local for the hub's own cluster or a configured clusters[].name.", false}
	}
	var capability capabilityError
	if errors.As(err, &capability) {
		return OperationFailure{"CapabilityUnavailable", capability.Error() + ".", false}
	}
	switch {
	case errors.Is(err, value.ErrHistorySelectionRequired):
		return OperationFailure{"RequiresSelection", "This policy captured its triggering Pod. Choose a current eligible Pod for the new manual request.", false}
	case errors.Is(err, value.ErrProfileChanged):
		return OperationFailure{"ProfileChanged", "A saved dependency version is unavailable or changed. Review a new request with current versions explicitly.", false}
	case errors.Is(err, value.ErrSettingsTooLarge):
		return OperationFailure{"SettingsTooLarge", "Saved settings exceed the response limit. Open the capture in the browser or repeat by reference.", false}
	case errors.Is(err, value.ErrSettingsUnavailable):
		return OperationFailure{"ParametersUnavailable", "Saved settings are unavailable. Start a new preview with your current settings.", true}
	case errors.Is(err, value.ErrProfileNotFound):
		return OperationFailure{"ProfileNotFound", "This profile version is not published in that catalog. List the catalog and choose an exact version.", false}
	case errors.Is(err, targets.ErrProfileLimit):
		return OperationFailure{"TooManyProfiles", "More profiles than one page. Narrow the list with catalog.", false}
	case errors.Is(err, errInvalidCursor):
		return OperationFailure{"InvalidCursor", "Refresh this view to continue with current access.", false}
	case errors.Is(err, value.ErrRecorderUnavailable):
		return OperationFailure{"RecorderUnavailable", "No recorder is available for this reviewed plan. No capture was started and nothing was reserved.", false}
	case errors.Is(err, value.ErrSharingDenied):
		// Decided from the caller's own scope (preview) or after the
		// caller's capture eligibility on the target (request): no oracle.
		return OperationFailure{"SharingNotPermitted", "Sharing the result needs the evidence-owner role on this workload and the evidence:share scope. No capture was started. Remove the recipients, or ask an administrator for the role.", false}
	case request && errors.Is(err, value.ErrStorageBindingExpired):
		// ADR-277: refused before admission (or by a rolled-back admission)
		// while the workload's storage binding refreshes: nothing was accepted.
		return OperationFailure{"StorageRefreshing", "Evidence storage for this workload is being refreshed. Nothing was accepted. Retry the same request with the same preview and request key in a few seconds.", true}
	case errors.Is(err, value.ErrPreparationUncertain):
		return OperationFailure{"AcquisitionUncertain", "Collection may already be in progress, or this attempt may no longer be usable. Check its status before starting a new investigation. The original may still produce a result.", false}
	case request && errors.Is(err, value.ErrAcquisitionNotStarted):
		// Admitted, and its start was refused before any start effect
		// (ADR-212): a passive same-key retry would only replay acceptance.
		return OperationFailure{"AcquisitionNotStarted", "The capture was accepted, but collection has not started. Check its status; do not create another capture.", false}
	case errors.Is(err, value.ErrAcquisitionClosed):
		return OperationFailure{"AcquisitionClosed", "The original collection interval has ended. Check its status for any recorded result. To collect again, start a new investigation explicitly.", false}
	case errors.Is(err, value.ErrConflict):
		return OperationFailure{"Conflict", "This submission conflicts with existing request or admission state. Keep the original preview and request key; do not assume an earlier attempt failed.", false}
	case errors.Is(err, value.ErrPreviewExpired):
		return OperationFailure{"PreviewExpired", "The reviewed plan is no longer valid for a new capture. Retry the same request and key to see whether an earlier attempt was accepted, or preview again.", false}
	case errors.Is(err, value.ErrChanged) && !request:
		// A preview has no earlier review to resolve: an observation that
		// changed or lapsed while it was assembled is a retryable unavailability
		// (installed native 63/69), not ReviewChanged.
		return OperationFailure{"NotAvailable", "The operation is unavailable. Check your access or retry when the service is available.", true}
	case errors.Is(err, value.ErrChanged):
		return OperationFailure{"ReviewChanged", "The reviewed plan or current conditions changed. Nothing new was accepted. Preview again to review the current plan.", false}
	case errors.Is(err, value.ErrProcessingCoverage):
		if request {
			return OperationFailure{"ProcessingCoverageUnavailable", "Evidence cannot currently be kept for the selected duration. Check the original request's status before trying again; an earlier attempt may have been accepted.", false}
		}
		return OperationFailure{"ProcessingCoverageUnavailable", "Evidence cannot currently be kept for the selected duration. Ask an administrator to review the retention limits and available capacity.", false}
	case request && errors.Is(err, targets.ErrChanged):
		// The requester already reviewed this Pod in its preview, so naming its
		// disappearance discloses nothing new. Retrying the same preview cannot
		// succeed; the workload must be reviewed again.
		return OperationFailure{"TargetGone", "The reviewed Pod no longer exists or was replaced. This request started no capture. Preview the workload again to select its current Pod.", false}
	case !request && errors.Is(err, value.ErrTargetReplaced):
		// Reported only after current collection eligibility on the new workload.
		return OperationFailure{"TargetReplaced", "The workload was recreated since the original capture, so its history does not carry over. Preview the workload by name to review the new one.", false}
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
		return OperationFailure{"UnsupportedRequest", "This request is not valid for the selected target, preset, profile or recordings. Review the inputs and preview again.", false}
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
	// get_capture and preview_capture replies may use the MCP result bound.
	resultBound bool
	grantReview          bool // Only the authenticated get_grant producer sets this budget.
	Body                 []byte
	ValidUntil           time.Time

	// These closed private facts preserve decisions through the intentionally
	// nondisclosing public error projection. They are never JSON fields and do
	// not establish the disposition of an earlier same-key request.
	auditDecision   operationAuditDecision
	auditNoDispatch bool
	auditEffect     operationAuditEffect
	owner           *operationReplyOwner
	browserSettings bool
	// failureStep is the service's fixed failure step behind a public error
	// reply, for content-free timing reports only.
	failureStep string
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
	case errors.Is(err, value.ErrInvalid), errors.Is(err, value.ErrDiagnosticUnavailable), errors.As(err, new(planning.CompositionError)), errors.As(err, new(capabilityError)), errors.Is(err, errInvalidCursor), errors.Is(err, errUnknownCluster):
		return operationAuditInvalid
	default:
		return operationAuditUnspecified
	}
}

// Call is shared by browser and MCP after their respective authentication.
// Inputs follow the canonical contract; an input this runtime cannot serve
// returns CapabilityUnavailable and is never silently ignored. after_revision
// waits belong to the shared wrapper.
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
	settings := name == "get_capture" && in.View == "settings"
	switch name {
	case "list_diagnostics":
		var listUntil time.Time
		out.Data, out.NextCursor, listUntil, operationErr = s.diagnostics(ctx, current, in)
		if operationErr == nil {
			until = identity.Earlier(until, listUntil)
		}
	case "preview_capture":
		planCtx, digest := app.WithPlanScope(ctx)
		var data any
		var previewUntil time.Time
		var p value.ContextPreview
		data, previewUntil, p, operationErr = s.previewCapture(planCtx, current, in)
		if operationErr == nil {
			until = identity.Earlier(until, previewUntil)
			plan := hash(digest(p))
			switch d := data.(type) {
			case ContextPreviewData:
				d.PlanDigest = plan
				out.Data = d
			case RecorderPreviewData:
				d.PlanDigest = plan
				out.Data, out.DataClass = d, "extract" // full composition settings are a protected extract
			}
		}
	case "get_capture_profile":
		var profileUntil time.Time
		out.Data, profileUntil, operationErr = s.profile(ctx, current, in)
		if operationErr == nil {
			until = identity.Earlier(until, profileUntil)
			out.DataClass = "extract"
		}
	case "list_capture_history":
		var historyUntil time.Time
		var cursor *string
		out.Data, cursor, historyUntil, operationErr = s.historyCall(ctx, current, i, in)
		if operationErr == nil {
			until = identity.Earlier(until, historyUntil)
			out.NextCursor = cursor
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
			accepted, operationErr = s.request(ctx, current, in)
			if operationErr == nil {
				until = identity.Earlier(until, accepted.MetadataValidUntil)
				data := ContextAcceptedData{CaptureID: accepted.CaptureID, Phase: "Accepted", NavigationURI: s.config.PublicOrigin + "/captures/" + accepted.CaptureID, Operation: acceptedRecordingOperation(accepted)}
				if accepted.RepeatedFrom != nil && accepted.RepeatedFrom.Valid(s.config.Now()) {
					data.RepeatedFrom = accepted.RepeatedFrom.CaptureID
				}
				if accepted.HistoryUnavailable {
					data.HistoryState = "unavailable"
				} else if accepted.HistoryRecorded {
					data.HistoryState = "available"
				}
				out.Data = data
			}
		}
	case "get_capture":
		if settings {
			var settingsUntil time.Time
			out.Data, settingsUntil, operationErr = s.settings(ctx, current, in.CaptureID)
			if operationErr == nil {
				until = identity.Earlier(until, settingsUntil)
				out.DataClass = "extract" // canonical class of a settings projection
			}
			break
		}
		var progress value.ContextProgress
		progress, operationErr = s.progress.Get(ctx, current, in.CaptureID)
		if operationErr == nil {
			until = identity.Earlier(until, progress.ValidUntil)
			operation := progress.Operation
			if operation == "" {
				operation = "collect"
			}
			actions, actionErr := recordingProgressActions(progress)
			if actionErr != nil {
				return OperationReply{}, actionErr
			}
			if progress.ReasonCode == "ProfileCancellationUncertain" {
				out.Warnings = append(out.Warnings, "Asservat stopped collecting this profile. Whether the application stopped profiling is unknown.")
			}
			data := ContextProgressData{CaptureID: progress.CaptureID, Revision: progress.Revision, Phase: capturePhase(progress.Phase), Actions: actions, CaseID: progress.CaseID, NavigationURI: s.config.PublicOrigin + "/captures/" + progress.CaptureID, CanCancel: progress.CanCancel, Blockers: []OperationBlocker{}, Operation: operation}
			data.CancellationRequested = progress.CancellationRequested
			data.Reason, data.ReasonState = progress.Reason, progress.ReasonState
			if operation == "recordingSave" {
				data.CanCancel = data.CanCancel && s.recordingSaveCancellationEnabled
			}
			data.HistoryState = progress.HistoryState
			if progress.RepeatedFrom != nil && progress.RepeatedFrom.Valid(s.config.Now()) {
				data.RepeatedFrom = progress.RepeatedFrom.CaptureID
			}
			if progress.Sharing != nil {
				data.Sharing = &ContextSharingData{State: progress.Sharing.State, ShareID: progress.Sharing.ShareID}
			}
			out.Data = data
		}
	default:
		return OperationReply{}, contracts.ErrInvestigationWire
	}
	if operationErr != nil {
		out.Status, out.DataClass, out.Data, out.NextCursor = "error", "metadata", publicCaptureFailure(operationErr, name == "request_capture"), nil
		if errors.Is(operationErr, value.ErrRecordingSelectionRequired) {
			out.Data = recordingSelectionFailure(s.config.PublicOrigin)
		}
		if settings && errors.Is(operationErr, value.ErrSettingsTooLarge) {
			out.Data = settingsSizeFailure(s.config.PublicOrigin, in.CaptureID)
		}
		if f, ok := approvalFailure(operationErr, s.config.PublicOrigin); ok && name == "request_capture" {
			out.Data = f
		}
	}
	finalIdentity, err := current.ResolveIdentity(ctx)
	if err != nil || ctx.Err() != nil || !i.Valid(s.config.Now()) || !finalIdentity.Valid(s.config.Now()) || finalIdentity.Principal != i.Principal {
		return OperationReply{}, identity.ErrDenied
	}
	until = identity.Earlier(until, finalIdentity.ValidUntil)
	b, err := json.Marshal(out)
	browserSettings := settings && browserSettingsView(ctx)
	if err == nil && browserSettings {
		canonical := jsontext.Value(b)
		if canonical.Canonicalize() != nil {
			return OperationReply{}, value.ErrUnavailable
		}
		b = canonical
	}
	// A settings view above the MCP result bound returns SettingsTooLarge with
	// browser navigation; a preview above it returns the same navigation
	// instead of a shortened plan (specs/mcp.md).
	if err == nil && !browserSettings && out.Status == "ok" && len(b) > contracts.InvestigationResultBound {
		out.Status, out.DataClass, out.Data = "error", "metadata", resultTooLarge(s.config.PublicOrigin, name, in.CaptureID)
		b, err = json.Marshal(out)
	}
	validate := s.contracts.ValidateOutput
	if browserSettings {
		validate = s.contracts.ValidateBrowserOutput
	}
	if err != nil || validate(name, b) != nil {
		return OperationReply{}, value.ErrUnavailable
	}
	if !s.config.Now().Before(until) || ctx.Err() != nil {
		clear(b)
		return OperationReply{}, value.ErrUnavailable
	}
	reply := OperationReply{Body: b, ValidUntil: until, auditDecision: captureAuditDecision(operationErr), auditNoDispatch: auditNoDispatch, browserSettings: browserSettings, resultBound: name == "get_capture" || name == "preview_capture"}
	if operationErr != nil {
		// Content-free timing label: the service's fixed step, if any.
		var step interface{ FixedStep() string }
		if errors.As(operationErr, &step) {
			reply.failureStep = step.FixedStep()
		}
	}
	return reply, nil
}

func settingsSizeFailure(origin, captureID string) any {
	return struct {
		OperationFailure
		NavigationURI string `json:"navigation_uri"`
	}{publicCaptureFailure(value.ErrSettingsTooLarge, false), origin + "/captures/" + captureID}
}

// resultTooLarge replaces a reply above the MCP result bound.
func resultTooLarge(origin, name, captureID string) any {
	switch name {
	case "get_capture":
		return settingsSizeFailure(origin, captureID)
	case "preview_capture":
		return struct {
			OperationFailure
			NavigationURI string `json:"navigation_uri"`
		}{OperationFailure{"PlanTooLarge", "This plan does not fit the MCP result. Review it in the browser.", false}, origin + "/captures/new"}
	}
	return OperationFailure{"ReduceLimit", "Request a smaller page to fit the result.", false}
}

// capturePhase projects stored parent phases onto the canonical capture
// phases; queued and validating work is pending, finalizing work runs.
func capturePhase(phase string) string {
	switch phase {
	case "Validating", "Queued":
		return "Pending"
	case "Finalizing":
		return "Running"
	}
	return phase
}

// lifecycleDuration parses a canonical duration (ms, s, m, h or d).
func lifecycleDuration(s string) (time.Duration, error) {
	if n, ok := strings.CutSuffix(s, "d"); ok {
		days, err := strconv.ParseInt(n, 10, 32)
		if err != nil || days < 1 {
			return 0, value.ErrInvalid
		}
		return time.Duration(days) * 24 * time.Hour, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil || d <= 0 {
		return 0, value.ErrInvalid
	}
	return d, nil
}

// unsupportedPreview names the first canonical preview input this runtime
// cannot serve.
func unsupportedPreview(in ContextOperationInput) error {
	switch {
	case in.TargetHandle != "":
		return capabilityError("target_handle")
	case in.DiagnosticHandle != "":
		return capabilityError("diagnostic_handle")
	case in.Preset.Name != "" && in.Preset.Name != "pod-status":
		return capabilityError("preset " + in.Preset.Name)
	case in.Reason != nil && len(in.RecordingHandles) == 0:
		return capabilityError("reason outside a recording save")
	case in.ResultAccess != nil && in.ResultAccess.NotAfter.IsZero():
		return capabilityError("result_access without notAfter")
	case in.ResultAccess != nil && (slices.Contains(in.ResultAccess.Operations, "read_memory") || slices.Contains(in.ResultAccess.Operations, "debugger_command")):
		return capabilityError("result_access memory and debugger operations")
	}
	return in.Sharing.unsupported()
}

// previewCapture computes the preview of one preview_capture input.
// request_capture recomputes it under the request's plan scope.
func (s *ContextOperations) previewCapture(ctx context.Context, current identities.CurrentIdentity, in ContextOperationInput) (any, time.Time, value.ContextPreview, error) {
	var zero value.ContextPreview
	if err := unsupportedPreview(in); err != nil {
		return nil, time.Time{}, zero, err
	}
	if len(in.RecordingHandles) > 0 {
		if s.recordingSaves == nil {
			return nil, time.Time{}, zero, capabilityError("recording saves")
		}
		var before time.Duration
		if in.Before != "" {
			var err error
			if before, err = lifecycleDuration(in.Before); err != nil {
				return nil, time.Time{}, zero, err
			}
		}
		result, err := s.recordingSaves.Preview(ctx, current, recordingSaveRequest(in.RecordingHandles, before, in.Sharing, in.RepeatedFromCaptureID, in.Reason))
		if err != nil {
			return nil, time.Time{}, zero, err
		}
		data, err := s.recordingSavePreview(result, in.RecordingHandles)
		return data, result.ValidUntil, result.Preview, err
	}
	var target targets.WorkloadRequest
	if in.HistoryCaptureID == "" {
		var err error
		if target, err = s.workload(in.Target); err != nil {
			return nil, time.Time{}, zero, err
		}
	}
	if in.Composition != nil && in.RepeatedFromCaptureID == "" {
		// ADR-243: a reviewed packet/syscall plan; recorder plans take no
		// capture-time sharing yet.
		if in.Sharing != nil {
			return nil, time.Time{}, zero, capabilityError("sharing with profile_composition")
		}
		use, ok := s.captures.(RecorderPreviewUseCase)
		if !ok {
			return nil, time.Time{}, zero, capabilityError("profile_composition")
		}
		composition, err := in.Composition.composition()
		if err != nil {
			return nil, time.Time{}, zero, value.ErrInvalid
		}
		result, err := use.PreviewComposition(ctx, current, value.ContextIntent{Target: target, RequestedSeconds: in.RequestedSeconds, Composition: composition})
		if err != nil {
			return nil, time.Time{}, zero, err
		}
		data, until, err := s.recorderPreviewResult(result, target)
		return data, until, result.Preview, err
	}
	var result app.ContextPreviewResult
	var err error
	repeated := ""
	if in.HistoryCaptureID != "" || in.RepeatedFromCaptureID != "" {
		// "Collect again" (ADR-236): the history entry supplies the target
		// and requested retention; the preview runs every current check.
		if s.history == nil {
			return nil, time.Time{}, zero, capabilityError("capture history")
		}
		var settings value.CaptureSettings
		sourceID := in.HistoryCaptureID
		if sourceID == "" {
			sourceID = in.RepeatedFromCaptureID
		}
		edits := value.HistoryRepeatEdits{Selection: in.HistorySelection}
		if in.RepeatedFromCaptureID != "" {
			edits.Target = &target
			edits.RequestedSeconds = in.RequestedSeconds
			if in.Composition != nil {
				if edits.Composition, err = in.Composition.composition(); err != nil {
					return nil, time.Time{}, zero, err
				}
			}
		}
		if edited, ok := s.history.(interface {
			PreviewEditedRepeat(context.Context, identities.CurrentIdentity, string, *value.ContextSharing, value.HistoryRepeatEdits) (app.ContextPreviewResult, value.CaptureSettings, error)
		}); ok {
			result, settings, err = edited.PreviewEditedRepeat(ctx, current, sourceID, in.Sharing.intent(), edits)
		} else if in.RepeatedFromCaptureID != "" || in.HistorySelection != "" {
			err = capabilityError("edited repeat")
		} else {
			result, settings, err = s.history.PreviewRepeat(ctx, current, sourceID, in.Sharing.intent())
		}
		target = targets.WorkloadRequest{ClusterID: settings.ClusterID, Namespace: settings.Namespace, Kind: settings.WorkloadKind, Name: settings.WorkloadName}
		repeated = sourceID
	} else {
		result, err = s.captures.Preview(ctx, current, value.ContextIntent{Target: target, Diagnostic: value.ContextDiagnosticName, RequestedSeconds: in.RequestedSeconds, Sharing: in.Sharing.intent()})
	}
	if err != nil {
		return nil, time.Time{}, zero, err
	}
	p := result.Preview
	if result.Recorder != nil {
		data, until, err := s.recorderPreviewResult(*result.Recorder, target)
		data.RepeatedFrom = repeated
		return data, until, p, err
	}
	selection := "lexicalEligiblePod"
	if target.Kind == "Pod" {
		selection = "explicitPod"
	}
	ref := targetOutput(target)
	data := ContextPreviewData{ExecutionDigest: hash(p.ScopeDigest), PodCount: 1, MaxBytes: result.Assessment.OutputLimit, CaptureEnabled: s.config.CollectionEnabled, Blockers: collectionBlockers(s.config.CollectionEnabled), Warnings: sharingWarning(p.Intent.Sharing), NavigationURI: s.config.PublicOrigin + "/captures/new", Lifecycle: ContextLifecycle(), Assessment: ContextAssessment(result.Assessment), Preset: &PresetReference{"pod-status", "v1"}, Target: &ref, SelectedPods: []SelectedPod{selectedPod(p)}, PodSelection: selection, RepeatedFrom: repeated}
	return data, identity.Earlier(result.ValidUntil, result.Assessment.ValidUntil), p, nil
}

func selectedPod(p value.ContextPreview) SelectedPod {
	return SelectedPod{ClusterID: p.Target.ClusterID, Namespace: p.Target.Namespace.Name, Name: p.Target.PodName, UID: p.Target.PodUID, Workload: SelectedWorkload{Kind: p.Target.Workload.Kind, Name: p.Target.Workload.Name, UID: p.Target.Workload.UID}}
}

// request submits the reviewed preview request of request_capture. The
// explicit recipe shape needs a recipe catalog this runtime does not have.
func (s *ContextOperations) request(ctx context.Context, current identities.CurrentIdentity, in ContextOperationInput) (value.Accepted, error) {
	if in.Preview == nil {
		return value.Accepted{}, capabilityError("explicit recipe request")
	}
	plan, err := hex.DecodeString(in.ExpectedPlanDigest)
	if err != nil || len(plan) != len(artifact.Digest{}) || artifact.Digest(plan) == (artifact.Digest{}) {
		return value.Accepted{}, value.ErrInvalid
	}
	preview := *in.Preview
	if err := unsupportedPreview(preview); err != nil {
		return value.Accepted{}, err
	}
	submission, err := json.Marshal(ContextOperationInput{Preview: in.Preview, ExpectedPlanDigest: in.ExpectedPlanDigest, IdempotencyKey: in.IdempotencyKey})
	if err != nil {
		return value.Accepted{}, value.ErrInvalid
	}
	return s.captures.Request(ctx, current, app.CaptureRequest{Key: in.IdempotencyKey, Plan: artifact.Digest(plan), Access: preview.ResultAccess.access(), Submission: submission, Preview: func(ctx context.Context) (value.ContextPreview, error) {
		_, _, p, err := s.previewCapture(ctx, current, preview)
		return p, err
	}})
}

// SubmitApproved submits a request_capture input that an approval stored,
// as the recorded requester current (ADR-335 D5). It takes the same path as
// request_capture: current bindings and denies decide, and a retry with the
// same key returns the same capture.
func (s *ContextOperations) SubmitApproved(ctx context.Context, current identities.CurrentIdentity, submission []byte) (string, error) {
	var in ContextOperationInput
	if s == nil || json.Unmarshal(submission, &in) != nil {
		return "", value.ErrInvalid
	}
	if !s.config.CollectionEnabled {
		return "", value.ErrUnavailable
	}
	if i, err := current.ResolveIdentity(ctx); err != nil || !slices.Contains(i.Scopes, "evidence:capture") {
		return "", value.ErrDenied
	}
	a, err := s.request(ctx, current, in)
	return a.CaptureID, err
}
