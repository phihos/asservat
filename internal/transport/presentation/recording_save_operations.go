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
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/domain/targets"
)

// RecordingSaveUseCase is the existing-source application boundary. Public
// inputs contain names/opaque selections, never runtime pins or an executor.
type RecordingSaveUseCase interface {
	List(context.Context, identities.CurrentIdentity, targets.WorkloadRequest, string, string, int) (app.RecordingPage, error)
	Preview(context.Context, identities.CurrentIdentity, app.RecordingSavePreviewRequest) (app.ContextPreviewResult, error)
}
type RecordingSaveOperationsConfig struct {
	PublicOrigin      string
	CollectionEnabled bool
	Now               func() time.Time
	NewID             func() string
}
type RecordingSaveOperations struct {
	config        RecordingSaveOperationsConfig
	saves         RecordingSaveUseCase
	contracts     *contracts.InvestigationContracts
	cancellations RecordingCancellationUseCase
}

func NewRecordingSaveOperations(c RecordingSaveOperationsConfig, saves RecordingSaveUseCase, cancellations ...RecordingCancellationUseCase) (*RecordingSaveOperations, error) {
	u, err := url.Parse(c.PublicOrigin)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" || len(c.PublicOrigin) > 1800 || saves == nil || c.Now == nil || c.NewID == nil || len(cancellations) > 1 {
		return nil, ErrOperationsConfiguration
	}
	wire, err := contracts.NewInvestigationContracts()
	if err != nil {
		return nil, err
	}
	out := &RecordingSaveOperations{config: c, saves: saves, contracts: wire}
	if len(cancellations) == 1 {
		out.cancellations = cancellations[0]
	}
	return out, nil
}
func (s *RecordingSaveOperations) PublicOrigin() string {
	if s == nil {
		return ""
	}
	return s.config.PublicOrigin
}
func (s *RecordingSaveOperations) ToolNames() []string {
	names := []string{"list_recordings", "preview_recording_save"}
	if s != nil && s.cancellations != nil {
		names = append(names, "cancel_capture")
	}
	return names
}
func (s *RecordingSaveOperations) Tool(name string) (contracts.InvestigationTool, bool) {
	if s == nil || !slices.Contains(s.ToolNames(), name) {
		return contracts.InvestigationTool{}, false
	}
	return s.contracts.Tool(name)
}
func NewInvestigationRecordingSaveOperations(base *InvestigationOperations, saves *RecordingSaveOperations) (*InvestigationOperations, error) {
	if saves == nil || base == nil {
		return nil, ErrOperationsConfiguration
	}
	composed := *saves
	composed.config.CollectionEnabled = saves.config.CollectionEnabled && base.captures != nil && base.captures.config.CollectionEnabled
	if base.captures == nil || !base.captures.config.CollectionEnabled {
		composed.cancellations = nil
	}
	out, err := withOperations(base, &composed)
	if err != nil {
		return nil, err
	}
	if base.captures != nil {
		capture := *base.captures
		capture.recordingSaveCancellationEnabled = composed.cancellations != nil
		out.captures = &capture
		for name, part := range out.routes {
			if part == base.captures {
				out.routes[name] = &capture
			}
		}
	}
	return out, nil
}

type RecordingRow struct {
	Handle          string     `json:"recording_handle,omitempty"`
	PolicyUID       string     `json:"policy_uid"`
	PodUID          string     `json:"pod_uid"`
	PodName         string     `json:"pod_name"`
	ActionID        string     `json:"action_id"`
	Kind            string     `json:"kind"`
	State           string     `json:"state"`
	History         string     `json:"history"`
	MaximumBefore   string     `json:"maximum_before"`
	Eligible        bool       `json:"save_eligible"`
	Blockers        []string   `json:"blockers"`
	IncidentPodCap  int        `json:"incident_pod_cap"`
	HandleExpiresAt *time.Time `json:"handle_expires_at,omitempty"`
}
type RecordingPageData struct {
	Kind           string         `json:"kind"`
	Recordings     []RecordingRow `json:"recordings"`
	ExpiresAt      time.Time      `json:"expires_at"`
	CaptureEnabled bool           `json:"capture_enabled"`
}
type RecordingWindow struct {
	Handle string `json:"recording_handle"`
	Before string `json:"before"`
	After  string `json:"after"`
}
type RecordingSavePreviewData struct {
	Kind           string            `json:"kind"`
	Operation      string            `json:"operation"`
	PreviewID      string            `json:"preview_id"`
	CaptureID      string            `json:"capture_id"`
	ExpiresAt      time.Time         `json:"expires_at"`
	ScopeDigest    string            `json:"save_scope_digest"`
	Selected       []RecordingRow    `json:"selected_recordings"`
	Windows        []RecordingWindow `json:"windows"`
	Assessment     CaptureAssessment `json:"capture_assessment"`
	Blockers       []string          `json:"blockers"`
	NavigationURI  string            `json:"navigation_uri"`
	CaptureEnabled bool              `json:"capture_enabled"`
	IncidentPodCap int               `json:"incident_pod_cap"`
}
type recordingSaveInput struct {
	CaptureID        string               `json:"capture_id,omitempty"`
	ExpectedRevision int64                `json:"expected_revision,omitempty"`
	IdempotencyKey   string               `json:"idempotency_key,omitempty"`
	Target           WorkloadReference    `json:"target_ref"`
	PolicyUID        string               `json:"policy_uid,omitempty"`
	Cursor           string               `json:"cursor,omitempty"`
	Limit            int                  `json:"limit,omitempty"`
	Handles          []string             `json:"recording_handles,omitempty"`
	Before           string               `json:"before,omitempty"`
	Sharing          *ContextSharingInput `json:"sharing,omitempty"`
	Reason           *string              `json:"reason,omitempty"`
	RepeatedFrom     string               `json:"repeated_from_capture_id,omitempty"`
}

func recordingRow(row app.RecordingRow, expires time.Time) RecordingRow {
	out := RecordingRow{Handle: row.Handle, PolicyUID: row.PolicyUID, PodUID: row.PodUID, PodName: row.PodName, ActionID: row.ActionID, Kind: row.Kind, State: row.State, History: row.History, MaximumBefore: artifact.LifecycleDuration(row.MaximumBefore), Eligible: row.Handle != "" && row.Blocker == "", Blockers: []string{}, IncidentPodCap: row.IncidentPodCap}
	if row.Blocker != "" {
		out.Blockers = append(out.Blockers, row.Blocker)
	}
	if out.Handle != "" && !expires.IsZero() {
		at := expires.UTC()
		out.HandleExpiresAt = &at
	}
	return out
}
func (s *RecordingSaveOperations) Call(ctx context.Context, current identities.CurrentIdentity, name string, raw json.RawMessage) (OperationReply, error) {
	if s == nil {
		return OperationReply{}, ErrOperationsConfiguration
	}
	return s.CallWithContext(ctx, current, OperationCall{requestID: s.config.NewID()}, name, raw)
}
func (s *RecordingSaveOperations) CallWithContext(ctx context.Context, current identities.CurrentIdentity, call OperationCall, name string, raw json.RawMessage) (OperationReply, error) {
	if s == nil || ctx == nil || current == nil {
		return OperationReply{}, value.ErrUnavailable
	}
	if _, ok := s.Tool(name); !ok {
		return OperationReply{}, contracts.ErrInvestigationWire
	}
	if err := s.contracts.ValidateInput(name, raw); err != nil {
		return OperationReply{}, err
	}
	var in recordingSaveInput
	if json.Unmarshal(raw, &in) != nil || !authorization.UUID(call.requestID) {
		return OperationReply{}, contracts.ErrInvestigationWire
	}
	started := s.config.Now()
	i, err := current.ResolveIdentity(ctx)
	if err != nil || !i.Valid(s.config.Now()) || !slices.Contains(i.Scopes, "evidence:read") || !slices.Contains(i.Scopes, "evidence:capture") {
		return OperationReply{}, identity.ErrDenied
	}
	until := identity.Earlier(started.Add(5*time.Second), i.ValidUntil)
	if end, ok := ctx.Deadline(); ok {
		until = identity.Earlier(until, end)
	}
	bounded, cancel := context.WithDeadline(ctx, until)
	defer cancel()
	if bounded.Err() != nil || !s.config.Now().Before(until) {
		return OperationReply{}, value.ErrUnavailable
	}
	out := OperationEnvelope{SchemaVersion: "mcp-result/v1", RequestID: call.requestID, DataClass: "metadata", Status: "ok", Warnings: []string{}, Provenance: []any{}}
	var operationErr error
	if name == "cancel_capture" {
		var decision value.Cancellation
		decision, operationErr = s.cancellations.Cancel(bounded, current, value.CancellationRequest{CaptureID: in.CaptureID, ExpectedRevision: in.ExpectedRevision, IdempotencyKey: in.IdempotencyKey})
		if decision.Valid(s.config.Now()) && decision.CaptureID == in.CaptureID {
			until = identity.Earlier(until, decision.ValidUntil)
			out.Data = RecordingCancellationData{decision.CaptureID, decision.Phase, decision.Revision, decision.Requested, s.config.PublicOrigin + "/captures/" + decision.CaptureID}
			if operationErr != nil && decision.Requested {
				out.Warnings = append(out.Warnings, "Cancellation delivery is unconfirmed; the durable request remains pending.")
				operationErr = nil
			}
		} else if operationErr == nil {
			operationErr = value.ErrChanged
		}
	} else if name == "list_recordings" {
		limit := in.Limit
		if limit == 0 {
			limit = 20
		}
		// A requested limit is an upper bound. Bound the service page before its
		// cursor advances so the existing 24 KiB envelope can retain whole rows.
		limit = min(limit, 20)
		var page app.RecordingPage
		page, operationErr = s.saves.List(bounded, current, in.Target.target(), in.PolicyUID, in.Cursor, limit)
		if operationErr == nil {
			if page.ValidUntil.IsZero() || !s.config.Now().Before(page.ExpiresAt) || len(page.Rows) > limit {
				return OperationReply{}, value.ErrUnavailable
			}
			until = identity.Earlier(until, page.ValidUntil)
			rows := make([]RecordingRow, 0, len(page.Rows))
			for _, row := range page.Rows {
				rows = append(rows, recordingRow(row, page.ExpiresAt))
			}
			out.Data = RecordingPageData{Kind: "recordingPage", Recordings: rows, ExpiresAt: page.ExpiresAt.UTC(), CaptureEnabled: s.config.CollectionEnabled}
			if page.Cursor != "" {
				cursor := page.Cursor
				out.NextCursor = &cursor
			}
		}
	} else {
		var before time.Duration
		if in.Before != "" {
			before, err = time.ParseDuration(in.Before)
			if err != nil {
				return OperationReply{}, contracts.ErrInvestigationWire
			}
		}
		var result app.ContextPreviewResult
		result, operationErr = s.saves.Preview(bounded, current, app.RecordingSavePreviewRequest{Handles: append([]string(nil), in.Handles...), Before: before, Sharing: in.Sharing.intent(), RepeatedFromCaptureID: in.RepeatedFrom, Reason: in.Reason})
		if operationErr == nil {
			p, m := result.Preview, result.RecordingSave
			if m == nil || p.ScopeDigest != result.Assessment.PlanDigest {
				return OperationReply{}, stopped("preview-shape", value.ErrUnavailable)
			}
			if !s.config.Now().Before(p.SelectionUntil) {
				return OperationReply{}, stopped("preview-selection-expired", value.ErrUnavailable)
			}
			rows, windows, selectionErr := recordingPreviewSelection(result, in.Handles)
			if selectionErr != nil {
				return OperationReply{}, stopped("preview-rows", selectionErr)
			}
			assessment, assessmentErr := recordingSaveAssessment(result)
			if assessmentErr != nil {
				return OperationReply{}, stopped("preview-assessment", assessmentErr)
			}
			until = identity.Earlier(until, result.ValidUntil)
			blockers := []string{}
			if !s.config.CollectionEnabled {
				blockers = append(blockers, "CollectionDisabled")
			}
			out.Data = RecordingSavePreviewData{Kind: "recordingSavePreview", Operation: "recordingSave", PreviewID: p.ID, CaptureID: p.CaptureID, ExpiresAt: p.SelectionUntil.UTC(), ScopeDigest: hash(p.ScopeDigest), Selected: rows, Windows: windows, Assessment: assessment, Blockers: blockers, NavigationURI: s.config.PublicOrigin + "/captures/new", CaptureEnabled: s.config.CollectionEnabled, IncidentPodCap: m.IncidentPodCap}
		}
	}
	if operationErr != nil {
		failure := publicCaptureFailure(operationErr, false)
		if errors.Is(operationErr, value.ErrInvalid) {
			failure.Message = "Choose current recording handles and a shorter positive lookback."
		}
		if errors.Is(operationErr, value.ErrCapacity) {
			failure.Message = "The selection exceeds the current incident cap or available capacity. Select fewer recordings or retry later."
		}
		out.Status, out.Data, out.NextCursor = "error", failure, nil
	}
	final, err := current.ResolveIdentity(bounded)
	if err != nil || bounded.Err() != nil || !final.Valid(s.config.Now()) || final.Principal != i.Principal {
		return OperationReply{}, identity.ErrDenied
	}
	until = identity.Earlier(until, final.ValidUntil)
	b, err := json.Marshal(out)
	limit := contracts.InvestigationOutputLimit
	if name == "preview_recording_save" {
		limit = contracts.InvestigationRecordingSavePreviewOutputLimit
	}
	if err == nil && len(b) > limit {
		out.Status, out.Data, out.NextCursor = "error", OperationFailure{"ReduceLimit", "Use a smaller inventory page or recording selection to fit the metadata response.", false}, nil
		b, err = json.Marshal(out)
	}
	if err != nil || s.contracts.ValidateOutput(name, b) != nil {
		return OperationReply{}, stopped("output-contract", value.ErrUnavailable)
	}
	if !s.config.Now().Before(until) || bounded.Err() != nil {
		clear(b)
		return OperationReply{}, stopped("reply-interval", value.ErrUnavailable)
	}
	return OperationReply{Body: b, ValidUntil: until, auditDecision: captureAuditDecision(operationErr), recordingSavePreview: name == "preview_recording_save"}, nil
}

func acceptedRecordingOperation(accepted value.Accepted) string {
	if accepted.Group != nil || accepted.Expectation.Snapshot != nil {
		return "recordingSave"
	}
	return "collect"
}
