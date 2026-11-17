package presentation

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"slices"
	"time"

	"asservat.local/asservat/internal/application/evidence"
	identities "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
)

// ContextDownloadUseCase is the existing C-14 current-authority coordinator.
// Transport code never reads custody, repairs a cache or starts native work.
type ContextDownloadUseCase interface {
	PrepareContextDownload(context.Context, identities.CurrentIdentity, string, string) (evidence.ContextDownloadView, error)
	GetContextDownload(context.Context, identities.CurrentIdentity, string) (evidence.ContextDownloadView, error)
}

type ContextDownloadStopUseCase interface {
	CancelContextDownload(context.Context, identities.CurrentIdentity, string, string, string) (artifact.DownloadStopReceipt, error)
}

type ContextDownloadOperationsConfig struct {
	PublicOrigin string
	Now          func() time.Time
	NewID        func() string
}
type ContextDownloadOperations struct {
	config    ContextDownloadOperationsConfig
	downloads ContextDownloadUseCase
	stop      ContextDownloadStopUseCase
	contracts *contracts.InvestigationContracts
}

func NewContextDownloadOperations(c ContextDownloadOperationsConfig, downloads ContextDownloadUseCase, stops ...ContextDownloadStopUseCase) (*ContextDownloadOperations, error) {
	if len(stops) > 1 {
		return nil, ErrOperationsConfiguration
	}
	u, err := url.Parse(c.PublicOrigin)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" || len(c.PublicOrigin) > 1800 || c.Now == nil || c.NewID == nil || downloads == nil {
		return nil, ErrOperationsConfiguration
	}
	wire, err := contracts.NewInvestigationContracts()
	if err != nil {
		return nil, err
	}
	out := &ContextDownloadOperations{config: c, downloads: downloads, contracts: wire}
	if len(stops) == 1 {
		out.stop = stops[0]
	}
	return out, nil
}
func (s *ContextDownloadOperations) PublicOrigin() string {
	if s == nil {
		return ""
	}
	return s.config.PublicOrigin
}
func (s *ContextDownloadOperations) ToolNames() []string { return []string{downloadTool} }
func (s *ContextDownloadOperations) Tool(name string) (contracts.InvestigationTool, bool) {
	if s == nil || name != downloadTool {
		return contracts.InvestigationTool{}, false
	}
	return s.contracts.Tool(name)
}

const downloadTool = "download_artifact"

// ContextDownloadInput is the download_artifact input. after_revision is
// accepted and ignored here; the shared wait wrapper handles it.
// representation is accepted: no served artifact kind is a core, so every
// download is the native file.
type ContextDownloadInput struct {
	Action         string `json:"action"`
	ArtifactID     string `json:"artifact_id,omitempty"`
	DownloadID     string `json:"download_id,omitempty"`
	Key            string `json:"idempotency_key,omitempty"`
	Representation string `json:"representation,omitempty"`
}

// DownloadAction returns the action of a download_artifact input, or "".
func DownloadAction(raw []byte) string {
	var in struct {
		Action string `json:"action"`
	}
	if json.Unmarshal(raw, &in) != nil {
		return ""
	}
	return in.Action
}

const downloadNotice = "Downloaded copies are outside Asservat's automatic deletion. Follow your organization's handling and deletion policy."

// ContextDownloadData is the canonical Ready status. Only active sessions
// with verified native facts produce it.
type ContextDownloadData struct {
	DownloadID       string    `json:"download_id"`
	ArtifactID       string    `json:"artifact_id"`
	State            string    `json:"state"`
	Revision         int64     `json:"revision"`
	Representation   string    `json:"representation"`
	Filename         string    `json:"filename"`
	NativeFormat     string    `json:"native_format"`
	SizeBytes        int64     `json:"size_bytes"`
	SHA256           string    `json:"sha256"`
	ETag             string    `json:"etag"`
	CoverageNotice   string    `json:"coverage_notice"`
	ContentPath      string    `json:"content_path"`
	BrowserURL       string    `json:"browser_url"`
	AccessUntil      time.Time `json:"access_until"`
	EmittedBytes     int64     `json:"emitted_bytes"`
	LocalCopyManaged bool      `json:"local_copy_managed"`
	HandlingNotice   string    `json:"handling_notice"`
}

func (s *ContextDownloadOperations) Call(ctx context.Context, current identities.CurrentIdentity, name string, raw json.RawMessage) (OperationReply, error) {
	if s == nil {
		return OperationReply{}, ErrOperationsConfiguration
	}
	return s.CallWithContext(ctx, current, OperationCall{requestID: s.config.NewID()}, name, raw)
}
func (s *ContextDownloadOperations) CallWithContext(ctx context.Context, current identities.CurrentIdentity, call OperationCall, name string, raw json.RawMessage) (OperationReply, error) {
	if s == nil || ctx == nil || current == nil {
		return OperationReply{}, artifact.ErrDownloadUnavailable
	}
	if name != downloadTool || s.contracts.ValidateInput(name, raw) != nil {
		return OperationReply{}, contracts.ErrInvestigationWire
	}
	var input ContextDownloadInput
	if json.Unmarshal(raw, &input) != nil {
		return OperationReply{}, contracts.ErrInvestigationWire
	}
	if input.Action == "cancel" {
		return s.cancel(ctx, current, call, input)
	}
	initial, err := current.ResolveIdentity(ctx)
	if err != nil || ctx.Err() != nil || !initial.Valid(s.config.Now()) {
		return OperationReply{}, identity.ErrDenied
	}
	// A valid session without download scope gets the ordinary audited denial
	// reply, not a transport failure (an approved-inspection-only login).
	scoped := slices.Contains(initial.Scopes, "evidence:read") && slices.Contains(initial.Scopes, "evidence:download")
	if !authorization.UUID(call.requestID) {
		return OperationReply{}, artifact.ErrDownloadUnavailable
	}
	until := initial.ValidUntil
	ctx, cancel := context.WithDeadline(ctx, until)
	defer cancel()
	var view evidence.ContextDownloadView
	prepare := input.Action == "prepare"
	if !scoped {
		err = identity.ErrDenied
	} else if prepare {
		view, err = s.downloads.PrepareContextDownload(ctx, current, input.ArtifactID, input.Key)
	} else {
		view, err = s.downloads.GetContextDownload(ctx, current, input.DownloadID)
	}
	out := OperationEnvelope{SchemaVersion: "mcp-result/v1", RequestID: call.requestID, DataClass: "metadata", Status: "ok", Warnings: []string{}, Provenance: []any{}}
	decision := operationAuditUnspecified
	if err != nil {
		out.Status = "error"
		out.Data = OperationFailure{Code: "NotAvailable", Message: "This download is not available with your current access or service conditions. Keep the same request key when checking an uncertain preparation.", Retryable: true}
		if errors.Is(err, identity.ErrDenied) {
			decision = operationAuditDenied
		}
		if prepare && errors.Is(err, authorization.ErrApprovalRequired) {
			out.Data = OperationFailure{Code: "RawApprovalRequired", Message: "Whole-file download needs independent approval. Review the selected artifact and its verified size, then continue this download after approval.", Retryable: false}
		}
	} else {
		if view.Session.Scope.Principal != initial.Principal || prepare && view.Session.Scope.ArtifactID != input.ArtifactID || !prepare && view.Session.ID != input.DownloadID {
			return OperationReply{}, stopped("download-scope", artifact.ErrDownloadUnavailable)
		}
		data, failure, e := contextDownloadData(view, s.config.Now())
		if e != nil {
			return OperationReply{}, stopped("download-view", e)
		}
		until = identity.Earlier(until, view.ValidUntil)
		if failure != nil {
			out.Status, out.Data = "error", *failure
		} else {
			out.Data = data
		}
	}
	final, e := current.ResolveIdentity(ctx)
	if e != nil || ctx.Err() != nil || !sameAuditIdentity(initial, final, s.config.Now()) {
		return OperationReply{}, identity.ErrDenied
	}
	until = identity.Earlier(until, final.ValidUntil)
	body, e := json.Marshal(out)
	if e != nil || s.contracts.ValidateOutput(name, body) != nil {
		clear(body)
		return OperationReply{}, stopped("download-output", artifact.ErrDownloadUnavailable)
	}
	if ctx.Err() != nil || !s.config.Now().Before(until) {
		clear(body)
		return OperationReply{}, stopped("download-expired", artifact.ErrDownloadUnavailable)
	}
	return OperationReply{Body: body, ValidUntil: until, auditDecision: decision}, nil
}

// contextDownloadData maps the session to the canonical status. Preparing
// has no public state: the caller repeats prepare with the same key. Terminal
// sessions no longer hold the verified native facts every canonical status
// carries, so they return CapabilityUnavailable naming the state.
func contextDownloadData(v evidence.ContextDownloadView, now time.Time) (ContextDownloadData, *OperationFailure, error) {
	s := v.Session
	if !s.Valid() || !now.Before(v.ValidUntil) || v.ValidUntil.After(now.Add(artifact.DownloadLease)) || !now.Before(v.AccessUntil) || !v.AccessUntil.Before(v.DeleteBy) {
		return ContextDownloadData{}, nil, artifact.ErrDownloadUnavailable
	}
	switch s.State {
	case artifact.DownloadPreparing:
		if v.Metadata != nil {
			return ContextDownloadData{}, nil, artifact.ErrDownloadUnavailable
		}
		return ContextDownloadData{}, &OperationFailure{Code: "RetryLater", Message: "This download is still being prepared. Repeat prepare with the same idempotency key.", Retryable: true}, nil
	case artifact.DownloadReady, artifact.DownloadStreaming, artifact.DownloadInterrupted:
	default:
		state := string(s.State)
		if s.State == artifact.DownloadExpired || s.State == artifact.DownloadDenied {
			state = "Failed (" + state + ")"
		}
		return ContextDownloadData{}, &OperationFailure{Code: "CapabilityUnavailable", Message: "This download session ended: " + state + ". Its verified size and checksum are not kept after the session ends. Prepare a new download to transfer the file again.", Retryable: false}, nil
	}
	m := v.Metadata
	if m == nil || !now.Before(s.Deadline) || m.ReadUntil.IsZero() || m.ReadUntil.After(v.AccessUntil) || m.DeleteBy.After(v.DeleteBy) || !now.Before(m.ReadUntil) || m.Size < 0 || m.Size > artifact.MaxNativeBytes || m.SHA256 == (artifact.Digest{}) {
		return ContextDownloadData{}, nil, artifact.ErrDownloadUnavailable
	}
	return ContextDownloadData{DownloadID: s.ID, ArtifactID: s.Scope.ArtifactID, State: "Ready", Revision: downloadRevision(s), Representation: "file", Filename: m.Filename, NativeFormat: m.Format, SizeBytes: m.Size, SHA256: hash(m.SHA256), ETag: m.ETag, CoverageNotice: m.Coverage, ContentPath: "/api/v1/downloads/" + s.ID + "/content", BrowserURL: "/downloads/" + s.ID, AccessUntil: identity.Earlier(s.Deadline, v.AccessUntil), EmittedBytes: s.EmittedBytes, HandlingNotice: downloadNotice}, nil, nil
}

// downloadRevision changes whenever the session state or its transfer
// generation changes; status waits compare it.
func downloadRevision(s artifact.DownloadSession) int64 {
	order := map[artifact.DownloadState]int64{artifact.DownloadPreparing: 1, artifact.DownloadReady: 2, artifact.DownloadStreaming: 3, artifact.DownloadInterrupted: 4, artifact.DownloadCompleted: 5, artifact.DownloadCancelled: 6, artifact.DownloadExpired: 7, artifact.DownloadDenied: 8, artifact.DownloadFailed: 9}
	return s.Generation*10 + order[s.State]
}

type ContextDownloadCancelData struct {
	DownloadID string `json:"download_id"`
	State      string `json:"state"`
}

func (s *ContextDownloadOperations) cancel(ctx context.Context, current identities.CurrentIdentity, call OperationCall, in ContextDownloadInput) (OperationReply, error) {
	if s.stop == nil || !authorization.UUID(call.requestID) {
		return OperationReply{}, artifact.ErrDownloadUnavailable
	}
	initial, e := current.ResolveIdentity(ctx)
	if e != nil || !initial.Valid(s.config.Now()) || ctx.Err() != nil {
		return OperationReply{}, identity.ErrDenied
	}
	until := initial.ValidUntil
	receipt, e := s.stop.CancelContextDownload(ctx, current, in.DownloadID, in.Key, call.requestID)
	out := OperationEnvelope{SchemaVersion: "mcp-result/v1", RequestID: call.requestID, DataClass: "metadata", Status: "ok", Warnings: []string{}, Provenance: []any{}}
	if e != nil {
		out.Status = "error"
		out.Data = OperationFailure{Code: "NotAvailable", Message: "This stop could not be confirmed. Retry with the same download and request key. Already downloaded copies cannot be recalled.", Retryable: true}
	} else {
		if !receipt.Valid(s.config.Now()) || receipt.DownloadID != in.DownloadID {
			return OperationReply{}, artifact.ErrDownloadUnavailable
		}
		until = identity.Earlier(until, receipt.ValidUntil)
		out.RequestID = receipt.RequestID
		out.Data = ContextDownloadCancelData{DownloadID: receipt.DownloadID, State: receipt.State}
	}
	final, e := current.ResolveIdentity(ctx)
	if e != nil || ctx.Err() != nil || !sameAuditIdentity(initial, final, s.config.Now()) {
		return OperationReply{}, identity.ErrDenied
	}
	until = identity.Earlier(until, final.ValidUntil)
	body, e := json.Marshal(out)
	if e != nil || s.contracts.ValidateOutput(downloadTool, body) != nil || !s.config.Now().Before(until) {
		clear(body)
		return OperationReply{}, artifact.ErrDownloadUnavailable
	}
	return OperationReply{Body: body, ValidUntil: until}, nil
}
