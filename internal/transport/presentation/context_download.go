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
func (s *ContextDownloadOperations) ToolNames() []string {
	names := []string{"prepare_artifact_download", "get_artifact_download"}
	if s != nil && s.stop != nil {
		names = append(names, "cancel_artifact_download")
	}
	return names
}
func (s *ContextDownloadOperations) Tool(name string) (contracts.InvestigationTool, bool) {
	if s == nil || !slices.Contains(s.ToolNames(), name) {
		return contracts.InvestigationTool{}, false
	}
	return s.contracts.Tool(name)
}

type ContextDownloadInput struct {
	ArtifactID string `json:"artifact_id,omitempty"`
	DownloadID string `json:"download_id,omitempty"`
	Key        string `json:"idempotency_key,omitempty"`
}

// Native fields are one verified group, never populated from catalog metadata.
type ContextDownloadData struct {
	DownloadID          string                 `json:"download_id"`
	ArtifactID          string                 `json:"artifact_id"`
	State               artifact.DownloadState `json:"state"`
	ExpiresAt           time.Time              `json:"expires_at"`
	ManagedReadUntil    time.Time              `json:"managed_read_until"`
	EmittedBytes        int64                  `json:"emitted_bytes"`
	ResumeAvailable     bool                   `json:"resume_available"`
	LocalCopyManaged    bool                   `json:"local_copy_managed"`
	HandlingNotice      string                 `json:"handling_notice"`
	Filename            string                 `json:"filename,omitempty"`
	NativeFormat        string                 `json:"native_format,omitempty"`
	SizeBytes           *int64                 `json:"size_bytes,omitempty"`
	SHA256              string                 `json:"sha256,omitempty"`
	ETag                string                 `json:"etag,omitempty"`
	CoverageNotice      *string                `json:"coverage_notice,omitempty"`
	ContentPath         string                 `json:"content_path,omitempty"`
	ContinuePreparation bool                   `json:"continue_preparation,omitempty"`
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
	if !slices.Contains(s.ToolNames(), name) || s.contracts.ValidateInput(name, raw) != nil {
		return OperationReply{}, contracts.ErrInvestigationWire
	}
	var input ContextDownloadInput
	if json.Unmarshal(raw, &input) != nil {
		return OperationReply{}, contracts.ErrInvestigationWire
	}
	if name == "cancel_artifact_download" {
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
	prepare := name == "prepare_artifact_download"
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
	} else {
		if view.Session.Scope.Principal != initial.Principal || prepare && view.Session.Scope.ArtifactID != input.ArtifactID || !prepare && view.Session.ID != input.DownloadID {
			return OperationReply{}, stopped("download-scope", artifact.ErrDownloadUnavailable)
		}
		data, e := contextDownloadData(view, prepare, s.config.Now())
		if e != nil {
			return OperationReply{}, stopped("download-view", e)
		}
		until = identity.Earlier(until, view.ValidUntil)
		// The callback exists only on this original authenticated browser POST.
		// It stores scheduling ownership, never changes download/identity rights.
		if prepare && !view.Session.State.Terminal() && call.downloadAttachment != nil {
			attachmentUntil, e := call.downloadAttachment(ctx, view.Session.ID)
			if e != nil {
				return OperationReply{}, stopped("download-attachment", artifact.ErrDownloadUnavailable)
			}
			until = identity.Earlier(until, attachmentUntil)
		}
		out.Data = data
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

func contextDownloadData(v evidence.ContextDownloadView, prepare bool, now time.Time) (ContextDownloadData, error) {
	s := v.Session
	if !s.Valid() || !now.Before(v.ValidUntil) || v.ValidUntil.After(now.Add(artifact.DownloadLease)) || !now.Before(v.AccessUntil) || !v.AccessUntil.Before(v.DeleteBy) || v.ContinuePreparation && (!prepare || s.State != artifact.DownloadPreparing) {
		return ContextDownloadData{}, artifact.ErrDownloadUnavailable
	}
	d := ContextDownloadData{DownloadID: s.ID, ArtifactID: s.Scope.ArtifactID, State: s.State, ExpiresAt: identity.Earlier(s.Deadline, v.AccessUntil), ManagedReadUntil: v.AccessUntil, EmittedBytes: s.EmittedBytes, HandlingNotice: "Evidence may contain user data. Asservat automatically deletes managed copies by " + v.DeleteBy.UTC().Format(time.RFC3339) + ". Restrict access and review before sharing. Downloaded copies are outside Asservat and cannot be recalled or automatically deleted.", ContinuePreparation: v.ContinuePreparation}
	active := s.State == artifact.DownloadReady || s.State == artifact.DownloadStreaming || s.State == artifact.DownloadInterrupted
	if !s.State.Terminal() && !now.Before(d.ExpiresAt) || active && v.Metadata == nil || s.State == artifact.DownloadPreparing && v.Metadata != nil {
		return ContextDownloadData{}, artifact.ErrDownloadUnavailable
	}
	if m := v.Metadata; m != nil {
		if m.ReadUntil.IsZero() || m.ReadUntil.After(v.AccessUntil) || m.DeleteBy.After(v.DeleteBy) || !now.Before(m.ReadUntil) || m.Size < 0 || m.Size > artifact.MaxNativeBytes || m.SHA256 == (artifact.Digest{}) {
			return ContextDownloadData{}, artifact.ErrDownloadUnavailable
		}
		d.Filename, d.NativeFormat, d.ETag = m.Filename, m.Format, m.ETag
		coverage := m.Coverage
		d.CoverageNotice = &coverage
		size := m.Size
		d.SizeBytes = &size
		d.SHA256 = hash(m.SHA256)
	}
	if active {
		d.ContentPath = "/api/v1/downloads/" + s.ID + "/content"
		d.ResumeAvailable = true
	}
	return d, nil
}

type ContextDownloadCancelData struct {
	DownloadID string `json:"download_id"`
	State      string `json:"state"`
	AuditState string `json:"audit_state"`
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
		out.Data = ContextDownloadCancelData{DownloadID: receipt.DownloadID, State: receipt.State, AuditState: receipt.AuditState}
	}
	final, e := current.ResolveIdentity(ctx)
	if e != nil || ctx.Err() != nil || !sameAuditIdentity(initial, final, s.config.Now()) {
		return OperationReply{}, identity.ErrDenied
	}
	until = identity.Earlier(until, final.ValidUntil)
	body, e := json.Marshal(out)
	if e != nil || s.contracts.ValidateOutput("cancel_artifact_download", body) != nil || !s.config.Now().Before(until) {
		clear(body)
		return OperationReply{}, artifact.ErrDownloadUnavailable
	}
	return OperationReply{Body: body, ValidUntil: until}, nil
}
