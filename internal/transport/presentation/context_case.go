package presentation

import (
	"context"
	"encoding/json"
	"net/url"
	"slices"
	"time"

	identities "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/catalog"
	"asservat.local/asservat/internal/domain/identity"
)

// ContextCaseUseCase is the current C-16 authorized catalog service. The
// transport never replaces it with a publication lookup or download reader.
type ContextCaseUseCase interface {
	GetContextCase(context.Context, identities.CurrentIdentity, string) (catalog.ContextCase, error)
}
type ContextCaseOperationsConfig struct {
	PublicOrigin string
	Now          func() time.Time
	NewID        func() string
}
type ContextCaseOperations struct {
	config    ContextCaseOperationsConfig
	cases     ContextCaseUseCase
	contracts *contracts.InvestigationContracts
}

func NewContextCaseOperations(c ContextCaseOperationsConfig, cases ContextCaseUseCase) (*ContextCaseOperations, error) {
	u, err := url.Parse(c.PublicOrigin)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" || len(c.PublicOrigin) > 1800 || cases == nil || c.Now == nil || c.NewID == nil {
		return nil, ErrOperationsConfiguration
	}
	wire, err := contracts.NewInvestigationContracts()
	if err != nil {
		return nil, err
	}
	return &ContextCaseOperations{config: c, cases: cases, contracts: wire}, nil
}
func (s *ContextCaseOperations) PublicOrigin() string {
	if s == nil {
		return ""
	}
	return s.config.PublicOrigin
}
func (s *ContextCaseOperations) ToolNames() []string { return []string{"get_case"} }
func (s *ContextCaseOperations) Tool(name string) (contracts.InvestigationTool, bool) {
	if s == nil || name != "get_case" {
		return contracts.InvestigationTool{}, false
	}
	return s.contracts.Tool(name)
}

type ContextCaseSummary struct {
	CaseID string `json:"case_id"`
	Status string `json:"status"`
	Access string `json:"access"`
}
type ArtifactHandlingNotice struct {
	Classification           string    `json:"classification"`
	MayContain               []string  `json:"mayContain"`
	ExpiresAt                time.Time `json:"expiresAt"`
	DeleteBy                 time.Time `json:"deleteBy"`
	DeletionState            string    `json:"deletionState"`
	AutomaticDeletion        bool      `json:"automaticDeletion"`
	ManagedCopiesOnly        bool      `json:"managedCopiesOnly"`
	ExternalCopiesRecallable bool      `json:"externalCopiesRecallable"`
	HandlingCodes            []string  `json:"handlingCodes"`
	PreservationException    bool      `json:"preservationException"`
	AsOf                     time.Time `json:"asOf"`
}
type ContextCaseArtifactData struct {
	ArtifactID     string                 `json:"artifact_id"`
	Digest         string                 `json:"digest"`
	Kind           string                 `json:"kind"`
	DataClass      string                 `json:"data_class"`
	Completeness   string                 `json:"completeness"`
	ExpiresAt      time.Time              `json:"expires_at"`
	HandlingNotice ArtifactHandlingNotice `json:"handling_notice"`
}
type ContextCaseData struct {
	Case      ContextCaseSummary        `json:"case"`
	Artifacts []ContextCaseArtifactData `json:"artifacts"`
	Timeline  []any                     `json:"timeline"`
}

func (s *ContextCaseOperations) Call(ctx context.Context, current identities.CurrentIdentity, name string, raw json.RawMessage) (OperationReply, error) {
	if s == nil {
		return OperationReply{}, ErrOperationsConfiguration
	}
	return s.CallWithContext(ctx, current, OperationCall{requestID: s.config.NewID()}, name, raw)
}

func (s *ContextCaseOperations) CallWithContext(ctx context.Context, current identities.CurrentIdentity, call OperationCall, name string, raw json.RawMessage) (OperationReply, error) {
	if s == nil || ctx == nil || current == nil {
		return OperationReply{}, catalog.ErrUnavailable
	}
	if name != "get_case" || s.contracts.ValidateInput(name, raw) != nil {
		return OperationReply{}, contracts.ErrInvestigationWire
	}
	var input struct {
		CaseID string `json:"case_id"`
	}
	if json.Unmarshal(raw, &input) != nil {
		return OperationReply{}, contracts.ErrInvestigationWire
	}
	initial, err := current.ResolveIdentity(ctx)
	if err != nil || ctx.Err() != nil || !initial.Valid(s.config.Now()) || !slices.Contains(initial.Scopes, "evidence:read") {
		return OperationReply{}, identity.ErrDenied
	}
	requestID := call.requestID
	if !authorization.UUID(requestID) {
		return OperationReply{}, catalog.ErrUnavailable
	}
	out := OperationEnvelope{SchemaVersion: "mcp-result/v1", RequestID: requestID, DataClass: "metadata", Status: "ok", Warnings: []string{}, Provenance: []any{}}
	until := initial.ValidUntil
	view, lookupErr := s.cases.GetContextCase(ctx, current, input.CaseID)
	if lookupErr != nil {
		// Existence, publication, owner, rights and provider failures have the same
		// nondisclosing outcome. No case ID, target, count or error body is echoed.
		out.Status = "error"
		out.Data = OperationFailure{Code: "NotAvailable", Message: "Evidence is not available with your current access or service conditions. Check your access or retry later.", Retryable: true}
	} else {
		if view.CaseID != input.CaseID || !view.Valid(s.config.Now()) {
			return OperationReply{}, catalog.ErrUnavailable
		}
		until = identity.Earlier(until, view.ValidUntil)
		data := ContextCaseData{Case: ContextCaseSummary{CaseID: view.CaseID, Status: "Ready", Access: "ordinary"}, Artifacts: make([]ContextCaseArtifactData, 0, len(view.Artifacts)), Timeline: []any{}}
		for _, a := range view.Artifacts {
			if a.Shared {
				// ADR-232: the view contains an artifact admitted by a share.
				data.Case.Access = "shared"
			}
			data.Artifacts = append(data.Artifacts, ContextCaseArtifactData{ArtifactID: a.ArtifactID, Digest: hash(a.Version), Kind: "pod-status", DataClass: "metadata", Completeness: "complete", ExpiresAt: a.ExpiresAt, HandlingNotice: ArtifactHandlingNotice{Classification: "potentialPersonalData", MayContain: []string{"personalIdentifiers", "networkAddresses", "paths"}, ExpiresAt: a.ExpiresAt, DeleteBy: a.DeleteBy, DeletionState: "scheduled", AutomaticDeletion: true, ManagedCopiesOnly: true, ExternalCopiesRecallable: false, HandlingCodes: []string{"minimizeCapture", "restrictAccess", "preferApprovedExtracts", "reviewBeforeSharing", "approvedClientsOnly", "externalCopiesNotRecalled"}, PreservationException: false, AsOf: view.ObservedAt}})
		}
		out.Data = data
	}
	final, err := current.ResolveIdentity(ctx)
	if err != nil || ctx.Err() != nil || !initial.Valid(s.config.Now()) || !final.Valid(s.config.Now()) || final.Principal != initial.Principal {
		return OperationReply{}, identity.ErrDenied
	}
	until = identity.Earlier(until, final.ValidUntil)
	b, err := json.Marshal(out)
	if err != nil || s.contracts.ValidateOutput(name, b) != nil {
		clear(b)
		return OperationReply{}, catalog.ErrUnavailable
	}
	if ctx.Err() != nil || !s.config.Now().Before(until) {
		clear(b)
		return OperationReply{}, catalog.ErrUnavailable
	}
	return OperationReply{Body: b, ValidUntil: until}, nil
}
