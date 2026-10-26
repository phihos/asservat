package presentation

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"time"

	authapp "asservat.local/asservat/internal/application/authorization"
	identities "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/capture"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
)

// AccessPreviewUseCase is the ADR-237 administrator impact preview.
type AccessPreviewUseCase interface {
	Preview(context.Context, identities.CurrentIdentity, []authapp.ProposedChange) (cfg.AccessPreview, time.Time, error)
}

// AccessPreviewOperations serves preview_access_change through the same
// audited operation path as every other operation. Its contract restricts it
// to the browser: MCP neither lists nor accepts it.
type AccessPreviewOperations struct {
	origin    string
	now       func() time.Time
	newID     func() string
	preview   AccessPreviewUseCase
	contracts *contracts.InvestigationContracts
}

func NewAccessPreviewOperations(origin string, now func() time.Time, newID func() string, preview AccessPreviewUseCase) (*AccessPreviewOperations, error) {
	u, err := url.Parse(origin)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.Path != "" || preview == nil || now == nil || newID == nil {
		return nil, ErrOperationsConfiguration
	}
	wire, err := contracts.NewInvestigationContracts()
	if err != nil {
		return nil, err
	}
	return &AccessPreviewOperations{origin: origin, now: now, newID: newID, preview: preview, contracts: wire}, nil
}

func (s *AccessPreviewOperations) PublicOrigin() string {
	if s == nil {
		return ""
	}
	return s.origin
}
func (s *AccessPreviewOperations) ToolNames() []string { return []string{"preview_access_change"} }
func (s *AccessPreviewOperations) Tool(name string) (contracts.InvestigationTool, bool) {
	if s == nil || name != "preview_access_change" {
		return contracts.InvestigationTool{}, false
	}
	return s.contracts.Tool(name)
}

// AccessPreviewInput is the closed preview_access_change input. Spec stays the
// raw AccessBinding spec; the application decodes it with the observed
// binding schema.
type AccessPreviewInput struct {
	Changes []struct {
		Action string          `json:"action"`
		Kind   string          `json:"kind"`
		UID    string          `json:"uid,omitempty"`
		Spec   json.RawMessage `json:"spec,omitempty"`
	} `json:"changes"`
}

type previewCellData struct {
	ClusterID      string `json:"cluster_id"`
	NamespaceUID   string `json:"namespace_uid"`
	WorkloadUID    string `json:"workload_uid"`
	OtherWorkloads bool   `json:"other_workloads"`
}
type previewSubjectData struct {
	Kind   string `json:"kind"`
	Issuer string `json:"issuer"`
	ID     string `json:"id"`
}
type previewDeltaData struct {
	previewCellData
	Subject    previewSubjectData `json:"subject"`
	Operation  string             `json:"operation"`
	Before     string             `json:"before"`
	After      string             `json:"after"`
	AfterUnmet string             `json:"after_unmet,omitempty"`
}
type previewUnavailableData struct {
	previewCellData
	Decision string `json:"decision"`
	Unmet    string `json:"unmet"`
}
type previewBasisData struct {
	Kind string `json:"kind"`
	UID  string `json:"uid"`
}
type accessPreviewData struct {
	Complete         bool                     `json:"complete"`
	Message          string                   `json:"message"`
	TargetsEvaluated int                      `json:"targets_evaluated"`
	DeltasTotal      int                      `json:"deltas_total"`
	Deltas           []previewDeltaData       `json:"deltas"`
	UnavailableTotal int                      `json:"unavailable_total"`
	Unavailable      []previewUnavailableData `json:"unavailable"`
	Unmatched        []previewBasisData       `json:"unmatched"`
}

var previewOperationNames = map[authorization.Operation]string{authorization.CollectContext: "capture", authorization.ReadApproved: "read", authorization.DownloadApproved: "download"}

// previewReplyBudget keeps one reply inside the shared operation output limit
// even with long issuer or subject IDs; the totals still count every row.
const previewReplyBudget = contracts.InvestigationOutputLimit - 2048

func previewCell(t authorization.Target) previewCellData {
	return previewCellData{ClusterID: t.ClusterID, NamespaceUID: t.NamespaceUID, WorkloadUID: t.WorkloadUID, OtherWorkloads: t.WorkloadUID == cfg.OtherWorkloads}
}

func previewMessage(p cfg.AccessPreview) string {
	switch {
	case !p.Complete():
		return "Some targets could not be evaluated and are listed as Indeterminate; their access after the change is unknown. Nothing was changed: apply the reviewed objects with kubectl or GitOps."
	case p.DeltasTotal == 0:
		return "No listed subject's Allow, Deny or Indeterminate decision would change on these targets. Nothing was changed: apply the reviewed objects with kubectl or GitOps."
	case p.DeltasTotal > len(p.Deltas):
		return "Only the first decision changes are listed; deltas_total counts all of them. Preview fewer objects to see every change. Nothing was changed: apply the reviewed objects with kubectl or GitOps."
	}
	return "The listed decisions would change once the proposed objects are applied and accepted. Nothing was changed: apply the reviewed objects with kubectl or GitOps."
}

func previewFailure(err error) OperationFailure {
	switch {
	case errors.Is(err, cfg.ErrLimit):
		return OperationFailure{"PreviewTooLarge", "The proposal exceeds the preview bounds: at most 16 objects and 1,000 workload targets. Preview fewer objects or narrower scopes.", false}
	case errors.Is(err, cfg.ErrInvalid):
		return OperationFailure{"InvalidProposal", "A proposed object is not a valid AccessBinding change. Create and update need a complete AccessBinding spec, update and delete the existing object's UID, and each object may appear once. PermissionSource changes can only be previewed as deletion.", false}
	case errors.Is(err, identity.ErrDenied):
		return OperationFailure{"AdministratorRequired", "Previewing permission changes needs a current fleet operator signed in with an operator client.", false}
	}
	return OperationFailure{"NotAvailable", "The preview is unavailable right now. Retry shortly.", true}
}

func (s *AccessPreviewOperations) Call(ctx context.Context, current identities.CurrentIdentity, name string, raw json.RawMessage) (OperationReply, error) {
	if s == nil {
		return OperationReply{}, ErrOperationsConfiguration
	}
	return s.CallWithContext(ctx, current, OperationCall{requestID: s.newID()}, name, raw)
}

func (s *AccessPreviewOperations) CallWithContext(ctx context.Context, current identities.CurrentIdentity, call OperationCall, name string, raw json.RawMessage) (OperationReply, error) {
	if s == nil || ctx == nil || current == nil {
		return OperationReply{}, value.ErrUnavailable
	}
	if name != "preview_access_change" {
		return OperationReply{}, contracts.ErrInvestigationWire
	}
	if err := s.contracts.ValidateInput(name, raw); err != nil {
		return OperationReply{}, err
	}
	var in AccessPreviewInput
	if json.Unmarshal(raw, &in) != nil || !authorization.UUID(call.requestID) {
		return OperationReply{}, contracts.ErrInvestigationWire
	}
	i, err := current.ResolveIdentity(ctx)
	if err != nil || !i.Valid(s.now()) {
		return OperationReply{}, identity.ErrDenied
	}
	changes := make([]authapp.ProposedChange, len(in.Changes))
	for n, c := range in.Changes {
		changes[n] = authapp.ProposedChange{Action: c.Action, Kind: c.Kind, UID: c.UID, Spec: c.Spec}
	}
	out := OperationEnvelope{SchemaVersion: "mcp-result/v1", RequestID: call.requestID, DataClass: "metadata", Status: "ok", Warnings: []string{}, Provenance: []any{}}
	until := i.ValidUntil
	p, valid, operationErr := s.preview.Preview(ctx, current, changes)
	if operationErr != nil {
		out.Status, out.Data = "error", previewFailure(operationErr)
	} else {
		until = identity.Earlier(until, valid)
		data := accessPreviewData{Complete: p.Complete(), Message: previewMessage(p), TargetsEvaluated: p.Targets, DeltasTotal: p.DeltasTotal, Deltas: []previewDeltaData{},
			UnavailableTotal: len(p.Unavailable), Unavailable: []previewUnavailableData{}, Unmatched: []previewBasisData{}}
		for _, c := range p.Unavailable {
			if len(data.Unavailable) == 16 {
				break
			}
			data.Unavailable = append(data.Unavailable, previewUnavailableData{previewCell(c.Target), string(authorization.Indeterminate), c.Unavailable})
		}
		for _, b := range p.Unmatched {
			data.Unmatched = append(data.Unmatched, previewBasisData{b.Kind, b.UID})
		}
		for _, d := range p.Deltas {
			data.Deltas = append(data.Deltas, previewDeltaData{previewCell(d.Target), previewSubjectData{d.Subject.Kind, d.Subject.Issuer, d.Subject.ID},
				previewOperationNames[d.Operation], string(d.Before), string(d.After), d.AfterUnmet})
		}
		for {
			b, err := json.Marshal(data)
			if err != nil {
				return OperationReply{}, value.ErrUnavailable
			}
			if len(b) <= previewReplyBudget || len(data.Deltas) == 0 {
				break
			}
			data.Deltas = data.Deltas[:len(data.Deltas)-1]
		}
		if len(data.Deltas) < p.DeltasTotal {
			p.Deltas = p.Deltas[:len(data.Deltas)]
			data.Message = previewMessage(p)
		}
		out.Data = data
	}
	final, err := current.ResolveIdentity(ctx)
	if err != nil || ctx.Err() != nil || !final.Valid(s.now()) || final.Principal != i.Principal {
		return OperationReply{}, identity.ErrDenied
	}
	until = identity.Earlier(until, final.ValidUntil)
	b, err := json.Marshal(out)
	if err != nil || s.contracts.ValidateOutput(name, b) != nil {
		return OperationReply{}, value.ErrUnavailable
	}
	if !s.now().Before(until) || ctx.Err() != nil {
		clear(b)
		return OperationReply{}, value.ErrUnavailable
	}
	return OperationReply{Body: b, ValidUntil: until, auditDecision: captureAuditDecision(operationErr)}, nil
}
