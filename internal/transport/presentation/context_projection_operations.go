package presentation

import (
	"context"
	"encoding/json"
	"time"

	analysisapp "asservat.local/asservat/internal/application/analysis"
	identities "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/contracts"
	value "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/identity"
)

// Initial admission and passive results are separate consumer capabilities.
// Both return the concrete C-18 owner; arbitrary result DTOs are insufficient.
type ContextExcerptService interface {
	BeginExcerpt(context.Context, identities.CurrentIdentity, analysisapp.ContextQueryInvocation, value.ContextExcerptSelection) (*analysisapp.ContextProjectionDelivery, error)
}
type ContextQueryResults interface {
	GetQueryResult(context.Context, identities.CurrentIdentity, analysisapp.ContextQueryInvocation, string) (*analysisapp.ContextProjectionDelivery, error)
}

// This adapter deliberately has no ToolNames, Tool or unaudited Call. Explicit
// installation composition adds its two operations to InvestigationOperations;
// the existing audit wrapper alone supplies each live invocation owner.
type ContextProjectionOperations struct {
	excerpts  ContextExcerptService
	results   ContextQueryResults
	contracts *contracts.InvestigationContracts
}

func NewContextProjectionOperations(excerpts ContextExcerptService, results ContextQueryResults) (*ContextProjectionOperations, error) {
	if excerpts == nil || results == nil {
		return nil, ErrOperationsConfiguration
	}
	wire, err := contracts.NewInvestigationContracts()
	if err != nil {
		return nil, err
	}
	return &ContextProjectionOperations{excerpts: excerpts, results: results, contracts: wire}, nil
}

func (s *ContextProjectionOperations) CallWithContext(ctx context.Context, current identities.CurrentIdentity, call OperationCall, name string, raw json.RawMessage) (OperationReply, error) {
	noDispatch := OperationReply{auditNoDispatch: true, auditEffect: operationEffectNone}
	if s == nil || ctx == nil || ctx.Err() != nil || current == nil || call.queryInvocation == nil ||
		!queryOperation(name) || s.contracts.ValidateInput(name, raw) != nil {
		return noDispatch, ErrOperationDelivery
	}
	i := call.queryInvocation
	record, err := i.Invocation(ctx)
	if err != nil || record.ID != call.requestID || record.Tool != name {
		return noDispatch, ErrOperationDelivery
	}
	var input analysisapp.ContextQueryInput
	if name == "get_file_excerpt" {
		var in struct {
			CaseID     string `json:"case_id"`
			ArtifactID string `json:"artifact_id"`
			LineStart  int    `json:"line_start"`
			MaxLines   int    `json:"max_lines"`
		}
		if json.Unmarshal(raw, &in) != nil {
			return noDispatch, ErrOperationDelivery
		}
		selection, e := value.NormalizeLineSelection(in.LineStart, in.MaxLines)
		if e != nil {
			return noDispatch, ErrOperationDelivery
		}
		input.Selection = value.ContextExcerptSelection{CaseID: in.CaseID, ArtifactID: in.ArtifactID, Selection: selection}
	} else {
		var in struct {
			QueryHandle string `json:"query_handle"`
		}
		if json.Unmarshal(raw, &in) != nil {
			return noDispatch, ErrOperationDelivery
		}
		input.QueryID = in.QueryHandle
	}
	if i.CheckInput(ctx, input) != nil {
		return noDispatch, ErrOperationDelivery
	}
	var d *analysisapp.ContextProjectionDelivery
	if name == "get_file_excerpt" {
		d, err = s.excerpts.BeginExcerpt(ctx, current, i, input.Selection)
	} else {
		d, err = s.results.GetQueryResult(ctx, current, i, input.QueryID)
	}
	// Any dispatched error may have spent query/read/control capacity. Closing
	// an accompanying handle is mandatory and never establishes no effect.
	transferred := false
	defer func() {
		if !transferred {
			i.close()
			if d != nil {
				until := identity.Earlier(record.WriteUntil, d.CleanupUntil())
				cleanup, cancel := context.WithDeadline(context.WithoutCancel(ctx), until)
				_ = d.Close(cleanup)
				cancel()
			}
		}
	}()
	if err != nil || d == nil {
		return OperationReply{}, ErrOperationDelivery
	}
	select {
	case <-d.Done():
		return OperationReply{}, ErrOperationDelivery
	default:
	}
	body, err := s.serialize(call.requestID, name, d)
	if err != nil {
		return OperationReply{}, ErrOperationDelivery
	}
	if i.bind(ctx, d, int64(len(body))) != nil {
		clear(body)
		return OperationReply{}, ErrOperationDelivery
	}
	reply := OperationReply{Body: body, ValidUntil: d.ValidUntil(), auditEffect: operationEffectAccepted}
	reply, err = ownOperationReply(ctx, reply, &contextProjectionGuard{delivery: d, invocation: i, preparedUntil: reply.ValidUntil},
		identity.Earlier(record.WriteUntil, d.CleanupUntil()), i.acknowledge)
	if err != nil {
		clear(body)
		return OperationReply{}, err
	}
	transferred = true
	return reply, nil
}

type queryViewTimes struct {
	ObservedAt time.Time `json:"query_observed_at"`
	ExpiresAt  time.Time `json:"query_expires_at"`
}

func (s *ContextProjectionOperations) serialize(requestID, name string, d *analysisapp.ContextProjectionDelivery) ([]byte, error) {
	times := queryViewTimes{ObservedAt: d.ObservedAt(), ExpiresAt: d.QueryDeadline()}
	envelope := OperationEnvelope{SchemaVersion: "mcp-result/v1", RequestID: requestID,
		DataClass: "metadata", Status: "ok", Warnings: []string{}, Provenance: []any{}}
	if d.Pending() {
		envelope.Status = "pending"
		envelope.Data = struct {
			QueryHandle string `json:"query_handle"`
			RetryAfter  int    `json:"retry_after_seconds"`
			queryViewTimes
		}{d.Association().QueryID, 1, times}
	} else {
		excerpt, ok := d.Excerpt()
		if !ok {
			return nil, ErrOperationDelivery
		}
		defer clear(excerpt.Lines)
		envelope.Data = struct {
			value.ContextExcerpt
			queryViewTimes
		}{excerpt, times}
		if name == "get_query_result" {
			inner := envelope
			envelope.Data = struct {
				QueryHandle string            `json:"query_handle"`
				ToolName    string            `json:"tool_name"`
				Result      OperationEnvelope `json:"result"`
				queryViewTimes
			}{d.Association().QueryID, "get_file_excerpt", inner, times}
		}
	}
	body, err := json.Marshal(envelope)
	if err != nil || s.contracts.ValidateOutput(name, body) != nil {
		clear(body)
		return nil, ErrOperationDelivery
	}
	return body, nil
}

type contextProjectionGuard struct {
	delivery      *analysisapp.ContextProjectionDelivery
	invocation    *contextQueryInvocation
	preparedUntil time.Time
}

func (g *contextProjectionGuard) CheckDisclosure(ctx context.Context) error {
	if err := g.delivery.CheckDisclosure(ctx); err != nil {
		return err
	}
	// The serialized reply/socket selected the prepared bound. A blocking
	// check that discovers an earlier lease rejects this exact response; it
	// cannot leave the transport using its older, longer deadline.
	if g.delivery.ValidUntil().Before(g.preparedUntil) {
		return ErrOperationDelivery
	}
	return nil
}
func (g *contextProjectionGuard) Done() <-chan struct{} { return g.delivery.Done() }
func (g *contextProjectionGuard) Close(ctx context.Context) error {
	g.invocation.close()
	return g.delivery.Close(ctx)
}
