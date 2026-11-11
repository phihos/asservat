package presentation

import (
	"bytes"
	"context"
	"encoding/json"
	"net/url"
	"time"

	identities "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/application/privacy"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/privacy"
)

const (
	processingDiscoveryOperation     = "search_processing_evidence"
	processingErasureStatusOperation = "get_processing_erasure"
)

type ProcessingDiscoveryOperations struct {
	origin        string
	now           func() time.Time
	newID         func() string
	reader        privacy.ProcessingEvidenceDiscovery
	erasureStatus *privacy.ProcessingErasureStatus
	contracts     *contracts.InvestigationContracts
}

func NewProcessingDiscoveryOperations(origin string, now func() time.Time, newID func() string, reader privacy.ProcessingEvidenceDiscovery, erasureStatus *privacy.ProcessingErasureStatus) (*ProcessingDiscoveryOperations, error) {
	u, err := url.Parse(origin)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.Path != "" || now == nil || newID == nil || reader.Discovery == nil {
		return nil, ErrOperationsConfiguration
	}
	wire, err := contracts.NewInvestigationContracts()
	if err != nil {
		return nil, err
	}
	return &ProcessingDiscoveryOperations{origin, now, newID, reader, erasureStatus, wire}, nil
}

func (s *ProcessingDiscoveryOperations) PublicOrigin() string { return s.origin }
func (s *ProcessingDiscoveryOperations) ToolNames() []string {
	if s.erasureStatus != nil {
		return []string{processingDiscoveryOperation, processingErasureStatusOperation}
	}
	return []string{processingDiscoveryOperation}
}
func (s *ProcessingDiscoveryOperations) Tool(name string) (contracts.InvestigationTool, bool) {
	if name != processingDiscoveryOperation && (name != processingErasureStatusOperation || s.erasureStatus == nil) {
		return contracts.InvestigationTool{}, false
	}
	return s.contracts.Tool(name)
}

func processingDiscoveryQuery(raw []byte) (value.ProcessingDiscoveryQuery, error) {
	q := value.ProcessingDiscoveryQuery{Limit: value.ProcessingDiscoveryLimit}
	if json.Unmarshal(raw, &q) != nil || !q.Valid() {
		return value.ProcessingDiscoveryQuery{}, contracts.ErrInvestigationWire
	}
	q.AcquiredFrom = q.AcquiredFrom.UTC()
	q.AcquiredUntil = q.AcquiredUntil.UTC()
	q.After.AnchorAt = q.After.AnchorAt.UTC()
	return q, nil
}

func (s *ProcessingDiscoveryOperations) Call(ctx context.Context, current identities.CurrentIdentity, name string, raw json.RawMessage) (OperationReply, error) {
	return s.CallWithContext(ctx, current, OperationCall{requestID: s.newID()}, name, raw)
}

func (s *ProcessingDiscoveryOperations) CallWithContext(ctx context.Context, current identities.CurrentIdentity, call OperationCall, name string, raw json.RawMessage) (OperationReply, error) {
	if _, supported := s.Tool(name); !supported || call.requestID == "" || s.contracts.ValidateInput(name, raw) != nil {
		return OperationReply{}, contracts.ErrInvestigationWire
	}
	var data any
	var validUntil time.Time
	if name == processingErasureStatusOperation {
		var input processingErasureStatusInput
		if json.Unmarshal(raw, &input) != nil || !authorization.UUID(input.RequestID) {
			return OperationReply{}, contracts.ErrInvestigationWire
		}
		status, err := s.erasureStatus.Get(ctx, current, input.RequestID)
		if err != nil {
			return OperationReply{}, err
		}
		data, validUntil = status, status.ValidUntil
	} else {
		q, err := processingDiscoveryQuery(raw)
		if err != nil {
			return OperationReply{}, err
		}
		page, err := s.reader.Search(ctx, current, q)
		if err != nil {
			return OperationReply{}, err
		}
		data = struct {
			Candidates []value.ProcessingDiscoveryCandidate `json:"candidates"`
			Next       value.ProcessingDiscoveryCursor      `json:"next,omitzero"`
		}{page.Candidates, page.Next}
		validUntil = page.ValidUntil
	}
	out := OperationEnvelope{SchemaVersion: "mcp-result/v1", RequestID: call.requestID, DataClass: "metadata", Status: "ok", Data: data, Warnings: []string{}, Provenance: []any{}}
	var body bytes.Buffer
	encoder := json.NewEncoder(&body)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(out); err != nil || body.Len() > contracts.InvestigationOutputLimit || s.contracts.ValidateOutput(name, body.Bytes()) != nil || ctx.Err() != nil || !s.now().Before(validUntil) {
		return OperationReply{}, value.ErrUnavailable
	}
	return OperationReply{Body: body.Bytes(), ValidUntil: validUntil}, nil
}

type processingErasureStatusInput struct {
	RequestID string `json:"request_id"`
}
