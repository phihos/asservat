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
	value "asservat.local/asservat/internal/domain/privacy"
)

const processingDiscoveryOperation = "search_processing_evidence"

type ProcessingDiscoveryOperations struct {
	origin    string
	now       func() time.Time
	newID     func() string
	reader    privacy.ProcessingEvidenceDiscovery
	contracts *contracts.InvestigationContracts
}

func NewProcessingDiscoveryOperations(origin string, now func() time.Time, newID func() string, reader privacy.ProcessingEvidenceDiscovery) (*ProcessingDiscoveryOperations, error) {
	u, err := url.Parse(origin)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.Path != "" || now == nil || newID == nil || reader.Discovery == nil {
		return nil, ErrOperationsConfiguration
	}
	wire, err := contracts.NewInvestigationContracts()
	if err != nil {
		return nil, err
	}
	return &ProcessingDiscoveryOperations{origin, now, newID, reader, wire}, nil
}

func (s *ProcessingDiscoveryOperations) PublicOrigin() string { return s.origin }
func (s *ProcessingDiscoveryOperations) ToolNames() []string {
	return []string{processingDiscoveryOperation}
}
func (s *ProcessingDiscoveryOperations) Tool(name string) (contracts.InvestigationTool, bool) {
	if name != processingDiscoveryOperation {
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
	if name != processingDiscoveryOperation || call.requestID == "" || s.contracts.ValidateInput(name, raw) != nil {
		return OperationReply{}, contracts.ErrInvestigationWire
	}
	q, err := processingDiscoveryQuery(raw)
	if err != nil {
		return OperationReply{}, err
	}
	page, err := s.reader.Search(ctx, current, q)
	if err != nil {
		return OperationReply{}, err
	}
	data := struct {
		Candidates []value.ProcessingDiscoveryCandidate `json:"candidates"`
		Next       value.ProcessingDiscoveryCursor      `json:"next,omitzero"`
	}{page.Candidates, page.Next}
	out := OperationEnvelope{SchemaVersion: "mcp-result/v1", RequestID: call.requestID, DataClass: "metadata", Status: "ok", Data: data, Warnings: []string{}, Provenance: []any{}}
	var body bytes.Buffer
	encoder := json.NewEncoder(&body)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(out); err != nil || body.Len() > contracts.InvestigationOutputLimit || s.contracts.ValidateOutput(name, body.Bytes()) != nil || ctx.Err() != nil || !s.now().Before(page.ValidUntil) {
		return OperationReply{}, value.ErrUnavailable
	}
	return OperationReply{Body: body.Bytes(), ValidUntil: page.ValidUntil}, nil
}
