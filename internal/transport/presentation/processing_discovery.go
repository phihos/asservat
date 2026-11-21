package presentation

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
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
	processingReportOperation        = "get_processing_report"
)

type ProcessingDiscoveryOperations struct {
	origin        string
	now           func() time.Time
	newID         func() string
	reader        privacy.ProcessingEvidenceDiscovery
	erasureStatus *privacy.ProcessingErasureStatus
	report        *privacy.ProcessingReport
	clusters      ClusterNames
	contracts     *contracts.InvestigationContracts
}

func NewProcessingDiscoveryOperations(origin string, now func() time.Time, newID func() string, clusters ClusterNames, reader privacy.ProcessingEvidenceDiscovery, erasureStatus *privacy.ProcessingErasureStatus, report *privacy.ProcessingReport) (*ProcessingDiscoveryOperations, error) {
	u, err := url.Parse(origin)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.Path != "" || now == nil || newID == nil || reader.Discovery == nil {
		return nil, ErrOperationsConfiguration
	}
	wire, err := contracts.NewInvestigationContracts()
	if err != nil {
		return nil, err
	}
	return &ProcessingDiscoveryOperations{origin: origin, now: now, newID: newID, reader: reader, erasureStatus: erasureStatus, report: report, clusters: clusters, contracts: wire}, nil
}

func (s *ProcessingDiscoveryOperations) PublicOrigin() string { return s.origin }
func (s *ProcessingDiscoveryOperations) ToolNames() []string {
	names := []string{processingDiscoveryOperation}
	if s.erasureStatus != nil {
		names = append(names, processingErasureStatusOperation)
	}
	if s.report != nil {
		names = append(names, processingReportOperation)
	}
	return names
}
func (s *ProcessingDiscoveryOperations) Tool(name string) (contracts.InvestigationTool, bool) {
	if name != processingDiscoveryOperation && (name != processingErasureStatusOperation || s.erasureStatus == nil) && (name != processingReportOperation || s.report == nil) {
		return contracts.InvestigationTool{}, false
	}
	return s.contracts.Tool(name)
}

func processingReportQuery(raw []byte) (value.ProcessingReportQuery, error) {
	var query value.ProcessingReportQuery
	if json.Unmarshal(raw, &query) != nil {
		return value.ProcessingReportQuery{}, contracts.ErrInvestigationWire
	}
	// A page ends at ProcessingReportLimit rows (the reply size target).
	query.Limit = min(query.Limit, value.ProcessingReportLimit)
	if !query.Valid() {
		return value.ProcessingReportQuery{}, contracts.ErrInvestigationWire
	}
	query = query.Normalized()
	query.CreatedBefore = query.CreatedBefore.UTC()
	query.After.CreatedAt = query.After.CreatedAt.UTC()
	return query, nil
}

// errProcessingUnknownCluster is a search naming no configured cluster.
var errProcessingUnknownCluster = errors.New("unknown cluster")

func (s *ProcessingDiscoveryOperations) processingDiscoveryQuery(raw []byte) (value.ProcessingDiscoveryQuery, error) {
	q := value.ProcessingDiscoveryQuery{Limit: value.ProcessingDiscoveryLimit}
	var named struct {
		Cluster string `json:"cluster"`
	}
	if json.Unmarshal(raw, &q) != nil || json.Unmarshal(raw, &named) != nil {
		return value.ProcessingDiscoveryQuery{}, contracts.ErrInvestigationWire
	}
	if named.Cluster != "" {
		id, ok := s.clusters.ID(named.Cluster)
		if !ok {
			return value.ProcessingDiscoveryQuery{}, errProcessingUnknownCluster
		}
		q.ClusterID = id
	}
	q.Limit = min(q.Limit, value.ProcessingDiscoveryLimit)
	if !q.Valid() {
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
	if name == processingReportOperation {
		query, err := processingReportQuery(raw)
		if err != nil {
			return OperationReply{}, err
		}
		page, err := s.report.Get(ctx, current, query)
		if err != nil {
			return OperationReply{}, err
		}
		data, validUntil = page, page.ValidUntil
	} else if name == processingErasureStatusOperation {
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
		q, err := s.processingDiscoveryQuery(raw)
		if errors.Is(err, errProcessingUnknownCluster) {
			return s.encode(ctx, name, OperationEnvelope{SchemaVersion: "mcp-result/v1", RequestID: call.requestID, DataClass: "metadata", Status: "error",
				Data: OperationFailure{"UnknownCluster", "No cluster of this installation has this name. Use local for the hub's own cluster or a configured clusters[].name.", false}, Warnings: []string{}, Provenance: []any{}}, s.now().Add(time.Second))
		}
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
	return s.encode(ctx, name, OperationEnvelope{SchemaVersion: "mcp-result/v1", RequestID: call.requestID, DataClass: "metadata", Status: "ok", Data: data, Warnings: []string{}, Provenance: []any{}}, validUntil)
}

func (s *ProcessingDiscoveryOperations) encode(ctx context.Context, name string, out OperationEnvelope, validUntil time.Time) (OperationReply, error) {
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
