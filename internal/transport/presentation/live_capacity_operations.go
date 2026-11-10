package presentation

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"time"

	identities "asservat.local/asservat/internal/application/identity"
	liveapp "asservat.local/asservat/internal/application/live"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/collector"
	"asservat.local/asservat/internal/domain/identity"
	v "asservat.local/asservat/internal/domain/live"
)

type LiveCapacityUseCase interface {
	Read(context.Context, identities.CurrentIdentity, string) (collector.LiveRuntimeSnapshot, time.Time, error)
}

// LiveCapacityOperations serves the browser-only administrator capacity view.
type LiveCapacityOperations struct {
	origin    string
	now       func() time.Time
	newID     func() string
	reader    LiveCapacityUseCase
	contracts *contracts.InvestigationContracts
}

func NewLiveCapacityOperations(origin string, now func() time.Time, newID func() string, reader LiveCapacityUseCase) (*LiveCapacityOperations, error) {
	u, err := url.Parse(origin)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.Path != "" || reader == nil || now == nil || newID == nil {
		return nil, ErrOperationsConfiguration
	}
	wire, err := contracts.NewInvestigationContracts()
	if err != nil {
		return nil, err
	}
	return &LiveCapacityOperations{origin: origin, now: now, newID: newID, reader: reader, contracts: wire}, nil
}

func (s *LiveCapacityOperations) PublicOrigin() string {
	if s == nil {
		return ""
	}
	return s.origin
}
func (s *LiveCapacityOperations) ToolNames() []string { return []string{"get_live_capacity"} }
func (s *LiveCapacityOperations) Tool(name string) (contracts.InvestigationTool, bool) {
	if s == nil || name != "get_live_capacity" {
		return contracts.InvestigationTool{}, false
	}
	return s.contracts.Tool(name)
}

type liveCapacityInput struct {
	ClusterID string `json:"cluster_id"`
}
type liveCapacityActivity struct {
	Cohorts           int   `json:"cohorts"`
	ScanEvents        int64 `json:"scan_events"`
	ScanBytes         int64 `json:"scan_bytes"`
	ScanCPUNanos      int64 `json:"scan_cpu_nanos"`
	DeliveredRows     int64 `json:"delivered_rows"`
	DeliveredBytes    int64 `json:"delivered_bytes"`
	RefusedAdmissions int64 `json:"refused_admissions"`
	LostEvents        int64 `json:"lost_events"`
	DroppedRows       int64 `json:"dropped_rows"`
	PendingRows       int   `json:"pending_rows"`
}
type liveCapacityRates struct {
	ScanEventsPerSecond        float64 `json:"scan_events_per_second"`
	ScanBytesPerSecond         float64 `json:"scan_bytes_per_second"`
	ScanCPUNanosPerSecond      float64 `json:"scan_cpu_nanos_per_second"`
	DeliveredRowsPerSecond     float64 `json:"delivered_rows_per_second"`
	DeliveredBytesPerSecond    float64 `json:"delivered_bytes_per_second"`
	RefusedAdmissionsPerSecond float64 `json:"refused_admissions_per_second"`
	LostEventsPerSecond        float64 `json:"lost_events_per_second"`
	DroppedRowsPerSecond       float64 `json:"dropped_rows_per_second"`
}
type liveCapacityData struct {
	ClusterID        string                `json:"cluster_id"`
	ObservedAt       time.Time             `json:"observed_at"`
	FreshUntil       time.Time             `json:"fresh_until"`
	Message          string                `json:"message"`
	Nodes            int                   `json:"nodes"`
	RatesUnavailable int                   `json:"rates_unavailable"`
	RatesComplete    bool                  `json:"rates_complete"`
	Live             *liveCapacityActivity `json:"live,omitempty"`
	Rates            liveCapacityRates     `json:"rates"`
}

func liveCapacityMessage(snapshot collector.LiveRuntimeSnapshot) string {
	if snapshot.Live == nil {
		return "No current node reports have live viewing enabled."
	}
	if !snapshot.RatesComplete {
		return "At least one current live-enabled node has no valid report predecessor. Cluster-wide rates are unavailable; cumulative counters still cover current reports."
	}
	return "Counters and per-second rates cover every current live-enabled node report."
}

func liveCapacityReply(snapshot collector.LiveRuntimeSnapshot) liveCapacityData {
	out := liveCapacityData{ClusterID: snapshot.ClusterID, ObservedAt: snapshot.ObservedAt.UTC(), FreshUntil: snapshot.FreshUntil.UTC(), Message: liveCapacityMessage(snapshot), Nodes: snapshot.Nodes, RatesUnavailable: snapshot.RatesUnavailable, RatesComplete: snapshot.RatesComplete,
		Rates: liveCapacityRates{ScanEventsPerSecond: snapshot.Rates.ScanEventsPerSecond, ScanBytesPerSecond: snapshot.Rates.ScanBytesPerSecond, ScanCPUNanosPerSecond: snapshot.Rates.ScanCPUNanosPerSecond, DeliveredRowsPerSecond: snapshot.Rates.DeliveredRowsPerSecond, DeliveredBytesPerSecond: snapshot.Rates.DeliveredBytesPerSecond, RefusedAdmissionsPerSecond: snapshot.Rates.RefusedAdmissionsPerSecond, LostEventsPerSecond: snapshot.Rates.LostEventsPerSecond, DroppedRowsPerSecond: snapshot.Rates.DroppedRowsPerSecond}}
	if snapshot.Live != nil {
		out.Live = &liveCapacityActivity{Cohorts: snapshot.Live.Cohorts, ScanEvents: snapshot.Live.ScanEvents, ScanBytes: snapshot.Live.ScanBytes, ScanCPUNanos: snapshot.Live.ScanCPUNanos, DeliveredRows: snapshot.Live.DeliveredRows, DeliveredBytes: snapshot.Live.DeliveredBytes, RefusedAdmissions: snapshot.Live.RefusedAdmissions, LostEvents: snapshot.Live.LostEvents, DroppedRows: snapshot.Live.DroppedRows, PendingRows: snapshot.Live.PendingRows}
	}
	return out
}

func liveCapacityFailure(err error) OperationFailure {
	if errors.Is(err, identity.ErrDenied) {
		return OperationFailure{"AdministratorRequired", "Reading live-view capacity needs a current fleet operator signed in with an operator client.", false}
	}
	if errors.Is(err, v.ErrInvalid) {
		return OperationFailure{"InvalidCluster", "Select one valid cluster ID.", false}
	}
	if errors.Is(err, liveapp.ErrClusterUnknown) {
		return OperationFailure{"UnknownCluster", "That cluster is not enrolled in this installation.", false}
	}
	return OperationFailure{"NotAvailable", "Live-view capacity is unavailable right now. Retry shortly.", true}
}

func (s *LiveCapacityOperations) Call(ctx context.Context, current identities.CurrentIdentity, name string, raw json.RawMessage) (OperationReply, error) {
	if s == nil {
		return OperationReply{}, ErrOperationsConfiguration
	}
	return s.CallWithContext(ctx, current, OperationCall{requestID: s.newID()}, name, raw)
}

func (s *LiveCapacityOperations) CallWithContext(ctx context.Context, current identities.CurrentIdentity, call OperationCall, name string, raw json.RawMessage) (OperationReply, error) {
	if s == nil || ctx == nil || current == nil {
		return OperationReply{}, ErrOperationsConfiguration
	}
	if name != "get_live_capacity" {
		return OperationReply{}, contracts.ErrInvestigationWire
	}
	if err := s.contracts.ValidateInput(name, raw); err != nil {
		return OperationReply{}, err
	}
	var in liveCapacityInput
	if json.Unmarshal(raw, &in) != nil || call.requestID == "" {
		return OperationReply{}, contracts.ErrInvestigationWire
	}
	caller, err := current.ResolveIdentity(ctx)
	if err != nil || !caller.Valid(s.now()) {
		return OperationReply{}, identity.ErrDenied
	}
	out := OperationEnvelope{SchemaVersion: "mcp-result/v1", RequestID: call.requestID, DataClass: "metadata", Status: "ok", Warnings: []string{}, Provenance: []any{}}
	until := caller.ValidUntil
	snapshot, valid, operationErr := s.reader.Read(ctx, current, in.ClusterID)
	if operationErr != nil {
		out.Status, out.Data = "error", liveCapacityFailure(operationErr)
		errorWindow := identity.Check(s.now(), identity.Recheck).Narrow(s.now().Add(time.Second))
		until = identity.Earlier(until, errorWindow.Until())
	} else {
		until = identity.Earlier(until, valid)
		out.Data = liveCapacityReply(snapshot)
	}
	final, err := current.ResolveIdentity(ctx)
	if err != nil || ctx.Err() != nil || !final.Valid(s.now()) || final.Principal != caller.Principal {
		return OperationReply{}, identity.ErrDenied
	}
	until = identity.Earlier(until, final.ValidUntil)
	body, err := json.Marshal(out)
	if err != nil || s.contracts.ValidateOutput(name, body) != nil {
		return OperationReply{}, v.ErrUnavailable
	}
	if !s.now().Before(until) || ctx.Err() != nil {
		clear(body)
		return OperationReply{}, v.ErrUnavailable
	}
	return OperationReply{Body: body, ValidUntil: until, auditDecision: captureAuditDecision(operationErr)}, nil
}
