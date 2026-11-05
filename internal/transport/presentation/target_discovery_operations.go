package presentation

import (
	"context"
	"encoding/json"
	"path"
	"time"

	analysisapp "asservat.local/asservat/internal/application/analysis"
	identities "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/contracts"
	value "asservat.local/asservat/internal/domain/analysis"
)

type TargetDiscoveryQueryService interface {
	Begin(context.Context, identities.CurrentIdentity, analysisapp.ContextQueryInvocation, value.TargetDiscoveryRequest) (*analysisapp.ContextProjectionDelivery, error)
}

type TargetDiscoveryOperationInput struct {
	CaptureID string `json:"capture_id"`
	Section   string `json:"section"`
	Cursor    string `json:"cursor,omitempty"`
	Limit     int    `json:"limit,omitempty"`
}

func (in TargetDiscoveryOperationInput) request() value.TargetDiscoveryRequest {
	return value.TargetDiscoveryRequest{CaptureID: in.CaptureID, Section: in.Section, Cursor: in.Cursor, Limit: in.Limit}
}

func normalizeTargetDiscoveryInput(in TargetDiscoveryOperationInput) TargetDiscoveryOperationInput {
	if in.Limit == 0 {
		in.Limit = 20
	}
	return in
}

func (s *ContextProjectionOperations) WithTargetDiscovery(discovery TargetDiscoveryQueryService) (*ContextProjectionOperations, error) {
	if s == nil || discovery == nil || s.discovery != nil {
		return nil, ErrOperationsConfiguration
	}
	out := *s
	out.discovery = discovery
	return &out, nil
}

type discoveryBasis struct {
	Confidence string `json:"confidence"`
	Reason     string `json:"reason"`
}

type discoveryProcessOutput struct {
	ProcessRef     string         `json:"process_ref"`
	PodUID         string         `json:"pod_uid"`
	DisplayPID     uint32         `json:"display_pid"`
	ExecutableName string         `json:"executable_name,omitempty"`
	ExecutablePath string         `json:"executable_path,omitempty"`
	Runtime        string         `json:"runtime"`
	IdentityBasis  discoveryBasis `json:"identity_basis"`
	ParentRef      string         `json:"parent_ref,omitempty"`
	RSSBytes       uint64         `json:"rss_bytes"`
	ObservedAt     time.Time      `json:"observed_at"`
}

type discoveryCoverage struct {
	RequestedPods     int    `json:"requested_pods"`
	CoveredPods       int    `json:"covered_pods"`
	InventoryComplete bool   `json:"process_inventory_complete"`
	TrafficComplete   bool   `json:"traffic_complete"`
	DroppedPackets    uint64 `json:"dropped_packets"`
	StopReason        string `json:"stop_reason"`
}

type discoverySummary struct {
	StartedAt     time.Time         `json:"started_at"`
	EndedAt       time.Time         `json:"ended_at"`
	WireBytes     int64             `json:"observed_wire_bytes"`
	RetainedBytes int64             `json:"retained_bytes"`
	Coverage      discoveryCoverage `json:"coverage"`
	CaptureMode   string            `json:"capture_mode"`
}

type targetDiscoveryOutput struct {
	Kind        string                    `json:"kind"`
	CaptureID   string                    `json:"capture_id"`
	ArtifactIDs []string                  `json:"source_artifact_ids"`
	ExpiresAt   time.Time                 `json:"expires_at"`
	Section     string                    `json:"section"`
	Summary     discoverySummary          `json:"summary"`
	Processes   *[]discoveryProcessOutput `json:"processes,omitempty"`
	Gaps        []string                  `json:"gaps"`
	queryViewTimes
}

const discoveryHandling = "SensitiveDataHandling: Executable paths and process references may contain user data. Runtime and build identity remain unknown unless qualified. This saved snapshot does not observe current processes. Deletion covers managed copies; delivered copies cannot be recalled."

var discoveryInvalidCursor = OperationFailure{Code: "InvalidCursor", Message: "The cursor does not match this process discovery. Start again without a cursor.", Retryable: false}
var discoveryNotAvailable = OperationFailure{Code: "NotAvailable", Message: "Process discovery is not available with your current artifact access and target collection rights.", Retryable: true}
var discoveryTooLarge = OperationFailure{Code: "AnalysisUnavailable", Message: "This process record does not fit the response limit. Download the original process snapshot to inspect it locally.", Retryable: false}

func renderTargetDiscoveryPage(requestID, name string, queryID string, p value.TargetDiscoveryPage, times queryViewTimes) ([]byte, error) {
	rows := make([]discoveryProcessOutput, 0, len(p.Processes))
	defer clear(rows)
	for _, r := range p.Processes {
		row := discoveryProcessOutput{ProcessRef: r.ProcessRef, PodUID: r.PodUID, DisplayPID: r.DisplayPID, ExecutablePath: r.ExecutablePath, Runtime: "unknown", IdentityBasis: discoveryBasis{"observed", "Exact runtime identity, process start and cgroup membership were verified at acquisition."}, ParentRef: r.ParentRef, RSSBytes: r.RSSBytes, ObservedAt: r.ObservedAt}
		if r.ExecutablePath != "" {
			name := path.Base(r.ExecutablePath)
			// The canonical display name is at most 255 characters. Preserve
			// the exact path and omit an oversized name instead of truncating it.
			if len([]rune(name)) <= 255 {
				row.ExecutableName = name
			}
		}
		rows = append(rows, row)
	}
	n := len(rows)
	for {
		data := targetDiscoveryOutput{Kind: "discoveryPage", CaptureID: p.CaptureID, ArtifactIDs: []string{p.ArtifactID}, ExpiresAt: times.ExpiresAt, Section: p.Section,
			Summary: discoverySummary{StartedAt: p.StartedAt, EndedAt: p.EndedAt, RetainedBytes: p.RetainedBytes, Coverage: discoveryCoverage{RequestedPods: 1, CoveredPods: p.CoveredPods, InventoryComplete: p.InventoryComplete, StopReason: p.StopReason}, CaptureMode: "none"}, Gaps: append([]string{}, p.Gaps...), queryViewTimes: times}
		if p.Section == "processes" {
			prefix := rows[:n]
			data.Processes = &prefix
		}
		inner := OperationEnvelope{SchemaVersion: "mcp-result/v1", RequestID: requestID, DataClass: "extract", Status: "ok", Data: data, Warnings: []string{discoveryHandling}, Provenance: []any{httpHeaderProvenance{ArtifactID: p.ArtifactID, Digest: hash(p.Version)}}}
		if cursor := p.Next(n); cursor != "" {
			inner.NextCursor, inner.Truncated = &cursor, true
			hint := "Use the next page to continue through the original saved process snapshot. This does not collect another snapshot."
			inner.NarrowingHint = &hint
		}
		outer := inner
		if name == "get_query_result" {
			outer.Truncated, outer.NextCursor, outer.NarrowingHint, outer.Provenance = false, nil, nil, []any{}
			outer.Data = queryResult(queryID, "get_target_discovery", inner, times)
		}
		body, err := json.Marshal(outer)
		if err != nil {
			return nil, ErrOperationDelivery
		}
		if len(body) <= contracts.InvestigationOutputLimit {
			return body, nil
		}
		clear(body)
		if n <= 1 {
			return nil, value.ErrRecordTooLarge
		}
		n--
	}
}
