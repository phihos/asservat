package presentation

import (
	analysisapp "asservat.local/asservat/internal/application/analysis"
	identities "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/contracts"
	value "asservat.local/asservat/internal/domain/analysis"
	"context"
	"time"
)

type PacketQueryService interface {
	Begin(context.Context, identities.CurrentIdentity, analysisapp.ContextQueryInvocation, value.PacketQueryRequest) (*analysisapp.ContextProjectionDelivery, error)
}

func (s *ContextProjectionOperations) WithPacketQueries(q PacketQueryService) (*ContextProjectionOperations, error) {
	if s == nil || q == nil || s.packetQueries != nil {
		return nil, ErrOperationsConfiguration
	}
	out := *s
	out.packetQueries = q
	return &out, nil
}

type packetQueryFlagInput struct {
	Mask  uint16 `json:"mask"`
	Value uint16 `json:"value"`
}
type packetQueryPrefixInput struct {
	Offset uint16 `json:"offset"`
	Length uint16 `json:"length"`
}
type PacketQueryOperationInput struct {
	CaseID         string                   `json:"case_id"`
	ArtifactID     string                   `json:"artifact_id"`
	GrantID        string                   `json:"grant_id,omitempty"`
	IdempotencyKey string                   `json:"idempotency_key"`
	PacketFilter   string                   `json:"packet_filter,omitempty"`
	Fields         []value.PacketQueryField `json:"fields"`
	StartTime      *time.Time               `json:"start_time,omitempty"`
	EndTime        *time.Time               `json:"end_time,omitempty"`
	TCPFlags       *packetQueryFlagInput    `json:"tcp_flags,omitempty"`
	FramePrefix    *packetQueryPrefixInput  `json:"frame_prefix,omitempty"`
	MaxPackets     int                      `json:"max_packets"`
	MaxScanBytes   int64                    `json:"max_scan_bytes"`
}

func (in PacketQueryOperationInput) request() value.PacketQueryRequest {
	r := value.PacketQueryRequest{CaseID: in.CaseID, ArtifactID: in.ArtifactID, GrantID: in.GrantID, IdempotencyKey: in.IdempotencyKey, PacketFilter: in.PacketFilter, Fields: in.Fields, StartTime: in.StartTime, EndTime: in.EndTime, MaxPackets: in.MaxPackets, MaxScanBytes: in.MaxScanBytes}
	if in.TCPFlags != nil {
		r.TCPFlags = &value.PacketQueryTCPFlags{Mask: in.TCPFlags.Mask, Value: in.TCPFlags.Value}
	}
	if in.FramePrefix != nil {
		r.FramePrefix = &value.PacketQueryFramePrefix{Offset: in.FramePrefix.Offset, Length: in.FramePrefix.Length}
	}
	return analysisapp.NormalizePacketQueryRequest(r)
}
func packetQueryInput(r value.PacketQueryRequest) PacketQueryOperationInput {
	r = analysisapp.NormalizePacketQueryRequest(r)
	in := PacketQueryOperationInput{CaseID: r.CaseID, ArtifactID: r.ArtifactID, GrantID: r.GrantID, IdempotencyKey: r.IdempotencyKey, PacketFilter: r.PacketFilter, Fields: r.Fields, StartTime: r.StartTime, EndTime: r.EndTime, MaxPackets: r.MaxPackets, MaxScanBytes: r.MaxScanBytes}
	if r.TCPFlags != nil {
		in.TCPFlags = &packetQueryFlagInput{r.TCPFlags.Mask, r.TCPFlags.Value}
	}
	if r.FramePrefix != nil {
		in.FramePrefix = &packetQueryPrefixInput{r.FramePrefix.Offset, r.FramePrefix.Length}
	}
	return in
}
func packetQueryPage(r value.PacketQueryResult) contracts.PacketQueryPage {
	p := contracts.PacketQueryPage{CaptureMode: r.CaptureMode, Fields: make([]string, len(r.Fields)), Rows: make([][]contracts.PacketQueryCell, len(r.Rows)), ScannedBytes: r.ScannedBytes, ScannedPackets: r.ScannedPackets, RowLimitReached: r.RowLimitReached, ScanLimitReached: r.ScanLimitReached, OutputLimitReached: r.OutputLimitReached}
	for i, f := range r.Fields {
		p.Fields[i] = string(f)
	}
	for i, row := range r.Rows {
		p.Rows[i] = make([]contracts.PacketQueryCell, len(row))
		for j, c := range row {
			p.Rows[i][j] = contracts.PacketQueryCell{Text: c.Text, Number: c.Number}
		}
	}
	return p
}

const packetQueryHandling = "SensitiveDataHandling: Packet fields and saved frame bytes may contain user data. Results describe saved records, not complete traffic. Managed deletion does not recall delivered copies."
