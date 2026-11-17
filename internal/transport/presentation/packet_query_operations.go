package presentation

import (
	analysisapp "asservat.local/asservat/internal/application/analysis"
	identities "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/contracts"
	value "asservat.local/asservat/internal/domain/analysis"
	"context"
)

type PacketQueryService interface {
	Begin(context.Context, identities.CurrentIdentity, string, value.PacketQueryRequest) (*analysisapp.ContextProjectionDelivery, error)
}

func (s *ContextProjectionOperations) WithPacketQueries(q PacketQueryService) (*ContextProjectionOperations, error) {
	if s == nil || q == nil || s.packetQueries != nil {
		return nil, ErrOperationsConfiguration
	}
	out := *s
	out.packetQueries = q
	return &out, nil
}

func (in projectionInput) packetQuery() value.PacketQueryRequest {
	r := value.PacketQueryRequest{CaseID: in.CaseID, ArtifactID: in.ArtifactID, GrantID: in.GrantID, IdempotencyKey: in.IdempotencyKey, PacketFilter: in.PacketFilter, Fields: in.Fields, StartTime: in.StartTime, EndTime: in.EndTime, MaxPackets: in.Limit, MaxScanBytes: value.PacketQueryMaxScanBytes}
	if in.TCPFlags != nil {
		r.TCPFlags = &value.PacketQueryTCPFlags{Mask: in.TCPFlags.Mask, Value: in.TCPFlags.Value}
	}
	if in.FramePrefix != nil {
		r.FramePrefix = &value.PacketQueryFramePrefix{Offset: in.FramePrefix.Offset, Length: in.FramePrefix.Length}
	}
	return analysisapp.NormalizePacketQueryRequest(r)
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
