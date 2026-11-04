package presentation

import (
	analysisapp "asservat.local/asservat/internal/application/analysis"
	identities "asservat.local/asservat/internal/application/identity"
	value "asservat.local/asservat/internal/domain/analysis"
	"context"
)

type PacketSummaryQueryService interface {
	Begin(context.Context, identities.CurrentIdentity, analysisapp.ContextQueryInvocation, value.PacketSummaryRequest) (*analysisapp.ContextProjectionDelivery, error)
}

func (s *ContextProjectionOperations) WithPacketSummaries(packets PacketSummaryQueryService) (*ContextProjectionOperations, error) {
	if s == nil || packets == nil || s.packets != nil {
		return nil, ErrOperationsConfiguration
	}
	out := *s
	out.packets = packets
	return &out, nil
}

const packetSummaryHandling = "SensitiveDataHandling: Numeric endpoints may contain user data. Counts describe saved records and labelled capture exclusions, not measured network loss. The summary omits payload, names and comments. Deletion covers Asservat-managed copies; delivered copies cannot be recalled."

var packetSummaryNotAvailable = OperationFailure{Code: "NotAvailable", Message: "This packet summary is not available with your current access or service conditions. Check your access or try again later.", Retryable: true}
