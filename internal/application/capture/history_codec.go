package capture

import (
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/capture"
	"context"
)

// HistoryParameterCodec encrypts private control data with purpose-separated
// associated data. It has no evidence catalog or collection authority.
type HistoryParameterCodec interface {
	SealHistory(context.Context, value.HistoryExpectation, value.HistoryParameters) (value.HistoryCiphertexts, error)
	OpenHistory(context.Context, value.HistoryExpectation, artifact.Copies, value.HistoryCiphertexts) (value.HistoryParameters, error)
}
