package mtls

import (
	"encoding/json"

	"asservat.local/asservat/internal/contracts"
)

func encodeNativeHello(h contracts.NativeHello) ([]byte, error) {
	if h.Format != contracts.NativeExchangeFormat || !contracts.ValidWorkerNonce(h.Nonce) {
		return nil, contracts.ErrNativeProtocol
	}
	b, err := json.Marshal(h)
	if err != nil || len(b) > contracts.NativeControlBytes {
		return nil, contracts.ErrNativeProtocol
	}
	return b, nil
}
