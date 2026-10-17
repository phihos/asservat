package contracts

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"time"
)

const OwnerRelayFormat = "asservat-owner-relay/v2"
const OwnerRelayPath = "/internal/hub-owner/v2/enroll-worker"
const OwnerRelayMaxRequest = 20 << 10
const OwnerRelayMaxResponse = WorkerEnrollmentMaxResponse + 512
const OwnerRelayContentType = "application/vnd.asservat.owner-enrollment-stream"

// This locator supplies no authority and no network address. The receiver
// resolves the exact independently registered live control operation.
type OwnerRelayLocator struct {
	RequestID    string    `json:"requestID"`
	PodUID       string    `json:"podUID"`
	ProcessEpoch string    `json:"processEpoch"`
	Fence        int64     `json:"fence"`
	Started      time.Time `json:"started"`
	Until        time.Time `json:"until"`
}
type OwnerRelayRequest struct {
	Format     string                  `json:"format"`
	Locator    OwnerRelayLocator       `json:"locator"`
	Enrollment WorkerEnrollmentRequest `json:"enrollment"`
}

func DecodeOwnerRelayRequest(r io.Reader) (OwnerRelayRequest, error) {
	return decodeClosedRPC[OwnerRelayRequest](r, OwnerRelayMaxRequest)
}

// One bounded JSON frame, prefixed by its four-byte big-endian length. The HTTP
// body MUST remain open after this frame for the lifetime of downstream delivery.
// EOF, any further byte or a read error cancels delivery; there is no success EOF,
// keepalive payload, replay, renewal, or second certificate on this connection.
type OwnerRelayResponse struct {
	Format     string                   `json:"format"`
	Until      time.Time                `json:"until"`
	Enrollment WorkerEnrollmentResponse `json:"enrollment"`
}

func EncodeOwnerRelayResponse(in OwnerRelayResponse) ([]byte, error) {
	b, err := json.Marshal(in)
	if err != nil || len(b) == 0 || len(b) > OwnerRelayMaxResponse {
		return nil, errors.New("invalid owner response")
	}
	out := make([]byte, 4+len(b))
	binary.BigEndian.PutUint32(out, uint32(len(b)))
	copy(out[4:], b)
	return out, nil
}

func DecodeOwnerRelayResponse(r io.Reader) (OwnerRelayResponse, error) {
	var zero OwnerRelayResponse
	var prefix [4]byte
	if _, err := io.ReadFull(r, prefix[:]); err != nil {
		return zero, err
	}
	n := binary.BigEndian.Uint32(prefix[:])
	if n == 0 || n > OwnerRelayMaxResponse {
		return zero, errors.New("invalid owner response length")
	}
	b := make([]byte, int(n))
	if _, err := io.ReadFull(r, b); err != nil {
		return zero, err
	}
	return decodeClosedRPC[OwnerRelayResponse](bytes.NewReader(b), OwnerRelayMaxResponse)
}
