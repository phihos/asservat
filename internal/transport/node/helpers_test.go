package node

import (
	"encoding/json"
	"io"

	"asservat.local/asservat/internal/contracts"
)

// pollResponse is a test batch of pushed work frames.
type pollResponse struct {
	Work []contracts.NodeWork `json:"work"`
}

func decodePollResponse(r io.Reader) (pollResponse, error) {
	var out pollResponse
	err := json.NewDecoder(r).Decode(&out)
	return out, err
}

func decodeStatus(r io.Reader) (contracts.NodeStatus, error) {
	var out contracts.NodeStatus
	err := json.NewDecoder(r).Decode(&out)
	return out, err
}
