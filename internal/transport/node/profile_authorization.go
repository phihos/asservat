package node

import (
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/collector"
	"asservat.local/asservat/internal/domain/execution"
)

// pollPrefix reserves the widest private authorization encoding before reading
// any material. Public queued work remains untouched and retained for receipts.
func pollPrefix(work []collector.Work) contracts.NodePollResponse {
	out := contracts.NodePollResponse{Format: contracts.NodePollFormat, Work: []contracts.NodeWork{}}
	for _, item := range work {
		wire := WireWork(item)
		if item.Profile != nil && item.Profile.AuthorizationRequired {
			wire.ProfileCapture.Authorization = make([]byte, execution.GoProfileAuthorizationLimit)
		}
		out.Work = append(out.Work, wire)
	}
	return out
}
