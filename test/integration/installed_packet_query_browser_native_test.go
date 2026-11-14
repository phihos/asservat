package integration

import (
	"context"
	"encoding/json"
	"testing"

	query "asservat.local/asservat/internal/domain/analysis"
)

type installedPacketQueryBrowserInput struct {
	Source  installedPacketQuerySource
	Request map[string]any
}

// The existing browser RPC owns only the real page. SQL assertions remain
// independently owned by the installed orchestration and run after rendered rows.
func queryInstalledPacketQueryBrowser(t *testing.T, ctx context.Context, browser *installedBrowser, address string, source installedPacketQuerySource, request map[string]any, check installedProjectionCheck) query.PacketQueryResult {
	t.Helper()
	if check == nil {
		t.Fatal("packet query browser requires independent SQL check")
	}
	verify := check(source.ArtifactID)
	operation, handle := "", ""
	checked := false
	defer func() {
		if !checked && operation != "" {
			verify(handle, operation)
		}
	}()
	call, _, finish := installedProjectionBrowserSource(t, ctx, browser, address, installedProfileComparisonSource{CaseID: source.CaseID, ArtifactID: source.ArtifactID, Version: source.Version, Expires: source.Expires}, "packet-query", func(reply installedComparisonReply) {
		if operation == "" {
			operation = reply.RequestID
		}
		if handle == "" && reply.Status == "pending" {
			var pending struct {
				Handle string `json:"query_handle"`
			}
			if json.Unmarshal(reply.Data, &pending) == nil {
				handle = pending.Handle
			}
		}
	}, packetQueryCaptureMode(source), &installedPacketQueryBrowserInput{source, request})
	defer finish()
	return queryInstalledPacketQueryWithCall(t, ctx, source, request, call, func(queryID, operationID string) func() {
		finish()
		checked = true
		return verify(queryID, operationID)
	})
}
