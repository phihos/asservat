package integration

import (
	"context"
	"encoding/json"
	"testing"

	query "asservat.local/asservat/internal/domain/analysis"
)

// The real React view replaces only the browser query call. The original Go
// owner schedules paid polls and checks the same canonical source/SQL proof.
func queryInstalledPacketSummaryBrowser(t *testing.T, ctx context.Context, browser *installedBrowser, address string, source installedPacketSummarySource, check installedProjectionCheck) query.PacketSummary {
	t.Helper()
	if check == nil {
		t.Fatal("browser packet summary requires independent SQL proof")
	}
	verify := check(source.ArtifactID) // Snapshot before any paid query.
	operation, handle := "", ""
	checked := false
	defer func() {
		if !checked && operation != "" {
			verify(handle, operation)
		}
	}()
	call, _, finish := installedProfileBrowserSourceMode(t, ctx, browser, address, installedProfileComparisonSource{CaseID: source.CaseID, ArtifactID: source.ArtifactID, Version: source.Version, Expires: source.Expires}, "packet", func(reply installedComparisonReply) {
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
	}, source.CaptureMode)
	defer finish() // Join Chrome before known-query failure inspection.
	return queryInstalledPacketSummaryWithCall(t, ctx, source, call, func(queryID, operationID string) func() {
		// Assert rendered values and close while the original view is live,
		// before the independent worker terminal wait can outlast that view.
		finish()
		checked = true
		return verify(queryID, operationID)
	})
}
