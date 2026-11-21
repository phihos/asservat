package presentation

import (
	"asservat.local/asservat/internal/contracts"
	"context"
)

type authenticatedBrowserSettingsKey struct{}
type authenticatedBrowserSettingsMarker struct{}

// AuthenticatedBrowserSettingsView is set by the browser handler only after
// real session/CSRF checks. It changes neither identity nor authority/deadlines.
// There is no wire field or client-chosen size, and no other operation gains it.
func AuthenticatedBrowserSettingsView(ctx context.Context) context.Context {
	return context.WithValue(ctx, authenticatedBrowserSettingsKey{}, authenticatedBrowserSettingsMarker{})
}
func browserSettingsView(ctx context.Context) bool {
	if ctx == nil {
		return false
	}
	_, ok := ctx.Value(authenticatedBrowserSettingsKey{}).(authenticatedBrowserSettingsMarker)
	return ok
}
func (r OperationReply) preparedOutputLimit(name string) int {
	if name == "get_grant" {
		return contracts.InvestigationGrantReviewOutputLimit
	}
	if name == "get_capture" && r.browserSettings {
		return contracts.InvestigationBrowserSettingsOutputLimit
	}
	if name == "get_capture" || name == "preview_capture" {
		return contracts.InvestigationResultBound
	}
	return contracts.InvestigationOutputLimit
}
