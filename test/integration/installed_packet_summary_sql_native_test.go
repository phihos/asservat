package integration

// Used by the installed readback and its real-role two-client regression.
func installedPacketSummaryPrincipalAccounting(allocated, exactAccountUnits int) bool {
	return exactAccountUnits > 0 && allocated == exactAccountUnits
}
