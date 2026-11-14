package integration

// installedClusterCount is the hub plus its workload clusters: two for the
// focused runs that use one workload cluster, three otherwise.
func installedClusterCount() int {
	if f := installedJourneyFocus(); f == "restart" || f == "journey" || f == "browser" || f == "upgrade" || f == "policy" || f == "alert" || f == "logresource" || f == "chain" || f == "share" || f == "approved-recording" || f == "manual-logs" || f == "manual-syscall" || f == "manual-arguments" || f == "manual-mixed" || f == "manual-raw" || f == "manual-http" || f == "manual-peers" || installedProfileFocus() || f == "native-paced" || f == "policy-recording" || f == "policy-arguments" || f == "policy-profile" || installedOngoingFocus() || f == "journey-store-failure" || f == "journey-start-failure" || f == "retention-shortening" || f == "early-erasure" || f == "processing-workload" || f == "privacy-inventory" || f == "share-retirement" {
		return 2
	}
	return 3
}
