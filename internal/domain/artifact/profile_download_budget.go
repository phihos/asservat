package artifact

// Profile download backing covers one complete maximum-size native trace and
// one separately admitted response. These bounds never refill a spent session.
const (
	ProfileDownloadResponses          int64 = 2
	ProfileDownloadWindowsPerResponse       = (MaxGoTraceBytes-1)/DownloadWindowBytes + 1
	ProfileDownloadContentWindows           = ProfileDownloadResponses * ProfileDownloadWindowsPerResponse
	// An unaligned 64 MiB selection touches at most nine encrypted frames and
	// two index pages. This reserves work, not memory or measured overhead.
	ProfileDownloadWindowReadWork         = 9*(FrameBytes+CipherOverhead) + 2*(PageBytes+CipherOverhead)
	ProfileDownloadMetadataReadWork int64 = 4 << 20
	ProfileDownloadReadBytes              = ProfileDownloadContentWindows*ProfileDownloadWindowReadWork + ProfileDownloadMetadataReadWork
	ProfileDownloadOutputBytes            = ProfileDownloadResponses * MaxGoTraceBytes
	// The first chunk's lease is bound by claim. Each subsequent fixed-size
	// chunk can require one owner renewal; failed reads terminate, without
	// replay. This includes all renewals even under adversarial backpressure.
	ProfileDownloadRenewalsPerWindow = (DownloadWindowBytes - 1) / DeliveryBytes
	// Claim/close pairs for preparation, one observation per response and
	// each content window, all possible renewals, then owner retirement.
	ProfileDownloadNativeTransitions = 2 + 2*ProfileDownloadResponses + (2+ProfileDownloadRenewalsPerWindow)*ProfileDownloadContentWindows + 1
)
