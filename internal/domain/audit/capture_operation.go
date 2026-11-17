package audit

// Historical capture-lane operation audit layouts. Capture admission now
// writes an audit_event row (ADR-330 D6); these remain only for the shared
// operation audit cleanup of rows written before that change.
const CaptureOperationName = "persist_capture_intent"
const CaptureOperationHistoryLayout = "capture-intent-history/v1"
const ShareCaptureOperationHistoryLayout = "capture-intent-history/v2"

func CaptureOperationPolicy(p OperationLifecyclePolicy) bool {
	return p.CertificateVerificationBacked() && p.Lane == "capture" && p.History != nil && captureHistoryLayout(p.History.Layout)
}
