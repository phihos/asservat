package bootstrap

import "errors"

// reportFailure never forwards arbitrary dependency error text or FixedStep
// values. Its finite vocabulary keeps eventLog's count map bounded as well as
// keeping private target, token, endpoint and provider details out of the log.
func (s RegionalContextStartConnections) reportFailure(stage string, cause error) {
	if s.Report == nil {
		return
	}
	switch stage {
	case "candidates", "candidates-empty", "open", "exchange":
	default:
		return
	}
	var fixed interface{ FixedStep() string }
	if errors.As(cause, &fixed) {
		switch step := fixed.FixedStep(); step {
		case "local", "route", "dial", "tls", "peer", "request", "response", "current":
			stage += "/" + step
		}
	}
	if cause != nil {
		stage += " (" + regionalCause(cause) + ")"
	}
	s.Report(stage)
}
