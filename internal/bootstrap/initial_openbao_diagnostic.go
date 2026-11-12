package bootstrap

import "errors"

// Only compiler-selected labels may enter CLI copy. Provider/Kubernetes bodies,
// credential values and arbitrary FixedStep implementations are never rendered.
func initialOpenBaoDiagnostic(err error) string {
	var failure initialOpenBaoCheck
	if !errors.As(err, &failure) {
		return ""
	}
	switch stage := string(failure); stage {
	case "source", "api-source", "tls", "native", "namespace", "account", "state", "jwt", "login", "marker", "identity", "ready", "context",
		"mint-claim", "mint-client", "mint-expiry", "mint-original-claim", "mint-profile", "mint-record", "mint-response", "mint-tls", "mint-verification",
		"mint-verification/input", "mint-verification/wrap-role", "mint-verification/unwrap-role", "mint-verification/policies", "mint-verification/issuer-profile", "mint-verification/final-deadline":
		return stage
	}
	return ""
}
