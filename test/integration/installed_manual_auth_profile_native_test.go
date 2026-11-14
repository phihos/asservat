package integration

import (
	"os"
)

// Synthetic fixture material only. It is supplied through the real private
// installer projection and app-only Secret, never a public capture parameter.
const manualProfileAuthorizationSentinel = "Bearer synthetic-installed-profile-authorization-9b670871"

func installedProfileAuthorization() bool {
	switch os.Getenv("ASSERVAT_PROFILE_AUTH") {
	case "", "none":
		return false
	case "required":
		if !installedTLSProfileTransport() {
			panic("profile authorization fixture requires TLS CPU")
		}
		return true
	default:
		panic("unknown installed profile authorization fixture")
	}
}
