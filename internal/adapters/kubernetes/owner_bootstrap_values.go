package kubernetes

import (
	"regexp"
)

var ownerBootstrapProviderName = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,128}$`)
