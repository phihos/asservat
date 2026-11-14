package kubernetes

import (
	"regexp"
)

var ownerBootstrapProviderName = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,128}$`)

func ownerBootstrapMount(s string) bool { return ownerBootstrapProviderName.MatchString(s) }

func ownerBootstrapLimits(connections, concurrency int) bool {
	return connections >= 1 && connections <= 64 && concurrency >= 1 && concurrency <= 16 && concurrency <= connections
}
