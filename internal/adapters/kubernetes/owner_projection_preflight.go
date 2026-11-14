package kubernetes

import (
	"context"
	"sync/atomic"
	"time"

	core "k8s.io/api/core/v1"
)

// This private prefix is not an admitted owner operation or a current native
// proof. The original root owns it; one bridge callback may finish its actual
// reads. A copy, foreign context or second completion cannot select any material.
type ownerProjectionPreflight struct {
	self     *ownerProjectionPreflight
	root     *OwnerIdentityRoleRoot
	ctx      context.Context
	used     *atomic.Bool
	retained initialRuntimeRetainedResources
	source   *ownerProjectionSourcePrefix
	account  core.ServiceAccount
	service  core.Service
	until    time.Time
	bracket  *ownerBracket // set when the preflight belongs to an installation bracket
}
