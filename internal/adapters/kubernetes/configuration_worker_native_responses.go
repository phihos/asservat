package kubernetes

import (
	auth "k8s.io/api/authentication/v1"
	core "k8s.io/api/core/v1"
)

// These are actual responses from one completed native source bracket. They
// have no independent clock, cannot implement a source port and are retained
// only by the existing operation-local proof. The API accepted each configured
// client's credential; SelfSubjectReview itself makes no new audience claim.
type configurationRoleNativeResponses struct {
	clients    [3]*PermissionClient
	identities [3]auth.UserInfo
	worker     core.ServiceAccount
}
