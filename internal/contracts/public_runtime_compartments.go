package contracts

import "slices"

// The existing A-HWORK workload runs at most one desired replica and retains
// at most two processes including failed/closing rollout children. Each fixed
// purpose owns one MaxConns=1 pool. Installer login verification is serialized
// across all purposes, so only one additional physical connection is active.
const PublicRuntimeRetainedWorkerProcesses = 2
const PublicRuntimeWorkerRoleConnections = PublicRuntimeRetainedWorkerProcesses + 1

// Federation logins are shared by all replicas, including overlapping rollout
// Pods. A process opens one pool connection per purpose and one LISTEN session
// for work. PostgreSQL's -1 leaves the installation-wide capacity to the server.
const PublicRuntimeFederationRoleConnections = -1

func PublicRuntimeFederationPurposes() []string {
	return []string{"connector-delivery", "connector-owner-read"}
}

// ConnectionLimit describes a fixed purpose, not permission to provision it.
// The compiled inventory and independently protected workload compartment must
// also support that purpose before any credential effect or runtime mount.
func PublicRuntimeRoleConnectionLimit(purpose string) (int, bool) {
	if slices.Contains(PublicRuntimeHubRolePurposes(), purpose) {
		limit, _ := PublicRuntimeRolePoolLimit(purpose)
		return PublicRuntimeRetainedHubProcesses*limit + 1, true
	}
	if purpose == "capacity" || purpose == "capacity-capture" || slices.Contains(PublicRuntimePermissionPurposes(), purpose) || slices.Contains(PublicRuntimeRetentionPurposes(), purpose) || slices.Contains(PublicRuntimeWorkerConfigurationPurposes(), purpose) || slices.Contains(PublicRuntimeContextDeletionPurposes(), purpose) {
		return PublicRuntimeWorkerRoleConnections, true
	}
	if slices.Contains(PublicRuntimeFederationPurposes(), purpose) {
		return PublicRuntimeFederationRoleConnections, true
	}
	if slices.Contains(PublicRuntimeKeyServicePurposes(), purpose) {
		return PublicRuntimeKeyServiceRoleConnections, true
	}
	return 0, false
}

// PublicRuntimeRolePoolLimit is the aggregate pool maximum for a credential
// in one process. The shared hub login owns an 18-slot ordinary pool and two
// one-slot resolution pools; other public credentials keep one connection.
func PublicRuntimeRolePoolLimit(purpose string) (int, bool) {
	if !slices.Contains(PublicRuntimeRolePurposes(), purpose) {
		return 0, false
	}
	if purpose == "hub-runtime" {
		return PublicRuntimeHubConnections, true
	}
	return 1, true
}
