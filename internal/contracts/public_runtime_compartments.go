package contracts

import "slices"

// The existing A-HWORK workload runs at most one desired replica and retains
// at most two processes including failed/closing rollout children. Each fixed
// purpose owns one MaxConns=1 pool. Installer login verification is serialized
// across all purposes, so only one additional physical connection is active.
const PublicRuntimeRetainedWorkerProcesses = 2
const PublicRuntimeWorkerRoleConnections = PublicRuntimeRetainedWorkerProcesses + 1

func PublicRuntimeCaptureCleanupPurposes() []string {
	return []string{"capture-cleanup", "capture-verifier", "capture-finalizer"}
}

// ADR-170: connector-facing hub duties run in a separate federation process
// kind, so they never count against the 32-connection hub replica budget.
const PublicRuntimeRetainedFederationProcesses = 2
const PublicRuntimeFederationRoleConnections = PublicRuntimeRetainedFederationProcesses + 1

func PublicRuntimeFederationPurposes() []string {
	return []string{"connector-source", "connector-journal", "connector-ack", "connector-read", "cluster-credential", "connector-owner-read"}
}

// ADR-181: the asynchronous publication verifier is its own process kind
// with its own recovery and retention read logins.
const PublicRuntimeRetainedPublisherProcesses = 2
const PublicRuntimePublisherRoleConnections = PublicRuntimeRetainedPublisherProcesses + 1

func PublicRuntimePublisherPurposes() []string {
	return []string{"publication-gate", "context-verify", "context-verification-audit", "context-publish", "publisher-identity-read", "publisher-retention-read"}
}

// SQL49 pins all six connector duty logins at first source staging, so the
// three maintenance duties exist from installation. They run in the worker
// compartment and are projected nowhere until that consumer is composed.
func PublicRuntimeConnectorMaintenancePurposes() []string {
	return []string{"connector-cleanup", "connector-verifier", "connector-finalizer"}
}

// ConnectionLimit describes a fixed purpose, not permission to provision it.
// The compiled inventory and independently protected workload compartment must
// also support that purpose before any credential effect or runtime mount.
func PublicRuntimeRoleConnectionLimit(purpose string) (int, bool) {
	if slices.Contains(PublicRuntimeHubRolePurposes(), purpose) {
		limit, _ := PublicRuntimeRolePoolLimit(purpose)
		return PublicRuntimeRetainedHubProcesses*limit + 1, true
	}
	if purpose == "browser-settings" || slices.Contains(PublicRuntimeCaptureCleanupPurposes(), purpose) || slices.Contains(PublicRuntimeConnectorMaintenancePurposes(), purpose) || purpose == "capacity" || purpose == "capacity-capture" || slices.Contains(PublicRuntimePermissionPurposes(), purpose) || slices.Contains(PublicRuntimeRetentionPurposes(), purpose) || slices.Contains(PublicRuntimeWorkerConfigurationPurposes(), purpose) || slices.Contains(PublicRuntimeContextDeletionPurposes(), purpose) {
		return PublicRuntimeWorkerRoleConnections, true
	}
	if slices.Contains(PublicRuntimeFederationPurposes(), purpose) {
		return PublicRuntimeFederationRoleConnections, true
	}
	if slices.Contains(PublicRuntimePublisherPurposes(), purpose) {
		return PublicRuntimePublisherRoleConnections, true
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
