package postgres

import (
	"crypto/sha256"
	"encoding/hex"
	"slices"
	"strconv"
	"strings"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
	"github.com/jackc/pgx/v5"
)

// Fixed source-owned plans, not operator-authored SQL or role descriptions.
// This initial inventory covers identity and retained-read subsets of the public graph.
// The complete graph must be accounted and qualified before installed startup.
// Numeric suffixes are permanent purpose identities; new purposes cannot reuse
// an old suffix to obtain that role's credentials, grants or original receipt.

func PublicRuntimeRoleName(installation, purpose string) (string, bool) {
	if !authorization.UUID(installation) {
		return "", false
	}
	index, known := contracts.PublicRuntimeRoleOrdinal(purpose)
	if !known {
		return "", false
	}
	return "as_" + strings.ReplaceAll(installation, "-", "") + "_pub_" + string([]byte{'0' + byte(index/10), '0' + byte(index%10)}), true
}

type publicRuntimeGrant struct{ kind, object, column, privilege string }

func (g publicRuntimeGrant) key() string {
	return g.kind + ":" + g.object + ":" + g.column + ":" + g.privilege
}
func (g publicRuntimeGrant) sql(role string) string {
	privilege := g.privilege
	if g.column != "" {
		privilege += "(" + pgx.Identifier{g.column}.Sanitize() + ")"
	}
	object := "TABLE " + pgx.Identifier{"public", g.object}.Sanitize()
	switch g.kind {
	case "schema":
		object = "SCHEMA " + pgx.Identifier{g.object}.Sanitize()
	case "function":
		// Function/type syntax is a closed constant below, never configuration.
		object = "FUNCTION public." + g.object
	}
	return "GRANT " + privilege + " ON " + object + " TO " + pgx.Identifier{role}.Sanitize()
}

// PublicRuntimeRoleGrantSQL renders the exact compiled grants of one fixed
// purpose for an existing role. Owned native fixtures use it to run product
// adapters under the product privilege layout; it creates no role.
func PublicRuntimeRoleGrantSQL(purpose, role string) ([]string, bool) {
	grants, ok := publicRuntimeRoleGrants(purpose)
	if !ok {
		return nil, false
	}
	out := make([]string, len(grants))
	for i, g := range grants {
		out[i] = g.sql(role)
	}
	return out, true
}

func publicRuntimeRoleGrants(purpose string) ([]publicRuntimeGrant, bool) {
	if !slices.Contains(contracts.PublicRuntimeRolePurposes(), purpose) {
		return nil, false
	}
	if out, ok := publicRuntimeCapacityGrants(purpose); ok {
		return out, true
	}
	if out, ok := publicRuntimeCaptureCleanupGrants(purpose); ok {
		return out, true
	}
	if out, ok := publicRuntimeConnectorGrants(purpose); ok {
		return out, true
	}
	if table, ok := publicRuntimeHubExtensionGrantTable[purpose]; ok {
		return slices.Clone(table), true
	}
	// The publisher retains its own narrow identity and retention credentials.
	// Consolidating hub metadata never expands this separate process's grants.
	switch purpose {
	case "publisher-identity-read":
		purpose = "identity-read"
	}
	out := []publicRuntimeGrant{{"schema", "public", "", "USAGE"}}
	add := func(table, privilege string, columns ...string) {
		if len(columns) == 0 {
			out = append(out, publicRuntimeGrant{"table", table, "", privilege})
			return
		}
		for _, column := range columns {
			out = append(out, publicRuntimeGrant{"table", table, column, privilege})
		}
	}
	read := func(tables ...string) {
		for _, table := range tables {
			add(table, "SELECT")
		}
	}
	read("goose_db_version")
	switch purpose {
	case "hub-metadata-read":
		// The hub's seven metadata facets share only their existing read and
		// row-lock privileges. No evidence-object locators, credentials or effect writes.
		read("authority_audit", "context_capture", "context_case_locator", "context_catalog", "context_control_account", "context_control_pool", "context_execution", "context_processing", "context_storage_binding", "context_verification", "custody_allocation", "custody_attempt", "custody_pool", "fleet_current_trust", "permission_assignment", "permission_basis", "permission_stream", "processing_root", "processing_rule", "retention_catchup", "retention_catchup_effect", "retention_checkpoint", "retention_decision", "retention_source")
		add("fleet_current_trust", "UPDATE", "installation_id")
		add("permission_stream", "UPDATE", "id")
		add("retention_source", "UPDATE", "root_id")
		out = append(out, publicRuntimeGrant{"function", "capacity_managed_admission_until(uuid,uuid,text,timestamptz)", "", "EXECUTE"})
	case "capacity-profile-read":
		// SQL54 independently pins this actual session_user OID and original
		// provenance. Root/qualification arguments are not a role boundary.
		out = append(out, publicRuntimeGrant{"function", "read_capacity_audit_profiles(uuid,uuid,uuid,bytea,text,timestamptz,timestamptz)", "", "EXECUTE"})
	case "capture-admit":
		// Original publication coverage only; no processing initialization,
		// restriction, lineage or counter mutation is delegated to admission.
		read("processing_root", "processing_rule")
		// The only effects are one reviewed capture, its original custody
		// reservation and the atomically prepaid private audit pair. Existing
		// storage binding and quota/source configuration remain read-only.
		read("fleet_current_trust", "permission_stream", "permission_basis", "permission_assignment", "authority_audit", "context_storage_binding", "context_preview", "context_preview_fence", "context_control_pool", "context_control_account", "context_control_charge", "context_capture", "custody_pool", "custody_allocation", "custody_attempt", "custody_copy", "custody_event", "retention_source", "retention_checkpoint", "retention_catchup", "retention_catchup_effect", "retention_decision")
		add("fleet_current_trust", "UPDATE", "installation_id")
		add("permission_stream", "UPDATE", "id")
		add("context_storage_binding", "UPDATE", "source_uid")
		for _, table := range []string{"retention_source", "context_control_pool", "context_control_account"} {
			add(table, "UPDATE", "root_id")
		}
		add("custody_pool", "UPDATE", "id")
		add("custody_allocation", "UPDATE", "id", "charged_bytes", "charged_objects")
		add("custody_attempt", "UPDATE", "id")
		for _, table := range []string{"context_capture", "custody_attempt", "custody_copy", "custody_event", "context_control_charge"} {
			add(table, "INSERT")
		}
		for _, signature := range []string{"lock_capture_audit_admission(uuid,uuid)", "reserve_capture_audit(uuid,uuid,jsonb,bytea,timestamptz)", "capacity_managed_admission_until(uuid,uuid,text,timestamptz)"} {
			out = append(out, publicRuntimeGrant{"function", signature, "", "EXECUTE"})
		}
	case "capture-journal":
		for _, signature := range []string{"read_capture_operation(uuid,uuid)", "capture_audit_journal(uuid,jsonb,text,jsonb)", "claim_capture_reconciliation(uuid,jsonb,text)"} {
			out = append(out, publicRuntimeGrant{"function", signature, "", "EXECUTE"})
		}
	case "capture-ack":
		for _, signature := range []string{"capture_audit_acknowledge(uuid,jsonb,text,jsonb,jsonb,jsonb)", "acknowledge_capture_pair(uuid,jsonb)"} {
			out = append(out, publicRuntimeGrant{"function", signature, "", "EXECUTE"})
		}
	case "capture-preview":
		// Passive private blueprints only. SQL33/36 prohibit live deletion,
		// content rewrites and restoring a closed preview. No capture admission.
		read("permission_stream", "context_preview", "context_preview_fence")
		add("permission_stream", "UPDATE", "id")
		add("context_preview", "INSERT")
		add("context_preview", "DELETE")
		add("context_preview_fence", "DELETE")
		// ADR-200: a refresh demand for an enrolled workload; no authority.
		out = append(out, publicRuntimeGrant{"function", "demand_capacity_refresh(uuid,uuid,text,text,text,text,text)", "", "EXECUTE"})
	case "capture-resolution":
		// Current same-actor request resolution may only close a passive draft
		// or fence its absent original ID. It cannot admit/cancel accepted work.
		read("fleet_current_trust", "permission_stream", "permission_basis", "permission_assignment", "authority_audit", "context_capture", "context_preview", "context_preview_fence")
		add("fleet_current_trust", "UPDATE", "installation_id")
		add("permission_stream", "UPDATE", "id")
		add("context_preview", "UPDATE", "closed_at", "closed_request_key", "closed_submission_digest")
		add("context_preview_fence", "INSERT")
		add("context_preview", "DELETE")
		add("context_preview_fence", "DELETE")
	case "identity-read":
		read("fleet_current_trust")
	case "permission-accept":
		// ADR-189: exactly the PermissionStore statements. Stream columns are
		// those of reset/renew/suspend/update; assignments only retire.
		read("permission_stream", "permission_basis", "permission_assignment", "permission_acceptance", "authority_audit")
		add("permission_stream", "INSERT")
		add("permission_stream", "UPDATE", "epoch", "sequence", "initial_audit_id", "trust_digest", "projection_digest", "lease_until", "observed_at", "fresh_until", "suspended")
		add("permission_acceptance", "INSERT")
		add("permission_basis", "INSERT")
		add("permission_basis", "UPDATE", "generation", "resource_version", "spec_digest", "scope_digest", "workload_uids", "effect", "not_after", "seen_sequence", "observation_version", "automation_json", "automation_audit_id")
		add("permission_assignment", "INSERT")
		add("permission_assignment", "UPDATE", "retired_at", "retirement_audit_id")
		add("authority_audit", "INSERT")
	case "permission-audit":
		// The publisher's pending read and acknowledgement only; the stream
		// column grant permits its existing FOR UPDATE lock.
		read("permission_stream", "authority_audit")
		add("permission_stream", "UPDATE", "id")
		add("authority_audit", "UPDATE", "acknowledged_at", "object_key", "object_version", "object_etag", "object_bytes", "object_sha256")
	case "retention-source":
		// ADR-195: the RetentionSources writer; the stream lock as for reads.
		read("permission_stream", "retention_source", "retention_checkpoint", "retention_source_epoch")
		add("permission_stream", "UPDATE", "id")
		add("retention_source", "INSERT")
		add("retention_checkpoint", "INSERT")
		add("retention_source_epoch", "INSERT")
		add("retention_source", "UPDATE", "epoch", "sequence", "lease_until", "suspended", "watch_cursor", "observed_sequence", "observed_at", "fresh_until", "list_cursor")
		add("retention_catchup", "INSERT", "checkpoint_id")
	case "retention-source-audit":
		read("retention_checkpoint")
		add("retention_checkpoint", "UPDATE", "audit_acknowledged_at", "audit_receipt")
	case "retention-catchup":
		read("permission_stream", "retention_source", "retention_checkpoint", "retention_catchup", "retention_catchup_effect", "context_capture", "custody_pool", "custody_allocation", "custody_attempt", "retention_decision")
		add("permission_stream", "UPDATE", "id")
		add("custody_pool", "UPDATE", "id")
		add("custody_allocation", "UPDATE", "id")
		add("retention_source", "UPDATE", "root_id")
		add("custody_attempt", "UPDATE", "effective_expires_at", "effective_delete_by", "retention_sequence")
		add("retention_catchup", "UPDATE", "after_attempt", "visited", "shortened", "completed_at")
		add("retention_decision", "INSERT")
		add("retention_catchup_effect", "INSERT")
	case "retention-lifecycle-audit":
		read("retention_decision")
		add("retention_decision", "UPDATE", "audit_acknowledged_at", "audit_receipt_json")
	case "key-configuration":
		// ADR-198: ADR-067 local key configuration acceptance only.
		read("fleet_current_trust", "fleet_trust", "local_key_configuration", "local_key_version")
		add("fleet_current_trust", "UPDATE", "installation_id")
		add("fleet_trust", "UPDATE", "installation_id")
		add("local_key_configuration", "INSERT")
		add("local_key_version", "INSERT")
		add("local_key_configuration", "UPDATE", "snapshot_json")
	case "key-wrap":
		// ContextKeyWrapGrantSQL, plus the staged connector profile the key
		// service's peer resolver reads (ADR-198).
		read("fleet_current_trust", "context_key_wrap")
		add("fleet_current_trust", "UPDATE", "installation_id")
		add("context_execution", "SELECT", "capture_id", "root_id", "attempt_id", "process_json", "expectation_digest", "not_after", "phase", "object_uid")
		add("context_execution", "UPDATE", "capture_id")
		add("context_capture", "SELECT", "id", "root_id", "expectation_json")
		add("connector_credential_attempt", "SELECT", "process_id", "root_id", "peer_id", "certificate_digest", "usage", "activated_at", "detached_at", "certificate_not_after")
		add("connector_identity_process", "SELECT", "id", "root_id", "pod_uid", "process_epoch", "serving", "retired_at")
		add("connector_identity_profile", "SELECT", "root_id", "peer_id", "cluster_id", "installation_id", "configuration", "suspended", "blocked")
		add("context_key_wrap", "INSERT", "attempt_id", "root_id", "certificate_sha256", "used_roles")
		add("context_key_wrap", "UPDATE", "used_roles")
	case "key-verify":
		// ContextKeyUnwrapGrantSQL (ADR-181).
		read("fleet_current_trust", "context_key_unwrap")
		add("fleet_current_trust", "UPDATE", "installation_id")
		add("context_execution", "SELECT", "capture_id", "root_id", "attempt_id", "expectation_digest", "phase")
		add("context_execution", "UPDATE", "capture_id")
		add("context_capture", "SELECT", "id", "root_id", "expectation_json")
		add("context_catalog", "SELECT", "capture_id")
		add("context_key_unwrap", "INSERT", "attempt_id", "root_id", "last_certificate_sha256", "unwraps")
		add("context_key_unwrap", "UPDATE", "unwraps", "last_certificate_sha256")
	case "key-acquisition":
		// ADR-204: NativeKeyAuthority's two resolvers, DownloadKeys for the
		// prepaid metadata batch and NativeKeys for a response window. These
		// are their recovery, permission, session, processing, retention,
		// catalog and worker configuration reads and locks, and the spend of
		// one slot of either key record. No binding, session, audit or worker
		// write; the lock columns are the ones the hub's binders lock with.
		read("fleet_current_trust", "permission_stream", "authority_audit", "artifact_download", "download_batch",
			"processing_root", "context_processing", "processing_rule",
			"retention_source", "retention_checkpoint", "retention_catchup", "retention_catchup_effect", "retention_decision",
			"context_capture", "context_verification", "download_key_binding", "download_native_key", "download_native_owner",
			"download_response", "download_window", "download_worker", "download_worker_enrollment", "download_worker_certificate",
			"download_worker_configuration", "download_worker_configuration_revision")
		// ReadPublishedContext reads only these catalog and attempt columns.
		add("context_catalog", "SELECT", "artifact_id", "root_id", "capture_id", "published_at")
		add("custody_attempt", "SELECT", "id", "artifact_id", "state", "copies_digest", "effective_expires_at", "effective_delete_by")
		add("fleet_current_trust", "UPDATE", "installation_id")
		for _, table := range []string{"permission_stream", "artifact_download", "download_response", "download_window", "download_worker"} {
			add(table, "UPDATE", "id")
		}
		add("retention_source", "UPDATE", "root_id")
		add("download_worker_configuration", "UPDATE", "source_uid")
		add("download_native_owner", "UPDATE", "worker_id")
		add("download_key_binding", "UPDATE", "used_roles")
		add("download_native_key", "UPDATE", "used_roles")
	case "worker-config-observe":
		// ADR-204 decision 7: the WorkerConfigurations observer statements
		// (ADR-070): stage a revision, refresh or fence the head. It cannot
		// acknowledge audit; the revision insert names no receipt column.
		read("fleet_current_trust", "download_worker_configuration", "download_worker_configuration_revision")
		add("fleet_current_trust", "UPDATE", "installation_id")
		add("download_worker_configuration", "INSERT", "installation_id", "cluster_id", "source_uid", "generation", "observed_at", "fresh_until")
		add("download_worker_configuration", "UPDATE", "generation", "observed_at", "fresh_until")
		add("download_worker_configuration_revision", "INSERT", "installation_id", "cluster_id", "source_uid", "generation", "snapshot_json")
	case "worker-config-audit":
		// The acknowledgement only: one receipt on an unacknowledged revision.
		// The head's identity column admits its FOR UPDATE lock; the head
		// trigger refuses any identity change.
		read("download_worker_configuration", "download_worker_configuration_revision")
		add("download_worker_configuration", "UPDATE", "source_uid")
		add("download_worker_configuration_revision", "UPDATE", "audit_receipt_json")
	case "context-cleanup", "context-cleanup-audit", "context-cleanup-finalize":
		// ADR-205 decision 2: exactly the ADR-111 ContextDeletions facets'
		// grants. Every facet locks recovery and the permission stream and reads
		// the joined writer completion and its execution and checkpoint.
		read("permission_stream", "fleet_current_trust", "context_execution", "context_writer_completion", "context_deletion_checkpoint")
		add("fleet_trust", "SELECT", "installation_id", "activated_postmaster_at", "activated_database_oid")
		add("fleet_current_trust", "UPDATE", "installation_id")
		add("permission_stream", "UPDATE", "id")
		if purpose != "context-cleanup-audit" {
			// The attempt, its copies and the charged allocation, locked in
			// pool, allocation, attempt order.
			read("custody_pool", "custody_allocation", "custody_attempt", "custody_copy")
			for _, table := range []string{"custody_pool", "custody_allocation", "custody_attempt"} {
				add(table, "UPDATE", "id")
			}
		}
		switch purpose {
		case "context-cleanup":
			// Claim the deletion lease and record the fenced purge only.
			add("custody_attempt", "UPDATE", "state", "deletion_fence", "lease_until")
			add("context_deletion_checkpoint", "INSERT")
		case "context-cleanup-audit":
			// One receipt on an unacknowledged checkpoint; the identity column
			// admits its FOR UPDATE lock, and the guard trigger refuses changes.
			add("context_deletion_checkpoint", "UPDATE", "attempt_id", "audit_receipt_json", "audit_acknowledged_at")
		case "context-cleanup-finalize":
			// The one-use finalization claim, charge release, receipt clearing,
			// tombstone and outbox event; triggers require the acknowledged audit.
			add("context_deletion_checkpoint", "UPDATE", "attempt_id", "finalization_xid")
			add("custody_allocation", "UPDATE", "charged_bytes", "charged_objects")
			add("custody_attempt", "UPDATE", "state", "deleted_at", "lease_until")
			add("custody_copy", "UPDATE", "ciphertext_bytes", "ciphertext_sha256", "etag", "version_id")
			add("custody_event", "INSERT")
		}
	case "publisher-retention-read":
		read("permission_stream", "retention_source", "retention_checkpoint", "retention_catchup", "retention_catchup_effect", "retention_decision")
		add("permission_stream", "UPDATE", "id")
		add("retention_source", "UPDATE", "root_id")
	case "capture-intent-read":
		read("capture_operation_intents")
		out = append(out, publicRuntimeGrant{"function", "capture_audit_role_ok(uuid,text)", "", "EXECUTE"})
	case "download-source":
		// Exact ciphertext receipts and minimized routing only. In particular,
		// there is no allocation/session/audit/key/native-operation mutation.
		read("fleet_current_trust", "permission_stream", "authority_audit", "context_catalog", "context_capture", "context_verification", "custody_attempt", "custody_copy", "context_case_locator", "retention_source", "retention_checkpoint", "retention_catchup", "retention_catchup_effect", "retention_decision", "processing_root", "context_processing", "processing_rule")
		add("fleet_current_trust", "UPDATE", "installation_id")
		add("permission_stream", "UPDATE", "id")
		add("retention_source", "UPDATE", "root_id")
	case "download-plan":
		read("download_allocation", "download_control_allocation", "download_native_backing", "download_stop_backing", "download_stop_pool", "fleet_current_trust")
		add("fleet_current_trust", "UPDATE", "installation_id")
	case "worker-config-read":
		read("download_worker_configuration", "download_worker_configuration_revision", "fleet_current_trust")
		add("fleet_current_trust", "UPDATE", "installation_id")
		add("download_worker_configuration", "UPDATE", "source_uid")
	case "audit-normal-journal", "audit-resolution-journal", "audit-normal-ack", "audit-resolution-ack":
		// The HTTP lanes use separate physical pools and login limits. These
		// existing public audit tables do not implement per-login human-lane
		// filtering; private peer/capture/processing authority remains in its
		// separately pinned SQL guards. No source/backing or cleanup grant is
		// inherited merely because OperationLifecycles also exposes those methods.
		read("fleet_current_trust", "operation_audit")
		add("fleet_current_trust", "UPDATE", "installation_id")
		add("operation_audit", "UPDATE", "id")
		if strings.HasSuffix(purpose, "-journal") {
			read("operation_audit_pool", "operation_audit_account", "operation_audit_lifecycle")
			add("operation_audit_pool", "UPDATE", "root_id")
			add("operation_audit", "INSERT")
			add("operation_audit", "UPDATE", "intent_started", "outcome", "outcome_started")
			// Positive writer completion uses recovery -> pool -> account ->
			// audit -> lifecycle locks and exact database-incarnation reads.
			add("fleet_trust", "SELECT", "installation_id", "activated_postmaster_at", "activated_database_oid")
			add("operation_audit_account", "UPDATE", "root_id")
			add("operation_audit_lifecycle", "UPDATE", "operation_id", "intent_completion", "outcome_completion")
		} else {
			add("operation_audit", "UPDATE", "intent_receipt", "outcome_receipt")
		}
	case "browser-settings":
		read("browser_session_root", "browser_session_epoch")
		add("browser_session_root", "INSERT")
		add("browser_session_root", "UPDATE")
		add("browser_session_epoch", "INSERT")
		add("browser_login", "DELETE")
		add("browser_session", "DELETE")
		add("browser_login", "SELECT", "root_id")
		add("browser_session", "SELECT", "root_id", "id", "epoch", "created_at", "expires_at", "refresh_at")
		add("browser_session", "UPDATE", "expires_at", "refresh_at")
	case "browser-session", "browser-cleanup":
		read("browser_session_root", "browser_login", "browser_session", "browser_logout", "browser_refresh_owner", "browser_refresh_consumer")
		add("browser_session_root", "UPDATE", "id")
		add("browser_refresh_owner", "UPDATE", "session_id")
		for _, table := range []string{"browser_login", "browser_session", "browser_logout"} {
			add(table, "DELETE")
			if purpose == "browser-session" {
				add(table, "INSERT")
				add(table, "UPDATE")
			} else {
				add(table, "UPDATE", "id")
			}
		}
		if purpose == "browser-cleanup" {
			add("browser_refresh_owner", "DELETE")
		} else {
			out = append(out, publicRuntimeGrant{"function", "browser_owned_refresh_busy(uuid,bytea)", "", "EXECUTE"})
		}
	case "refresh-admit", "refresh-owner", "refresh-read":
		read("browser_session_root", "browser_session", "browser_refresh_owner", "browser_refresh_consumer", "fleet_current_trust", "artifact_download", "download_response", "context_catalog", "context_capture", "context_verification", "custody_attempt")
		add("fleet_current_trust", "UPDATE", "installation_id")
		add("browser_session_root", "UPDATE", "id")
		if purpose == "refresh-read" {
			break
		}
		read("permission_stream", "authority_audit", "retention_source", "retention_checkpoint", "retention_source_epoch", "retention_catchup", "retention_catchup_effect", "retention_decision", "processing_root", "context_processing", "processing_rule")
		add("browser_session", "UPDATE", "id")
		add("artifact_download", "UPDATE", "id")
		add("permission_stream", "UPDATE", "id")
		add("retention_source", "UPDATE", "root_id")
		add("browser_refresh_owner", "UPDATE", "session_id")
		add("browser_refresh_consumer", "UPDATE", "download_id", "owner_id", "owner_generation")
		fields := []string{"lease_until", "joined_at", "claim", "claim_version", "claim_until", "claim_joined_at", "claim_download_id", "claim_response_id", "claim_response_owner", "claim_response_generation"}
		if purpose == "refresh-admit" {
			add("browser_refresh_owner", "INSERT")
			add("browser_refresh_consumer", "INSERT")
			fields = append(fields, "owner_id", "generation", "installation_id", "cluster_id", "pod_uid", "process_epoch", "started_at", "session_expires_at")
		} else {
			read("browser_logout")
			add("browser_refresh_owner", "DELETE")
			add("browser_session", "UPDATE", "refresh_claim", "claim_until")
		}
		add("browser_refresh_owner", "UPDATE", fields...)
	}
	slices.SortFunc(out, func(a, b publicRuntimeGrant) int { return strings.Compare(a.key(), b.key()) })
	return slices.CompactFunc(out, func(a, b publicRuntimeGrant) bool { return a == b }), true
}

// The protected producer pins the entire compiled grant layout, including
// fixed role attributes and procedure signatures, before any role is created.
func PublicRuntimeRoleLayoutDigest() string {
	h := sha256.New()
	h.Write([]byte("asservat-public-runtime-role-layout/v1\x00login:noinherit:nosuperuser:nocreatedb:nocreaterole:noreplication:nobypassrls:connections=" + strconv.Itoa(contracts.PublicRuntimeRoleConnections) + "\x00"))
	for _, purpose := range contracts.PublicRuntimeRolePurposes() {
		ordinal, _ := contracts.PublicRuntimeRoleOrdinal(purpose)
		connections, _ := contracts.PublicRuntimeRoleConnectionLimit(purpose)
		h.Write([]byte(strconv.Itoa(ordinal) + ":" + purpose + ":connections=" + strconv.Itoa(connections) + "\x00"))
		grants, _ := publicRuntimeRoleGrants(purpose)
		for _, g := range grants {
			h.Write([]byte(g.key() + "\x00"))
		}
	}
	h.Write([]byte("hub-projection\x00"))
	h.Write([]byte(contracts.PublicRuntimeCredentialManifestFile + "\x00"))
	h.Write([]byte(contracts.PublicAuditKeysFile + "\x00"))
	for _, purpose := range contracts.PublicRuntimeHubRolePurposes() {
		h.Write([]byte("sql-public-" + purpose + ".json\x00"))
	}
	return hex.EncodeToString(h.Sum(nil))
}
