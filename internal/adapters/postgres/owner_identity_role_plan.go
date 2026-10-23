package postgres

import (
	"crypto/sha256"
	"encoding/hex"
	"slices"
	"strconv"
	"strings"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
)

// A different fixed namespace prevents a public or configuration purpose from
// being reinterpreted as a private owner credential during provisioning.
func OwnerIdentityRoleName(installation, purpose string) (string, bool) {
	n, ok := contracts.OwnerIdentityRoleOrdinal(purpose)
	if !ok || !authorization.UUID(installation) {
		return "", false
	}
	return "as_" + strings.ReplaceAll(installation, "-", "") + "_own_0" + strconv.Itoa(n), true
}

// The context-start ingress reads a connector's activated leaf on the hub's
// native-read pool. The function is a read-only SECURITY DEFINER check.
const nativeReadConnectorLeaf = "read_connector_activated_leaf(uuid,uuid,text,bytea,jsonb)"

func ownerIdentityRoleGrants(purpose string) ([]publicRuntimeGrant, bool) {
	if purpose != "owner-runtime" {
		return nil, false
	}
	var out []publicRuntimeGrant
	for _, duty := range []string{"enrollment", "audit", "activation", "registry", "routing", "native-read"} {
		grants, _ := ownerIdentityDutyGrants(duty)
		out = append(out, grants...)
	}
	return ownerIdentityGrantSet(out), true
}

func ownerIdentityDutyGrants(purpose string) ([]publicRuntimeGrant, bool) {
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
	// ADR-184: the hub's backend pools are identity purposes too. Their grants
	// are the qualified worker-routing and native-metadata reader sets; neither
	// can dispatch, enroll, claim or bind keys.
	switch purpose {
	case "routing":
		for _, table := range []string{"goose_db_version", "context_query", "download_worker", "artifact_download", "fleet_trust", "fleet_current_trust", "download_worker_configuration", "download_worker_configuration_revision"} {
			add(table, "SELECT")
		}
		add("fleet_trust", "UPDATE", "installation_id")
		add("fleet_current_trust", "UPDATE", "installation_id")
		add("download_worker_configuration", "UPDATE", "source_uid")
		return ownerIdentityGrantSet(out), true
	case "native-read":
		for _, table := range []string{"goose_db_version", "fleet_trust", "fleet_current_trust", "permission_stream", "authority_audit", "context_catalog", "context_capture", "context_verification", "custody_attempt", "artifact_download", "download_batch", "retention_source", "retention_checkpoint", "retention_catchup", "retention_catchup_effect", "retention_decision", "download_worker", "download_worker_configuration", "download_worker_configuration_revision", "download_worker_enrollment", "download_worker_certificate", "download_key_binding", "download_response", "download_window", "download_control_allocation", "download_native_owner", "download_native_key", "download_native_backing", "processing_root", "context_processing", "processing_rule"} {
			add(table, "SELECT")
		}
		add("fleet_current_trust", "UPDATE", "installation_id")
		for _, table := range []string{"permission_stream", "artifact_download", "download_worker", "download_response", "download_window"} {
			add(table, "UPDATE", "id")
		}
		add("retention_source", "UPDATE", "root_id")
		add("download_worker_configuration", "UPDATE", "source_uid")
		add("download_native_owner", "UPDATE", "worker_id")
		out = append(out, publicRuntimeGrant{"function", nativeReadConnectorLeaf, "", "EXECUTE"})
		return ownerIdentityGrantSet(out), true
	}
	// Derived from OwnerEnrollments and its current/historical transaction
	// helpers. Historical audit cannot renew configuration or activation.
	for _, table := range []string{"goose_db_version", "hub_owner_configuration", "hub_owner_enrollment", "hub_owner_certificate"} {
		add(table, "SELECT")
	}
	add("hub_owner_configuration", "UPDATE", "source_uid") // row locks only
	if purpose != "audit" {
		add("fleet_current_trust", "SELECT")
		add("fleet_current_trust", "UPDATE", "installation_id") // recovery lock
		add("hub_owner_configuration_revision", "SELECT")
	}
	switch purpose {
	case "enrollment":
		add("hub_owner_enrollment", "INSERT", "id", "installation_id", "cluster_id", "issuer_epoch", "pod_uid", "process_epoch", "usage", "enrollment_json", "created_at", "hold_until")
		add("hub_owner_enrollment", "UPDATE", "highest_epoch", "hold_until")
		add("hub_owner_certificate", "INSERT", "id", "enrollment_id", "epoch", "ordinal", "not_after", "attempt_json")
		add("hub_owner_certificate", "UPDATE", "certificate_json", "certificate_sha256")
		// ClaimOwnerEnrollment prunes only expired registrations through the
		// existing current transaction and original certificate grace periods.
		add("hub_owner_certificate", "DELETE")
		add("hub_owner_enrollment", "DELETE")
	case "audit":
		add("hub_owner_enrollment", "UPDATE", "audit_receipt_json")
		add("hub_owner_certificate", "UPDATE", "audit_receipt_json")
	case "activation":
		add("hub_owner_certificate", "UPDATE", "activated_at")
	}
	return ownerIdentityGrantSet(out), true
}

func ownerIdentityGrantSet(out []publicRuntimeGrant) []publicRuntimeGrant {
	slices.SortFunc(out, func(a, b publicRuntimeGrant) int { return strings.Compare(a.key(), b.key()) })
	return slices.CompactFunc(out, func(a, b publicRuntimeGrant) bool { return a == b })
}

func OwnerIdentityRoleLayoutDigest() string {
	h := sha256.New()
	h.Write([]byte("asservat-owner-identity-role-layout/v1\x00login:noinherit:nosuperuser:nocreatedb:nocreaterole:noreplication:nobypassrls:connections=" + strconv.Itoa(contracts.OwnerIdentityRoleConnections) + "\x00"))
	for _, purpose := range contracts.OwnerIdentityRolePurposes() {
		n, _ := contracts.OwnerIdentityRoleOrdinal(purpose)
		h.Write([]byte(strconv.Itoa(n) + ":" + purpose + "\x00"))
		grants, _ := ownerIdentityRoleGrants(purpose)
		for _, g := range grants {
			h.Write([]byte(g.key() + "\x00"))
		}
	}
	h.Write([]byte("identity-projection\x00" + contracts.OwnerIdentityRoleManifestFile + "\x00"))
	for _, purpose := range contracts.OwnerIdentityRolePurposes() {
		h.Write([]byte("sql-" + purpose + ".json\x00"))
	}
	return hex.EncodeToString(h.Sum(nil))
}
