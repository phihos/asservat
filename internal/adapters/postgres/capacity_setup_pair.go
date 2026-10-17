package postgres

import (
	"context"
	"encoding/json"
	"time"

	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"github.com/jackc/pgx/v5"
)

func (s *PublicRuntimeSQLRoles) capacitySetupPair(ctx context.Context, tx pgx.Tx, in capacitySetupInput, receipt contracts.CapacityRootSetupReceipt, roles []capacitySetupRole, fresh bool) error {
	if len(roles) != len(contracts.CapacitySetupRolePurposes()) {
		return cfg.ErrInvalid
	}
	receiptBytes, err := json.Marshal(receipt)
	if err != nil {
		return cfg.ErrInvalid
	}
	roleBytes, err := json.Marshal(roles)
	if err != nil || len(roleBytes) > 16<<10 {
		return cfg.ErrInvalid
	}
	roleIDs := map[string]uint32{}
	for _, r := range roles {
		roleIDs[r.Purpose] = r.Receipt.RoleOID
	}
	var sourceExists, captureExists bool
	err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM public.capacity_source WHERE root_id=$1),EXISTS(SELECT 1 FROM public.capture_audit_root WHERE root_id=$1)`, in.value.PermissionRootID).Scan(&sourceExists, &captureExists)
	if err != nil {
		return cfg.ErrUnavailable
	}
	if sourceExists || captureExists {
		if fresh || !sourceExists || !captureExists {
			return cfg.ErrChanged
		}
	} else {
		if !fresh || ctx.Err() != nil || !time.Now().Before(receipt.Until) {
			return cfg.ErrUnavailable
		}
		q := in.qualification
		readerProvenance, err := json.Marshal(roles[2].Provenance)
		if err != nil || roles[2].Purpose != "capacity-profile-read" {
			return cfg.ErrInvalid
		}
		if _, err = tx.Exec(ctx, `INSERT INTO public.capture_audit_root(root_id,installation_id,source_role,admission_role,journal_role,acknowledge_role,cleanup_role,verifier_role,finalizer_role,reader_role,revision,paused,valid_until)
 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,1,false,$11)`, in.value.PermissionRootID, in.value.InstallationID, roleIDs["capacity-capture"], roleIDs["capture-admit"], roleIDs["capture-journal"], roleIDs["capture-ack"], roleIDs["capture-cleanup"], roleIDs["capture-verifier"], roleIDs["capture-finalizer"], roleIDs["capture-intent-read"], q.RootBacking.Capture.Policy.ValidUntil); err != nil {
			return cfg.ErrUnavailable
		}
		if _, err = tx.Exec(ctx, `INSERT INTO public.capacity_source(root_id,installation_id,control_cluster_id,control_namespace_uid,source_guard_digest,writer_role,capture_role,audit_reader_role,audit_reader_provenance,account_version,process_limit,qualification,qualification_digest,setup_receipt,setup_input,setup_roles)
 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,2,$11,$12,$13,$14,$15)`, in.value.PermissionRootID, in.value.InstallationID, in.value.ControlClusterID, in.value.ControlNamespaceUID, in.guard[:], roleIDs["capacity"], roleIDs["capacity-capture"], roleIDs["capacity-profile-read"], readerProvenance, in.value.AccountVersion, in.value.Qualification, q.Digest[:], receiptBytes, in.bytes, roleBytes); err != nil {
			return cfg.ErrUnavailable
		}
	}
	// Exact committed replay is independent of current mutable source/root
	// progress. It verifies every immutable setup pin and the original pair.
	// No UPDATE repairs a missing/foreign half, even after a lost SQL response.
	var exact bool
	err = tx.QueryRow(ctx, `SELECT s.setup_receipt=$2::jsonb AND s.setup_input=$3::jsonb AND s.setup_roles=$4::jsonb AND public.capacity_setup_original_valid(s)
 FROM public.capacity_source s WHERE s.root_id=$1`, in.value.PermissionRootID, receiptBytes, in.bytes, roleBytes).Scan(&exact)
	if err != nil || !exact || ctx.Err() != nil || fresh && !time.Now().Before(receipt.Until) {
		return cfg.ErrUnavailable
	}
	return nil
}
