-- name: LeaseOverdueOperationPurge :execrows
UPDATE operation_audit_lifecycle SET overdue_selected_at=COALESCE(overdue_selected_at,$3),lease=$4,lease_fence=$5 WHERE root_id=$1 AND operation_id=$2;
-- name: SaveOverdueOperationPurge :execrows
UPDATE operation_audit_lifecycle SET overdue_purge=$3 WHERE root_id=$1 AND operation_id=$2 AND overdue_selected_at IS NOT NULL AND overdue_purge IS NULL;
