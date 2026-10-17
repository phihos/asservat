-- name: LockWorkerOwner :one
SELECT * FROM download_worker_owner WHERE worker_id=$1 FOR UPDATE;

-- name: InsertWorkerOwner :exec
INSERT INTO download_worker_owner(worker_id,request_id,pod_uid,process_epoch,fence,started_at,expires_at)
VALUES($1,$2,$3,$4,1,$5,$6);

-- name: ReplaceWorkerOwner :execrows
UPDATE download_worker_owner SET request_id=$2,pod_uid=$3,process_epoch=$4,fence=fence+1,started_at=$5,expires_at=$6,released_at=NULL
WHERE worker_id=$1 AND fence=$7 AND (released_at IS NOT NULL OR expires_at<=clock_timestamp());

-- name: ReadWorkerOwner :one
SELECT sqlc.embed(o), sqlc.embed(w) FROM download_worker_owner o JOIN download_worker w ON w.id=o.worker_id
JOIN artifact_download d ON d.id=w.session_id
WHERE w.id=$1 AND w.session_id=$2 AND w.root_id=$3 AND w.installation_id=$4
AND o.released_at IS NULL AND o.expires_at>clock_timestamp()
AND w.audit_receipt_json IS NOT NULL AND w.claimed_at IS NOT NULL AND w.binding_json IS NOT NULL
AND w.termination_json IS NULL AND w.retired_proof_json IS NULL
AND w.run_until>clock_timestamp() AND d.deadline>clock_timestamp()
AND d.state IN ('Preparing','Ready','Streaming','Interrupted');

-- name: ReleaseWorkerOwner :execrows
UPDATE download_worker_owner o SET released_at=clock_timestamp()
FROM download_worker w WHERE w.id=o.worker_id AND w.root_id=$1 AND w.installation_id=$2 AND w.session_id=$3
AND o.worker_id=$4 AND o.request_id=$5 AND o.pod_uid=$6 AND o.process_epoch=$7 AND o.fence=$8
AND o.started_at=$9 AND o.expires_at=$10 AND o.released_at IS NULL;
