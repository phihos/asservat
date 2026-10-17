-- name: InsertBlockedBrowserRoot :exec
INSERT INTO browser_session_root(id,epoch,enabled,max_logins,max_sessions,max_logout_events) VALUES($1,$2,false,$3,$4,$5) ON CONFLICT(id) DO NOTHING;
-- name: BrowserEpochSeen :one
SELECT EXISTS(SELECT 1 FROM browser_session_epoch WHERE root_id=$1 AND epoch=$2) AS seen;
-- name: RecordBrowserEpoch :exec
INSERT INTO browser_session_epoch(root_id,epoch,source_generation) VALUES($1,$2,$3) ON CONFLICT(root_id,epoch) DO NOTHING;
-- name: ObserveBrowserSettings :exec
UPDATE browser_session_root SET epoch=$2,enabled=$3,max_logins=$4,max_sessions=$5,max_logout_events=$6,source_uid=$7,source_generation=$8,source_digest=$9,observed_at=$10,fresh_until=$11,issuer=$12,client_id=$13,origin=$14,max_lifetime_seconds=$15 WHERE id=$1;
-- name: FenceBrowserSettings :exec
UPDATE browser_session_root SET enabled=false WHERE id=$1 AND (observed_at IS NULL OR observed_at<=$2);
-- name: RevokeUnqualifiedBrowserLogins :exec
DELETE FROM browser_login WHERE root_id=$1;
-- name: RevokeUnqualifiedBrowserSessions :exec
DELETE FROM browser_session WHERE root_id=$1;
-- name: ClampBrowserSessionLifetimes :exec
UPDATE browser_session SET expires_at=LEAST(expires_at,created_at+make_interval(secs=>sqlc.arg(max_lifetime_seconds)::integer)),refresh_at=LEAST(refresh_at,created_at+make_interval(secs=>sqlc.arg(max_lifetime_seconds)::integer)) WHERE root_id=$1 AND expires_at>created_at+make_interval(secs=>sqlc.arg(max_lifetime_seconds)::integer);
