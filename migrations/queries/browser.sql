-- name: LockBrowserRoot :one
SELECT * FROM browser_session_root WHERE id=$1 FOR UPDATE;
-- name: ShareBrowserRoot :one
SELECT * FROM browser_session_root WHERE id=$1 FOR SHARE;
-- name: PruneBrowserLogins :exec
DELETE FROM browser_login AS target WHERE target.root_id=$1 AND target.id IN (SELECT candidate.id FROM browser_login AS candidate WHERE candidate.root_id=$1 AND (candidate.expires_at<=clock_timestamp() OR candidate.epoch<>$2) ORDER BY candidate.expires_at,candidate.id LIMIT 256 FOR UPDATE SKIP LOCKED);
-- name: PruneBrowserSessions :exec
DELETE FROM browser_session AS target WHERE target.root_id=$1 AND target.id IN (SELECT candidate.id FROM browser_session AS candidate WHERE candidate.root_id=$1 AND (candidate.expires_at<=clock_timestamp() OR candidate.epoch<>$2 OR candidate.claim_until<=clock_timestamp()) ORDER BY candidate.expires_at,candidate.id LIMIT 256 FOR UPDATE SKIP LOCKED);
-- name: PruneBrowserLogout :exec
DELETE FROM browser_logout AS target WHERE target.root_id=$1 AND target.id IN (SELECT candidate.id FROM browser_logout AS candidate WHERE candidate.root_id=$1 AND (candidate.expires_at<=clock_timestamp() OR candidate.epoch<>$2) ORDER BY candidate.expires_at,candidate.id LIMIT 256 FOR UPDATE SKIP LOCKED);
-- name: CountBrowserLogins :one
SELECT count(*) FROM browser_login WHERE root_id=$1;
-- name: CountBrowserSessions :one
SELECT count(*) FROM browser_session WHERE root_id=$1;
-- name: CountBrowserSubject :one
SELECT count(*) FROM browser_session WHERE root_id=$1 AND issuer=$2 AND client_id=$3 AND subject=$4;
-- name: CountBrowserLogout :one
SELECT count(*) FROM browser_logout WHERE root_id=$1;
-- name: InsertBrowserLogin :exec
INSERT INTO browser_login(root_id,epoch,id,browser,ciphertext,created_at,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7);
-- name: ConsumeBrowserLogin :one
DELETE FROM browser_login WHERE root_id=$1 AND epoch=$2 AND id=$3 AND browser=$4 RETURNING *;
-- name: InsertBrowserSession :exec
INSERT INTO browser_session(root_id,epoch,id,issuer,client_id,subject,provider_session,ciphertext,created_at,authenticated_at,expires_at,refresh_at,version) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,1);
-- name: LockBrowserSession :one
SELECT * FROM browser_session WHERE root_id=$1 AND epoch=$2 AND id=$3 FOR UPDATE;
-- name: ReadBrowserSession :one
SELECT * FROM browser_session WHERE root_id=$1 AND epoch=$2 AND id=$3 FOR SHARE;
-- name: ClaimBrowserRefresh :exec
UPDATE browser_session SET refresh_claim=$4,claim_until=$5 WHERE root_id=$1 AND epoch=$2 AND id=$3;
-- name: FinishBrowserRefresh :exec
UPDATE browser_session SET version=version+1,refresh_claim=NULL,claim_until=NULL,ciphertext=$4,refresh_at=$5 WHERE root_id=$1 AND epoch=$2 AND id=$3;
-- name: DeleteBrowserSession :exec
DELETE FROM browser_session WHERE root_id=$1 AND epoch=$2 AND id=$3;
-- name: ReadBrowserLogout :one
SELECT * FROM browser_logout WHERE root_id=$1 AND epoch=$2 AND id=$3;
-- name: BrowserSessionLoggedOut :one
SELECT EXISTS(SELECT 1 FROM browser_logout WHERE root_id=$1 AND epoch=$2 AND issuer=$3 AND client_id=$4 AND expires_at>clock_timestamp() AND ((provider_session<>'' AND provider_session=$5 AND (subject='' OR subject=$6)) OR (provider_session='' AND subject=$6 AND issued_at>=$7))) AS blocked;
-- name: InsertBrowserLogout :exec
INSERT INTO browser_logout(root_id,epoch,id,issuer,client_id,subject,provider_session,issued_at,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9);
-- name: RevokeBrowserProviderSessions :exec
DELETE FROM browser_session WHERE root_id=$1 AND epoch=$2 AND issuer=$3 AND client_id=$4 AND ((sqlc.arg(provider_session)::text<>'' AND provider_session=sqlc.arg(provider_session) AND (sqlc.arg(subject)::text='' OR subject=sqlc.arg(subject))) OR (sqlc.arg(provider_session)::text='' AND subject=sqlc.arg(subject) AND authenticated_at<=sqlc.arg(issued_at)));

