-- name: PruneBrowserLogins :exec
DELETE FROM browser_login WHERE expires_at<=clock_timestamp();
-- name: PruneBrowserSessions :exec
DELETE FROM browser_session WHERE expires_at<=clock_timestamp() OR claim_until<=clock_timestamp() OR last_used_at+make_interval(secs=>sqlc.arg(inactivity_seconds)::bigint)<=clock_timestamp();
-- name: PruneBrowserLogout :exec
DELETE FROM browser_logout WHERE expires_at<=clock_timestamp();
-- name: ExtendBrowserLogoutReceipts :exec
UPDATE browser_logout SET expires_at=issued_at+make_interval(secs=>sqlc.arg(max_lifetime_seconds)::bigint)+interval '1 hour' WHERE expires_at>clock_timestamp() AND expires_at<issued_at+make_interval(secs=>sqlc.arg(max_lifetime_seconds)::bigint)+interval '1 hour';
-- name: ClampBrowserSessionLifetimes :exec
UPDATE browser_session SET expires_at=LEAST(expires_at,created_at+make_interval(secs=>sqlc.arg(max_lifetime_seconds)::bigint)),refresh_at=LEAST(refresh_at,created_at+make_interval(secs=>sqlc.arg(max_lifetime_seconds)::bigint)) WHERE expires_at>created_at+make_interval(secs=>sqlc.arg(max_lifetime_seconds)::bigint);
-- name: InsertBrowserLogin :exec
INSERT INTO browser_login(id,browser,ciphertext,created_at,expires_at) VALUES($1,$2,$3,$4,$5);
-- name: ConsumeBrowserLogin :one
DELETE FROM browser_login WHERE id=$1 AND browser=$2 RETURNING *;
-- name: InsertBrowserSession :exec
INSERT INTO browser_session(id,issuer,client_id,subject,provider_session,ciphertext,created_at,authenticated_at,expires_at,last_used_at,refresh_at,version) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$7,$10,1);
-- name: LockBrowserSession :one
SELECT * FROM browser_session WHERE id=$1 FOR UPDATE;
-- name: ReadBrowserSession :one
SELECT * FROM browser_session WHERE id=$1 AND last_used_at+make_interval(secs=>sqlc.arg(inactivity_seconds)::bigint)>clock_timestamp();
-- name: TouchBrowserSession :exec
UPDATE browser_session SET last_used_at=clock_timestamp() WHERE id=$1 AND last_used_at<clock_timestamp()-interval '1 minute';
-- name: ClaimBrowserRefresh :exec
UPDATE browser_session SET refresh_claim=$2,claim_until=$3 WHERE id=$1;
-- name: FinishBrowserRefresh :exec
UPDATE browser_session SET version=version+1,refresh_claim=NULL,claim_until=NULL,ciphertext=$2,refresh_at=$3 WHERE id=$1;
-- name: DeleteBrowserSession :exec
DELETE FROM browser_session WHERE id=$1;
-- name: ReadBrowserLogout :one
SELECT * FROM browser_logout WHERE id=$1;
-- name: BrowserSessionLoggedOut :one
SELECT EXISTS(SELECT 1 FROM browser_logout WHERE issuer=$1 AND client_id=$2 AND expires_at>clock_timestamp() AND ((provider_session<>'' AND provider_session=$3 AND (subject='' OR subject=$4)) OR (provider_session='' AND subject=$4 AND issued_at>=$5))) AS blocked;
-- name: InsertBrowserLogout :exec
INSERT INTO browser_logout(id,issuer,client_id,subject,provider_session,issued_at,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7);
-- name: RevokeBrowserProviderSessions :exec
DELETE FROM browser_session WHERE issuer=$1 AND client_id=$2 AND ((sqlc.arg(provider_session)::text<>'' AND provider_session=sqlc.arg(provider_session) AND (sqlc.arg(subject)::text='' OR subject=sqlc.arg(subject))) OR (sqlc.arg(provider_session)::text='' AND subject=sqlc.arg(subject) AND authenticated_at<=sqlc.arg(issued_at)));
