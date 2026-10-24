BEGIN READ ONLY;
SET LOCAL statement_timeout='5s';
SELECT c.id AS capture_id,c.attempt_id,v.verified_at,v.audit_acknowledged_at,cat.artifact_id,cat.published_at,a.state AS custody_state,a.effective_expires_at,a.effective_delete_by FROM context_capture c JOIN custody_attempt a ON a.id=c.attempt_id LEFT JOIN context_verification v ON v.capture_id=c.id AND v.root_id=c.root_id LEFT JOIN context_catalog cat ON cat.capture_id=c.id AND cat.root_id=c.root_id;
SELECT count(*) AS download_sessions FROM context_download_session;
COMMIT;
