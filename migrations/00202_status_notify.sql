-- +goose Up
-- REQ-INT-003 / ADR-330 D1: status readers wait for a committed change
-- instead of polling. A grant change and a download state change notify their
-- own ID on the status channel, like a capture progress revision (00168).
-- No Down: every statement can be reapplied.
DROP TRIGGER IF EXISTS access_grant_status_notify ON access_grant;
CREATE TRIGGER access_grant_status_notify AFTER UPDATE ON access_grant
 FOR EACH ROW WHEN (NEW IS DISTINCT FROM OLD) EXECUTE FUNCTION notify_capture_progress();
DROP TRIGGER IF EXISTS artifact_download_status_notify ON artifact_download;
CREATE TRIGGER artifact_download_status_notify AFTER UPDATE ON artifact_download
 FOR EACH ROW WHEN (NEW.state IS DISTINCT FROM OLD.state) EXECUTE FUNCTION notify_capture_progress();
