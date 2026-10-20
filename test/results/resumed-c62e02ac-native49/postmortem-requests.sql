BEGIN READ ONLY;
SET LOCAL statement_timeout='5s';
SELECT id,created_at,deadline,closed_at FROM context_preview ORDER BY created_at;
SELECT id,intent->>'Name' AS operation_name,outcome->>'Status' AS status,outcome->>'Reason' AS reason,outcome->>'Effect' AS effect,outcome->>'RecordedAt' AS recorded_at,outcome->>'MetadataUntil' AS metadata_until FROM operation_audit ORDER BY intent->>'CreatedAt';
COMMIT;
