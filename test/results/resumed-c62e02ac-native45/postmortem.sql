BEGIN READ ONLY;
SET LOCAL statement_timeout = '5s';
SELECT c.id,c.created_at,c.deadline,c.state,c.intent_acknowledged_at,a.request_until,a.write_until,EXTRACT(EPOCH FROM a.request_until-c.created_at) AS initial_intent_seconds,a.intent_started,a.intent_receipt IS NOT NULL AS intent_acknowledged,a.outcome IS NOT NULL AS outcome_set,a.outcome_receipt IS NOT NULL AS outcome_acknowledged,l.intent_completion->>'StoredAt' AS intent_stored_at,l.intent_completion->>'ClosedAt' AS intent_closed_at,b.intent_reads,b.intent_first_until,b.intent_second_until FROM context_capture c LEFT JOIN operation_audit a ON a.id=c.id LEFT JOIN operation_audit_lifecycle l ON l.operation_id=a.id LEFT JOIN capture_audit_binding b ON b.capture_id=c.id;
SELECT id,lane,intent->>'Name' AS operation_name,intent->>'CreatedAt' AS created_at,request_until,write_until,intent_started,intent_receipt IS NOT NULL AS intent_acknowledged,outcome IS NOT NULL AS outcome_set,outcome_receipt IS NOT NULL AS outcome_acknowledged FROM operation_audit ORDER BY intent->>'CreatedAt';
SELECT capture_id,phase,created_at,not_before,not_after,started_at,acquired_at,completed_at FROM context_execution;
SELECT state,count(*) FROM custody_attempt GROUP BY state;
COMMIT;
