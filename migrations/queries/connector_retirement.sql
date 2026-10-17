-- name: ReadConnectorProcessTicket :one
SELECT read_connector_process_ticket(sqlc.arg(root_id)::uuid,sqlc.arg(current_value)::jsonb)::jsonb AS plan;

-- name: ReadConnectorSuccessorCohorts :one
SELECT read_connector_successor_cohorts(sqlc.arg(root_id)::uuid,sqlc.arg(current_value)::jsonb)::jsonb AS cohorts;

-- name: AdmitConnectorProcessReserved :one
SELECT admit_connector_process_reserved(sqlc.arg(root_id)::uuid,sqlc.arg(current_value)::jsonb,sqlc.arg(intent_value)::jsonb,sqlc.arg(process_value)::jsonb,sqlc.arg(ticket_images)::bytea[])::jsonb AS admission;

-- name: AdmitConnectorBackingReserved :one
SELECT admit_connector_backing_reserved(sqlc.arg(root_id)::uuid,sqlc.arg(current_value)::jsonb,sqlc.arg(intent_value)::jsonb,sqlc.arg(ticket_images)::bytea[])::jsonb AS admission;

-- name: ReadConnectorRetirement :one
SELECT read_connector_retirement(sqlc.arg(root_id)::uuid,sqlc.arg(ticket_id)::uuid,sqlc.arg(observed_at)::timestamptz,sqlc.arg(until_time)::timestamptz)::jsonb AS result;

-- name: RestrictConnectorRetirement :one
SELECT restrict_connector_retirement(sqlc.arg(root_id)::uuid,sqlc.arg(ticket_id)::uuid,sqlc.arg(cause)::text,sqlc.arg(current_value)::jsonb)::jsonb AS result;

-- name: AdmitConnectorRetirement :one
SELECT admit_connector_retirement(sqlc.arg(root_id)::uuid,sqlc.arg(ticket_id)::uuid,sqlc.arg(intent_value)::jsonb,sqlc.arg(observed_at)::timestamptz,sqlc.arg(until_time)::timestamptz)::jsonb AS result;

-- name: CloseConnectorRetirementAdmission :one
SELECT close_connector_retirement_admission(sqlc.arg(root_id)::uuid,sqlc.arg(ticket_id)::uuid)::boolean AS closed;

-- name: CloseConnectorRetirementWriterReference :one
SELECT close_connector_retirement_writer_reference(sqlc.arg(root_id)::uuid,sqlc.arg(ticket_id)::uuid)::boolean AS closed;

-- name: DeleteConnectorRetirementTicket :one
SELECT delete_connector_retirement_ticket(sqlc.arg(root_id)::uuid,sqlc.arg(ticket_id)::uuid)::boolean AS deleted;

-- name: StoreConnectorRetirementOutcome :one
SELECT store_connector_retirement_outcome(sqlc.arg(root_id)::uuid,sqlc.arg(ticket_id)::uuid,sqlc.arg(outcome_value)::jsonb,sqlc.arg(observed_at)::timestamptz,sqlc.arg(until_time)::timestamptz)::jsonb AS result;
