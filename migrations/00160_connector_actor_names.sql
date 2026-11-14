-- +goose Up
-- Helm-native installation: the connector's audited process actor names its
-- Deployment, ServiceAccount and namespace; Kubernetes UIDs are no longer
-- pinned (RBAC protects the release namespace), so the audit actor check
-- requires the names instead of the removed UIDs.

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION connector_operation_actor_valid(i jsonb)
 RETURNS boolean
 LANGUAGE plpgsql
 IMMUTABLE
 SET search_path TO 'pg_catalog', 'pg_temp'
AS $function$
DECLARE name text:=i->>'Name'; actor jsonb; b jsonb;
BEGIN
 IF name='connector_retirement' THEN
  RETURN COALESCE(NOT(i ? 'Actor') AND NOT(i ? 'Peer') AND NOT(i ? 'Process') AND NOT(i ? 'ConnectorReservations') AND i->>'InputFormat'='connector-retirement/v1' AND
   public.connector_retirement_ticket_valid(i->'RetirementOrigin'->'Ticket') AND (i->>'ID')::uuid=(i->'RetirementOrigin'->'Ticket'->>'ID')::uuid AND (i->>'RootID')::uuid=(i->'RetirementOrigin'->'Ticket'->>'RootID')::uuid AND
   octet_length(public.connector_digest(i->'RetirementOrigin'->'TicketDigest'))=32 AND i->'RetirementOrigin'->>'Cause' IN('protectedRetiringSource','originalAdmissionEnd'),false);
 END IF;
 IF i ? 'RetirementOrigin' THEN RETURN false;END IF;
 IF public.operation_audit_lane(name)<>'identity' THEN
  RETURN NOT(i ? 'Peer') AND NOT(i ? 'Process') AND public.operation_audit_human_input_valid(name,i->>'InputFormat');
 END IF;
 IF i ? 'Actor' OR (i ? 'Peer')=(i ? 'Process') THEN RETURN false;END IF;
 IF i ? 'Process' THEN
  actor:=i->'Process';b:=actor->'Process'->'Binding';
  IF NOT COALESCE((actor->'Process'->>'PodUID')::uuid IS NOT NULL AND (actor->'Process'->>'ProcessEpoch')::uuid IS NOT NULL AND
   COALESCE(actor->'Deployment'->>'Namespace','')<>'' AND COALESCE(actor->'Deployment'->>'ServiceAccount','')<>'' AND COALESCE(actor->'Deployment'->>'Deployment','')<>'' AND
   jsonb_array_length(actor->'ClientKeyDigest')=32 AND jsonb_array_length(actor->'ServerKeyDigest')=32 AND actor->'ClientKeyDigest'<>actor->'ServerKeyDigest',false) THEN RETURN false;END IF;
 ELSE
  IF name IN('connector_process_enrollment','connector_backing_acceptance') THEN RETURN false;END IF;
  actor:=i->'Peer';b:=actor->'Binding';
  IF NOT COALESCE(jsonb_array_length(actor->'CertificateDigest')=32,false) THEN RETURN false;END IF;
 END IF;
 RETURN COALESCE(b->>'Role'='connector' AND b->>'NodeUID'='' AND b->>'NodeBootID'='' AND b->>'CollectorEpoch'='' AND
  (b->>'InstallationID')::uuid IS NOT NULL AND (b->>'ClusterID')::uuid IS NOT NULL AND (b->>'IssuerEpoch')::uuid IS NOT NULL AND (b->>'PeerID')::uuid IS NOT NULL AND
  i->>'InputFormat'=(CASE WHEN name='connector_process_enrollment' THEN 'connector-process/v1' WHEN name='connector_backing_acceptance' THEN 'connector-backing/v1' ELSE 'connector-credential/v1' END),false);
END $function$;
-- +goose StatementEnd

-- +goose Down
SELECT 1;
