-- +goose Up
-- Purpose-bound prepaid retirement of original connector cohorts.
-- Reservation, restrictive admission and reference cleanup are separate from
-- independently verified audit-object/history deletion. No runtime role is granted.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION operation_audit_lane(operation_name text) RETURNS text
LANGUAGE sql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
 SELECT CASE WHEN operation_name IN ('connector_process_enrollment','connector_client_certificate','connector_server_certificate','connector_backing_acceptance','connector_retirement') THEN 'identity'
 WHEN operation_name='release_processing' THEN 'processing'
 WHEN operation_name='resolve_capture_request' THEN 'resolution'
 WHEN operation_name IN ('list_diagnostics','preview_capture','request_capture','get_capture','get_case','prepare_artifact_download','get_artifact_download','invalid_operation','initialize_processing','restrict_processing') THEN 'normal' ELSE NULL END
$$;
CREATE OR REPLACE FUNCTION operation_audit_history_layout_valid(lane text,layout text) RETURNS boolean
LANGUAGE sql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
 SELECT COALESCE((lane IN ('normal','resolution') AND layout IN ('operation-audit-history/v1','operation-audit-history/v2','operation-audit-history/v3')) OR (lane='identity' AND layout IN ('connector-operation-history/v1','connector-operation-history/v2')) OR (lane='processing' AND layout='processing-release-history/v1'),false)
$$;
CREATE OR REPLACE FUNCTION operation_audit_history_fixed_transitions(layout text) RETURNS bigint
LANGUAGE sql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
 SELECT CASE layout WHEN 'operation-audit-history/v1' THEN 16 WHEN 'operation-audit-history/v2' THEN 19 WHEN 'operation-audit-history/v3' THEN 21 WHEN 'connector-operation-history/v1' THEN 32 WHEN 'connector-operation-history/v2' THEN 40 WHEN 'processing-release-history/v1' THEN 32 ELSE NULL END::bigint
$$;
CREATE OR REPLACE FUNCTION operation_audit_history_verifier_backed(layout text) RETURNS boolean
LANGUAGE sql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
 SELECT COALESCE(layout IN ('operation-audit-history/v3','connector-operation-history/v1','connector-operation-history/v2','processing-release-history/v1'),false)
$$;
CREATE OR REPLACE FUNCTION operation_audit_history_minimum_row(layout text) RETURNS bigint
LANGUAGE sql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
 SELECT CASE WHEN layout IN ('connector-operation-history/v1','connector-operation-history/v2') THEN 1048576 WHEN layout IN ('operation-audit-history/v1','operation-audit-history/v2','operation-audit-history/v3','processing-release-history/v1') THEN 131072 ELSE NULL END::bigint
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION operation_audit_lane(text),operation_audit_history_layout_valid(text,text),operation_audit_history_fixed_transitions(text),operation_audit_history_verifier_backed(text),operation_audit_history_minimum_row(text) FROM PUBLIC;

-- Retained installation control, not a copy of the ticket's actor/audit image.
-- These fixed columns remain covered by the original profile row reservation
-- while later possible leaves/process references retain their own lifetimes.
ALTER TABLE connector_identity_profile ADD COLUMN retirement_ticket uuid;
ALTER TABLE connector_identity_profile ADD COLUMN retirement_at timestamptz;
ALTER TABLE connector_identity_profile ADD CHECK((retirement_ticket IS NULL)=(retirement_at IS NULL));
ALTER TABLE connector_identity_profile ADD CHECK(retirement_at IS NULL OR isfinite(retirement_at));

CREATE TABLE connector_retirement_ticket (
 id uuid PRIMARY KEY,
 root_id uuid NOT NULL, peer_id uuid NOT NULL,
 acceptance_id uuid NOT NULL,
 -- The immutable ID remains historical provenance. Its live FK is retained
 -- only while it can authorize ticket admission/activation, never past that
 -- acceptance pair's original purge schedule. Exact closure is irreversible.
 acceptance_reference uuid REFERENCES operation_audit(id) DEFERRABLE INITIALLY DEFERRED,
 admission_closed_at timestamptz,
 behavior_uid uuid NOT NULL, behavior_generation bigint NOT NULL CHECK(behavior_generation BETWEEN 1 AND 2147483647),
 behavior_digest bytea NOT NULL CHECK(octet_length(behavior_digest)=32),
 backing_revision bigint NOT NULL CHECK(backing_revision BETWEEN 1 AND 1152921504606846976),
 backing_digest bytea NOT NULL CHECK(octet_length(backing_digest)=32),
 principal_digest bytea NOT NULL CHECK(octet_length(principal_digest)=32),
 canonical_bytes bytea NOT NULL CHECK(octet_length(canonical_bytes) BETWEEN 1 AND 16384),
 ticket jsonb NOT NULL CHECK(jsonb_typeof(ticket)='object' AND octet_length(ticket::text)<=32768),
 ticket_digest bytea NOT NULL CHECK(octet_length(ticket_digest)=32),
 reserved_at timestamptz NOT NULL CHECK(isfinite(reserved_at)),
 admission_until timestamptz NOT NULL CHECK(isfinite(admission_until)),
 consume_until timestamptz NOT NULL CHECK(isfinite(consume_until)),
 original_purge_at timestamptz NOT NULL CHECK(isfinite(original_purge_at)),
 retain_until timestamptz NOT NULL CHECK(isfinite(retain_until)),
 activated_at timestamptz, superseded_at timestamptz,
 restriction_at timestamptz, restriction_source jsonb,
 admitted_at timestamptz, closed_unused_at timestamptz,
 retirement_operation uuid,
 retirement_reference uuid REFERENCES operation_audit(id) DEFERRABLE INITIALLY DEFERRED,
 audit_dependency_closed_at timestamptz,
 FOREIGN KEY(root_id,peer_id) REFERENCES connector_identity_profile(root_id,peer_id),
 UNIQUE(root_id,peer_id,backing_revision,behavior_uid,behavior_generation,behavior_digest),
 UNIQUE(root_id,id),
 CHECK(id<>acceptance_id),
 CHECK(acceptance_reference IS NULL OR acceptance_reference=acceptance_id),
 CHECK((acceptance_reference IS NULL)=(admission_closed_at IS NOT NULL)),
 CHECK(admission_closed_at IS NULL OR admission_closed_at>=reserved_at),
 CHECK(reserved_at<admission_until AND admission_until<=original_purge_at-interval '1 minute'),
 CHECK(consume_until=original_purge_at-interval '30 seconds' AND original_purge_at<retain_until),
 CHECK((admitted_at IS NULL)=(retirement_operation IS NULL)),
 CHECK(retirement_operation IS NULL OR retirement_operation=id),
 CHECK((admitted_at IS NULL AND retirement_reference IS NULL AND audit_dependency_closed_at IS NULL) OR
  (admitted_at IS NOT NULL AND ((retirement_reference=retirement_operation AND audit_dependency_closed_at IS NULL) OR (retirement_reference IS NULL AND audit_dependency_closed_at IS NOT NULL AND audit_dependency_closed_at>=admitted_at)))),
 CHECK(admitted_at IS NULL OR closed_unused_at IS NULL),
 CHECK(admitted_at IS NULL OR activated_at IS NOT NULL AND superseded_at IS NULL AND restriction_at IS NOT NULL),
 CHECK(superseded_at IS NULL OR admitted_at IS NULL AND restriction_at IS NULL),
 CHECK(restriction_at IS NULL OR activated_at IS NOT NULL AND superseded_at IS NULL),
 CHECK(restriction_source IS NULL OR jsonb_typeof(restriction_source)='object' AND octet_length(restriction_source::text)<=2048),
 CHECK(admitted_at IS NULL OR admitted_at>=reserved_at AND admitted_at<consume_until),
 CHECK(closed_unused_at IS NULL OR closed_unused_at>=reserved_at)
);
CREATE UNIQUE INDEX connector_ticket_active ON connector_retirement_ticket(root_id,peer_id)
 WHERE activated_at IS NOT NULL AND superseded_at IS NULL;
CREATE INDEX connector_ticket_reservations ON connector_retirement_ticket(root_id,principal_digest)
 WHERE admitted_at IS NULL AND closed_unused_at IS NULL;
CREATE INDEX connector_ticket_acceptance ON connector_retirement_ticket(root_id,acceptance_id,peer_id);
CREATE INDEX connector_ticket_retirement ON connector_retirement_ticket(root_id,retain_until,id);

-- Versioned canonical bytes are emitted/strictly rechecked by the typed
-- application producer. Do not substitute jsonb::text or an extension digest.
-- SQL compares each decoded field with original accepted scope separately.
-- +goose StatementBegin
CREATE FUNCTION connector_retirement_ticket_digest(canonical bytea) RETURNS bytea
LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
BEGIN
 IF canonical IS NULL OR octet_length(canonical) NOT BETWEEN 1 AND 16384 THEN
  RAISE EXCEPTION 'connector ticket image unavailable' USING ERRCODE='23514';
 END IF;
 RETURN sha256(convert_to('asservat-connector-retirement-ticket/v1','UTF8')||decode('00','hex')||int4send(octet_length(canonical))||canonical);
END $$;
CREATE FUNCTION connector_retirement_set_digest(r uuid,acceptance uuid) RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE item record; n bigint; body bytea:=''::bytea; expected bytea;
BEGIN
 -- This private function returns only a set commitment, not ticket/actor data.
 -- Read/lock grant composition and role currentness remain separately required.
 IF NOT(public.connector_identity_role_ok(r,'journal') OR public.connector_identity_role_ok(r,'acknowledgement') OR public.connector_identity_role_ok(r,'source')) THEN
  RAISE EXCEPTION 'connector ticket set reader unavailable' USING ERRCODE='23514';
 END IF;
 SELECT count(*) INTO n FROM public.connector_retirement_ticket t WHERE t.root_id=r AND t.acceptance_id=acceptance;
 IF n NOT BETWEEN 1 AND 4096 THEN RAISE EXCEPTION 'connector ticket set unavailable' USING ERRCODE='23514';END IF;
 IF EXISTS(SELECT 1 FROM public.connector_retirement_ticket t WHERE t.root_id=r AND t.acceptance_id=acceptance GROUP BY t.peer_id HAVING count(*)<>1) THEN
  RAISE EXCEPTION 'connector ticket set duplicates a peer' USING ERRCODE='23514';END IF;
 FOR item IN SELECT t.canonical_bytes,t.ticket,t.ticket_digest FROM public.connector_retirement_ticket t WHERE t.root_id=r AND t.acceptance_id=acceptance ORDER BY t.peer_id LOOP
  IF convert_from(item.canonical_bytes,'UTF8')::jsonb IS DISTINCT FROM item.ticket THEN RAISE EXCEPTION 'connector ticket image mismatch' USING ERRCODE='23514';END IF;
  expected:=public.connector_retirement_ticket_digest(item.canonical_bytes);
  IF expected IS DISTINCT FROM item.ticket_digest THEN RAISE EXCEPTION 'connector ticket digest mismatch' USING ERRCODE='23514';END IF;
  body:=body||expected;
 END LOOP;
 expected:=sha256(convert_to('asservat-connector-retirement-set/v1','UTF8')||decode('00','hex')||int4send(n::integer)||body);
 RETURN jsonb_build_object('Version','connector-retirement-set/v1','Count',n,
   'Digest',to_jsonb(ARRAY(SELECT get_byte(expected,i) FROM generate_series(0,31) i)));
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION connector_retirement_ticket_digest(bytea),connector_retirement_set_digest(uuid,uuid) FROM PUBLIC;

-- Structural historical input checks only. The INSERT guard separately checks
-- exact source/acceptance/account/backing state under current recovery locks.
-- No stored date/digest from this predicate is admission authority.
-- +goose StatementBegin
CREATE FUNCTION connector_retirement_ticket_valid(t jsonb) RETURNS boolean
LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
DECLARE p jsonb:=t->'Policy'; b jsonb:=t->'Binding'; actor jsonb:=t->'OriginalActor';
 a timestamptz; ordinary_end timestamptz; consume_end timestamptz; retained timestamptz; original_end timestamptz;
BEGIN
 IF jsonb_typeof(t) IS DISTINCT FROM 'object' OR octet_length(t::text)>32768 OR
  NOT(t ?& ARRAY['ID','RootID','AcceptanceID','Binding','OriginalActor','Behavior','ServingSlots','RetainedProcesses','BackingRevision','BackingDigest','AccountVersion','PrincipalDigest','ReservedAt','AdmissionUntil','ConsumeUntil','RetainUntil','OriginalAcceptancePurgeAt','Policy']) OR
  (t-ARRAY['ID','RootID','AcceptanceID','Binding','OriginalActor','Behavior','ServingSlots','RetainedProcesses','BackingRevision','BackingDigest','AccountVersion','PrincipalDigest','ReservedAt','AdmissionUntil','ConsumeUntil','RetainUntil','OriginalAcceptancePurgeAt','Policy'])<>'{}'::jsonb THEN RETURN false;END IF;
 a:=(t->>'ReservedAt')::timestamptz;ordinary_end:=(t->>'AdmissionUntil')::timestamptz;consume_end:=(t->>'ConsumeUntil')::timestamptz;retained:=(t->>'RetainUntil')::timestamptz;
 original_end:=retained-make_interval(secs=>(2*(p->>'BackupHorizonSeconds')::bigint+3*(p->>'CleanupBudgetSeconds')::bigint+(p->>'ProofWindowSeconds')::bigint)::double precision);
 RETURN COALESCE((t->>'ID')::uuid<>(t->>'AcceptanceID')::uuid AND (t->>'RootID')::uuid IS NOT NULL AND
  b->>'Role'='connector' AND b->>'NodeUID'='' AND b->>'NodeBootID'='' AND b->>'CollectorEpoch'='' AND
  (b->>'InstallationID')::uuid=(actor->'Process'->'Binding'->>'InstallationID')::uuid AND (b->>'IssuerEpoch')::uuid=(actor->'Process'->'Binding'->>'IssuerEpoch')::uuid AND
  (b->>'ClusterID')::uuid IS NOT NULL AND (b->>'PeerID')::uuid IS NOT NULL AND
  (actor->'Process'->>'PodUID')::uuid IS NOT NULL AND (actor->'Process'->>'ProcessEpoch')::uuid IS NOT NULL AND
  (actor->'Process'->'Binding'->>'PeerID')::uuid IS NOT NULL AND (actor->'Process'->'Binding'->>'ClusterID')::uuid IS NOT NULL AND
  (t->>'ServingSlots')::bigint BETWEEN 1 AND 16 AND (t->>'RetainedProcesses')::bigint BETWEEN (t->>'ServingSlots')::bigint+1 AND 256 AND
  (t->'Behavior'->>'UID')::uuid IS NOT NULL AND (t->'Behavior'->>'Generation')::bigint BETWEEN 1 AND 2147483647 AND octet_length(public.connector_digest(t->'Behavior'->'Digest'))=32 AND
  (t->>'BackingRevision')::bigint BETWEEN 1 AND 1152921504606846976 AND octet_length(public.connector_digest(t->'BackingDigest'))=32 AND octet_length(public.connector_digest(t->'PrincipalDigest'))=32 AND octet_length(t->>'AccountVersion') BETWEEN 1 AND 64 AND
  p->>'Lane'='identity' AND p->'History'->>'Layout'='connector-operation-history/v2' AND p->>'OverdueTerminal'='overdue-original/v1' AND
  p->>'RootID'=t->>'RootID' AND p->>'InstallationID'=b->>'InstallationID' AND p->>'PolicyID'=t->>'ID' AND p->>'BackingRevision'=t->>'BackingRevision' AND
  (p->>'ValidUntil')::timestamptz=consume_end AND isfinite(a) AND isfinite(ordinary_end) AND isfinite(consume_end) AND isfinite(retained) AND isfinite(original_end) AND
  a<ordinary_end AND ordinary_end<=original_end-interval '1 minute' AND consume_end=original_end-interval '30 seconds' AND original_end>a+interval '1 minute' AND
  original_end<retained AND retained<=a+interval '3660 days' AND original_end<=(t->>'OriginalAcceptancePurgeAt')::timestamptz,false);
EXCEPTION WHEN invalid_text_representation OR datetime_field_overflow OR numeric_value_out_of_range THEN RETURN false;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION connector_retirement_ticket_valid(jsonb) FROM PUBLIC;

-- +goose StatementBegin
CREATE FUNCTION connector_retirement_row_valid(row_value public.connector_retirement_ticket) RETURNS boolean
LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
DECLARE t jsonb:=row_value.ticket; p jsonb:=t->'Policy';
BEGIN
 RETURN COALESCE(public.connector_retirement_ticket_valid(t) AND
  convert_from(row_value.canonical_bytes,'UTF8')::jsonb=t AND public.connector_retirement_ticket_digest(row_value.canonical_bytes)=row_value.ticket_digest AND
  (t->>'ID')::uuid=row_value.id AND (t->>'RootID')::uuid=row_value.root_id AND (t->>'AcceptanceID')::uuid=row_value.acceptance_id AND (t->'Binding'->>'PeerID')::uuid=row_value.peer_id AND
  (t->'Behavior'->>'UID')::uuid=row_value.behavior_uid AND (t->'Behavior'->>'Generation')::bigint=row_value.behavior_generation AND public.connector_digest(t->'Behavior'->'Digest')=row_value.behavior_digest AND
  (t->>'BackingRevision')::bigint=row_value.backing_revision AND public.connector_digest(t->'BackingDigest')=row_value.backing_digest AND public.connector_digest(t->'PrincipalDigest')=row_value.principal_digest AND
  (t->>'ReservedAt')::timestamptz=row_value.reserved_at AND (t->>'AdmissionUntil')::timestamptz=row_value.admission_until AND (t->>'ConsumeUntil')::timestamptz=row_value.consume_until AND (t->>'RetainUntil')::timestamptz=row_value.retain_until AND
  row_value.original_purge_at=row_value.retain_until-make_interval(secs=>(2*(p->>'BackupHorizonSeconds')::bigint+3*(p->>'CleanupBudgetSeconds')::bigint+(p->>'ProofWindowSeconds')::bigint)::double precision),false);
END $$;

-- Deferred until the original accepting event exists in the same transaction.
-- A process may reserve only its own first profile ticket. A root backing event
-- may bind other logical peers while keeping the actual acceptor as historical
-- provenance; no synthetic Process branch is minted for those peers.
CREATE FUNCTION check_connector_ticket_acceptance() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE current_ticket public.connector_retirement_ticket; event public.operation_audit; expected jsonb;
BEGIN
 IF TG_RELID<>'public.connector_retirement_ticket'::regclass OR TG_WHEN<>'AFTER' OR TG_OP<>'INSERT' OR TG_LEVEL<>'ROW' THEN RAISE EXCEPTION 'invalid connector reservation source' USING ERRCODE='23514';END IF;
 SELECT * INTO STRICT current_ticket FROM public.connector_retirement_ticket WHERE id=NEW.id AND root_id=NEW.root_id;
 SELECT * INTO STRICT event FROM public.operation_audit WHERE id=current_ticket.acceptance_id AND root_id=current_ticket.root_id AND lane='identity';
 expected:=event.intent->'ConnectorReservations';
 IF NOT COALESCE(public.connector_retirement_row_valid(current_ticket) AND event.intent->>'Name' IN('connector_process_enrollment','connector_backing_acceptance') AND event.intent->'Process'=current_ticket.ticket->'OriginalActor' AND
   expected IS NOT NULL AND event.intent->'Lifecycle'->'Policy'->'History'->>'Layout'='connector-operation-history/v2' AND
   (event.intent->>'CreatedAt')::timestamptz=current_ticket.reserved_at AND event.retain_until=current_ticket.retain_until AND
   (event.intent->'Lifecycle'->>'OriginalPurgeAt')::timestamptz=(current_ticket.ticket->>'OriginalAcceptancePurgeAt')::timestamptz AND
   (event.intent->>'Name'<>'connector_process_enrollment' OR (expected->>'Count')::bigint=1 AND event.intent->'Process'->'Process'->'Binding'=current_ticket.ticket->'Binding' AND event.principal_digest=current_ticket.principal_digest AND event.intent->'Process'->'Deployment'->>'ServingSlots'=current_ticket.ticket->>'ServingSlots' AND event.intent->'Process'->'Deployment'->>'RetainedProcesses'=current_ticket.ticket->>'RetainedProcesses') AND
   ((current_ticket.ticket->'Policy') - ARRAY['PolicyID','PolicyDigest','BackingRevision','ValidUntil'])=((event.intent->'Lifecycle'->'Policy') - ARRAY['PolicyID','PolicyDigest','BackingRevision','ValidUntil']),false) THEN
  RAISE EXCEPTION 'connector original retirement acceptance mismatch' USING ERRCODE='23514';END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION connector_retirement_row_valid(public.connector_retirement_ticket),check_connector_ticket_acceptance() FROM PUBLIC;
CREATE CONSTRAINT TRIGGER connector_ticket_acceptance_guard AFTER INSERT ON connector_retirement_ticket
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION check_connector_ticket_acceptance();

-- One set verification per event, not one complete rehash per ticket. The row
-- INSERT guard prohibits appending after this event exists, and immutable row
-- guards prohibit replacing bytes afterward. Final acknowledgement/promotion
-- each repeat the same bounded linear verification once.
-- +goose StatementBegin
CREATE FUNCTION check_connector_reservation_event() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE root public.connector_identity_root; cfg public.connector_identity_profile; expected jsonb; peer uuid; missing boolean;
BEGIN
 IF TG_RELID<>'public.operation_audit'::regclass OR TG_WHEN<>'AFTER' OR TG_OP<>'INSERT' OR TG_LEVEL<>'ROW' THEN RAISE EXCEPTION 'invalid connector reservation event' USING ERRCODE='23514';END IF;
 IF NEW.lane<>'identity' THEN
  IF NEW.intent ? 'ConnectorReservations' OR NEW.intent ? 'RetirementOrigin' THEN RAISE EXCEPTION 'private connector fields on human operation' USING ERRCODE='23514';END IF;
  RETURN NEW;
 END IF;
 IF NEW.intent->'Lifecycle'->'Policy'->'History'->>'Layout' IS DISTINCT FROM 'connector-operation-history/v2' THEN
  IF NEW.intent ? 'ConnectorReservations' OR NEW.intent ? 'RetirementOrigin' THEN RAISE EXCEPTION 'unqualified connector reservation layout' USING ERRCODE='23514';END IF;
  RETURN NEW;
 END IF;
 IF NEW.intent->>'Name' NOT IN('connector_process_enrollment','connector_backing_acceptance') THEN
  IF NEW.intent ? 'ConnectorReservations' THEN RAISE EXCEPTION 'operation cannot reserve connector retirement' USING ERRCODE='23514';END IF;
  RETURN NEW;
 END IF;
 SELECT * INTO STRICT root FROM public.connector_identity_root WHERE root_id=NEW.root_id FOR UPDATE;
 peer:=(NEW.intent->'Process'->'Process'->'Binding'->>'PeerID')::uuid;
 SELECT * INTO STRICT cfg FROM public.connector_identity_profile WHERE root_id=NEW.root_id AND peer_id=peer FOR UPDATE;
 IF NOT(NEW.intent ? 'ConnectorReservations') THEN
  -- An ordinary process restart does not create another profile allowance.
  -- Its exact existing active cohort must still be current and unconsumed.
  IF NEW.intent->>'Name'<>'connector_process_enrollment' OR NOT EXISTS(
   SELECT 1 FROM public.connector_retirement_ticket t WHERE t.root_id=NEW.root_id AND t.peer_id=peer AND t.activated_at IS NOT NULL AND t.superseded_at IS NULL AND t.restriction_at IS NULL AND t.closed_unused_at IS NULL AND t.admitted_at IS NULL
    AND t.behavior_uid=cfg.source_uid AND t.behavior_generation=cfg.source_generation AND t.behavior_digest=cfg.source_digest
    AND t.backing_revision=(root.policy->>'BackingRevision')::bigint AND t.backing_digest=root.backing_digest
    AND clock_timestamp()<t.admission_until) THEN RAISE EXCEPTION 'connector profile lacks prepaid retirement' USING ERRCODE='23514';END IF;
  RETURN NEW;
 END IF;
 expected:=public.connector_retirement_set_digest(NEW.root_id,NEW.id);
 IF NEW.intent->'ConnectorReservations' IS DISTINCT FROM expected THEN RAISE EXCEPTION 'connector reservation set differs' USING ERRCODE='23514';END IF;
 IF NEW.intent->>'Name'='connector_backing_acceptance' THEN
  -- The source-owned candidate identifies one finite root-wide revision. Each
  -- currently accepted cohort gets exactly one successor, including peers
  -- whose complete ConfigMap observation has not yet advanced to the candidate.
  IF root.pending_id IS DISTINCT FROM NEW.id THEN RAISE EXCEPTION 'connector reservation candidate changed' USING ERRCODE='23514';END IF;
  SELECT EXISTS(
   SELECT 1 FROM (SELECT * FROM public.connector_retirement_ticket WHERE root_id=NEW.root_id AND activated_at IS NOT NULL AND superseded_at IS NULL AND restriction_at IS NULL AND admitted_at IS NULL AND closed_unused_at IS NULL AND NOT EXISTS(SELECT 1 FROM public.connector_identity_profile removed WHERE removed.root_id=connector_retirement_ticket.root_id AND removed.peer_id=connector_retirement_ticket.peer_id AND COALESCE((removed.configuration->>'Retiring')::boolean,false))) old_ticket
   FULL JOIN (SELECT * FROM public.connector_retirement_ticket WHERE root_id=NEW.root_id AND acceptance_id=NEW.id) successor
    ON old_ticket.root_id=successor.root_id AND old_ticket.peer_id=successor.peer_id
   WHERE (old_ticket.id IS NULL OR successor.id IS NULL OR old_ticket.restriction_at IS NOT NULL OR old_ticket.admitted_at IS NOT NULL OR old_ticket.closed_unused_at IS NOT NULL
      OR successor.behavior_uid<>old_ticket.behavior_uid OR successor.behavior_generation<>old_ticket.behavior_generation OR successor.behavior_digest<>old_ticket.behavior_digest OR successor.ticket->'ServingSlots'<>old_ticket.ticket->'ServingSlots' OR successor.ticket->'RetainedProcesses'<>old_ticket.ticket->'RetainedProcesses'
      OR successor.backing_revision<>(root.pending_backing->'Policy'->>'BackingRevision')::bigint OR successor.backing_digest<>root.pending_digest)
  ) INTO missing;
  IF missing THEN RAISE EXCEPTION 'connector successor reservation set incomplete' USING ERRCODE='23514';END IF;
 END IF;
 IF clock_timestamp()>=NEW.request_until THEN RAISE EXCEPTION 'connector reservation original request expired' USING ERRCODE='23514';END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION check_connector_reservation_event() FROM PUBLIC;
CREATE TRIGGER connector_reservation_event AFTER INSERT ON operation_audit FOR EACH ROW EXECUTE FUNCTION check_connector_reservation_event();

-- +goose StatementBegin
CREATE FUNCTION guard_connector_ticket_reservation() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE root public.connector_identity_root; cfg public.connector_identity_profile; pool public.operation_audit_pool; account public.operation_audit_account; trust public.fleet_current_trust;
 original_policy jsonb; selected_backing jsonb; reserved bigint; n timestamptz; event public.operation_audit; successor public.connector_retirement_ticket;
BEGIN
 IF TG_RELID<>'public.connector_retirement_ticket'::regclass OR TG_WHEN<>'BEFORE' OR TG_LEVEL<>'ROW' THEN RAISE EXCEPTION 'invalid connector ticket mutation source' USING ERRCODE='23514';END IF;
 IF TG_OP='UPDATE' THEN
  IF OLD.activated_at IS NULL AND NEW.activated_at IS NOT NULL OR OLD.superseded_at IS NULL AND NEW.superseded_at IS NOT NULL THEN
   -- Fixed SECURITY DEFINER activation composes current proof before this
   -- trigger. Independently require its exact acknowledged original event and
   -- immutable candidate here; no direct role write can invent a successor.
   SELECT * INTO STRICT trust FROM public.fleet_current_trust WHERE installation_id=(OLD.ticket->'Binding'->>'InstallationID')::uuid FOR SHARE;
   SELECT * INTO STRICT root FROM public.connector_identity_root WHERE root_id=OLD.root_id FOR UPDATE;
   SELECT * INTO STRICT cfg FROM public.connector_identity_profile WHERE root_id=OLD.root_id AND peer_id=OLD.peer_id FOR UPDATE;
   n:=clock_timestamp();
   IF NOT(public.connector_identity_role_ok(OLD.root_id,'journal') OR public.connector_identity_role_ok(OLD.root_id,'source')) OR
    trust.recovery_blocked OR trust.suspended OR trust.observed_at>n OR n>=trust.fresh_until OR trust.issuer_epoch<>root.issuer_epoch OR
    (to_jsonb(NEW)-ARRAY['activated_at','superseded_at']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['activated_at','superseded_at']) OR
    OLD.restriction_at IS NOT NULL OR OLD.admitted_at IS NOT NULL OR OLD.closed_unused_at IS NOT NULL OR OLD.superseded_at IS NOT NULL OR OLD.admission_closed_at IS NOT NULL OR
    n>=root.valid_until THEN RAISE EXCEPTION 'connector ticket activation authority unavailable' USING ERRCODE='23514';END IF;
   IF OLD.activated_at IS NULL THEN
    SELECT * INTO STRICT event FROM public.operation_audit WHERE id=OLD.acceptance_id AND root_id=OLD.root_id AND lane='identity';
    IF NEW.activated_at<n-interval '5 seconds' OR NEW.activated_at>n OR NEW.superseded_at IS NOT NULL OR n>=OLD.admission_until OR OLD.acceptance_reference IS DISTINCT FROM event.id OR
     NOT public.connector_reservation_acknowledged(OLD.root_id,event.id) OR
     EXISTS(SELECT 1 FROM public.connector_retirement_ticket other WHERE other.root_id=OLD.root_id AND other.peer_id=OLD.peer_id AND other.id<>OLD.id AND other.activated_at IS NOT NULL AND other.superseded_at IS NULL) OR
     NOT COALESCE((event.intent->>'Name'='connector_process_enrollment' AND public.connector_identity_role_ok(OLD.root_id,'journal') AND
       OLD.backing_revision=(root.policy->>'BackingRevision')::bigint AND OLD.backing_digest=root.backing_digest AND
       ROW(OLD.behavior_uid,OLD.behavior_generation,OLD.behavior_digest)=ROW(cfg.source_uid,cfg.source_generation,cfg.source_digest)) OR
      (event.intent->>'Name'='connector_backing_acceptance' AND public.connector_identity_role_ok(OLD.root_id,'source') AND root.pending_id=event.id AND
       OLD.backing_revision=(root.pending_backing->'Policy'->>'BackingRevision')::bigint AND OLD.backing_digest=root.pending_digest AND
       EXISTS(SELECT 1 FROM public.connector_retirement_ticket previous_ticket WHERE previous_ticket.root_id=OLD.root_id AND previous_ticket.peer_id=OLD.peer_id AND previous_ticket.activated_at IS NOT NULL AND previous_ticket.superseded_at=NEW.activated_at AND
        previous_ticket.backing_revision+1=OLD.backing_revision AND previous_ticket.behavior_uid=OLD.behavior_uid AND previous_ticket.behavior_generation=OLD.behavior_generation AND previous_ticket.behavior_digest=OLD.behavior_digest)),false) THEN
     RAISE EXCEPTION 'connector ticket activation differs from original acceptance' USING ERRCODE='23514';END IF;
   ELSE
    SELECT * INTO STRICT successor FROM public.connector_retirement_ticket WHERE root_id=OLD.root_id AND peer_id=OLD.peer_id AND acceptance_id=root.pending_id;
    IF NOT public.connector_identity_role_ok(OLD.root_id,'source') OR NEW.activated_at IS DISTINCT FROM OLD.activated_at OR NEW.superseded_at<n-interval '5 seconds' OR NEW.superseded_at>n OR
     successor.activated_at IS NOT NULL OR successor.admission_closed_at IS NOT NULL OR successor.acceptance_reference IS DISTINCT FROM successor.acceptance_id OR n>=successor.admission_until OR
     successor.restriction_at IS NOT NULL OR successor.admitted_at IS NOT NULL OR successor.closed_unused_at IS NOT NULL OR successor.backing_revision<>OLD.backing_revision+1 OR
     successor.backing_revision<>(root.pending_backing->'Policy'->>'BackingRevision')::bigint OR successor.backing_digest<>root.pending_digest OR
     ROW(successor.behavior_uid,successor.behavior_generation,successor.behavior_digest) IS DISTINCT FROM ROW(OLD.behavior_uid,OLD.behavior_generation,OLD.behavior_digest) OR
     NOT public.connector_reservation_acknowledged(OLD.root_id,successor.acceptance_id) THEN RAISE EXCEPTION 'connector ticket supersession lacks exact acknowledged successor' USING ERRCODE='23514';END IF;
   END IF;
   RETURN NEW;
  END IF;
  IF OLD.restriction_at IS NULL AND NEW.restriction_at IS NOT NULL THEN
   IF NOT public.connector_identity_role_ok(OLD.root_id,'journal') OR OLD.activated_at IS NULL OR OLD.superseded_at IS NOT NULL OR OLD.admitted_at IS NOT NULL OR
    (to_jsonb(NEW)-ARRAY['restriction_at','restriction_source']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['restriction_at','restriction_source']) OR NEW.restriction_source IS NULL THEN RAISE EXCEPTION 'connector restrictive ticket transition unavailable' USING ERRCODE='23514';END IF;
   SELECT * INTO STRICT trust FROM public.fleet_current_trust WHERE installation_id=(OLD.ticket->'Binding'->>'InstallationID')::uuid FOR SHARE;
   SELECT * INTO STRICT root FROM public.connector_identity_root WHERE root_id=OLD.root_id FOR UPDATE;
   SELECT * INTO STRICT cfg FROM public.connector_identity_profile WHERE root_id=OLD.root_id AND peer_id=OLD.peer_id FOR UPDATE;
   n:=clock_timestamp();
   IF trust.recovery_blocked OR trust.suspended OR trust.observed_at>n OR n>=trust.fresh_until OR trust.issuer_epoch<>root.issuer_epoch OR NEW.restriction_at>n OR NEW.restriction_at<n-interval '5 seconds' OR
    cfg.retirement_ticket IS NOT NULL OR cfg.source_uid<>OLD.behavior_uid OR cfg.backing_revision<>OLD.backing_revision OR cfg.backing_digest<>OLD.backing_digest OR cfg.account_digest<>OLD.principal_digest OR
    NOT COALESCE((NEW.restriction_source->>'Cause'='originalAdmissionEnd' AND n>=OLD.admission_until AND NOT(NEW.restriction_source ? 'RetiringSource') AND
      (ROW(cfg.source_uid,cfg.source_generation,cfg.source_digest)=ROW(OLD.behavior_uid,OLD.behavior_generation,OLD.behavior_digest) OR cfg.suspended AND (cfg.configuration->>'Retiring')::boolean AND cfg.source_generation>OLD.behavior_generation)) OR
     (NEW.restriction_source->>'Cause'='protectedRetiringSource' AND cfg.suspended AND (cfg.configuration->>'Retiring')::boolean AND cfg.source_generation>OLD.behavior_generation AND
      NEW.restriction_source->'RetiringSource'->'Revision'=cfg.configuration->'Revision' AND public.connector_digest(NEW.restriction_source->'RetiringSource'->'CompleteDigest')=cfg.complete_digest),false) THEN RAISE EXCEPTION 'connector restrictive ticket differs from original cohort' USING ERRCODE='23514';END IF;
   RETURN NEW;
  END IF;
  IF OLD.admitted_at IS NULL AND NEW.admitted_at IS NOT NULL THEN
   IF NOT public.connector_identity_role_ok(OLD.root_id,'journal') OR OLD.activated_at IS NULL OR OLD.superseded_at IS NOT NULL OR OLD.restriction_at IS NULL OR OLD.closed_unused_at IS NOT NULL OR OLD.admission_closed_at IS NOT NULL OR OLD.acceptance_reference IS DISTINCT FROM OLD.acceptance_id OR
    (to_jsonb(NEW)-ARRAY['admitted_at','retirement_operation','retirement_reference']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['admitted_at','retirement_operation','retirement_reference']) OR NEW.retirement_operation IS DISTINCT FROM OLD.id OR NEW.retirement_reference IS DISTINCT FROM OLD.id THEN RAISE EXCEPTION 'connector retirement conversion unavailable' USING ERRCODE='23514';END IF;
   SELECT * INTO STRICT trust FROM public.fleet_current_trust WHERE installation_id=(OLD.ticket->'Binding'->>'InstallationID')::uuid FOR SHARE;
   SELECT * INTO STRICT root FROM public.connector_identity_root WHERE root_id=OLD.root_id FOR UPDATE;
   SELECT * INTO STRICT cfg FROM public.connector_identity_profile WHERE root_id=OLD.root_id AND peer_id=OLD.peer_id FOR UPDATE;
   n:=clock_timestamp();
   IF trust.recovery_blocked OR trust.suspended OR trust.observed_at>n OR n>=trust.fresh_until OR trust.issuer_epoch<>root.issuer_epoch OR NEW.admitted_at>n OR NEW.admitted_at<n-interval '5 seconds' OR n>=OLD.consume_until OR
    cfg.retirement_ticket IS DISTINCT FROM OLD.id OR cfg.retirement_at IS DISTINCT FROM OLD.restriction_at OR NOT cfg.fenced OR
    NOT public.connector_reservation_acknowledged(OLD.root_id,OLD.acceptance_id) OR EXISTS(SELECT 1 FROM public.operation_audit WHERE id=OLD.id) THEN RAISE EXCEPTION 'connector retirement original conversion interval unavailable' USING ERRCODE='23514';END IF;
   RETURN NEW;
  END IF;
  IF OLD.audit_dependency_closed_at IS NULL AND NEW.audit_dependency_closed_at IS NOT NULL THEN
   IF NOT public.connector_identity_role_ok(OLD.root_id,'cleanup') OR OLD.admitted_at IS NULL OR OLD.retirement_reference IS DISTINCT FROM OLD.id OR NEW.retirement_reference IS NOT NULL OR
    (to_jsonb(NEW)-ARRAY['retirement_reference','audit_dependency_closed_at']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['retirement_reference','audit_dependency_closed_at']) THEN RAISE EXCEPTION 'connector writer reference closure unavailable' USING ERRCODE='23514';END IF;
   SELECT * INTO STRICT trust FROM public.fleet_current_trust WHERE installation_id=(OLD.ticket->'Binding'->>'InstallationID')::uuid FOR SHARE;
   PERFORM 1 FROM public.connector_identity_root WHERE root_id=OLD.root_id FOR UPDATE;
   SELECT * INTO STRICT event FROM public.operation_audit WHERE id=OLD.retirement_reference AND root_id=OLD.root_id AND lane='identity' FOR UPDATE;
   n:=clock_timestamp();
   IF trust.recovery_blocked OR trust.suspended OR trust.observed_at>n OR n>=trust.fresh_until OR trust.issuer_epoch<>(OLD.ticket->'Binding'->>'IssuerEpoch')::uuid OR NEW.audit_dependency_closed_at>n OR NEW.audit_dependency_closed_at<n-interval '5 seconds' OR
    event.intent->>'Name' IS DISTINCT FROM 'connector_retirement' OR event.intent->'RetirementOrigin'->'Ticket' IS DISTINCT FROM OLD.ticket OR n<event.write_until THEN RAISE EXCEPTION 'connector writer still admits original effects' USING ERRCODE='23514';END IF;
   RETURN NEW;
  END IF;
  -- Closure is irreversible, separate from activation and from proving any
  -- admitted audit writer/object absent.
  IF NOT public.connector_identity_role_ok(OLD.root_id,'cleanup') OR OLD.admission_closed_at IS NOT NULL OR
   (to_jsonb(NEW)-ARRAY['acceptance_reference','admission_closed_at','closed_unused_at']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['acceptance_reference','admission_closed_at','closed_unused_at']) OR
   NEW.acceptance_reference IS NOT NULL OR NEW.admission_closed_at IS NULL THEN RAISE EXCEPTION 'connector ticket transition unavailable' USING ERRCODE='23514';END IF;
  SELECT * INTO STRICT trust FROM public.fleet_current_trust WHERE installation_id=(OLD.ticket->'Binding'->>'InstallationID')::uuid FOR SHARE;
  PERFORM 1 FROM public.connector_identity_root WHERE root_id=OLD.root_id FOR UPDATE;
  PERFORM 1 FROM public.connector_identity_profile WHERE root_id=OLD.root_id AND peer_id=OLD.peer_id FOR UPDATE;
  n:=clock_timestamp();
  IF trust.recovery_blocked OR trust.suspended OR trust.issuer_epoch<>(OLD.ticket->'Binding'->>'IssuerEpoch')::uuid OR trust.observed_at>n OR n>=trust.fresh_until OR
   NEW.admission_closed_at>n OR NEW.admission_closed_at<n-interval '5 seconds' OR
   NOT public.connector_ticket_admission_ended(OLD,n) OR
   (OLD.admitted_at IS NULL AND (NEW.closed_unused_at IS DISTINCT FROM NEW.admission_closed_at OR EXISTS(SELECT 1 FROM public.operation_audit WHERE id=OLD.id))) OR
   (OLD.admitted_at IS NOT NULL AND NEW.closed_unused_at IS NOT NULL) THEN RAISE EXCEPTION 'connector ticket closure is not proven restrictive' USING ERRCODE='23514';END IF;
  -- A positive unused closure spends no pair. Admitted/unknown pair charges
  -- are untouched; their independent verification/deletion still must finish.
  RETURN NEW;
 END IF;
 IF TG_OP='DELETE' THEN
  IF NOT public.connector_identity_role_ok(OLD.root_id,'cleanup') OR OLD.admission_closed_at IS NULL OR OLD.acceptance_reference IS NOT NULL OR OLD.retirement_reference IS NOT NULL OR (OLD.admitted_at IS NULL AND OLD.closed_unused_at IS NULL) THEN RAISE EXCEPTION 'connector ticket still admits work or retains audit dependency' USING ERRCODE='23514';END IF;
  SELECT * INTO STRICT trust FROM public.fleet_current_trust WHERE installation_id=(OLD.ticket->'Binding'->>'InstallationID')::uuid FOR SHARE;
  PERFORM 1 FROM public.connector_identity_root WHERE root_id=OLD.root_id FOR UPDATE;
  SELECT * INTO STRICT cfg FROM public.connector_identity_profile WHERE root_id=OLD.root_id AND peer_id=OLD.peer_id FOR UPDATE;
  n:=clock_timestamp();original_policy:=OLD.ticket->'Policy';
  IF trust.recovery_blocked OR trust.suspended OR trust.observed_at>n OR n>=trust.fresh_until OR trust.issuer_epoch<>(OLD.ticket->'Binding'->>'IssuerEpoch')::uuid OR
   n<OLD.retain_until-make_interval(secs=>((original_policy->>'BackupHorizonSeconds')::bigint+(original_policy->>'CleanupBudgetSeconds')::bigint)::double precision) OR
   EXISTS(SELECT 1 FROM public.operation_audit WHERE id=OLD.id) OR EXISTS(SELECT 1 FROM public.operation_audit_lifecycle WHERE operation_id=OLD.id) OR
   EXISTS(SELECT 1 FROM public.operation_audit_history h WHERE h.root_id=OLD.root_id AND h.lane='identity' AND h.principal_digest=OLD.principal_digest AND h.release_at=OLD.retain_until-make_interval(secs=>((original_policy->>'BackupHorizonSeconds')::bigint+(original_policy->>'CleanupBudgetSeconds')::bigint)::double precision) AND h.delete_by=OLD.retain_until-make_interval(secs=>(original_policy->>'BackupHorizonSeconds')::double precision)) OR
   (OLD.activated_at IS NOT NULL AND OLD.superseded_at IS NULL AND (NOT cfg.fenced OR cfg.retirement_ticket IS DISTINCT FROM OLD.id OR cfg.retirement_at IS DISTINCT FROM OLD.restriction_at)) THEN RAISE EXCEPTION 'connector original ticket history or cohort fence remains unresolved' USING ERRCODE='23514';END IF;
  -- Positive exact history absence above is mandatory: reaching the original
  -- history-release instant alone proves no cleanup. Independent source-row
  -- backing remains reserved through retain_until after this row is deleted.
  -- The profile's separately paid minimal control fence remains. Later
  -- possible leaves keep their own process/audit charges and original dates.
  RETURN OLD;
 END IF;
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'connector ticket mutation unavailable' USING ERRCODE='23514';END IF;
 IF NOT public.connector_identity_role_ok(NEW.root_id,'journal') OR NOT public.connector_retirement_row_valid(NEW) OR NEW.acceptance_reference IS DISTINCT FROM NEW.acceptance_id OR NEW.admission_closed_at IS NOT NULL OR NEW.activated_at IS NOT NULL OR NEW.superseded_at IS NOT NULL OR NEW.restriction_at IS NOT NULL OR NEW.restriction_source IS NOT NULL OR NEW.admitted_at IS NOT NULL OR NEW.closed_unused_at IS NOT NULL OR NEW.retirement_operation IS NOT NULL OR NEW.retirement_reference IS NOT NULL OR NEW.audit_dependency_closed_at IS NOT NULL THEN RAISE EXCEPTION 'connector reservation source unavailable' USING ERRCODE='23514';END IF;
 SELECT * INTO STRICT trust FROM public.fleet_current_trust WHERE installation_id=(NEW.ticket->'Binding'->>'InstallationID')::uuid FOR SHARE;
 SELECT * INTO STRICT root FROM public.connector_identity_root WHERE root_id=NEW.root_id FOR UPDATE;
 SELECT * INTO STRICT cfg FROM public.connector_identity_profile WHERE root_id=NEW.root_id AND peer_id=NEW.peer_id FOR UPDATE;
 SELECT * INTO STRICT pool FROM public.operation_audit_pool WHERE root_id=NEW.root_id AND lane='identity' FOR UPDATE;
 n:=clock_timestamp();original_policy:=NEW.ticket->'Policy';
 IF NEW.acceptance_id=root.pending_id THEN selected_backing:=root.pending_backing;ELSE selected_backing:=root.backing;END IF;
 IF NOT COALESCE(NOT trust.recovery_blocked AND NOT trust.suspended AND trust.issuer_epoch=root.issuer_epoch AND trust.observed_at<=n AND n<trust.fresh_until AND n<root.valid_until AND n<pool.valid_until AND NOT pool.paused AND
  NEW.reserved_at<=n AND n<NEW.reserved_at+interval '5 seconds' AND n<NEW.admission_until AND
  NEW.ticket->'Binding'=cfg.configuration->'Binding' AND
  ((NEW.acceptance_id IS DISTINCT FROM root.pending_id AND NEW.behavior_uid=cfg.source_uid AND NEW.behavior_generation=cfg.source_generation AND NEW.behavior_digest=cfg.source_digest AND NEW.ticket->'ServingSlots'=cfg.configuration->'Deployment'->'ServingSlots' AND NEW.ticket->'RetainedProcesses'=cfg.configuration->'Deployment'->'RetainedProcesses') OR
   (NEW.acceptance_id=root.pending_id AND NOT COALESCE((cfg.configuration->>'Retiring')::boolean,false) AND EXISTS(SELECT 1 FROM public.connector_retirement_ticket previous_ticket WHERE previous_ticket.root_id=NEW.root_id AND previous_ticket.peer_id=NEW.peer_id AND previous_ticket.activated_at IS NOT NULL AND previous_ticket.superseded_at IS NULL AND previous_ticket.restriction_at IS NULL AND previous_ticket.admitted_at IS NULL AND previous_ticket.closed_unused_at IS NULL AND previous_ticket.backing_revision=(root.policy->>'BackingRevision')::bigint AND previous_ticket.backing_digest=root.backing_digest AND previous_ticket.behavior_uid=NEW.behavior_uid AND previous_ticket.behavior_generation=NEW.behavior_generation AND previous_ticket.behavior_digest=NEW.behavior_digest AND previous_ticket.ticket->'ServingSlots'=NEW.ticket->'ServingSlots' AND previous_ticket.ticket->'RetainedProcesses'=NEW.ticket->'RetainedProcesses' AND previous_ticket.principal_digest=NEW.principal_digest))) AND
  NEW.backing_revision=(selected_backing->'Policy'->>'BackingRevision')::bigint AND NEW.backing_digest=(CASE WHEN NEW.acceptance_id=root.pending_id THEN root.pending_digest ELSE root.backing_digest END) AND
  NEW.admission_until=(selected_backing->'Policy'->>'ValidUntil')::timestamptz AND NEW.ticket->>'AccountVersion'=pool.account_version AND
  (cfg.account_digest IS NULL OR cfg.account_digest=NEW.principal_digest) AND
  (original_policy - ARRAY['PolicyID','PolicyDigest','ValidUntil'])=((selected_backing->'Policy') - ARRAY['PolicyID','PolicyDigest','ValidUntil']) AND
  original_policy->'History'=root.qualification AND original_policy->'History'->>'Layout'='connector-operation-history/v2' AND
  NEW.retain_until=NEW.reserved_at+make_interval(secs=>pool.retained_seconds::double precision),false) THEN RAISE EXCEPTION 'connector reservation original backing unavailable' USING ERRCODE='23514';END IF;
 IF EXISTS(SELECT 1 FROM public.operation_audit WHERE id=NEW.acceptance_id) OR
  EXISTS(SELECT 1 FROM public.connector_retirement_ticket old_ticket WHERE old_ticket.root_id=NEW.root_id AND old_ticket.peer_id=NEW.peer_id AND old_ticket.activated_at IS NOT NULL AND old_ticket.superseded_at IS NULL AND (old_ticket.restriction_at IS NOT NULL OR old_ticket.admitted_at IS NOT NULL)) THEN
  RAISE EXCEPTION 'connector reservation acceptance closed or cohort retired' USING ERRCODE='23514';END IF;
 SELECT * INTO account FROM public.operation_audit_account WHERE root_id=NEW.root_id AND lane='identity' AND principal_digest=NEW.principal_digest FOR UPDATE;
 IF NOT FOUND THEN
  IF pool.accounts>=pool.account_limit THEN RAISE EXCEPTION 'connector reservation accounts exhausted' USING ERRCODE='23514';END IF;
  UPDATE public.operation_audit_pool SET accounts=accounts+1 WHERE root_id=NEW.root_id AND lane='identity';
  INSERT INTO public.operation_audit_account(root_id,lane,principal_digest) VALUES(NEW.root_id,'identity',NEW.principal_digest) RETURNING * INTO account;
 END IF;
 SELECT count(*) INTO reserved FROM public.connector_retirement_ticket WHERE root_id=NEW.root_id AND principal_digest=NEW.principal_digest AND admitted_at IS NULL AND closed_unused_at IS NULL;
 IF account.charged+reserved>=pool.records_per_account OR clock_timestamp()>=NEW.reserved_at+interval '5 seconds' OR clock_timestamp()>=trust.fresh_until OR clock_timestamp()>=root.valid_until THEN RAISE EXCEPTION 'connector restrictive reservation capacity or interval unavailable' USING ERRCODE='23514';END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION guard_connector_ticket_reservation() FROM PUBLIC;
CREATE TRIGGER connector_ticket_reservation_guard BEFORE INSERT OR UPDATE OR DELETE ON connector_retirement_ticket
 FOR EACH ROW EXECUTE FUNCTION guard_connector_ticket_reservation();

-- +goose StatementBegin
CREATE FUNCTION preserve_connector_ticket_backing() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE pool public.operation_audit_pool; account public.operation_audit_account; reserved bigint; n timestamptz;
BEGIN
 IF TG_RELID<>'public.operation_audit'::regclass OR TG_WHEN<>'BEFORE' OR TG_OP<>'INSERT' OR TG_LEVEL<>'ROW' THEN RAISE EXCEPTION 'invalid connector ticket accounting source' USING ERRCODE='23514';END IF;
 IF NEW.lane<>'identity' THEN RETURN NEW;END IF;
 IF NOT public.connector_identity_role_ok(NEW.root_id,'journal') THEN RAISE EXCEPTION 'connector reservation accounting role unavailable' USING ERRCODE='23514';END IF;
 -- The purpose-fixed business entry point locks recovery/root/profile before
 -- reaching the pool. Holding root here also serializes ticket release/consume;
 -- generic callers have no base-table INSERT or callable admission capability.
 PERFORM 1 FROM public.connector_identity_root WHERE root_id=NEW.root_id FOR UPDATE;
 SELECT * INTO STRICT pool FROM public.operation_audit_pool WHERE root_id=NEW.root_id AND lane='identity' FOR UPDATE;
 SELECT * INTO account FROM public.operation_audit_account WHERE root_id=NEW.root_id AND lane='identity' AND principal_digest=NEW.principal_digest FOR UPDATE;
 SELECT count(*) INTO reserved FROM public.connector_retirement_ticket WHERE root_id=NEW.root_id AND principal_digest=NEW.principal_digest AND admitted_at IS NULL AND closed_unused_at IS NULL;
 n:=clock_timestamp();
 IF COALESCE(account.charged,0)+reserved>=pool.records_per_account OR n>=NEW.request_until THEN RAISE EXCEPTION 'ordinary connector work cannot spend restrictive reservation' USING ERRCODE='23514';END IF;
 IF NEW.intent->>'Name'='connector_retirement' THEN
  -- Admission atomically converts exactly one pre-existing reservation to its
  -- original audit charge before this INSERT. It is not extra capacity.
  IF NOT EXISTS(SELECT 1 FROM public.connector_retirement_ticket t WHERE t.id=NEW.id AND t.root_id=NEW.root_id AND t.principal_digest=NEW.principal_digest AND t.retirement_operation=NEW.id AND t.admitted_at=(NEW.intent->>'CreatedAt')::timestamptz AND t.restriction_at IS NOT NULL AND t.superseded_at IS NULL AND t.closed_unused_at IS NULL AND t.admission_closed_at IS NULL AND t.acceptance_reference=t.acceptance_id AND t.ticket=NEW.intent->'RetirementOrigin'->'Ticket' AND public.connector_digest(NEW.intent->'RetirementOrigin'->'TicketDigest')=t.ticket_digest) THEN RAISE EXCEPTION 'connector retirement has no exact prepaid admission' USING ERRCODE='23514';END IF;
 END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION preserve_connector_ticket_backing() FROM PUBLIC;
CREATE TRIGGER operation_audit_01_connector_reserve BEFORE INSERT ON operation_audit FOR EACH ROW EXECUTE FUNCTION preserve_connector_ticket_backing();


-- Admission and closure serialize on the existing root. This function does not
-- retire a workload, claim audit completion, delete evidence or reclaim an
-- admitted pair. It proves only that this exact ticket can never admit again.
-- +goose StatementBegin
CREATE FUNCTION close_connector_retirement_admission(r uuid,ticket_id uuid) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE started timestamptz:=clock_timestamp(); trust public.fleet_current_trust; root public.connector_identity_root;
 ticket_row public.connector_retirement_ticket; n timestamptz;
BEGIN
 IF NOT public.connector_identity_role_ok(r,'cleanup') THEN RAISE EXCEPTION 'connector ticket close role unavailable' USING ERRCODE='23514';END IF;
 SELECT t.* INTO STRICT trust FROM public.fleet_current_trust t JOIN public.connector_identity_root x ON x.installation_id=t.installation_id WHERE x.root_id=r FOR SHARE OF t;
 SELECT * INTO STRICT root FROM public.connector_identity_root WHERE root_id=r FOR UPDATE;
 -- Derive only immutable routing fields after the root is held, then acquire
 -- the same profile/pool/account/ticket order as reservation and admission.
 SELECT * INTO STRICT ticket_row FROM public.connector_retirement_ticket WHERE root_id=r AND id=ticket_id;
 PERFORM 1 FROM public.connector_identity_profile WHERE root_id=r AND peer_id=ticket_row.peer_id FOR UPDATE;
 PERFORM 1 FROM public.operation_audit_pool WHERE root_id=r AND lane='identity' FOR UPDATE;
 PERFORM 1 FROM public.operation_audit_account WHERE root_id=r AND lane='identity' AND principal_digest=ticket_row.principal_digest FOR UPDATE;
 SELECT * INTO STRICT ticket_row FROM public.connector_retirement_ticket WHERE root_id=r AND id=ticket_id FOR UPDATE;
 n:=clock_timestamp();
 IF trust.recovery_blocked OR trust.suspended OR trust.issuer_epoch<>root.issuer_epoch OR trust.observed_at>n OR n>=trust.fresh_until OR n>=started+interval '5 seconds' THEN RAISE EXCEPTION 'connector ticket close recovery unavailable' USING ERRCODE='23514';END IF;
 IF ticket_row.admission_closed_at IS NOT NULL THEN RETURN true;END IF;
 IF NOT public.connector_ticket_admission_ended(ticket_row,n) THEN RAISE EXCEPTION 'connector ticket still admits original work' USING ERRCODE='23514';END IF;
 IF ticket_row.admitted_at IS NULL AND EXISTS(SELECT 1 FROM public.operation_audit WHERE id=ticket_row.id) THEN RAISE EXCEPTION 'connector ticket admission outcome unresolved' USING ERRCODE='23514';END IF;
 UPDATE public.connector_retirement_ticket SET acceptance_reference=NULL,admission_closed_at=n,
  closed_unused_at=CASE WHEN admitted_at IS NULL THEN n ELSE NULL END WHERE root_id=r AND id=ticket_id;
 IF clock_timestamp()>=trust.fresh_until OR clock_timestamp()>=started+interval '5 seconds' THEN RAISE EXCEPTION 'connector ticket close original interval expired' USING ERRCODE='23514';END IF;
 RETURN true;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION close_connector_retirement_admission(uuid,uuid) FROM PUBLIC;


-- V2 independently backs every retained ticket-row generation as source
-- state. No ticket borrows a released audit-pair slot. The v1 predicate remains
-- unchanged; no qualification or capacity is synthesized by this check.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION guard_connector_identity_root() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE t public.fleet_current_trust; login record; role_name name; role_oid oid; n timestamptz; q jsonb;
BEGIN
 IF TG_RELID<>'public.connector_identity_root'::regclass OR TG_WHEN<>'BEFORE' OR TG_LEVEL<>'ROW' OR TG_OP='DELETE' THEN RAISE EXCEPTION 'connector backing retirement unavailable' USING ERRCODE='23514';END IF;
 SELECT * INTO STRICT t FROM public.fleet_current_trust WHERE installation_id=NEW.installation_id FOR SHARE;
 n:=clock_timestamp();
 IF t.recovery_blocked OR t.suspended OR n>=t.fresh_until OR t.observed_at>n OR NEW.issuer_epoch<>t.issuer_epoch OR NEW.postmaster_at<>pg_postmaster_start_time() OR NEW.database_oid<>(SELECT oid FROM pg_catalog.pg_database WHERE datname=current_database()) THEN RAISE EXCEPTION 'connector backing recovery unavailable' USING ERRCODE='23514';END IF;
 IF TG_OP='INSERT' THEN
  IF NEW.profiles<>0 OR NEW.source_transitions<>0 OR NEW.source_name<>session_user OR NEW.valid_until<=n OR NEW.pending_id IS NOT NULL OR NEW.active_backing_id IS NOT NULL OR NEW.closed_candidate_id IS NOT NULL THEN RAISE EXCEPTION 'connector source role unavailable' USING ERRCODE='23514';END IF;
  FOR role_name,role_oid IN SELECT * FROM (VALUES(NEW.source_name,NEW.source_oid),(NEW.journal_name,NEW.journal_oid),(NEW.acknowledgement_name,NEW.acknowledgement_oid),(NEW.cleanup_name,NEW.cleanup_oid),(NEW.verifier_name,NEW.verifier_oid),(NEW.finalizer_name,NEW.finalizer_oid)) AS pin(role_name,role_oid) LOOP
   SELECT oid,rolname,rolcanlogin,rolsuper,rolcreaterole,rolcreatedb,rolreplication,rolbypassrls INTO login FROM pg_catalog.pg_roles WHERE oid=role_oid AND rolname=role_name;
   IF NOT FOUND OR NOT login.rolcanlogin OR login.rolsuper OR login.rolcreaterole OR login.rolcreatedb OR login.rolreplication OR login.rolbypassrls OR EXISTS(SELECT 1 FROM pg_catalog.pg_auth_members WHERE member=role_oid) OR EXISTS(SELECT 1 FROM pg_catalog.pg_class WHERE relowner=role_oid) OR EXISTS(SELECT 1 FROM pg_catalog.pg_namespace WHERE nspowner=role_oid) THEN RAISE EXCEPTION 'connector role pin unavailable' USING ERRCODE='23514';END IF;
  END LOOP;
 ELSE
  IF NOT public.connector_identity_role_ok(NEW.root_id,'source') THEN RAISE EXCEPTION 'connector source role unavailable' USING ERRCODE='23514';END IF;
  IF NEW.backing IS DISTINCT FROM OLD.backing THEN
   IF NEW.profiles<>OLD.profiles OR NEW.source_transitions<>OLD.source_transitions OR
    OLD.pending_id IS NULL OR NEW.active_backing_id IS DISTINCT FROM OLD.pending_id OR NEW.pending_id IS NOT NULL OR
    NEW.backing IS DISTINCT FROM OLD.pending_backing OR NEW.backing_digest IS DISTINCT FROM OLD.pending_digest OR
    NEW.policy IS DISTINCT FROM NEW.backing->'Policy' OR NEW.valid_until<>(NEW.policy->>'ValidUntil')::timestamptz OR
    NOT public.connector_backing_can_renew(OLD.backing,NEW.backing) OR
    (to_jsonb(NEW)-ARRAY['backing','backing_digest','policy','valid_until','active_backing_id','pending_id','pending_backing','pending_digest','pending_at','source_transitions']) IS DISTINCT FROM
    (to_jsonb(OLD)-ARRAY['backing','backing_digest','policy','valid_until','active_backing_id','pending_id','pending_backing','pending_digest','pending_at','source_transitions']) OR
    NOT EXISTS(SELECT 1 FROM public.connector_backing_transition b JOIN public.operation_audit a ON a.id=b.id AND a.root_id=b.root_id JOIN public.operation_audit_lifecycle l ON l.operation_id=a.id AND l.root_id=a.root_id
      WHERE b.id=OLD.pending_id AND b.root_id=OLD.root_id AND b.previous_backing=OLD.backing AND b.proposed->'Backing'=NEW.backing AND b.activated_at IS NOT NULL AND b.closed_at IS NULL
      AND a.intent_receipt IS NOT NULL AND a.outcome_receipt IS NOT NULL AND l.intent_completion->'Receipt'=a.intent_receipt AND l.outcome_completion->'Receipt'=a.outcome_receipt)
    THEN RAISE EXCEPTION 'connector backing promotion unavailable' USING ERRCODE='23514';END IF;
  ELSIF NEW.pending_id IS DISTINCT FROM OLD.pending_id THEN
   IF (to_jsonb(NEW)-ARRAY['pending_id','pending_backing','pending_digest','pending_at','closed_candidate_id','closed_candidate_digest','closed_candidate_revision','closed_candidate_at','source_transitions']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['pending_id','pending_backing','pending_digest','pending_at','closed_candidate_id','closed_candidate_digest','closed_candidate_revision','closed_candidate_at','source_transitions']) OR NEW.source_transitions<>OLD.source_transitions+(CASE WHEN OLD.pending_id IS NULL THEN 2 ELSE 0 END) OR NEW.source_transitions>OLD.source_transition_limit THEN RAISE EXCEPTION 'connector candidate mutation unavailable' USING ERRCODE='23514';END IF;
   IF OLD.pending_id IS NULL THEN
    IF NEW.pending_id IS NULL OR NEW.pending_at>n OR n>=OLD.valid_until OR NEW.pending_id IS NOT DISTINCT FROM OLD.closed_candidate_id OR ROW(NEW.closed_candidate_id,NEW.closed_candidate_digest,NEW.closed_candidate_revision,NEW.closed_candidate_at) IS DISTINCT FROM ROW(OLD.closed_candidate_id,OLD.closed_candidate_digest,OLD.closed_candidate_revision,OLD.closed_candidate_at) OR NOT public.connector_backing_can_renew(OLD.backing,NEW.pending_backing) THEN RAISE EXCEPTION 'connector candidate backing unavailable' USING ERRCODE='23514';END IF;
   ELSIF NEW.pending_id IS NOT NULL OR NEW.closed_candidate_id IS DISTINCT FROM OLD.pending_id OR NEW.closed_candidate_digest IS DISTINCT FROM OLD.pending_digest OR NEW.closed_candidate_revision<>(OLD.pending_backing->'Policy'->>'BackingRevision')::bigint OR NEW.closed_candidate_at IS NULL OR NEW.closed_candidate_at>n OR
    EXISTS(SELECT 1 FROM public.connector_backing_transition b WHERE b.id=OLD.pending_id AND b.root_id=OLD.root_id AND b.closed_at IS NULL) OR
    EXISTS(SELECT 1 FROM public.operation_audit a WHERE a.id=OLD.pending_id AND NOT EXISTS(SELECT 1 FROM public.connector_backing_transition b WHERE b.id=a.id AND b.root_id=OLD.root_id AND b.closed_at IS NOT NULL)) THEN RAISE EXCEPTION 'connector candidate must be positively closed' USING ERRCODE='23514';END IF;
  ELSIF (to_jsonb(NEW)-ARRAY['profiles','source_transitions']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['profiles','source_transitions']) OR pg_trigger_depth()<2 OR
    NEW.profiles NOT BETWEEN OLD.profiles AND OLD.profiles+1 OR NEW.source_transitions<>OLD.source_transitions+1 THEN RAISE EXCEPTION 'immutable connector role/backing pins' USING ERRCODE='23514';END IF;
 END IF;
 q:=NEW.qualification;
 IF NOT COALESCE(q->>'Layout' IN('connector-operation-history/v1','connector-operation-history/v2') AND NEW.policy->'History'=q AND NEW.backing->'Policy'=NEW.policy AND NEW.policy->>'Lane'='identity' AND NEW.policy->>'OverdueTerminal'='overdue-original/v1' AND (NEW.policy->>'RootID')::uuid=NEW.root_id AND (NEW.policy->>'InstallationID')::uuid=NEW.installation_id AND
  (q->>'ID')::uuid IS NOT NULL AND jsonb_array_length(q->'Digest')=32 AND
  (q->>'MaximumRowFootprintBytes')::bigint BETWEEN 1048576 AND 16777216 AND (q->>'MaximumTransitionWALBytes')::bigint BETWEEN 131072 AND 67108864 AND (q->>'BackupCopies')::bigint BETWEEN 1 AND 64 AND (q->>'WALCopies')::bigint BETWEEN 1 AND 64 AND
  NEW.source_backup_bytes/(NEW.profile_limit+1+(CASE WHEN q->>'Layout'='connector-operation-history/v2' THEN NEW.profile_limit*(NEW.source_transition_limit+1) ELSE 0 END))>=2*(q->>'MaximumRowFootprintBytes')::bigint*(q->>'BackupCopies')::bigint AND NEW.source_wal_bytes/(q->>'MaximumTransitionWALBytes')::bigint/(q->>'WALCopies')::bigint>=2*NEW.source_transition_limit+(CASE WHEN q->>'Layout'='connector-operation-history/v2' THEN 10*NEW.profile_limit*(NEW.source_transition_limit+1) ELSE 0 END) AND NEW.valid_until=(NEW.policy->>'ValidUntil')::timestamptz,false) THEN RAISE EXCEPTION 'connector qualification/backing unavailable' USING ERRCODE='23514';END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION guard_connector_identity_root() FROM PUBLIC;

-- Closed private producer helpers. No direct runtime EXECUTE is granted. The
-- concrete admission wrappers retain the actual original process/current proof
-- and root lock; callers cannot turn a retained JSON image into current scope.
-- +goose StatementBegin
CREATE FUNCTION reserve_connector_retirement_images(r uuid,acceptance uuid,images bytea[],request_until timestamptz) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE root public.connector_identity_root; raw bytea; item jsonb; maximum integer; total bigint:=0; started timestamptz:=clock_timestamp();
BEGIN
 IF NOT public.connector_identity_role_ok(r,'journal') OR array_ndims(images) IS DISTINCT FROM 1 OR array_lower(images,1) IS DISTINCT FROM 1 OR cardinality(images) NOT BETWEEN 1 AND 4096 OR request_until IS NULL OR request_until>started+interval '5 seconds' THEN RAISE EXCEPTION 'connector reservation producer unavailable' USING ERRCODE='23514';END IF;
 SELECT profile_limit::integer INTO STRICT maximum FROM public.connector_identity_root WHERE root_id=r FOR UPDATE;
 IF cardinality(images)>maximum OR EXISTS(SELECT 1 FROM public.operation_audit WHERE id=acceptance) OR EXISTS(SELECT 1 FROM public.connector_retirement_ticket WHERE root_id=r AND acceptance_id=acceptance) THEN RAISE EXCEPTION 'connector reservation already committed or over capacity' USING ERRCODE='23514';END IF;
 FOREACH raw IN ARRAY images LOOP
  IF raw IS NULL OR octet_length(raw) NOT BETWEEN 1 AND 16384 THEN RAISE EXCEPTION 'connector ticket image exceeds fixed bound' USING ERRCODE='23514';END IF;
  total:=total+octet_length(raw);
 END LOOP;
 -- At most 64 MiB of immutable accepted input across the existing 4096-peer
 -- ceiling. Each row is independently checked before it enters the set; no
 -- unbounded retained map or replacement after the event INSERT exists.
 IF total>67108864 OR clock_timestamp()>=request_until THEN RAISE EXCEPTION 'connector reservation input or original interval unavailable' USING ERRCODE='23514';END IF;
 FOREACH raw IN ARRAY images LOOP
  IF clock_timestamp()>=request_until THEN RAISE EXCEPTION 'connector reservation original interval expired' USING ERRCODE='23514';END IF;
  item:=convert_from(raw,'UTF8')::jsonb;
  IF NOT public.connector_retirement_ticket_valid(item) OR (item->>'RootID')::uuid<>r OR (item->>'AcceptanceID')::uuid<>acceptance THEN RAISE EXCEPTION 'connector reservation image differs from original acceptance' USING ERRCODE='23514';END IF;
  INSERT INTO public.connector_retirement_ticket(id,root_id,peer_id,acceptance_id,acceptance_reference,behavior_uid,behavior_generation,behavior_digest,backing_revision,backing_digest,principal_digest,canonical_bytes,ticket,ticket_digest,reserved_at,admission_until,consume_until,original_purge_at,retain_until)
  VALUES((item->>'ID')::uuid,r,(item->'Binding'->>'PeerID')::uuid,acceptance,acceptance,(item->'Behavior'->>'UID')::uuid,(item->'Behavior'->>'Generation')::bigint,public.connector_digest(item->'Behavior'->'Digest'),(item->>'BackingRevision')::bigint,public.connector_digest(item->'BackingDigest'),public.connector_digest(item->'PrincipalDigest'),raw,item,public.connector_retirement_ticket_digest(raw),(item->>'ReservedAt')::timestamptz,(item->>'AdmissionUntil')::timestamptz,(item->>'ConsumeUntil')::timestamptz,(item->>'ConsumeUntil')::timestamptz+interval '30 seconds',(item->>'RetainUntil')::timestamptz);
 END LOOP;
 IF clock_timestamp()>=request_until THEN RAISE EXCEPTION 'connector reservation expired after writes' USING ERRCODE='23514';END IF;
 RETURN public.connector_retirement_set_digest(r,acceptance);
END $$;

CREATE FUNCTION admit_connector_process_reserved(r uuid,c jsonb,i jsonb,process_value jsonb,images bytea[]) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE existing jsonb; commitment jsonb; cfg public.connector_identity_profile; operation uuid:=(i->>'ID')::uuid;
BEGIN
 -- The ordinary exact-current reader locks recovery/root/profile and rejects
 -- caller-selected identity, replacement keys, recovery or source changes.
 cfg:=public.lock_connector_process_current(r,c,true);
 existing:=public.read_connector_process_admission(r,operation,c);
 IF existing IS NOT NULL THEN RETURN existing;END IF;
 IF i->'Lifecycle'->'Policy'->'History'->>'Layout' IS DISTINCT FROM 'connector-operation-history/v2' THEN RAISE EXCEPTION 'connector retirement reservation qualification missing' USING ERRCODE='23514';END IF;
 IF i ? 'ConnectorReservations' THEN
  IF cardinality(images) IS DISTINCT FROM 1 THEN RAISE EXCEPTION 'initial connector ticket set differs' USING ERRCODE='23514';END IF;
  commitment:=public.reserve_connector_retirement_images(r,operation,images,(c->>'Until')::timestamptz);
  IF commitment IS DISTINCT FROM i->'ConnectorReservations' THEN RAISE EXCEPTION 'initial connector ticket digest differs' USING ERRCODE='23514';END IF;
 ELSIF COALESCE(cardinality(images),0)<>0 THEN RAISE EXCEPTION 'unbound connector ticket image' USING ERRCODE='23514';END IF;
 -- INSERT's v2 set guard distinguishes a matching existing active ticket from
 -- first admission. The same transaction rolls back every row on a mismatch.
 RETURN public.admit_connector_process(r,c,i,process_value);
END $$;

CREATE FUNCTION admit_connector_backing_reserved(r uuid,c jsonb,i jsonb,images bytea[]) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE existing jsonb; commitment jsonb; cfg public.connector_identity_profile; operation uuid:=(i->>'ID')::uuid;
BEGIN
 cfg:=public.lock_connector_backing_current(r,c);
 existing:=public.read_connector_backing_admission(r,operation,c);
 IF existing IS NOT NULL THEN RETURN existing;END IF;
 IF i->'Lifecycle'->'Policy'->'History'->>'Layout' IS DISTINCT FROM 'connector-operation-history/v2' OR NOT(i ? 'ConnectorReservations') THEN RAISE EXCEPTION 'connector successor reservation qualification missing' USING ERRCODE='23514';END IF;
 commitment:=public.reserve_connector_retirement_images(r,operation,images,(c->>'Until')::timestamptz);
 IF commitment IS DISTINCT FROM i->'ConnectorReservations' THEN RAISE EXCEPTION 'connector successor ticket digest differs' USING ERRCODE='23514';END IF;
 -- The event INSERT independently compares the exact full eligible old/new
 -- set, even when another peer has not observed its new complete source yet.
 RETURN public.admit_connector_backing(r,c,i);
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION reserve_connector_retirement_images(uuid,uuid,bytea[],timestamptz),admit_connector_process_reserved(uuid,jsonb,jsonb,jsonb,bytea[]),admit_connector_backing_reserved(uuid,jsonb,jsonb,bytea[]) FROM PUBLIC;

-- Only minimized original cohort/account facts leave these current private
-- readers. A new peer-specific source observation is never constructed here.
-- +goose StatementBegin
CREATE FUNCTION read_connector_process_ticket(r uuid,c jsonb) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE cfg public.connector_identity_profile; root public.connector_identity_root; result boolean;
BEGIN
 cfg:=public.lock_connector_process_current(r,c,true);
 SELECT * INTO STRICT root FROM public.connector_identity_root WHERE root_id=r FOR UPDATE;
 SELECT EXISTS(SELECT 1 FROM public.connector_retirement_ticket t WHERE t.root_id=r AND t.peer_id=cfg.peer_id AND t.activated_at IS NOT NULL AND t.superseded_at IS NULL AND t.restriction_at IS NULL AND t.admitted_at IS NULL AND t.closed_unused_at IS NULL AND t.admission_closed_at IS NULL AND t.acceptance_reference=t.acceptance_id
   AND t.behavior_uid=cfg.source_uid AND t.behavior_generation=cfg.source_generation AND t.behavior_digest=cfg.source_digest
   AND t.backing_revision=(root.policy->>'BackingRevision')::bigint AND t.backing_digest=root.backing_digest AND clock_timestamp()<t.admission_until)
 INTO result;
 IF clock_timestamp()>=(c->>'Until')::timestamptz THEN RAISE EXCEPTION 'connector ticket reader original interval expired' USING ERRCODE='23514';END IF;
 RETURN jsonb_build_object('Existing',result,'Cohort',jsonb_build_object('RootID',r,'Binding',cfg.configuration->'Binding','Behavior',cfg.configuration->'Revision','ServingSlots',cfg.configuration->'Deployment'->'ServingSlots','RetainedProcesses',cfg.configuration->'Deployment'->'RetainedProcesses','BackingRevision',(root.policy->>'BackingRevision')::bigint,'BackingDigest',to_jsonb(ARRAY(SELECT get_byte(root.backing_digest,i) FROM generate_series(0,31) i))));
END $$;

CREATE FUNCTION read_connector_successor_cohorts(r uuid,c jsonb) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE cfg public.connector_identity_profile; root public.connector_identity_root; result jsonb; total bigint;
BEGIN
 cfg:=public.lock_connector_backing_current(r,c);
 SELECT * INTO STRICT root FROM public.connector_identity_root WHERE root_id=r FOR UPDATE;
 IF root.pending_id IS NULL OR root.pending_backing IS DISTINCT FROM c->'Configuration'->'Backing' OR root.qualification->>'Layout' IS DISTINCT FROM 'connector-operation-history/v2' THEN RAISE EXCEPTION 'connector successor candidate unavailable' USING ERRCODE='23514';END IF;
 SELECT count(*),jsonb_agg(jsonb_build_object('Cohort',jsonb_build_object('RootID',r,'Binding',t.ticket->'Binding','Behavior',t.ticket->'Behavior','ServingSlots',t.ticket->'ServingSlots','RetainedProcesses',t.ticket->'RetainedProcesses','BackingRevision',t.backing_revision,'BackingDigest',t.ticket->'BackingDigest'),'AccountDigest',t.ticket->'PrincipalDigest') ORDER BY t.peer_id)
 INTO total,result
 FROM public.connector_retirement_ticket t JOIN public.connector_identity_profile p ON p.root_id=t.root_id AND p.peer_id=t.peer_id
 WHERE t.root_id=r AND t.activated_at IS NOT NULL AND t.superseded_at IS NULL AND t.restriction_at IS NULL AND t.admitted_at IS NULL AND t.closed_unused_at IS NULL
  AND NOT COALESCE((p.configuration->>'Retiring')::boolean,false);
 IF total NOT BETWEEN 1 AND root.profile_limit OR total>4096 OR octet_length(result::text)>8388608 OR clock_timestamp()>=(c->>'Until')::timestamptz THEN RAISE EXCEPTION 'connector successor set bound or interval unavailable' USING ERRCODE='23514';END IF;
 RETURN result;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION read_connector_process_ticket(uuid,jsonb),read_connector_successor_cohorts(uuid,jsonb) FROM PUBLIC;

-- A writer receipt can never acknowledge a different or missing immutable
-- reservation set. This repeats one bounded linear hash, not one hash per row.
-- +goose StatementBegin
CREATE FUNCTION guard_connector_reservation_acknowledgement() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE actual jsonb;
BEGIN
 IF TG_RELID<>'public.operation_audit'::regclass OR TG_WHEN<>'BEFORE' OR TG_OP<>'UPDATE' OR TG_LEVEL<>'ROW' THEN RAISE EXCEPTION 'invalid connector reservation acknowledgement source' USING ERRCODE='23514';END IF;
 IF NEW.lane<>'identity' OR NOT(NEW.intent ? 'ConnectorReservations') OR ROW(NEW.intent_receipt,NEW.outcome_receipt) IS NOT DISTINCT FROM ROW(OLD.intent_receipt,OLD.outcome_receipt) THEN RETURN NEW;END IF;
 IF NOT public.connector_identity_role_ok(NEW.root_id,'acknowledgement') THEN RAISE EXCEPTION 'connector reservation acknowledgement role unavailable' USING ERRCODE='23514';END IF;
 PERFORM 1 FROM public.connector_identity_root WHERE root_id=NEW.root_id FOR UPDATE;
 actual:=public.connector_retirement_set_digest(NEW.root_id,NEW.id);
 IF actual IS DISTINCT FROM NEW.intent->'ConnectorReservations' OR EXISTS(SELECT 1 FROM public.connector_retirement_ticket t WHERE t.root_id=NEW.root_id AND t.acceptance_id=NEW.id AND (t.acceptance_reference IS DISTINCT FROM NEW.id OR t.admission_closed_at IS NOT NULL OR t.closed_unused_at IS NOT NULL)) OR clock_timestamp()>=NEW.write_until THEN RAISE EXCEPTION 'connector reservation no longer matches original writer acknowledgement' USING ERRCODE='23514';END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION guard_connector_reservation_acknowledgement() FROM PUBLIC;
CREATE TRIGGER aab_connector_reservation_ack BEFORE UPDATE ON operation_audit FOR EACH ROW EXECUTE FUNCTION guard_connector_reservation_acknowledgement();

-- Durable paired acknowledgements are reusable facts only. They do not renew
-- current caller/source observation, ticket deadlines or original pair dates.
-- +goose StatementBegin
CREATE FUNCTION connector_reservation_acknowledged(r uuid,operation uuid) RETURNS boolean
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
BEGIN
 IF NOT(public.connector_identity_role_ok(r,'journal') OR public.connector_identity_role_ok(r,'source')) THEN RETURN false;END IF;
 RETURN EXISTS(SELECT 1 FROM public.operation_audit event JOIN public.operation_audit_lifecycle life ON life.operation_id=event.id AND life.root_id=event.root_id AND life.lane=event.lane
  WHERE event.root_id=r AND event.id=operation AND event.lane='identity' AND event.intent->>'Name' IN('connector_process_enrollment','connector_backing_acceptance') AND
   event.intent->'Lifecycle'->'Policy'->'History'->>'Layout'='connector-operation-history/v2' AND event.intent ? 'ConnectorReservations' AND
   event.intent_receipt IS NOT NULL AND event.outcome_receipt IS NOT NULL AND event.outcome->'Intent'=event.intent AND event.outcome->>'Status'='success' AND event.outcome->>'Effect'='accepted' AND
   life.intent_completion->'Receipt'=event.intent_receipt AND life.outcome_completion->'Receipt'=event.outcome_receipt);
END $$;

CREATE FUNCTION activate_connector_reservations(r uuid,operation uuid,c jsonb) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE event public.operation_audit; root public.connector_identity_root; cfg public.connector_identity_profile; item public.connector_retirement_ticket;
 expected jsonb; n timestamptz; missing boolean; until_time timestamptz:=(c->>'Until')::timestamptz;
BEGIN
 IF NOT(public.connector_identity_role_ok(r,'journal') OR public.connector_identity_role_ok(r,'source')) THEN RAISE EXCEPTION 'connector activation role unavailable' USING ERRCODE='23514';END IF;
 -- The branch selector is read-only and never returned; the selected existing
 -- proof checker takes recovery/root/profile locks before any mutation.
 SELECT * INTO STRICT event FROM public.operation_audit WHERE root_id=r AND id=operation AND lane='identity';
 IF event.intent->>'Name'='connector_process_enrollment' THEN
  cfg:=public.lock_connector_process_current(r,c,true);
 ELSIF event.intent->>'Name'='connector_backing_acceptance' AND public.connector_identity_role_ok(r,'source') THEN
  cfg:=public.lock_connector_backing_current(r,c);
 ELSE RAISE EXCEPTION 'connector accepting operation unavailable' USING ERRCODE='23514';END IF;
 SELECT * INTO STRICT root FROM public.connector_identity_root WHERE root_id=r FOR UPDATE;
 SELECT * INTO STRICT event FROM public.operation_audit WHERE root_id=r AND id=operation AND lane='identity' FOR UPDATE;
 IF event.intent->'Lifecycle'->'Policy'->'History'->>'Layout' IS DISTINCT FROM 'connector-operation-history/v2' THEN RETURN;END IF;
 PERFORM 1 FROM public.connector_identity_profile p WHERE p.root_id=r ORDER BY p.peer_id FOR UPDATE;
 PERFORM 1 FROM public.operation_audit_pool WHERE root_id=r AND lane='identity' FOR UPDATE;
 PERFORM 1 FROM public.connector_retirement_ticket t WHERE t.root_id=r AND (t.acceptance_id=operation OR t.activated_at IS NOT NULL AND t.superseded_at IS NULL) ORDER BY t.peer_id,t.id FOR UPDATE;
 n:=clock_timestamp();
 IF n>=until_time OR until_time>(c->>'ObservedAt')::timestamptz+interval '5 seconds' OR n>=root.valid_until THEN RAISE EXCEPTION 'connector ticket original activation interval expired' USING ERRCODE='23514';END IF;
 IF NOT(event.intent ? 'ConnectorReservations') THEN
  -- A replacement process reuses its profile's still-current reservation; it
  -- neither obtains a second ticket nor revives the old acceptance event.
  IF event.intent->>'Name'<>'connector_process_enrollment' OR NOT EXISTS(SELECT 1 FROM public.connector_retirement_ticket t WHERE t.root_id=r AND t.peer_id=cfg.peer_id AND t.activated_at IS NOT NULL AND t.superseded_at IS NULL AND t.restriction_at IS NULL AND t.admitted_at IS NULL AND t.closed_unused_at IS NULL AND t.admission_closed_at IS NULL AND t.acceptance_reference=t.acceptance_id AND
   t.behavior_uid=cfg.source_uid AND t.behavior_generation=cfg.source_generation AND t.behavior_digest=cfg.source_digest AND t.backing_revision=(root.policy->>'BackingRevision')::bigint AND t.backing_digest=root.backing_digest AND n<t.admission_until) THEN RAISE EXCEPTION 'connector replacement lacks current retirement reservation' USING ERRCODE='23514';END IF;
  RETURN;
 END IF;
 expected:=public.connector_retirement_set_digest(r,operation);
 IF expected IS DISTINCT FROM event.intent->'ConnectorReservations' OR NOT public.connector_reservation_acknowledged(r,operation) OR EXISTS(SELECT 1 FROM public.connector_retirement_ticket t WHERE t.root_id=r AND t.acceptance_id=operation AND (t.activated_at IS NOT NULL OR t.superseded_at IS NOT NULL OR t.restriction_at IS NOT NULL OR t.admitted_at IS NOT NULL OR t.closed_unused_at IS NOT NULL OR t.admission_closed_at IS NOT NULL OR t.acceptance_reference IS DISTINCT FROM operation OR n>=t.admission_until)) THEN RAISE EXCEPTION 'connector original reservation acknowledgements unavailable' USING ERRCODE='23514';END IF;
 IF event.intent->>'Name'='connector_backing_acceptance' THEN
  IF root.pending_id IS DISTINCT FROM operation THEN RAISE EXCEPTION 'connector reservation candidate changed' USING ERRCODE='23514';END IF;
  SELECT EXISTS(SELECT 1 FROM
   (SELECT t.* FROM public.connector_retirement_ticket t JOIN public.connector_identity_profile p ON p.root_id=t.root_id AND p.peer_id=t.peer_id WHERE t.root_id=r AND t.activated_at IS NOT NULL AND t.superseded_at IS NULL AND t.restriction_at IS NULL AND t.admitted_at IS NULL AND t.closed_unused_at IS NULL AND NOT COALESCE((p.configuration->>'Retiring')::boolean,false)) old_ticket
   FULL JOIN (SELECT t.* FROM public.connector_retirement_ticket t WHERE t.root_id=r AND t.acceptance_id=operation) successor ON old_ticket.root_id=successor.root_id AND old_ticket.peer_id=successor.peer_id
   WHERE old_ticket.id IS NULL OR successor.id IS NULL OR old_ticket.admission_closed_at IS NOT NULL OR old_ticket.backing_revision<>(root.policy->>'BackingRevision')::bigint OR old_ticket.backing_digest<>root.backing_digest OR
    ROW(successor.behavior_uid,successor.behavior_generation,successor.behavior_digest,successor.principal_digest) IS DISTINCT FROM ROW(old_ticket.behavior_uid,old_ticket.behavior_generation,old_ticket.behavior_digest,old_ticket.principal_digest) OR
    successor.ticket->'ServingSlots' IS DISTINCT FROM old_ticket.ticket->'ServingSlots' OR successor.ticket->'RetainedProcesses' IS DISTINCT FROM old_ticket.ticket->'RetainedProcesses' OR
    successor.backing_revision<>old_ticket.backing_revision+1 OR successor.backing_revision<>(root.pending_backing->'Policy'->>'BackingRevision')::bigint OR successor.backing_digest<>root.pending_digest) INTO missing;
  IF missing THEN RAISE EXCEPTION 'connector successor set changed before activation' USING ERRCODE='23514';END IF;
  -- Old and new rows change under the same root transaction. No concurrent
  -- consumer can interleave; rollback restores the complete previous set.
  UPDATE public.connector_retirement_ticket old_ticket SET superseded_at=n WHERE old_ticket.root_id=r AND old_ticket.activated_at IS NOT NULL AND old_ticket.superseded_at IS NULL AND EXISTS(SELECT 1 FROM public.connector_retirement_ticket successor WHERE successor.root_id=r AND successor.acceptance_id=operation AND successor.peer_id=old_ticket.peer_id);
 END IF;
 FOR item IN SELECT t.* FROM public.connector_retirement_ticket t WHERE t.root_id=r AND t.acceptance_id=operation ORDER BY t.peer_id LOOP
  IF clock_timestamp()>=until_time THEN RAISE EXCEPTION 'connector reservation activation original interval expired' USING ERRCODE='23514';END IF;
  UPDATE public.connector_retirement_ticket SET activated_at=n WHERE id=item.id AND root_id=r;
 END LOOP;
 IF clock_timestamp()>=until_time OR clock_timestamp()>=root.valid_until THEN RAISE EXCEPTION 'connector reservation activation original interval expired after writes' USING ERRCODE='23514';END IF;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION connector_reservation_acknowledged(uuid,uuid),activate_connector_reservations(uuid,uuid,jsonb) FROM PUBLIC;

-- Existing purpose-specific paths now activate the exact paid set before
-- acceptance/promotion in the same transaction. Historical v1 behavior is
-- unchanged; delayed accepted replay never reactivates a superseded ticket.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION guard_connector_audit_access() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE r uuid; l text; source_role boolean; journal_role boolean; ack_role boolean; cleanup_role boolean; verifier_role boolean; finalizer_role boolean;
BEGIN
 IF TG_TABLE_SCHEMA<>'public' OR TG_LEVEL<>'ROW' OR TG_WHEN<>'BEFORE' OR TG_TABLE_NAME NOT IN ('operation_audit_pool','operation_audit_account','operation_audit','operation_audit_lifecycle','operation_audit_history') THEN RAISE EXCEPTION 'invalid connector audit boundary' USING ERRCODE='23514';END IF;
 IF TG_OP='DELETE' THEN r:=OLD.root_id;l:=OLD.lane;ELSE r:=NEW.root_id;l:=NEW.lane;END IF;
 IF l<>'identity' THEN
  IF public.connector_identity_login_is_private() THEN RAISE EXCEPTION 'private connector role cannot use human audit lanes' USING ERRCODE='23514';END IF;
  IF TG_OP='DELETE' THEN RETURN OLD;ELSE RETURN NEW;END IF;
 END IF;
 source_role:=public.connector_identity_role_ok(r,'source');journal_role:=public.connector_identity_role_ok(r,'journal');ack_role:=public.connector_identity_role_ok(r,'acknowledgement');cleanup_role:=public.connector_identity_role_ok(r,'cleanup');verifier_role:=public.connector_identity_role_ok(r,'verifier');finalizer_role:=public.connector_identity_role_ok(r,'finalizer');
 IF TG_TABLE_NAME='operation_audit_pool' THEN
  IF NOT source_role AND NOT(pg_trigger_depth()>1 AND (journal_role OR finalizer_role)) THEN RAISE EXCEPTION 'connector backing role unavailable' USING ERRCODE='23514';END IF;
 ELSIF TG_TABLE_NAME='operation_audit_account' THEN
  IF pg_trigger_depth()<2 OR NOT(journal_role OR finalizer_role) THEN RAISE EXCEPTION 'connector account role unavailable' USING ERRCODE='23514';END IF;
 ELSIF TG_TABLE_NAME='operation_audit_history' THEN
  IF NOT finalizer_role THEN RAISE EXCEPTION 'connector history role unavailable' USING ERRCODE='23514';END IF;
 ELSIF TG_TABLE_NAME='operation_audit' THEN
  IF TG_OP='DELETE' THEN
   IF NOT finalizer_role THEN RAISE EXCEPTION 'connector retirement role unavailable' USING ERRCODE='23514';END IF;
  ELSIF TG_OP='INSERT' THEN
   IF NOT journal_role OR NOT COALESCE(NEW.intent->'Lifecycle'->'Policy'->'History'->>'Layout' IN('connector-operation-history/v1','connector-operation-history/v2'),false) THEN RAISE EXCEPTION 'connector admission role unavailable' USING ERRCODE='23514';END IF;
  ELSIF ack_role THEN
   IF (to_jsonb(NEW)-ARRAY['intent_receipt','outcome_receipt']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['intent_receipt','outcome_receipt']) THEN RAISE EXCEPTION 'connector acknowledgement cannot create work' USING ERRCODE='23514';END IF;
  ELSIF NOT journal_role OR ROW(NEW.intent_receipt,NEW.outcome_receipt) IS DISTINCT FROM ROW(OLD.intent_receipt,OLD.outcome_receipt) THEN RAISE EXCEPTION 'connector writer cannot acknowledge itself' USING ERRCODE='23514';END IF;
 ELSE
  IF TG_OP='INSERT' THEN
   IF NOT journal_role OR pg_trigger_depth()<2 THEN RAISE EXCEPTION 'connector lifecycle admission unavailable' USING ERRCODE='23514';END IF;
  ELSIF TG_OP='DELETE' THEN
   IF NOT finalizer_role THEN RAISE EXCEPTION 'connector lifecycle retirement unavailable' USING ERRCODE='23514';END IF;
  ELSIF ack_role THEN
   IF (to_jsonb(NEW)-ARRAY['intent_completion','outcome_completion']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['intent_completion','outcome_completion']) THEN RAISE EXCEPTION 'connector writer acknowledgement scope unavailable' USING ERRCODE='23514';END IF;
  ELSIF verifier_role THEN
   IF (to_jsonb(NEW)-ARRAY['certificate_verify_attempts','certificate_receipt','certificate_acknowledged_at','terminal_acknowledged_at']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['certificate_verify_attempts','certificate_receipt','certificate_acknowledged_at','terminal_acknowledged_at']) THEN RAISE EXCEPTION 'connector verifier cannot create cleanup work' USING ERRCODE='23514';END IF;
  ELSIF finalizer_role THEN
   IF (to_jsonb(NEW)-'finalization_xid') IS DISTINCT FROM (to_jsonb(OLD)-'finalization_xid') THEN RAISE EXCEPTION 'connector finalizer cannot acknowledge cleanup' USING ERRCODE='23514';END IF;
  ELSIF cleanup_role THEN
   IF ROW(NEW.intent_completion,NEW.outcome_completion,NEW.certificate_verify_attempts,NEW.certificate_receipt,NEW.certificate_acknowledged_at,NEW.terminal_acknowledged_at,NEW.finalization_xid) IS DISTINCT FROM ROW(OLD.intent_completion,OLD.outcome_completion,OLD.certificate_verify_attempts,OLD.certificate_receipt,OLD.certificate_acknowledged_at,OLD.terminal_acknowledged_at,OLD.finalization_xid) THEN RAISE EXCEPTION 'connector cleanup cannot acknowledge itself' USING ERRCODE='23514';END IF;
  ELSE RAISE EXCEPTION 'connector lifecycle role unavailable' USING ERRCODE='23514';END IF;
  IF TG_OP='UPDATE' AND NEW.lease IS DISTINCT FROM OLD.lease AND (
   EXISTS(SELECT 1 FROM public.connector_retirement_ticket t WHERE t.acceptance_reference=NEW.operation_id OR t.retirement_reference=NEW.operation_id) OR
   EXISTS(SELECT 1 FROM public.connector_backing_transition b WHERE b.id=NEW.operation_id) OR
   EXISTS(SELECT 1 FROM public.connector_credential_attempt a WHERE a.id=NEW.operation_id) OR
   EXISTS(SELECT 1 FROM public.connector_identity_process c WHERE c.id=NEW.operation_id) OR
   EXISTS(SELECT 1 FROM public.connector_identity_profile p WHERE p.candidate_id=NEW.operation_id OR p.accepted_id=NEW.operation_id)) THEN RAISE EXCEPTION 'connector credential dependencies remain charged' USING ERRCODE='23514';END IF;
 END IF;
 IF TG_OP='DELETE' THEN RETURN OLD;ELSE RETURN NEW;END IF;
END $$;
CREATE OR REPLACE FUNCTION accept_connector_process(r uuid,operation uuid,c jsonb) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE cfg public.connector_identity_profile; child public.connector_identity_process; event public.operation_audit; result jsonb;
BEGIN
 cfg:=public.lock_connector_process_current(r,c,true);
 result:=public.read_connector_process_admission(r,operation,c);
 IF result IS NULL THEN RAISE EXCEPTION 'connector process admission missing' USING ERRCODE='23514';END IF;
 SELECT * INTO STRICT child FROM public.connector_identity_process WHERE id=operation AND root_id=r FOR UPDATE;
 SELECT * INTO STRICT event FROM public.operation_audit WHERE id=operation AND root_id=r FOR UPDATE;
 IF event.intent_receipt IS NULL OR event.outcome_receipt IS NULL OR event.outcome->>'Status' IS DISTINCT FROM 'success' OR event.outcome->>'Effect' IS DISTINCT FROM 'accepted' OR clock_timestamp()>=child.run_until OR cfg.account_digest IS NOT NULL AND cfg.account_digest<>event.principal_digest THEN RAISE EXCEPTION 'connector process acknowledgements unavailable' USING ERRCODE='23514';END IF;
 IF child.accepted_at IS NULL THEN
  PERFORM public.activate_connector_reservations(r,operation,c);
  UPDATE public.connector_identity_process SET accepted_at=clock_timestamp() WHERE id=operation AND root_id=r;
 END IF;
 -- This acceptance changes no source timestamp and grants no certificate/bytes.
 UPDATE public.connector_identity_profile SET account_digest=event.principal_digest,candidate_id=operation,accepted_id=operation,fenced=false WHERE root_id=r AND peer_id=cfg.peer_id;
 IF clock_timestamp()>=(c->>'Until')::timestamptz THEN RAISE EXCEPTION 'connector process acceptance expired' USING ERRCODE='23514';END IF;
 RETURN child.process;
END $$;
CREATE OR REPLACE FUNCTION promote_connector_backing(r uuid,operation uuid,c jsonb) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE cfg public.connector_identity_profile; root public.connector_identity_root; child public.connector_backing_transition; pool public.operation_audit_pool; n timestamptz; result jsonb;
BEGIN
 IF NOT public.connector_identity_role_ok(r,'source') THEN RAISE EXCEPTION 'connector backing source unavailable' USING ERRCODE='23514';END IF;
 cfg:=public.lock_connector_backing_current(r,c);
 result:=public.read_connector_backing_admission(r,operation,c);IF result IS NULL THEN RAISE EXCEPTION 'connector backing acceptance missing' USING ERRCODE='23514';END IF;
 SELECT * INTO STRICT root FROM public.connector_identity_root WHERE root_id=r FOR UPDATE;
 SELECT * INTO STRICT pool FROM public.operation_audit_pool WHERE root_id=r AND lane='identity' FOR UPDATE;
 SELECT * INTO STRICT child FROM public.connector_backing_transition WHERE id=operation AND root_id=r FOR UPDATE;
 n:=clock_timestamp();
 IF child.closed_at IS NOT NULL OR n>=least((c->>'Until')::timestamptz,root.valid_until,child.authority_until) THEN RAISE EXCEPTION 'connector backing promotion expired' USING ERRCODE='23514';END IF;
 IF child.activated_at IS NOT NULL THEN
  IF root.active_backing_id IS DISTINCT FROM operation OR root.backing IS DISTINCT FROM child.proposed->'Backing' THEN RAISE EXCEPTION 'connector backing superseded' USING ERRCODE='23514';END IF;RETURN root.backing;
 END IF;
 IF root.pending_id IS DISTINCT FROM operation OR root.backing IS DISTINCT FROM child.previous_backing OR pool.revision<>(root.policy->>'BackingRevision')::bigint OR pool.valid_until<>root.valid_until OR pool.paused THEN RAISE EXCEPTION 'connector backing old revision changed' USING ERRCODE='23514';END IF;
 -- Child trigger checks both independently acknowledged joined writers. Updating
 -- the root/pool follows in the same transaction and cannot change old bindings.
 PERFORM public.activate_connector_reservations(r,operation,c);
 UPDATE public.connector_backing_transition SET activated_at=n WHERE id=operation AND root_id=r;
 UPDATE public.connector_identity_root SET backing=child.proposed->'Backing',backing_digest=pending_digest,policy=child.proposed->'Backing'->'Policy',valid_until=child.authority_until,active_backing_id=operation,pending_id=NULL,pending_backing=NULL,pending_digest=NULL,pending_at=NULL WHERE root_id=r;
 UPDATE public.operation_audit_pool SET revision=revision+1,valid_until=child.authority_until WHERE root_id=r AND lane='identity';
 IF clock_timestamp()>=(c->>'Until')::timestamptz OR clock_timestamp()>=root.valid_until THEN RAISE EXCEPTION 'connector backing promotion expired after writes' USING ERRCODE='23514';END IF;
 RETURN child.proposed->'Backing';
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION guard_connector_audit_access(),accept_connector_process(uuid,uuid,jsonb),promote_connector_backing(uuid,uuid,jsonb) FROM PUBLIC;

-- Current proof is purpose-specific. Historical expiry reads only the actual
-- recovery/role and exact original active cohort; it fabricates no live actor.
-- An explicit removal additionally needs the separate online retirement proof.
-- +goose StatementBegin
CREATE FUNCTION restrict_connector_retirement(r uuid,ticket_id uuid,cause text,current_value jsonb) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE started timestamptz:=clock_timestamp(); trust public.fleet_current_trust; root public.connector_identity_root; cfg public.connector_identity_profile; ticket_row public.connector_retirement_ticket;
 proof jsonb:=current_value->'Proof'; observation jsonb:=proof->'Configuration'; profile jsonb:=observation->'Profile'; scope jsonb; n timestamptz; until_time timestamptz:=(current_value->>'Until')::timestamptz;
BEGIN
 IF NOT public.connector_identity_role_ok(r,'journal') OR cause NOT IN('originalAdmissionEnd','protectedRetiringSource') OR octet_length(current_value::text)>393216 THEN RAISE EXCEPTION 'connector restrictive authority unavailable' USING ERRCODE='23514';END IF;
 SELECT t.* INTO STRICT trust FROM public.fleet_current_trust t JOIN public.connector_identity_root x ON x.installation_id=t.installation_id WHERE x.root_id=r FOR SHARE OF t;
 SELECT * INTO STRICT root FROM public.connector_identity_root WHERE root_id=r FOR UPDATE;
 SELECT * INTO STRICT ticket_row FROM public.connector_retirement_ticket WHERE root_id=r AND id=ticket_id;
 SELECT * INTO STRICT cfg FROM public.connector_identity_profile WHERE root_id=r AND peer_id=ticket_row.peer_id FOR UPDATE;
 PERFORM 1 FROM public.operation_audit_pool WHERE root_id=r AND lane='identity' FOR UPDATE;
 PERFORM 1 FROM public.operation_audit_account WHERE root_id=r AND lane='identity' AND principal_digest=ticket_row.principal_digest FOR UPDATE;
 SELECT * INTO STRICT ticket_row FROM public.connector_retirement_ticket WHERE root_id=r AND id=ticket_id FOR UPDATE;
 n:=clock_timestamp();
 IF NOT COALESCE(NOT trust.recovery_blocked AND NOT trust.suspended AND trust.observed_at<=n AND n<trust.fresh_until AND trust.issuer_epoch=root.issuer_epoch AND
  (current_value->>'ObservedAt')::timestamptz<=n AND n<until_time AND until_time<=(current_value->>'ObservedAt')::timestamptz+interval '5 seconds' AND until_time<=trust.fresh_until AND n<started+interval '5 seconds' AND
  ticket_row.activated_at IS NOT NULL AND ticket_row.superseded_at IS NULL AND ticket_row.peer_id=(ticket_row.ticket->'Binding'->>'PeerID')::uuid AND ticket_row.behavior_uid=cfg.source_uid AND
  cfg.backing_revision=ticket_row.backing_revision AND cfg.backing_digest=ticket_row.backing_digest AND cfg.account_digest=ticket_row.principal_digest AND
  (cfg.retirement_ticket IS NULL OR cfg.retirement_ticket=ticket_id),false) THEN RAISE EXCEPTION 'connector original restrictive cohort unavailable' USING ERRCODE='23514';END IF;
 IF cause='originalAdmissionEnd' THEN
  IF current_value ? 'Proof' OR n<ticket_row.admission_until OR NOT COALESCE(ROW(cfg.source_uid,cfg.source_generation,cfg.source_digest)=ROW(ticket_row.behavior_uid,ticket_row.behavior_generation,ticket_row.behavior_digest) OR cfg.suspended AND (cfg.configuration->>'Retiring')::boolean AND cfg.source_generation>ticket_row.behavior_generation,false) THEN RAISE EXCEPTION 'connector original admission end unavailable' USING ERRCODE='23514';END IF;
  scope:=jsonb_build_object('Cause',cause);
 ELSE
  IF NOT COALESCE(profile=cfg.configuration AND (profile->>'Suspended')::boolean AND (profile->>'Retiring')::boolean AND (profile->>'RootID')::uuid=r AND profile->'Binding'=ticket_row.ticket->'Binding' AND
   (profile->'Revision'->>'UID')::uuid=ticket_row.behavior_uid AND (profile->'Revision'->>'Generation')::bigint>ticket_row.behavior_generation AND
   proof->'Process'->'Binding'=profile->'Binding' AND (proof->'Process'->>'PodUID')::uuid IS NOT NULL AND (proof->'Process'->>'ProcessEpoch')::uuid IS NOT NULL AND
   public.connector_digest(proof->'ClientKeyDigest')<>public.connector_digest(proof->'ServerKeyDigest') AND octet_length(public.connector_digest(proof->'TokenDigest'))=32 AND octet_length(public.connector_digest(proof->'WorkloadDigest'))=32 AND octet_length(public.connector_digest(proof->'ProtectionDigest'))=32 AND
   (proof->>'ObservedAt')::timestamptz<=n AND n<(proof->>'FreshUntil')::timestamptz AND (proof->>'FreshUntil')::timestamptz<=(proof->>'ObservedAt')::timestamptz+interval '5 seconds' AND until_time<=(proof->>'FreshUntil')::timestamptz AND
   (observation->>'ObservedAt')::timestamptz<=n AND n<(observation->>'FreshUntil')::timestamptz AND (observation->>'FreshUntil')::timestamptz<=(observation->>'ObservedAt')::timestamptz+interval '5 seconds' AND until_time<=(observation->>'FreshUntil')::timestamptz AND
   (observation->'Backing'->>'Revision')::bigint=cfg.backing_revision AND public.connector_digest(observation->'Backing'->'Digest')=cfg.backing_digest AND public.connector_digest(observation->'Backing'->'SourceDigest')=cfg.complete_digest,false) THEN RAISE EXCEPTION 'connector current retiring proof unavailable' USING ERRCODE='23514';END IF;
  scope:=jsonb_build_object('Cause',cause,'RetiringSource',jsonb_build_object('Revision',profile->'Revision','CompleteDigest',observation->'Backing'->'SourceDigest'));
 END IF;
 IF ticket_row.restriction_at IS NULL THEN
  UPDATE public.connector_retirement_ticket SET restriction_at=n,restriction_source=scope WHERE root_id=r AND id=ticket_id;
  UPDATE public.connector_identity_profile SET fenced=true,retirement_ticket=ticket_id,retirement_at=n WHERE root_id=r AND peer_id=ticket_row.peer_id;
 ELSE
  IF cfg.retirement_ticket IS DISTINCT FROM ticket_id OR cfg.retirement_at IS DISTINCT FROM ticket_row.restriction_at OR NOT cfg.fenced THEN RAISE EXCEPTION 'connector restriction state mismatch' USING ERRCODE='23514';END IF;
 END IF;
 IF clock_timestamp()>=until_time OR clock_timestamp()>=started+interval '5 seconds' THEN RAISE EXCEPTION 'connector restrictive original interval expired after writes' USING ERRCODE='23514';END IF;
 SELECT * INTO STRICT ticket_row FROM public.connector_retirement_ticket WHERE root_id=r AND id=ticket_id;
 RETURN jsonb_build_object('Ticket',ticket_row.ticket,'RestrictedAt',ticket_row.restriction_at,'Restriction',ticket_row.restriction_source,
  'AdmissionOpen',ticket_row.admission_closed_at IS NULL AND ticket_row.acceptance_reference=ticket_row.acceptance_id AND clock_timestamp()<ticket_row.consume_until);
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION restrict_connector_retirement(uuid,uuid,text,jsonb) FROM PUBLIC;

-- The fixed profile fence survives the retirement audit payload until exact
-- possible-leaf/process cleanup. Source renewal cannot erase or bypass it.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION guard_connector_identity_profile() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE r public.connector_identity_root; n timestamptz; c jsonb; a public.operation_audit; attempt public.connector_credential_attempt; child public.connector_identity_process;
BEGIN
 IF TG_RELID<>'public.connector_identity_profile'::regclass OR TG_WHEN<>'BEFORE' OR TG_LEVEL<>'ROW' OR TG_OP='DELETE' THEN RAISE EXCEPTION 'connector profile retirement unavailable' USING ERRCODE='23514';END IF;
 SELECT * INTO STRICT r FROM public.connector_identity_root WHERE root_id=NEW.root_id FOR UPDATE;
 n:=clock_timestamp();
 IF TG_OP='INSERT' AND (NEW.retirement_ticket IS NOT NULL OR NEW.retirement_at IS NOT NULL) THEN RAISE EXCEPTION 'new profile cannot invent retirement' USING ERRCODE='23514';END IF;
 IF TG_OP='UPDATE' AND OLD.retirement_ticket IS NULL AND NEW.retirement_ticket IS NOT NULL THEN
  IF NOT public.connector_identity_role_ok(NEW.root_id,'journal') OR NOT NEW.fenced OR NEW.retirement_at IS NULL OR NEW.retirement_at>n OR NEW.retirement_at<n-interval '5 seconds' OR
   (to_jsonb(NEW)-ARRAY['fenced','retirement_ticket','retirement_at']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['fenced','retirement_ticket','retirement_at']) OR
   NOT EXISTS(SELECT 1 FROM public.connector_retirement_ticket t WHERE t.id=NEW.retirement_ticket AND t.root_id=NEW.root_id AND t.peer_id=NEW.peer_id AND t.activated_at IS NOT NULL AND t.superseded_at IS NULL AND t.restriction_at=NEW.retirement_at AND
    t.behavior_uid=NEW.source_uid AND t.backing_revision=NEW.backing_revision AND t.backing_digest=NEW.backing_digest AND t.principal_digest=NEW.account_digest) THEN RAISE EXCEPTION 'connector restriction is not prepaid for this cohort' USING ERRCODE='23514';END IF;
  -- Its original ticket prepaid this fixed control transition. Exhaustion of
  -- ordinary source/admission counters cannot block a restrictive close.
  RETURN NEW;
 END IF;
 IF TG_OP='UPDATE' AND (ROW(NEW.retirement_ticket,NEW.retirement_at) IS DISTINCT FROM ROW(OLD.retirement_ticket,OLD.retirement_at) OR
  OLD.retirement_ticket IS NOT NULL AND (NOT NEW.fenced OR NOT public.connector_identity_role_ok(NEW.root_id,'cleanup'))) THEN RAISE EXCEPTION 'irreversible connector retirement fence' USING ERRCODE='23514';END IF;
 IF TG_OP='UPDATE' AND public.connector_identity_role_ok(NEW.root_id,'cleanup') THEN
  IF NOT NEW.fenced OR NEW.candidate_id IS NOT NULL OR NEW.accepted_id IS NOT NULL OR (to_jsonb(NEW)-ARRAY['fenced','candidate_id','accepted_id']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['fenced','candidate_id','accepted_id']) OR
   EXISTS(SELECT 1 FROM public.connector_identity_process p WHERE p.root_id=OLD.root_id AND p.peer_id=OLD.peer_id AND (p.id IN(OLD.candidate_id,OLD.accepted_id) OR EXISTS(SELECT 1 FROM public.connector_credential_attempt a WHERE a.process_id=p.id AND a.id IN(OLD.candidate_id,OLD.accepted_id))) AND n<p.run_until+interval '1 minute') THEN RAISE EXCEPTION 'connector accepted source still referenced' USING ERRCODE='23514';END IF;
  RETURN NEW;
 END IF;
 -- Restrict an already-retained profile even when its backing is no longer
 -- current. This branch can only add a fence/watermark, never clear either.
 IF TG_OP='UPDATE' AND public.connector_identity_role_ok(NEW.root_id,'source') AND NEW.fenced AND (NOT OLD.blocked OR NEW.blocked) AND
  (to_jsonb(NEW)-ARRAY['fenced','blocked'])=(to_jsonb(OLD)-ARRAY['fenced','blocked']) AND ROW(NEW.fenced,NEW.blocked) IS DISTINCT FROM ROW(OLD.fenced,OLD.blocked) THEN
  IF r.source_transitions>=r.source_transition_limit THEN RAISE EXCEPTION 'connector restrictive transition backing exhausted' USING ERRCODE='23514';END IF;
  UPDATE public.connector_identity_root SET source_transitions=source_transitions+1 WHERE root_id=NEW.root_id;
  RETURN NEW;
 END IF;c:=NEW.configuration;
 IF NOT COALESCE(NEW.installation_id=r.installation_id AND NEW.issuer_epoch=r.issuer_epoch AND ((NEW.backing_revision=(r.policy->>'BackingRevision')::bigint AND NEW.backing_digest=r.backing_digest) OR (r.pending_id IS NOT NULL AND NEW.backing_revision=(r.pending_backing->'Policy'->>'BackingRevision')::bigint AND NEW.backing_digest=r.pending_digest)) AND (c->>'RootID')::uuid=NEW.root_id AND (c->'Binding'->>'PeerID')::uuid=NEW.peer_id AND (c->'Binding'->>'InstallationID')::uuid=NEW.installation_id AND (c->'Binding'->>'ClusterID')::uuid=NEW.cluster_id AND (c->'Binding'->>'IssuerEpoch')::uuid=NEW.issuer_epoch AND c->'Binding'->>'Role'='connector' AND public.connector_digest(c->'Revision'->'Digest')=NEW.source_digest AND public.connector_digest(c->'ProtectionDigest')=NEW.protection_digest AND (c->'Revision'->>'UID')::uuid=NEW.source_uid AND (c->'Revision'->>'Generation')::bigint=NEW.source_generation AND (c->>'Suspended')::boolean=NEW.suspended,false) THEN RAISE EXCEPTION 'connector source identity mismatch' USING ERRCODE='23514';END IF;
 IF TG_OP='UPDATE' AND NEW.configuration=OLD.configuration AND ROW(NEW.complete_digest,NEW.backing_revision,NEW.backing_digest) IS DISTINCT FROM ROW(OLD.complete_digest,OLD.backing_revision,OLD.backing_digest) THEN
  IF NOT public.connector_identity_role_ok(NEW.root_id,'source') OR n>=r.valid_until OR NEW.backing_revision<>OLD.backing_revision+1 OR NOT ((NEW.backing_revision=(r.policy->>'BackingRevision')::bigint AND NEW.backing_digest=r.backing_digest) OR (r.pending_id IS NOT NULL AND NEW.backing_revision=(r.pending_backing->'Policy'->>'BackingRevision')::bigint AND NEW.backing_digest=r.pending_digest)) OR
   (to_jsonb(NEW)-ARRAY['complete_digest','backing_revision','backing_digest']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['complete_digest','backing_revision','backing_digest']) OR r.source_transitions>=r.source_transition_limit THEN RAISE EXCEPTION 'connector complete source revision unavailable' USING ERRCODE='23514';END IF;
  UPDATE public.connector_identity_root SET source_transitions=source_transitions+1 WHERE root_id=NEW.root_id;
  RETURN NEW;
 END IF;
 IF TG_OP='INSERT' OR NEW.configuration IS DISTINCT FROM OLD.configuration THEN
  IF NOT public.connector_identity_role_ok(NEW.root_id,'source') OR n>=r.valid_until OR NEW.candidate_id IS NOT NULL OR NEW.accepted_id IS NOT NULL OR TG_OP='INSERT' AND NEW.account_digest IS NOT NULL OR TG_OP='UPDATE' AND NEW.account_digest IS DISTINCT FROM OLD.account_digest OR NOT NEW.fenced OR NEW.blocked OR r.source_transitions>=r.source_transition_limit OR TG_OP='INSERT' AND r.profiles>=r.profile_limit THEN RAISE EXCEPTION 'connector profile backing unavailable' USING ERRCODE='23514';END IF;
  IF TG_OP='UPDATE' AND (ROW(NEW.root_id,NEW.peer_id,NEW.installation_id,NEW.cluster_id,NEW.issuer_epoch,NEW.source_uid) IS DISTINCT FROM ROW(OLD.root_id,OLD.peer_id,OLD.installation_id,OLD.cluster_id,OLD.issuer_epoch,OLD.source_uid) OR NEW.source_generation<=OLD.source_generation) THEN RAISE EXCEPTION 'connector source rollback or replacement' USING ERRCODE='23514';END IF;
  UPDATE public.connector_identity_root SET profiles=profiles+(CASE WHEN TG_OP='INSERT' THEN 1 ELSE 0 END),source_transitions=source_transitions+1 WHERE root_id=NEW.root_id;
  RETURN NEW;
 END IF;
 IF (to_jsonb(NEW)-ARRAY['candidate_id','accepted_id','fenced','blocked','account_digest']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['candidate_id','accepted_id','fenced','blocked','account_digest']) THEN RAISE EXCEPTION 'immutable connector source' USING ERRCODE='23514';END IF;
 IF NEW.account_digest IS DISTINCT FROM OLD.account_digest AND (OLD.account_digest IS NOT NULL OR NOT public.connector_identity_role_ok(NEW.root_id,'journal')) THEN RAISE EXCEPTION 'immutable logical connector account' USING ERRCODE='23514';END IF;
 IF NEW.account_digest IS NOT DISTINCT FROM OLD.account_digest AND NEW.candidate_id IS NOT DISTINCT FROM OLD.candidate_id AND NEW.accepted_id IS NOT DISTINCT FROM OLD.accepted_id AND
   ROW(NEW.fenced,NEW.blocked) IS DISTINCT FROM ROW(OLD.fenced,OLD.blocked) THEN
  IF NOT public.connector_identity_role_ok(NEW.root_id,'source') OR r.source_transitions>=r.source_transition_limit OR
   OLD.blocked AND NOT NEW.blocked OR NEW.blocked AND NOT NEW.fenced OR NOT NEW.fenced AND (NEW.accepted_id IS NULL OR NEW.blocked OR n>=r.valid_until) THEN RAISE EXCEPTION 'connector source transition unavailable' USING ERRCODE='23514';END IF;
  UPDATE public.connector_identity_root SET source_transitions=source_transitions+1 WHERE root_id=NEW.root_id;
  RETURN NEW;
 END IF;
 IF OLD.account_digest IS NOT NULL AND NEW.account_digest IS DISTINCT FROM OLD.account_digest THEN RAISE EXCEPTION 'immutable logical connector account' USING ERRCODE='23514';END IF;
 IF OLD.fenced AND OLD.accepted_id IS NOT NULL OR OLD.blocked THEN RAISE EXCEPTION 'connector current source proof unavailable' USING ERRCODE='23514';END IF;
 IF NOT public.connector_identity_role_ok(NEW.root_id,'journal') OR NEW.suspended OR n>=r.valid_until OR NEW.blocked OR NEW.candidate_id IS NULL THEN RAISE EXCEPTION 'connector candidate unavailable' USING ERRCODE='23514';END IF;
 SELECT * INTO STRICT a FROM public.operation_audit WHERE id=NEW.candidate_id AND root_id=NEW.root_id AND lane='identity';
 IF NEW.account_digest IS DISTINCT FROM a.principal_digest THEN RAISE EXCEPTION 'connector account changed' USING ERRCODE='23514';END IF;
 IF a.intent->>'Name'='connector_process_enrollment' THEN
  SELECT * INTO STRICT child FROM public.connector_identity_process WHERE id=a.id AND root_id=NEW.root_id AND peer_id=NEW.peer_id;
  IF ROW(child.source_uid,child.source_generation,child.source_digest) IS DISTINCT FROM ROW(NEW.source_uid,NEW.source_generation,NEW.source_digest) THEN RAISE EXCEPTION 'connector process source mismatch' USING ERRCODE='23514';END IF;
 ELSE
  SELECT * INTO STRICT attempt FROM public.connector_credential_attempt WHERE id=a.id AND root_id=NEW.root_id AND peer_id=NEW.peer_id;
  IF ROW(attempt.source_uid,attempt.source_generation,attempt.source_digest) IS DISTINCT FROM ROW(NEW.source_uid,NEW.source_generation,NEW.source_digest) THEN RAISE EXCEPTION 'connector signing source mismatch' USING ERRCODE='23514';END IF;
 END IF;
 IF OLD.accepted_id IS NULL AND NEW.accepted_id IS NULL AND NEW.fenced AND a.intent->>'Name'='connector_process_enrollment' AND child.accepted_at IS NULL AND n<a.request_until THEN RETURN NEW;END IF;
 IF a.intent_receipt IS NULL OR a.outcome_receipt IS NULL OR a.outcome->>'Status' IS DISTINCT FROM 'success' OR NEW.accepted_id IS DISTINCT FROM NEW.candidate_id OR NEW.fenced OR (a.intent->>'Name'='connector_process_enrollment' AND (child.accepted_at IS NULL OR n>=child.run_until)) OR (a.intent->>'Name'<>'connector_process_enrollment' AND n>=attempt.certificate_not_after) THEN RAISE EXCEPTION 'connector candidate acknowledgement unavailable' USING ERRCODE='23514';END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION guard_connector_identity_profile() FROM PUBLIC;

-- This exception is an exact conversion of one original paid reservation,
-- never a generic expired-pool bypass or caller-supplied lifecycle grant.
-- +goose StatementBegin
CREATE FUNCTION connector_retirement_prepaid(event public.operation_audit) RETURNS boolean
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE t public.connector_retirement_ticket;
BEGIN
 IF event.lane<>'identity' OR event.intent->>'Name' IS DISTINCT FROM 'connector_retirement' OR NOT public.connector_identity_role_ok(event.root_id,'journal') THEN RETURN false;END IF;
 SELECT * INTO t FROM public.connector_retirement_ticket WHERE root_id=event.root_id AND id=event.id;
 IF NOT FOUND THEN RETURN false;END IF;
 RETURN COALESCE(t.activated_at IS NOT NULL AND t.superseded_at IS NULL AND t.restriction_at IS NOT NULL AND t.closed_unused_at IS NULL AND t.admission_closed_at IS NULL AND t.acceptance_reference=t.acceptance_id AND
  t.admitted_at=(event.intent->>'CreatedAt')::timestamptz AND t.retirement_operation=event.id AND t.retirement_reference=event.id AND t.audit_dependency_closed_at IS NULL AND
  event.principal_digest=t.principal_digest AND event.retain_until=t.retain_until AND event.write_until<=t.consume_until AND clock_timestamp()<t.consume_until AND
  event.intent->'RetirementOrigin'->'Ticket'=t.ticket AND public.connector_digest(event.intent->'RetirementOrigin'->'TicketDigest')=t.ticket_digest AND
  ((event.intent->'RetirementOrigin')-ARRAY['Ticket','TicketDigest'])=t.restriction_source AND event.intent->'Lifecycle'->'Policy'=t.ticket->'Policy' AND
  (event.intent->'Lifecycle'->>'OriginalPurgeAt')::timestamptz=t.original_purge_at AND public.connector_reservation_acknowledged(event.root_id,t.acceptance_id) AND
  EXISTS(SELECT 1 FROM public.connector_identity_profile p WHERE p.root_id=t.root_id AND p.peer_id=t.peer_id AND p.fenced AND p.retirement_ticket=t.id AND p.retirement_at=t.restriction_at AND p.source_uid=t.behavior_uid AND p.backing_revision=t.backing_revision AND p.backing_digest=t.backing_digest),false);
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION connector_retirement_prepaid(public.operation_audit) FROM PUBLIC;

-- Generic human/public behavior remains unchanged. Only the independently
-- joined original ticket can spend its paid private interval after the normal
-- identity pool admission deadline; every original writer/retention check stays.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION connector_operation_actor_valid(i jsonb) RETURNS boolean
LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
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
   (actor->'Deployment'->>'NamespaceUID')::uuid IS NOT NULL AND (actor->'Deployment'->>'AccountUID')::uuid IS NOT NULL AND (actor->'Deployment'->>'DeploymentUID')::uuid IS NOT NULL AND
   jsonb_array_length(actor->'ClientKeyDigest')=32 AND jsonb_array_length(actor->'ServerKeyDigest')=32 AND actor->'ClientKeyDigest'<>actor->'ServerKeyDigest',false) THEN RETURN false;END IF;
 ELSE
  IF name IN('connector_process_enrollment','connector_backing_acceptance') THEN RETURN false;END IF;
  actor:=i->'Peer';b:=actor->'Binding';
  IF NOT COALESCE(jsonb_array_length(actor->'CertificateDigest')=32,false) THEN RETURN false;END IF;
 END IF;
 RETURN COALESCE(b->>'Role'='connector' AND b->>'NodeUID'='' AND b->>'NodeBootID'='' AND b->>'CollectorEpoch'='' AND
  (b->>'InstallationID')::uuid IS NOT NULL AND (b->>'ClusterID')::uuid IS NOT NULL AND (b->>'IssuerEpoch')::uuid IS NOT NULL AND (b->>'PeerID')::uuid IS NOT NULL AND
  i->>'InputFormat'=(CASE WHEN name='connector_process_enrollment' THEN 'connector-process/v1' WHEN name='connector_backing_acceptance' THEN 'connector-backing/v1' ELSE 'connector-credential/v1' END),false);
END $$;
CREATE OR REPLACE FUNCTION guard_operation_audit() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE p public.operation_audit_pool; a public.operation_audit_account; n timestamptz; prepaid boolean:=false;
BEGIN
 IF TG_TABLE_SCHEMA<>'public' OR TG_RELID<>'public.operation_audit'::regclass OR TG_WHEN<>'BEFORE' OR TG_LEVEL<>'ROW' THEN
  RAISE EXCEPTION 'invalid operation audit source' USING ERRCODE='23514'; END IF;
 IF TG_OP='DELETE' THEN
  IF NOT EXISTS(SELECT 1 FROM public.operation_audit_lifecycle d JOIN public.fleet_current_trust t ON t.installation_id=d.installation_id
   WHERE d.operation_id=OLD.id AND d.root_id=OLD.root_id AND d.finalization_xid=pg_current_xact_id() AND d.terminal_acknowledged_at IS NOT NULL AND
    NOT t.recovery_blocked AND NOT t.suspended AND clock_timestamp()<t.fresh_until AND t.issuer_epoch=d.issuer_epoch AND pg_postmaster_start_time()=d.postmaster_at AND (SELECT oid FROM pg_catalog.pg_database WHERE datname=current_database())=d.database_oid AND clock_timestamp()<(d.lease->>'Until')::timestamptz)
   THEN RAISE EXCEPTION 'audit retirement unavailable' USING ERRCODE='23514'; END IF;
  RETURN OLD;
 END IF;
 IF TG_OP='INSERT' THEN
  SELECT * INTO STRICT p FROM public.operation_audit_pool WHERE root_id=NEW.root_id AND lane=NEW.lane FOR UPDATE;
  n:=clock_timestamp();
  prepaid:=public.connector_retirement_prepaid(NEW);
  IF NEW.intent->>'Name'='connector_retirement' AND NOT prepaid THEN RAISE EXCEPTION 'connector retirement has no paid original ticket' USING ERRCODE='23514';END IF;
  IF (NOT prepaid AND (p.paused OR n>=p.valid_until)) OR n>=NEW.request_until OR n<(NEW.intent->>'CreatedAt')::timestamptz OR NEW.intent_started OR NEW.intent_receipt IS NOT NULL OR NEW.outcome IS NOT NULL OR NEW.outcome_started OR NEW.outcome_receipt IS NOT NULL OR
   NOT (NEW.intent ?& ARRAY['ID','RootID','MACVersion','AccountVersion','Name','CreatedAt','RequestUntil','WriteUntil','RetainUntil']) OR public.operation_audit_lane(NEW.intent->>'Name') IS NULL OR NOT public.connector_operation_actor_valid(NEW.intent) OR
   (NEW.intent->>'ID')::uuid<>NEW.id OR (NEW.intent->>'RootID')::uuid<>NEW.root_id OR NEW.intent->>'AccountVersion'<>p.account_version OR
   NEW.request_until<>(NEW.intent->>'RequestUntil')::timestamptz OR NEW.write_until<>(NEW.intent->>'WriteUntil')::timestamptz OR NEW.retain_until<>(NEW.intent->>'RetainUntil')::timestamptz OR
   NEW.request_until>(NEW.intent->>'CreatedAt')::timestamptz+interval '5 seconds' OR NEW.write_until>(NEW.intent->>'CreatedAt')::timestamptz+interval '30 seconds' OR
   NEW.retain_until>(NEW.intent->>'CreatedAt')::timestamptz+make_interval(secs=>p.retained_seconds::double precision) OR
   NEW.lane IS DISTINCT FROM public.operation_audit_lane(NEW.intent->>'Name') THEN
   RAISE EXCEPTION 'operation audit unavailable' USING ERRCODE='23514'; END IF;
  SELECT * INTO a FROM public.operation_audit_account WHERE root_id=NEW.root_id AND lane=NEW.lane AND principal_digest=NEW.principal_digest FOR UPDATE;
  IF NOT FOUND THEN
   IF p.accounts>=p.account_limit THEN RAISE EXCEPTION 'audit accounts exhausted' USING ERRCODE='23514'; END IF;
   UPDATE public.operation_audit_pool SET accounts=accounts+1 WHERE root_id=NEW.root_id AND lane=NEW.lane;
   INSERT INTO public.operation_audit_account(root_id,lane,principal_digest) VALUES(NEW.root_id,NEW.lane,NEW.principal_digest) RETURNING * INTO a;
  END IF;
  IF a.charged>=p.records_per_account THEN RAISE EXCEPTION 'audit records exhausted' USING ERRCODE='23514'; END IF;
  UPDATE public.operation_audit_account SET charged=charged+1 WHERE root_id=NEW.root_id AND lane=NEW.lane AND principal_digest=NEW.principal_digest;
 ELSE
  IF ROW(NEW.id,NEW.root_id,NEW.lane,NEW.issuer_epoch,NEW.principal_digest,NEW.intent,NEW.request_until,NEW.write_until,NEW.retain_until) IS DISTINCT FROM ROW(OLD.id,OLD.root_id,OLD.lane,OLD.issuer_epoch,OLD.principal_digest,OLD.intent,OLD.request_until,OLD.write_until,OLD.retain_until) OR
   (OLD.intent_started AND NOT NEW.intent_started) OR (OLD.outcome_started AND NOT NEW.outcome_started) OR
   (OLD.intent_receipt IS NOT NULL AND NEW.intent_receipt IS DISTINCT FROM OLD.intent_receipt) OR
   (OLD.outcome IS NOT NULL AND NEW.outcome IS DISTINCT FROM OLD.outcome) OR
   (OLD.outcome_receipt IS NOT NULL AND NEW.outcome_receipt IS DISTINCT FROM OLD.outcome_receipt) THEN
   RAISE EXCEPTION 'immutable operation audit' USING ERRCODE='23514'; END IF;
  IF NEW.intent ? 'Lifecycle' AND NOT EXISTS(SELECT 1 FROM public.operation_audit_lifecycle d WHERE d.operation_id=NEW.id AND
    (NEW.intent_receipt IS NULL OR d.intent_completion->'Receipt'=NEW.intent_receipt) AND (NEW.outcome_receipt IS NULL OR d.outcome_completion->'Receipt'=NEW.outcome_receipt)) THEN
   RAISE EXCEPTION 'receipt lacks positive writer completion' USING ERRCODE='23514'; END IF;
  n:=clock_timestamp();
  IF n>=NEW.write_until OR (NOT OLD.intent_started AND NEW.intent_started AND n>=NEW.request_until) THEN
   RAISE EXCEPTION 'operation audit interval expired' USING ERRCODE='23514'; END IF;
  IF NEW.outcome IS NOT NULL AND NEW.outcome->'Intent' IS DISTINCT FROM NEW.intent THEN
   RAISE EXCEPTION 'outcome intent mismatch' USING ERRCODE='23514'; END IF;
 END IF;
 RETURN NEW;
END $$;
CREATE OR REPLACE FUNCTION create_operation_audit_lifecycle() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE b jsonb; p jsonb; t public.fleet_current_trust; a public.operation_audit_pool; n timestamptz:=clock_timestamp(); budget interval; horizon interval; proof interval; prepaid boolean:=false;
BEGIN
 IF TG_RELID<>'public.operation_audit'::regclass OR TG_WHEN<>'AFTER' OR TG_OP<>'INSERT' OR TG_LEVEL<>'ROW' THEN RAISE EXCEPTION 'invalid audit lifecycle source' USING ERRCODE='23514'; END IF;
 b:=NEW.intent->'Lifecycle';
 IF b IS NULL THEN RETURN NEW; END IF;
 p:=b->'Policy';
 SELECT * INTO STRICT t FROM public.fleet_current_trust WHERE installation_id=(p->>'InstallationID')::uuid FOR SHARE;
 SELECT * INTO STRICT a FROM public.operation_audit_pool WHERE root_id=NEW.root_id AND lane=NEW.lane FOR UPDATE;
 n:=clock_timestamp();
 prepaid:=public.connector_retirement_prepaid(NEW);
 budget:=make_interval(secs=>(p->>'CleanupBudgetSeconds')::double precision);
 horizon:=make_interval(secs=>(p->>'BackupHorizonSeconds')::double precision);
 proof:=make_interval(secs=>(p->>'ProofWindowSeconds')::double precision);
 IF (p ? 'OverdueTerminal' AND p->>'OverdueTerminal' IS DISTINCT FROM 'overdue-original/v1') OR b->>'Protocol' IS DISTINCT FROM 'closed-operation-audit/v1' OR jsonb_typeof(p)<>'object' OR
  NOT(p ?& ARRAY['MaxPurgeLeases','RootID','Lane','InstallationID','StoreID','PolicyID','BackupProfileID','PolicyDigest','BackupProfileDigest','BackingRevision','MetadataSlots','BackupReservedBytes','WALReservedBytes','BackupHorizonSeconds','CleanupBudgetSeconds','ProofWindowSeconds','ValidUntil']) OR
  (p->>'RootID')::uuid<>NEW.root_id OR p->>'Lane'<>NEW.lane OR (p->>'StoreID')::uuid IS NULL OR (p->>'PolicyID')::uuid IS NULL OR (p->>'BackupProfileID')::uuid IS NULL OR
  jsonb_array_length(p->'PolicyDigest')<>32 OR jsonb_array_length(p->'BackupProfileDigest')<>32 OR
  (NOT prepaid AND (p->>'BackingRevision')::bigint<>a.revision) OR (p->>'MetadataSlots')::bigint<a.account_limit*a.records_per_account OR (p->>'MetadataSlots')::bigint>1000000000000 OR
  budget<interval '1 second' OR budget>interval '1 day' OR horizon<interval '0 seconds' OR horizon>interval '3660 days' OR proof<interval '1 second' OR proof>interval '3660 days' OR
  (p->>'BackupReservedBytes')::bigint<0 OR (p->>'WALReservedBytes')::bigint<0 OR horizon>interval '0 seconds' AND ((p->>'BackupReservedBytes')::bigint<=0 OR (p->>'WALReservedBytes')::bigint<=0) OR
  n>=(p->>'ValidUntil')::timestamptz OR n>=NEW.request_until OR (NOT prepaid AND n>=a.valid_until) OR t.recovery_blocked OR t.suspended OR n>=t.fresh_until OR t.observed_at>n OR t.issuer_epoch<>NEW.issuer_epoch OR
  (p->>'MaxPurgeLeases')::bigint NOT BETWEEN 2 AND 32 OR
  (b->>'HistoryReleaseAt')::timestamptz<>NEW.retain_until-horizon-budget OR (b->>'HistoryDeleteBy')::timestamptz<>NEW.retain_until-horizon OR
  (b->>'LiveRetireBy')::timestamptz<>NEW.retain_until-2*horizon-budget OR (b->>'CertificatePurgeAt')::timestamptz<>(b->>'LiveRetireBy')::timestamptz-budget OR
  (b->>'OriginalPurgeAt')::timestamptz<>(b->>'CertificatePurgeAt')::timestamptz-proof-budget OR (b->>'OriginalPurgeAt')::timestamptz<=NEW.write_until THEN
  RAISE EXCEPTION 'audit lifecycle backing unavailable' USING ERRCODE='23514'; END IF;
 -- A qualification is an exact accepted layout/profile, with conservative
 -- measured full-transaction bounds. Positive arbitrary byte counts are not a
 -- qualification; source acceptance is deliberately outside this adapter.
 IF p->'History' IS NULL OR NOT public.operation_audit_history_verifier_backed(p->'History'->>'Layout') OR NOT public.operation_audit_history_layout_valid(NEW.lane,p->'History'->>'Layout') OR
   NOT(p->'History' ?& ARRAY['ID','Digest','Layout','MaximumRowFootprintBytes','MaximumTransitionWALBytes','BackupCopies','WALCopies']) OR
   (p->'History'->>'ID')::uuid IS NULL OR jsonb_array_length(p->'History'->'Digest')<>32 OR
   (p->'History'->>'MaximumRowFootprintBytes')::bigint NOT BETWEEN public.operation_audit_history_minimum_row(p->'History'->>'Layout') AND 16777216 OR
   (p->'History'->>'MaximumTransitionWALBytes')::bigint NOT BETWEEN 131072 AND 67108864 OR
   (p->'History'->>'BackupCopies')::bigint NOT BETWEEN 1 AND 64 OR (p->'History'->>'WALCopies')::bigint NOT BETWEEN 1 AND 64 OR
   (p->>'BackupReservedBytes')::bigint/(p->>'MetadataSlots')::bigint < 2*(p->'History'->>'MaximumRowFootprintBytes')::bigint*(p->'History'->>'BackupCopies')::bigint OR
   (p->>'WALReservedBytes')::bigint/(p->>'MetadataSlots')::bigint < 2*(p->'History'->>'MaximumTransitionWALBytes')::bigint*(p->'History'->>'WALCopies')::bigint*(public.operation_audit_history_fixed_transitions(p->'History'->>'Layout')+3*(p->>'MaxPurgeLeases')::bigint) THEN
   RAISE EXCEPTION 'audit history qualification unavailable' USING ERRCODE='23514'; END IF;

 IF a.history_backing_until IS NOT NULL AND n<a.history_backing_until AND NOT public.operation_audit_profile_covers((p-ARRAY['ValidUntil','BackingRevision','MetadataSlots','BackupReservedBytes','WALReservedBytes','PolicyID','PolicyDigest','CleanupBudgetSeconds','ProofWindowSeconds']),a.history_profile) THEN
  RAISE EXCEPTION 'residual audit history backing protected' USING ERRCODE='23514'; END IF;
 -- Renewal may refresh a source/revision or increase backing. Outstanding
 -- obligations cannot be moved to a smaller/different backup or account profile.
 IF EXISTS(SELECT 1 FROM public.operation_audit_lifecycle d WHERE d.root_id=NEW.root_id AND d.lane=NEW.lane AND
   NOT public.operation_audit_profile_covers((p-ARRAY['ValidUntil','BackingRevision','MetadataSlots','BackupReservedBytes','WALReservedBytes','PolicyID','PolicyDigest','CleanupBudgetSeconds','ProofWindowSeconds']),((d.binding->'Policy') - ARRAY['ValidUntil','BackingRevision','MetadataSlots','BackupReservedBytes','WALReservedBytes','PolicyID','PolicyDigest','CleanupBudgetSeconds','ProofWindowSeconds']))) OR
  EXISTS(SELECT 1 FROM public.operation_audit_history h WHERE h.root_id=NEW.root_id AND h.lane=NEW.lane AND NOT public.operation_audit_profile_covers((p-ARRAY['ValidUntil','BackingRevision','MetadataSlots','BackupReservedBytes','WALReservedBytes','PolicyID','PolicyDigest','CleanupBudgetSeconds','ProofWindowSeconds']),h.history_policy)) THEN
  RAISE EXCEPTION 'outstanding audit history profile mismatch' USING ERRCODE='23514'; END IF;
 IF horizon>interval '0 seconds' THEN
  UPDATE public.operation_audit_pool SET
   history_profile=p-ARRAY['ValidUntil','BackingRevision','MetadataSlots','BackupReservedBytes','WALReservedBytes','PolicyID','PolicyDigest','CleanupBudgetSeconds','ProofWindowSeconds'],
   history_backing_until=GREATEST(history_backing_until,NEW.retain_until)
  WHERE root_id=NEW.root_id AND lane=NEW.lane;
 END IF;
 INSERT INTO public.operation_audit_lifecycle(operation_id,root_id,lane,principal_digest,installation_id,issuer_epoch,postmaster_at,database_oid,binding,original_purge_at,certificate_purge_at,live_retire_by,certificate_verify_attempts)
 VALUES(NEW.id,NEW.root_id,NEW.lane,NEW.principal_digest,t.installation_id,t.issuer_epoch,pg_postmaster_start_time(),(SELECT oid FROM pg_catalog.pg_database WHERE datname=current_database()),b,(b->>'OriginalPurgeAt')::timestamptz,(b->>'CertificatePurgeAt')::timestamptz,(b->>'LiveRetireBy')::timestamptz,0);
 RETURN NEW;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION connector_operation_actor_valid(jsonb),guard_operation_audit(),create_operation_audit_lifecycle() FROM PUBLIC;

-- The restriction is a prior committed operation. A failure here cannot erase
-- that fence. Original-ID lookup precedes any new intent/date choice, and the
-- exact reservation becomes one charged pair atomically with its immutable row.
-- +goose StatementBegin
CREATE FUNCTION admit_connector_retirement(r uuid,ticket_id uuid,intent_value jsonb,observed_at timestamptz,until_time timestamptz) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE started timestamptz:=clock_timestamp(); trust public.fleet_current_trust; root public.connector_identity_root; cfg public.connector_identity_profile; ticket_row public.connector_retirement_ticket;
 event public.operation_audit; n timestamptz;
BEGIN
 IF NOT public.connector_identity_role_ok(r,'journal') OR NOT COALESCE(isfinite(observed_at) AND isfinite(until_time) AND observed_at<until_time AND until_time<=observed_at+interval '5 seconds',false) THEN RAISE EXCEPTION 'connector retirement journal unavailable' USING ERRCODE='23514';END IF;
 SELECT t.* INTO STRICT trust FROM public.fleet_current_trust t JOIN public.connector_identity_root x ON x.installation_id=t.installation_id WHERE x.root_id=r FOR SHARE OF t;
 SELECT * INTO STRICT root FROM public.connector_identity_root WHERE root_id=r FOR UPDATE;
 SELECT * INTO STRICT ticket_row FROM public.connector_retirement_ticket WHERE root_id=r AND id=ticket_id;
 SELECT * INTO STRICT cfg FROM public.connector_identity_profile WHERE root_id=r AND peer_id=ticket_row.peer_id FOR UPDATE;
 PERFORM 1 FROM public.operation_audit_pool WHERE root_id=r AND lane='identity' FOR UPDATE;
 PERFORM 1 FROM public.operation_audit_account WHERE root_id=r AND lane='identity' AND principal_digest=ticket_row.principal_digest FOR UPDATE;
 SELECT * INTO STRICT ticket_row FROM public.connector_retirement_ticket WHERE root_id=r AND id=ticket_id FOR UPDATE;
 n:=clock_timestamp();
 IF trust.recovery_blocked OR trust.suspended OR trust.observed_at>n OR n>=trust.fresh_until OR trust.issuer_epoch<>root.issuer_epoch OR observed_at>n OR n>=until_time OR until_time>observed_at+interval '5 seconds' OR until_time>trust.fresh_until OR n>=started+interval '5 seconds' OR
  ticket_row.restriction_at IS NULL OR ticket_row.superseded_at IS NOT NULL OR NOT cfg.fenced OR cfg.retirement_ticket IS DISTINCT FROM ticket_id OR cfg.retirement_at IS DISTINCT FROM ticket_row.restriction_at THEN RAISE EXCEPTION 'connector retirement current restrictive state unavailable' USING ERRCODE='23514';END IF;
 SELECT * INTO event FROM public.operation_audit WHERE root_id=r AND id=ticket_id AND lane='identity' FOR UPDATE;
 IF FOUND THEN
  IF event.intent->>'Name' IS DISTINCT FROM 'connector_retirement' OR ticket_row.retirement_operation IS DISTINCT FROM event.id OR event.intent->'RetirementOrigin'->'Ticket' IS DISTINCT FROM ticket_row.ticket THEN RAISE EXCEPTION 'connector retirement original-key mismatch' USING ERRCODE='23514';END IF;
 ELSE
  IF ticket_row.admitted_at IS NOT NULL OR ticket_row.admission_closed_at IS NOT NULL OR ticket_row.acceptance_reference IS DISTINCT FROM ticket_row.acceptance_id OR ticket_row.closed_unused_at IS NOT NULL OR n>=ticket_row.consume_until OR intent_value IS NULL OR octet_length(intent_value::text)>16384 OR
   (intent_value->>'ID')::uuid IS DISTINCT FROM ticket_id OR (intent_value->>'RootID')::uuid IS DISTINCT FROM r OR intent_value->>'Name' IS DISTINCT FROM 'connector_retirement' OR
   (intent_value->>'CreatedAt')::timestamptz IS DISTINCT FROM observed_at OR (intent_value->>'RequestUntil')::timestamptz>until_time OR (intent_value->>'WriteUntil')::timestamptz>ticket_row.consume_until OR
   intent_value->'RetirementOrigin'->'Ticket' IS DISTINCT FROM ticket_row.ticket OR ((intent_value->'RetirementOrigin')-ARRAY['Ticket','TicketDigest']) IS DISTINCT FROM ticket_row.restriction_source OR
   NOT public.connector_reservation_acknowledged(r,ticket_row.acceptance_id) THEN RAISE EXCEPTION 'connector original restrictive allowance unavailable' USING ERRCODE='23514';END IF;
  UPDATE public.connector_retirement_ticket SET admitted_at=observed_at,retirement_operation=ticket_id,retirement_reference=ticket_id WHERE root_id=r AND id=ticket_id;
  INSERT INTO public.operation_audit(id,root_id,lane,issuer_epoch,principal_digest,intent,request_until,write_until,retain_until)
   VALUES(ticket_id,r,'identity',root.issuer_epoch,ticket_row.principal_digest,intent_value,(intent_value->>'RequestUntil')::timestamptz,(intent_value->>'WriteUntil')::timestamptz,ticket_row.retain_until) RETURNING * INTO event;
 END IF;
 IF clock_timestamp()>=until_time OR clock_timestamp()>=trust.fresh_until OR clock_timestamp()>=started+interval '5 seconds' THEN RAISE EXCEPTION 'connector retirement original admission interval expired after locks' USING ERRCODE='23514';END IF;
 RETURN public.connector_audit_snapshot(event);
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION admit_connector_retirement(uuid,uuid,jsonb,timestamptz,timestamptz) FROM PUBLIC;

-- Read-only status never admits a writer, renews the original ticket or treats
-- missing minimized history as success. Its exact role/recovery interval is new
-- metadata authority only; all business and writer dates remain original.
-- +goose StatementBegin
CREATE FUNCTION read_connector_retirement(r uuid,ticket_id uuid,observed_at timestamptz,until_time timestamptz) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE started timestamptz:=clock_timestamp(); trust public.fleet_current_trust; root public.connector_identity_root; ticket_row public.connector_retirement_ticket; event public.operation_audit; snap jsonb:=NULL; n timestamptz;
BEGIN
 IF NOT public.connector_identity_role_ok(r,'journal') THEN RAISE EXCEPTION 'connector retirement reader unavailable' USING ERRCODE='23514';END IF;
 SELECT t.* INTO STRICT trust FROM public.fleet_current_trust t JOIN public.connector_identity_root x ON x.installation_id=t.installation_id WHERE x.root_id=r FOR SHARE OF t;
 SELECT * INTO STRICT root FROM public.connector_identity_root WHERE root_id=r FOR UPDATE;
 SELECT * INTO STRICT ticket_row FROM public.connector_retirement_ticket WHERE root_id=r AND id=ticket_id FOR SHARE;
 SELECT * INTO event FROM public.operation_audit WHERE root_id=r AND id=ticket_id AND lane='identity';
 IF FOUND THEN
  IF event.intent->>'Name' IS DISTINCT FROM 'connector_retirement' OR event.intent->'RetirementOrigin'->'Ticket' IS DISTINCT FROM ticket_row.ticket OR ticket_row.retirement_operation IS DISTINCT FROM ticket_id THEN RAISE EXCEPTION 'connector original retirement record differs' USING ERRCODE='23514';END IF;
  snap:=public.connector_audit_snapshot(event);
 END IF;
 n:=clock_timestamp();
 IF NOT COALESCE(NOT trust.recovery_blocked AND NOT trust.suspended AND trust.observed_at<=n AND n<trust.fresh_until AND trust.issuer_epoch=root.issuer_epoch AND
   observed_at<=n AND n<until_time AND until_time<=observed_at+interval '5 seconds' AND until_time<=trust.fresh_until AND n<started+interval '5 seconds',false) THEN RAISE EXCEPTION 'connector retirement status interval unavailable' USING ERRCODE='23514';END IF;
 RETURN jsonb_build_object('Ticket',ticket_row.ticket,'RestrictedAt',ticket_row.restriction_at,'Restriction',ticket_row.restriction_source,
  'AdmissionOpen',ticket_row.admission_closed_at IS NULL AND ticket_row.acceptance_reference=ticket_row.acceptance_id AND n<ticket_row.consume_until,'Snapshot',snap);
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION read_connector_retirement(uuid,uuid,timestamptz,timestamptz) FROM PUBLIC;

-- A business reference is detachable only when its exact admission/writer
-- interval can never create another effect. Detachment itself proves no object
-- absence and releases no admitted charge: the existing independently verified
-- operation lifecycle remains mandatory before its pair/history can retire.
-- +goose StatementBegin
CREATE FUNCTION connector_ticket_admission_ended(t public.connector_retirement_ticket,n timestamptz) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
 SELECT COALESCE(n>=t.consume_until OR t.superseded_at IS NOT NULL OR
  (t.activated_at IS NULL AND (EXISTS(SELECT 1 FROM public.connector_identity_process p WHERE p.root_id=t.root_id AND p.id=t.acceptance_id AND p.retired_at IS NOT NULL) OR
   EXISTS(SELECT 1 FROM public.connector_backing_transition b WHERE b.root_id=t.root_id AND b.id=t.acceptance_id AND b.closed_at IS NOT NULL))),false)
$$;
CREATE FUNCTION close_connector_retirement_writer_reference(r uuid,ticket_id uuid) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE started timestamptz:=clock_timestamp(); trust public.fleet_current_trust; root public.connector_identity_root; ticket_row public.connector_retirement_ticket; event public.operation_audit; n timestamptz;
BEGIN
 IF NOT public.connector_identity_role_ok(r,'cleanup') THEN RAISE EXCEPTION 'connector ticket writer close role unavailable' USING ERRCODE='23514';END IF;
 SELECT t.* INTO STRICT trust FROM public.fleet_current_trust t JOIN public.connector_identity_root x ON x.installation_id=t.installation_id WHERE x.root_id=r FOR SHARE OF t;
 SELECT * INTO STRICT root FROM public.connector_identity_root WHERE root_id=r FOR UPDATE;
 SELECT * INTO STRICT ticket_row FROM public.connector_retirement_ticket WHERE root_id=r AND id=ticket_id;
 PERFORM 1 FROM public.connector_identity_profile WHERE root_id=r AND peer_id=ticket_row.peer_id FOR UPDATE;
 PERFORM 1 FROM public.operation_audit_pool WHERE root_id=r AND lane='identity' FOR UPDATE;
 PERFORM 1 FROM public.operation_audit_account WHERE root_id=r AND lane='identity' AND principal_digest=ticket_row.principal_digest FOR UPDATE;
 SELECT * INTO STRICT ticket_row FROM public.connector_retirement_ticket WHERE root_id=r AND id=ticket_id FOR UPDATE;
 n:=clock_timestamp();
 IF trust.recovery_blocked OR trust.suspended OR trust.observed_at>n OR n>=trust.fresh_until OR trust.issuer_epoch<>root.issuer_epoch OR n>=started+interval '5 seconds' THEN RAISE EXCEPTION 'connector ticket writer close recovery unavailable' USING ERRCODE='23514';END IF;
 IF ticket_row.admitted_at IS NULL OR ticket_row.audit_dependency_closed_at IS NOT NULL THEN RETURN true;END IF;
 SELECT * INTO STRICT event FROM public.operation_audit WHERE root_id=r AND id=ticket_row.retirement_reference AND lane='identity' FOR UPDATE;
 IF ticket_row.retirement_reference IS DISTINCT FROM ticket_id OR event.intent->>'Name' IS DISTINCT FROM 'connector_retirement' OR event.intent->'RetirementOrigin'->'Ticket' IS DISTINCT FROM ticket_row.ticket OR clock_timestamp()<event.write_until THEN RAISE EXCEPTION 'connector ticket original writer interval remains open' USING ERRCODE='23514';END IF;
 UPDATE public.connector_retirement_ticket SET retirement_reference=NULL,audit_dependency_closed_at=clock_timestamp() WHERE root_id=r AND id=ticket_id;
 IF clock_timestamp()>=trust.fresh_until OR clock_timestamp()>=started+interval '5 seconds' THEN RAISE EXCEPTION 'connector ticket writer close original interval expired' USING ERRCODE='23514';END IF;
 RETURN true;
END $$;

CREATE FUNCTION delete_connector_retirement_ticket(r uuid,ticket_id uuid) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE started timestamptz:=clock_timestamp(); trust public.fleet_current_trust; root public.connector_identity_root; ticket_row public.connector_retirement_ticket; n timestamptz;
BEGIN
 IF NOT public.connector_identity_role_ok(r,'cleanup') THEN RAISE EXCEPTION 'connector ticket cleanup role unavailable' USING ERRCODE='23514';END IF;
 SELECT t.* INTO STRICT trust FROM public.fleet_current_trust t JOIN public.connector_identity_root x ON x.installation_id=t.installation_id WHERE x.root_id=r FOR SHARE OF t;
 SELECT * INTO STRICT root FROM public.connector_identity_root WHERE root_id=r FOR UPDATE;
 SELECT * INTO ticket_row FROM public.connector_retirement_ticket WHERE root_id=r AND id=ticket_id;
 n:=clock_timestamp();
 IF trust.recovery_blocked OR trust.suspended OR trust.observed_at>n OR n>=trust.fresh_until OR trust.issuer_epoch<>root.issuer_epoch OR n>=started+interval '5 seconds' THEN RAISE EXCEPTION 'connector ticket cleanup recovery unavailable' USING ERRCODE='23514';END IF;
 IF ticket_row.id IS NULL THEN RETURN false;END IF;
 PERFORM 1 FROM public.connector_identity_profile WHERE root_id=r AND peer_id=ticket_row.peer_id FOR UPDATE;
 PERFORM 1 FROM public.operation_audit_pool WHERE root_id=r AND lane='identity' FOR UPDATE;
 PERFORM 1 FROM public.operation_audit_account WHERE root_id=r AND lane='identity' AND principal_digest=ticket_row.principal_digest FOR UPDATE;
 DELETE FROM public.connector_retirement_ticket WHERE root_id=r AND id=ticket_id;
 IF clock_timestamp()>=trust.fresh_until OR clock_timestamp()>=started+interval '5 seconds' THEN RAISE EXCEPTION 'connector ticket cleanup interval expired' USING ERRCODE='23514';END IF;
 RETURN true;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION connector_ticket_admission_ended(public.connector_retirement_ticket,timestamptz),close_connector_retirement_writer_reference(uuid,uuid),delete_connector_retirement_ticket(uuid,uuid) FROM PUBLIC;

-- The paid restrictive business transaction, not the audit writer, freezes the
-- exact result before encrypted outcome creation. Current recovery and the
-- original ticket/writer interval remain mandatory after every blocking lock.
-- +goose StatementBegin
CREATE FUNCTION store_connector_retirement_outcome(r uuid,ticket_id uuid,outcome_value jsonb,observed_at timestamptz,until_time timestamptz) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE started timestamptz:=clock_timestamp(); snapshot jsonb; event public.operation_audit; ticket_row public.connector_retirement_ticket; n timestamptz;
BEGIN
 IF NOT public.connector_identity_role_ok(r,'journal') OR NOT COALESCE(isfinite(observed_at) AND isfinite(until_time) AND observed_at<until_time AND until_time<=observed_at+interval '5 seconds',false) THEN RAISE EXCEPTION 'connector restrictive outcome role unavailable' USING ERRCODE='23514';END IF;
 -- Acquires current recovery/root/ticket in the same fixed order as admission.
 snapshot:=public.read_connector_retirement(r,ticket_id,observed_at,until_time);
 SELECT * INTO STRICT ticket_row FROM public.connector_retirement_ticket WHERE root_id=r AND id=ticket_id FOR UPDATE;
 SELECT * INTO STRICT event FROM public.operation_audit WHERE root_id=r AND id=ticket_id AND lane='identity' FOR UPDATE;
 n:=clock_timestamp();
 IF NOT COALESCE(ticket_row.restriction_at IS NOT NULL AND ticket_row.retirement_reference=ticket_id AND ticket_row.audit_dependency_closed_at IS NULL AND
  ticket_row.superseded_at IS NULL AND event.intent->>'Name'='connector_retirement' AND event.intent->'RetirementOrigin'->'Ticket'=ticket_row.ticket AND event.intent_receipt IS NOT NULL AND
  n<event.write_until AND n<until_time AND n<started+interval '5 seconds' AND jsonb_typeof(outcome_value)='object' AND octet_length(outcome_value::text)<=24576 AND
  outcome_value->'Intent'=event.intent AND outcome_value->>'Status'='success' AND outcome_value->>'Reason'='prepared' AND outcome_value->>'Effect'='accepted' AND outcome_value->>'ClientReceipt'='unknown' AND NOT(outcome_value ? 'Credential') AND
  octet_length(public.connector_digest(outcome_value->'OutputDigest'))=32 AND (outcome_value->>'OutputBytes')::bigint BETWEEN 1 AND 4096 AND
  (outcome_value->>'RecordedAt')::timestamptz>=ticket_row.restriction_at AND (outcome_value->>'RecordedAt')::timestamptz>=event.request_until-interval '5 seconds' AND (outcome_value->>'RecordedAt')::timestamptz<=n AND
  (outcome_value->>'MetadataUntil')::timestamptz<=event.request_until AND (outcome_value->>'MetadataUntil')::timestamptz<=until_time AND (outcome_value->>'RecordedAt')::timestamptz<(outcome_value->>'MetadataUntil')::timestamptz,false) THEN RAISE EXCEPTION 'connector exact restrictive outcome unavailable' USING ERRCODE='23514';END IF;
 IF event.outcome IS NOT NULL THEN
  IF event.outcome IS DISTINCT FROM outcome_value THEN RAISE EXCEPTION 'immutable connector restrictive outcome' USING ERRCODE='23514';END IF;
 ELSE
  UPDATE public.operation_audit SET outcome=outcome_value WHERE root_id=r AND id=ticket_id;
 END IF;
 -- This repeats the current recovery and original caller interval before reply.
 RETURN public.read_connector_retirement(r,ticket_id,observed_at,until_time);
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION store_connector_retirement_outcome(uuid,uuid,jsonb,timestamptz,timestamptz) FROM PUBLIC;
