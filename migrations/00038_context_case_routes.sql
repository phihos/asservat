-- +goose Up
-- Published-only private routing, not evidence authority. No native checksum,
-- filename, title, reason, actor, audience or object locator enters this index.
CREATE TABLE context_case_locator (
 artifact_id uuid PRIMARY KEY REFERENCES context_catalog(artifact_id) ON DELETE NO ACTION,
 capture_id uuid NOT NULL UNIQUE,
 root_id uuid NOT NULL,
 case_id uuid NOT NULL,
 cluster_id uuid NOT NULL,
 namespace_uid text NOT NULL CHECK(octet_length(namespace_uid) BETWEEN 1 AND 64),
 workload_uid text NOT NULL CHECK(octet_length(workload_uid) BETWEEN 1 AND 64),
 pod_uid text NOT NULL CHECK(octet_length(pod_uid) BETWEEN 1 AND 64),
 FOREIGN KEY(capture_id,root_id) REFERENCES context_capture(id,root_id) ON DELETE NO ACTION
);
CREATE INDEX context_case_locator_by_case ON context_case_locator(root_id,case_id,artifact_id);

-- Only the exact catalog INSERT can invoke the owner-privileged projection.
-- Runtime publishers cannot write caller-chosen case-to-scope associations.
-- +goose StatementBegin
CREATE FUNCTION project_context_case_locator() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE e jsonb;
BEGIN
 IF TG_WHEN<>'AFTER' OR TG_LEVEL<>'ROW' OR TG_OP<>'INSERT' OR TG_TABLE_SCHEMA<>'public' OR TG_RELID<>'public.context_catalog'::regclass THEN
  RAISE EXCEPTION 'invalid case routing source' USING ERRCODE='23514';
 END IF;
 SELECT convert_from(c.expectation_json,'UTF8')::jsonb INTO STRICT e FROM public.context_capture c WHERE c.id=NEW.capture_id AND c.root_id=NEW.root_id;
 IF (e->>'CaptureUID')::uuid IS DISTINCT FROM NEW.capture_id OR (e#>>'{Registration,Location,ArtifactID}')::uuid IS DISTINCT FROM NEW.artifact_id THEN
  RAISE EXCEPTION 'invalid case routing binding' USING ERRCODE='23514';
 END IF;
 INSERT INTO public.context_case_locator(artifact_id,capture_id,root_id,case_id,cluster_id,namespace_uid,workload_uid,pod_uid)
 VALUES(NEW.artifact_id,NEW.capture_id,NEW.root_id,(e->>'CaseID')::uuid,(e#>>'{Registration,Location,ClusterID}')::uuid,e->>'NamespaceUID',e->>'WorkloadUID',e->>'PodUID');
 RETURN NEW;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION project_context_case_locator() FROM PUBLIC;
CREATE TRIGGER context_case_from_catalog AFTER INSERT ON context_catalog FOR EACH ROW EXECUTE FUNCTION project_context_case_locator();

-- Existing verified catalog membership is the only backfill source. An accepted
-- request or stored_unpublished receipt alone never creates a case locator.
INSERT INTO context_case_locator(artifact_id,capture_id,root_id,case_id,cluster_id,namespace_uid,workload_uid,pod_uid)
SELECT cat.artifact_id,cat.capture_id,cat.root_id,(e.doc->>'CaseID')::uuid,
 (e.doc#>>'{Registration,Location,ClusterID}')::uuid,e.doc->>'NamespaceUID',e.doc->>'WorkloadUID',e.doc->>'PodUID'
FROM context_catalog cat JOIN context_capture c ON c.id=cat.capture_id AND c.root_id=cat.root_id
CROSS JOIN LATERAL (SELECT convert_from(c.expectation_json,'UTF8')::jsonb AS doc) e;

-- Retirement is deliberately not invented here. No cascade may delete capture
-- associations before the owner of metadata retention proves safe retirement.
-- +goose StatementBegin
CREATE FUNCTION protect_context_case_locator() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $$
BEGIN
 RAISE EXCEPTION 'immutable context case routing; retirement protocol required' USING ERRCODE='23514';
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION protect_context_case_locator() FROM PUBLIC;
CREATE TRIGGER context_case_locator_immutable BEFORE UPDATE OR DELETE ON context_case_locator FOR EACH ROW EXECUTE FUNCTION protect_context_case_locator();
