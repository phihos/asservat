-- +goose Up
-- ADR-193: generation 1 of a cluster enrollment lineage arises only from a
-- fleet operator's audited bootstrap. The activation row binds the claimed
-- bootstrap, its acknowledged claim audit, the activated key and the staged
-- connector source; its own encrypted audit is acknowledged before the atomic
-- activation writes the lineage.
CREATE TABLE cluster_bootstrap_activation (
 installation_id uuid NOT NULL, bootstrap_id uuid NOT NULL,
 root_id uuid NOT NULL, peer_id uuid NOT NULL, cluster_id uuid NOT NULL, issuer_epoch uuid NOT NULL,
 lineage_id uuid NOT NULL UNIQUE,
 claim_audit_digest bytea NOT NULL CHECK(octet_length(claim_audit_digest)=32),
 public_key bytea NOT NULL UNIQUE CHECK(octet_length(public_key)=32),
 key_digest bytea NOT NULL CHECK(octet_length(key_digest)=32),
 source_uid uuid NOT NULL, source_generation bigint NOT NULL CHECK(source_generation BETWEEN 1 AND 2147483647),
 protection_digest bytea NOT NULL CHECK(octet_length(protection_digest)=32),
 validity_seconds bigint NOT NULL CHECK(validity_seconds BETWEEN 3600 AND 2592000),
 rotation_seconds bigint NOT NULL CHECK(rotation_seconds >= 60 AND 3*rotation_seconds <= validity_seconds),
 reserved_at timestamptz NOT NULL,
 audit_acknowledged_at timestamptz,
 audit_object_key text CHECK(octet_length(audit_object_key) BETWEEN 1 AND 1024),
 audit_object_version text CHECK(octet_length(audit_object_version) BETWEEN 1 AND 1024),
 audit_object_etag text CHECK(octet_length(audit_object_etag) BETWEEN 1 AND 256),
 audit_object_bytes bigint CHECK(audit_object_bytes BETWEEN 1 AND 65536),
 audit_object_sha256 bytea CHECK(octet_length(audit_object_sha256)=32),
 activated_at timestamptz,
 CHECK((audit_acknowledged_at IS NULL)=(audit_object_key IS NULL) AND (audit_acknowledged_at IS NULL)=(audit_object_version IS NULL) AND
  (audit_acknowledged_at IS NULL)=(audit_object_etag IS NULL) AND (audit_acknowledged_at IS NULL)=(audit_object_bytes IS NULL) AND (audit_acknowledged_at IS NULL)=(audit_object_sha256 IS NULL)),
 CHECK(activated_at IS NULL OR audit_acknowledged_at IS NOT NULL),
 PRIMARY KEY(installation_id,bootstrap_id),
 FOREIGN KEY(installation_id,bootstrap_id) REFERENCES fleet_bootstrap(installation_id,id),
 FOREIGN KEY(root_id,peer_id) REFERENCES connector_identity_profile(root_id,peer_id)
);

-- +goose StatementBegin
CREATE FUNCTION guard_cluster_bootstrap_activation() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $$
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'cluster bootstrap activation is append-only' USING ERRCODE='23514'; END IF;
 IF ROW(NEW.installation_id,NEW.bootstrap_id,NEW.root_id,NEW.peer_id,NEW.cluster_id,NEW.issuer_epoch,NEW.lineage_id,NEW.claim_audit_digest,NEW.public_key,NEW.key_digest,
        NEW.source_uid,NEW.source_generation,NEW.protection_digest,NEW.validity_seconds,NEW.rotation_seconds,NEW.reserved_at)
    IS DISTINCT FROM ROW(OLD.installation_id,OLD.bootstrap_id,OLD.root_id,OLD.peer_id,OLD.cluster_id,OLD.issuer_epoch,OLD.lineage_id,OLD.claim_audit_digest,OLD.public_key,OLD.key_digest,
        OLD.source_uid,OLD.source_generation,OLD.protection_digest,OLD.validity_seconds,OLD.rotation_seconds,OLD.reserved_at)
  OR OLD.audit_acknowledged_at IS NOT NULL AND ROW(NEW.audit_acknowledged_at,NEW.audit_object_key,NEW.audit_object_version,NEW.audit_object_etag,NEW.audit_object_bytes,NEW.audit_object_sha256)
    IS DISTINCT FROM ROW(OLD.audit_acknowledged_at,OLD.audit_object_key,OLD.audit_object_version,OLD.audit_object_etag,OLD.audit_object_bytes,OLD.audit_object_sha256)
  OR OLD.activated_at IS NOT NULL AND NEW.activated_at IS DISTINCT FROM OLD.activated_at THEN
  RAISE EXCEPTION 'cluster bootstrap activation transition unavailable' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
CREATE TRIGGER cluster_bootstrap_activation_guard BEFORE UPDATE OR DELETE ON cluster_bootstrap_activation FOR EACH ROW EXECUTE FUNCTION guard_cluster_bootstrap_activation();

-- A lineage exists only for an activated, audited bootstrap.
-- +goose StatementBegin
CREATE FUNCTION require_cluster_bootstrap_lineage() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $$
BEGIN
 IF NOT EXISTS(SELECT 1 FROM public.cluster_bootstrap_activation WHERE lineage_id=NEW.lineage_id AND activated_at IS NOT NULL AND audit_acknowledged_at IS NOT NULL
   AND root_id=NEW.root_id AND peer_id=NEW.peer_id AND installation_id=NEW.installation_id AND cluster_id=NEW.cluster_id) THEN
  RAISE EXCEPTION 'cluster enrollment lineage requires an activated bootstrap' USING ERRCODE='23514';
 END IF;
 RETURN NULL;
END $$;
-- +goose StatementEnd
CREATE CONSTRAINT TRIGGER cluster_enrollment_lineage_bootstrap AFTER INSERT ON cluster_enrollment_lineage DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION require_cluster_bootstrap_lineage();

-- Reserve the generation-1 binding: the claimed bootstrap, its key and the
-- staged source. The same call again returns the same lineage; any other key
-- or source is refused.
-- +goose StatementBegin
CREATE FUNCTION reserve_cluster_bootstrap(i uuid, b uuid, r uuid, k bytea, s uuid, g bigint, p bytea, validity bigint, rotation bigint) RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE t public.fleet_current_trust; fb public.fleet_bootstrap; a public.cluster_bootstrap_activation; pr public.connector_identity_profile; n timestamptz; lineage uuid;
BEGIN
 SELECT * INTO STRICT t FROM public.fleet_current_trust WHERE installation_id=i FOR SHARE;
 SELECT * INTO STRICT fb FROM public.fleet_bootstrap WHERE installation_id=i AND id=b FOR UPDATE;
 SELECT * INTO a FROM public.cluster_bootstrap_activation WHERE installation_id=i AND bootstrap_id=b FOR UPDATE;
 IF FOUND THEN
  IF a.root_id<>r OR a.public_key<>k OR a.source_uid<>s OR a.source_generation<>g OR a.protection_digest<>p OR a.validity_seconds<>validity OR a.rotation_seconds<>rotation THEN
   RAISE EXCEPTION 'cluster bootstrap reservation changed' USING ERRCODE='23514';
  END IF;
  RETURN a.lineage_id;
 END IF;
 n:=clock_timestamp();
 IF t.recovery_blocked OR t.suspended OR NOT COALESCE(t.observed_at<=n AND n<t.fresh_until,false) OR t.issuer_epoch<>fb.issuer_epoch OR fb.revoked OR
    NOT (fb.not_before<=n AND n<fb.not_after) OR fb.claimed_at IS NULL OR fb.claim_acknowledged_at IS NULL OR octet_length(k)<>32 OR
    fb.public_key_sha256<>sha256('\x302a300506032b6570032100'::bytea||k) THEN
  RAISE EXCEPTION 'cluster bootstrap unavailable' USING ERRCODE='23514';
 END IF;
 SELECT * INTO STRICT pr FROM public.connector_identity_profile WHERE root_id=r AND peer_id=fb.peer_id FOR SHARE;
 IF pr.installation_id<>i OR pr.cluster_id<>fb.cluster_id OR pr.issuer_epoch<>fb.issuer_epoch OR pr.source_uid<>s OR pr.source_generation<>g OR
    pr.protection_digest<>p OR pr.blocked OR pr.suspended OR
    EXISTS(SELECT 1 FROM public.cluster_enrollment_lineage WHERE root_id=r AND peer_id=fb.peer_id AND retired_at IS NULL) THEN
  RAISE EXCEPTION 'cluster bootstrap source unavailable' USING ERRCODE='23514';
 END IF;
 lineage:=gen_random_uuid();
 INSERT INTO public.cluster_bootstrap_activation(installation_id,bootstrap_id,root_id,peer_id,cluster_id,issuer_epoch,lineage_id,claim_audit_digest,public_key,key_digest,
   source_uid,source_generation,protection_digest,validity_seconds,rotation_seconds,reserved_at)
  VALUES(i,b,r,fb.peer_id,fb.cluster_id,fb.issuer_epoch,lineage,fb.claim_audit_digest,k,fb.public_key_sha256,s,g,p,validity,rotation,n);
 RETURN lineage;
END $$;
-- +goose StatementEnd

-- Acknowledge the encrypted generation-1 audit once; the identical receipt
-- again is a no-op, any other receipt is refused.
-- +goose StatementBegin
CREATE FUNCTION acknowledge_cluster_bootstrap(i uuid, b uuid, object_key text, version text, etag text, size bigint, sha bytea) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE a public.cluster_bootstrap_activation;
BEGIN
 SELECT * INTO STRICT a FROM public.cluster_bootstrap_activation WHERE installation_id=i AND bootstrap_id=b FOR UPDATE;
 IF a.audit_acknowledged_at IS NOT NULL THEN
  IF ROW(a.audit_object_key,a.audit_object_version,a.audit_object_etag,a.audit_object_bytes,a.audit_object_sha256) IS DISTINCT FROM ROW(object_key,version,etag,size,sha) THEN
   RAISE EXCEPTION 'cluster bootstrap audit receipt is immutable' USING ERRCODE='23514';
  END IF;
  RETURN;
 END IF;
 IF object_key<>'cluster-bootstrap/v1/'||i::text||'/'||b::text||'/record' THEN RAISE EXCEPTION 'cluster bootstrap audit key mismatch' USING ERRCODE='23514'; END IF;
 UPDATE public.cluster_bootstrap_activation SET audit_acknowledged_at=clock_timestamp(),audit_object_key=object_key,audit_object_version=version,audit_object_etag=etag,
  audit_object_bytes=size,audit_object_sha256=sha WHERE installation_id=i AND bootstrap_id=b;
END $$;
-- +goose StatementEnd

-- Activate generation 1 atomically. A replay returns the original result,
-- also after expiry, and grants nothing new; a replay after generation 1 was
-- used or rotated commits a fork fence.
-- +goose StatementBegin
CREATE FUNCTION activate_cluster_bootstrap(i uuid, b uuid, secret bytea, k bytea)
RETURNS TABLE(lineage uuid, generation bigint, issued_at timestamptz, valid_until timestamptz, replay boolean, fenced text)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE t public.fleet_current_trust; fb public.fleet_bootstrap; a public.cluster_bootstrap_activation; pr public.connector_identity_profile;
 l public.cluster_enrollment_lineage; c public.cluster_enrollment_credential; n timestamptz;
BEGIN
 SELECT * INTO STRICT t FROM public.fleet_current_trust WHERE installation_id=i FOR SHARE;
 SELECT * INTO STRICT fb FROM public.fleet_bootstrap WHERE installation_id=i AND id=b FOR UPDATE;
 SELECT * INTO STRICT a FROM public.cluster_bootstrap_activation WHERE installation_id=i AND bootstrap_id=b FOR UPDATE;
 IF fb.secret_sha256<>secret OR a.public_key<>k THEN RAISE EXCEPTION 'cluster bootstrap mismatch' USING ERRCODE='23514'; END IF;
 IF a.activated_at IS NOT NULL THEN
  IF fb.revoked THEN RAISE EXCEPTION 'cluster bootstrap revoked' USING ERRCODE='23514'; END IF;
  SELECT * INTO STRICT l FROM public.cluster_enrollment_lineage WHERE lineage_id=a.lineage_id FOR UPDATE;
  SELECT * INTO STRICT c FROM public.cluster_enrollment_credential WHERE lineage_id=a.lineage_id AND cluster_enrollment_credential.generation=1;
  IF l.fenced IS NOT NULL THEN
   RETURN QUERY SELECT a.lineage_id,1::bigint,c.issued_at,c.valid_until,true,l.fenced;
   RETURN;
  END IF;
  IF l.current_generation<>1 OR c.first_used_at IS NOT NULL OR c.superseded_at IS NOT NULL OR l.retired_at IS NOT NULL THEN
   n:=clock_timestamp();
   UPDATE public.cluster_enrollment_lineage SET fenced='fork',fenced_at=n WHERE lineage_id=a.lineage_id;
   RETURN QUERY SELECT a.lineage_id,1::bigint,c.issued_at,c.valid_until,true,'fork'::text;
   RETURN;
  END IF;
  RETURN QUERY SELECT a.lineage_id,1::bigint,c.issued_at,c.valid_until,true,NULL::text;
  RETURN;
 END IF;
 n:=clock_timestamp();
 IF a.audit_acknowledged_at IS NULL OR t.recovery_blocked OR t.suspended OR NOT COALESCE(t.observed_at<=n AND n<t.fresh_until,false) OR
    t.issuer_epoch<>a.issuer_epoch OR fb.revoked OR n>=fb.not_after THEN
  RAISE EXCEPTION 'cluster bootstrap activation unavailable' USING ERRCODE='23514';
 END IF;
 SELECT * INTO STRICT pr FROM public.connector_identity_profile WHERE root_id=a.root_id AND peer_id=a.peer_id FOR SHARE;
 IF pr.source_uid<>a.source_uid OR pr.source_generation<>a.source_generation OR pr.protection_digest<>a.protection_digest OR pr.blocked OR pr.suspended OR
    EXISTS(SELECT 1 FROM public.cluster_enrollment_lineage WHERE root_id=a.root_id AND peer_id=a.peer_id AND retired_at IS NULL) THEN
  RAISE EXCEPTION 'cluster bootstrap source changed' USING ERRCODE='23514';
 END IF;
 INSERT INTO public.cluster_enrollment_lineage(lineage_id,root_id,peer_id,installation_id,cluster_id,validity_seconds,rotation_seconds,current_generation,created_at)
  VALUES(a.lineage_id,a.root_id,a.peer_id,a.installation_id,a.cluster_id,a.validity_seconds,a.rotation_seconds,1,n);
 INSERT INTO public.cluster_enrollment_credential(lineage_id,generation,public_key,issued_at,valid_until)
  VALUES(a.lineage_id,1,a.public_key,n,n+make_interval(secs=>a.validity_seconds));
 UPDATE public.cluster_bootstrap_activation SET activated_at=n WHERE installation_id=i AND bootstrap_id=b;
 IF clock_timestamp()>=fb.not_after THEN RAISE EXCEPTION 'cluster bootstrap expired before commit' USING ERRCODE='23514'; END IF;
 RETURN QUERY SELECT a.lineage_id,1::bigint,n,n+make_interval(secs=>a.validity_seconds),false,NULL::text;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION reserve_cluster_bootstrap(uuid,uuid,uuid,bytea,uuid,bigint,bytea,bigint,bigint), acknowledge_cluster_bootstrap(uuid,uuid,text,text,text,bigint,bytea),
 activate_cluster_bootstrap(uuid,uuid,bytea,bytea) FROM PUBLIC;

-- +goose Down
DROP TRIGGER cluster_enrollment_lineage_bootstrap ON cluster_enrollment_lineage;
DROP FUNCTION activate_cluster_bootstrap(uuid,uuid,bytea,bytea);
DROP FUNCTION acknowledge_cluster_bootstrap(uuid,uuid,text,text,text,bigint,bytea);
DROP FUNCTION reserve_cluster_bootstrap(uuid,uuid,uuid,bytea,uuid,bigint,bytea,bigint,bigint);
DROP FUNCTION require_cluster_bootstrap_lineage();
DROP TABLE cluster_bootstrap_activation;
DROP FUNCTION guard_cluster_bootstrap_activation();
