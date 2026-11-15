-- +goose Up
-- ADR-330 D1/D13: the fleet trust row is static installation identity that
-- setup seeds. No observer refreshes it and nothing suspends it. The view keeps
-- its columns for the stored function bodies that still name them: suspended
-- is false and the freshness interval never ends.
CREATE OR REPLACE VIEW public.fleet_current_trust AS
 SELECT t.installation_id,t.issuer_epoch,t.source_uid,t.source_generation,
 t.source_digest,false AS suspended,
 '-infinity'::timestamptz AS observed_at,
 'infinity'::timestamptz AS fresh_until
 FROM public.fleet_trust t;
DROP FUNCTION IF EXISTS public.observe_fleet_administration(uuid,bigint,timestamptz,oid,timestamptz,uuid,text,bigint,bytea,boolean,timestamptz,timestamptz);
DROP FUNCTION IF EXISTS public.fence_fleet_observation(uuid,bigint,timestamptz,oid,timestamptz);
DROP TRIGGER IF EXISTS fleet_semantic_version_guard ON public.fleet_trust;
DROP FUNCTION IF EXISTS public.fleet_semantic_version_guard();
DROP TABLE IF EXISTS public.fleet_observation;
ALTER TABLE public.fleet_trust DROP CONSTRAINT IF EXISTS fleet_trust_check,
 DROP COLUMN IF EXISTS suspended,DROP COLUMN IF EXISTS observed_at,
 DROP COLUMN IF EXISTS fresh_until,DROP COLUMN IF EXISTS semantic_version;

-- +goose Down
-- Downgrade probes run the Down sections of 00173 and earlier, which name the
-- observation table and these columns. Restore their shape; the values are
-- not restored.
ALTER TABLE public.fleet_trust
 ADD COLUMN IF NOT EXISTS suspended boolean NOT NULL DEFAULT false,
 ADD COLUMN IF NOT EXISTS observed_at timestamptz NOT NULL DEFAULT 'epoch',
 ADD COLUMN IF NOT EXISTS fresh_until timestamptz NOT NULL DEFAULT 'epoch',
 ADD COLUMN IF NOT EXISTS semantic_version bigint NOT NULL DEFAULT 1;
CREATE TABLE IF NOT EXISTS public.fleet_observation (
 installation_id uuid PRIMARY KEY REFERENCES public.fleet_trust(installation_id),
 semantic_version bigint NOT NULL,
 issuer_epoch uuid NOT NULL,
 source_uid text NOT NULL,
 source_generation bigint NOT NULL,
 source_digest bytea NOT NULL,
 activated_postmaster_at timestamptz NOT NULL,
 activated_database_oid oid NOT NULL,
 observed_at timestamptz NOT NULL,
 fresh_until timestamptz NOT NULL
);
