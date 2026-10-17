-- Isolated concurrency model, not the product schema or a production migration.
CREATE TABLE config(id int PRIMARY KEY, epoch bigint NOT NULL, ready bool NOT NULL);
INSERT INTO config VALUES (1,1,true);
CREATE TABLE grants(id text PRIMARY KEY, revoked bool NOT NULL DEFAULT false,
 expires timestamptz NOT NULL, max_starts bigint NOT NULL, starts bigint NOT NULL DEFAULT 0,
 max_result bigint NOT NULL DEFAULT 64, result_spent bigint NOT NULL DEFAULT 0,
 max_artifacts int NOT NULL DEFAULT 2, clients text[] NOT NULL DEFAULT '{web,mcp}',
 CHECK(starts BETWEEN 0 AND max_starts), CHECK(result_spent BETWEEN 0 AND max_result));
CREATE TABLE pool(id int PRIMARY KEY, burst_b bigint NOT NULL, burst_o bigint NOT NULL,
 used_b bigint NOT NULL DEFAULT 0, used_o bigint NOT NULL DEFAULT 0,
 CHECK(used_b BETWEEN 0 AND burst_b), CHECK(used_o BETWEEN 0 AND burst_o));
INSERT INTO pool VALUES(1,40,40,0,0);
CREATE TABLE workload(id text PRIMARY KEY, protected_b bigint NOT NULL DEFAULT 16,
 protected_o bigint NOT NULL DEFAULT 16, context_b bigint NOT NULL DEFAULT 1,
 context_o bigint NOT NULL DEFAULT 1, hard_b bigint NOT NULL DEFAULT 32,
 hard_o bigint NOT NULL DEFAULT 32, non_b bigint NOT NULL DEFAULT 0,
 non_o bigint NOT NULL DEFAULT 0, ctx_b bigint NOT NULL DEFAULT 0, ctx_o bigint NOT NULL DEFAULT 0,
 CHECK(context_b<=protected_b AND protected_b<=hard_b),
 CHECK(context_o<=protected_o AND protected_o<=hard_o),
 CHECK(non_b BETWEEN 0 AND hard_b-context_b), CHECK(non_o BETWEEN 0 AND hard_o-context_o),
 CHECK(ctx_b BETWEEN 0 AND context_b), CHECK(ctx_o BETWEEN 0 AND context_o));
CREATE TABLE operation(id text PRIMARY KEY, digest text NOT NULL, grant_id text NOT NULL REFERENCES grants,
 workload_id text NOT NULL REFERENCES workload, bytes bigint NOT NULL CHECK(bytes>0),
 objects bigint NOT NULL CHECK(objects>0), context bool NOT NULL, state text NOT NULL DEFAULT 'reserved');
CREATE TABLE work(id text PRIMARY KEY REFERENCES operation, audited bool NOT NULL DEFAULT false,
 fence bigint NOT NULL DEFAULT 0, lease_until timestamptz, done bool NOT NULL DEFAULT false);
CREATE TABLE artifact(id text PRIMARY KEY, capture text NOT NULL, committed bool NOT NULL DEFAULT false);
CREATE TABLE result_artifact(grant_id text REFERENCES grants, artifact_id text REFERENCES artifact,
 PRIMARY KEY(grant_id,artifact_id));
CREATE TABLE child(grant_id text REFERENCES grants, artifact_id text REFERENCES artifact, client text,
 PRIMARY KEY(grant_id,artifact_id,client));
