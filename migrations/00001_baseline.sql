-- Asservat hub schema baseline.
--
-- Creates the complete schema of an empty database. It replaces the
-- pre-release migration chain (00001-00201); no released database used
-- that chain, so there is no upgrade path from it. There is no Down section:
-- the schema is never downgraded. Later changes are new numbered migrations.
--
-- Runtime roles and their grants are created by `asservat setup`, not here.

-- +goose Up

-- Tables, with their keys, checks and indexes.

CREATE TABLE access_grant (
    id uuid NOT NULL,
    root_id uuid NOT NULL,
    kind text NOT NULL,
    preview_id uuid,
    capture_id uuid,
    cluster_id uuid,
    namespace_uid text,
    workload_uid text,
    pod_uid text,
    execution_digest bytea NOT NULL,
    result_access_digest bytea,
    review_digest bytea NOT NULL,
    data_class text NOT NULL,
    reasons jsonb NOT NULL,
    review bytea NOT NULL,
    scope bytea NOT NULL,
    requester_issuer text NOT NULL,
    requester_subject text NOT NULL,
    requester_client text NOT NULL,
    lifetime_seconds integer NOT NULL,
    result_access jsonb,
    not_after timestamp with time zone,
    max_artifacts integer DEFAULT 0 NOT NULL,
    max_bytes bigint DEFAULT 0 NOT NULL,
    max_operations bigint DEFAULT 0 NOT NULL,
    artifacts_spent integer DEFAULT 0 NOT NULL,
    bytes_spent bigint DEFAULT 0 NOT NULL,
    operations_spent bigint DEFAULT 0 NOT NULL,
    idempotency_key text NOT NULL,
    request_digest bytea NOT NULL,
    requested_at timestamp with time zone DEFAULT clock_timestamp() NOT NULL,
    review_until timestamp with time zone,
    decision text,
    approver_issuer text,
    approver_subject text,
    approver_client text,
    decision_reason text,
    decision_acr text,
    decision_auth_time timestamp with time zone,
    decided_at timestamp with time zone,
    decision_key text,
    expires_at timestamp with time zone,
    revoked_at timestamp with time zone,
    revoker_issuer text,
    revoker_subject text,
    revoker_client text,
    revoke_key text,
    revision smallint DEFAULT 1 NOT NULL,
    requester_kind text DEFAULT 'human'::text NOT NULL,
    request_operation text DEFAULT 'requestGrant'::text NOT NULL,
    requester_key bytea,
    policy_uid text,
    policy_acceptance_id uuid,
    policy_scope jsonb,
    policy_not_after timestamp with time zone,
    policy_max_executions bigint GENERATED ALWAYS AS (((policy_scope #>> '{Limits,MaxExecutions}'::text[]))::bigint) STORED,
    policy_max_bytes bigint GENERATED ALWAYS AS (((policy_scope #>> '{Limits,MaxBytes}'::text[]))::bigint) STORED,
    policy_max_observed_bytes bigint GENERATED ALWAYS AS (((policy_scope #>> '{Limits,MaxObservedBytes}'::text[]))::bigint) STORED,
    policy_executions_spent bigint DEFAULT 0 NOT NULL,
    policy_bytes_spent bigint DEFAULT 0 NOT NULL,
    policy_observed_bytes_spent bigint DEFAULT 0 NOT NULL,
    policy_observed_events_spent bigint DEFAULT 0 NOT NULL,
    raw_query jsonb,
    submission jsonb,
    CONSTRAINT access_grant_approver_client_check CHECK (((octet_length(approver_client) >= 1) AND (octet_length(approver_client) <= 256))),
    CONSTRAINT access_grant_approver_issuer_check CHECK (((octet_length(approver_issuer) >= 1) AND (octet_length(approver_issuer) <= 2048))),
    CONSTRAINT access_grant_approver_subject_check CHECK (((octet_length(approver_subject) >= 1) AND (octet_length(approver_subject) <= 256))),
    CONSTRAINT access_grant_check CHECK (((octet_length(execution_digest) = 32) AND (execution_digest = sha256(scope)))),
    CONSTRAINT access_grant_check10 CHECK (((policy_observed_events_spent >= 0) AND (policy_observed_events_spent <= COALESCE(((policy_scope #>> '{Limits,MaxObservedEvents}'::text[]))::bigint, (0)::bigint)))),
    CONSTRAINT access_grant_check11 CHECK ((((revoked_at IS NULL) = (revoke_key IS NULL)) AND ((revoked_at IS NULL) = (revoker_issuer IS NULL)) AND ((revoked_at IS NULL) = (revoker_subject IS NULL)) AND ((revoked_at IS NULL) = (revoker_client IS NULL)))),
    CONSTRAINT access_grant_check4 CHECK ((((artifacts_spent >= 0) AND (artifacts_spent <= max_artifacts)) AND ((bytes_spent >= 0) AND (bytes_spent <= max_bytes)) AND ((operations_spent >= 0) AND (operations_spent <= max_operations)))),
    CONSTRAINT access_grant_check6 CHECK ((((decision IS NULL) = (approver_issuer IS NULL)) AND ((decision IS NULL) = (approver_subject IS NULL)) AND ((decision IS NULL) = (approver_client IS NULL)) AND ((decision IS NULL) = (decision_reason IS NULL)) AND ((decision IS NULL) = (decided_at IS NULL)) AND ((decision IS NULL) = (decision_key IS NULL)))),
    CONSTRAINT access_grant_check7 CHECK (((decision IS NULL) OR (NOT ((approver_issuer = requester_issuer) AND (approver_subject = requester_subject))))),
    CONSTRAINT access_grant_check8 CHECK (((decided_at IS NULL) OR ((decided_at >= requested_at) AND (decided_at <= review_until)))),
    CONSTRAINT access_grant_check9 CHECK (((NOT (decision IS DISTINCT FROM 'approved'::text)) = (expires_at IS NOT NULL))),
    CONSTRAINT access_grant_data_class_check CHECK ((data_class = ANY (ARRAY['metadata'::text, 'extract'::text, 'raw'::text]))),
    CONSTRAINT access_grant_decision_acr_check CHECK (((octet_length(decision_acr) >= 1) AND (octet_length(decision_acr) <= 128))),
    CONSTRAINT access_grant_decision_check CHECK ((decision = ANY (ARRAY['approved'::text, 'denied'::text]))),
    CONSTRAINT access_grant_decision_key_check CHECK (((octet_length(decision_key) >= 1) AND (octet_length(decision_key) <= 128))),
    CONSTRAINT access_grant_decision_reason_check CHECK (((octet_length(decision_reason) >= 1) AND (octet_length(decision_reason) <= 512))),
    CONSTRAINT access_grant_followup_operations CHECK (((result_access IS NULL) OR ((result_access -> 'operations'::text) = ANY (ARRAY['["download_artifact"]'::jsonb, '["get_logs"]'::jsonb, '["pcap_query"]'::jsonb, '["syscall_query"]'::jsonb, '["download_artifact", "get_logs"]'::jsonb, '["download_artifact", "pcap_query"]'::jsonb, '["download_artifact", "syscall_query"]'::jsonb, '["get_logs", "pcap_query"]'::jsonb, '["get_logs", "syscall_query"]'::jsonb, '["pcap_query", "syscall_query"]'::jsonb, '["download_artifact", "get_logs", "pcap_query"]'::jsonb, '["download_artifact", "get_logs", "syscall_query"]'::jsonb, '["download_artifact", "pcap_query", "syscall_query"]'::jsonb, '["get_logs", "pcap_query", "syscall_query"]'::jsonb, '["download_artifact", "get_logs", "pcap_query", "syscall_query"]'::jsonb])))),
    CONSTRAINT access_grant_idempotency_key_check CHECK (((octet_length(idempotency_key) >= 1) AND (octet_length(idempotency_key) <= 128))),
    CONSTRAINT access_grant_kind CHECK ((kind = ANY (ARRAY['adHocCapture'::text, 'policy'::text, 'rawQuery'::text]))),
    CONSTRAINT access_grant_namespace_uid_check CHECK (((octet_length(namespace_uid) >= 1) AND (octet_length(namespace_uid) <= 64))),
    CONSTRAINT access_grant_not_after CHECK (((not_after IS NULL) OR (not_after > requested_at))),
    CONSTRAINT access_grant_pod_uid_check CHECK (((octet_length(pod_uid) >= 1) AND (octet_length(pod_uid) <= 64))),
    CONSTRAINT access_grant_policy_pool CHECK (((policy_executions_spent >= 0) AND (policy_bytes_spent >= 0) AND (policy_observed_bytes_spent >= 0) AND ((kind <> 'policy'::text) OR ((policy_executions_spent <= policy_max_executions) AND (policy_bytes_spent <= policy_max_bytes) AND (policy_observed_bytes_spent <= policy_max_observed_bytes) AND ((NOT (decision IS DISTINCT FROM 'approved'::text)) OR ((policy_executions_spent = 0) AND (policy_bytes_spent = 0) AND (policy_observed_bytes_spent = 0))))))),
    CONSTRAINT access_grant_pool_bounds CHECK (((max_artifacts >= 0) AND (max_bytes >= 0) AND (max_operations >= 0))),
    CONSTRAINT access_grant_reasons_check CHECK (((jsonb_typeof(reasons) = 'array'::text) AND (jsonb_array_length(reasons) >= 1))),
    CONSTRAINT access_grant_request_digest_check CHECK ((octet_length(request_digest) = 32)),
    CONSTRAINT access_grant_requester_client_check CHECK (((octet_length(requester_client) >= 1) AND (octet_length(requester_client) <= 256))),
    CONSTRAINT access_grant_requester_issuer_check CHECK (((octet_length(requester_issuer) >= 1) AND (octet_length(requester_issuer) <= 2048))),
    CONSTRAINT access_grant_requester_kind CHECK ((requester_kind = ANY (ARRAY['human'::text, 'workload'::text]))),
    CONSTRAINT access_grant_requester_subject_check CHECK (((octet_length(requester_subject) >= 1) AND (octet_length(requester_subject) <= 256))),
    CONSTRAINT access_grant_result_access_check CHECK (((jsonb_typeof(result_access) = 'object'::text) AND (octet_length((result_access)::text) <= 8192))),
    CONSTRAINT access_grant_result_access_digest_check CHECK ((octet_length(result_access_digest) = 32)),
    CONSTRAINT access_grant_result_digest CHECK (((result_access IS NULL) = (result_access_digest IS NULL))),
    CONSTRAINT access_grant_result_pool CHECK (((kind = 'rawQuery'::text) OR (((result_access IS NULL) = (not_after IS NULL)) AND ((result_access IS NULL) = (max_artifacts = 0)) AND ((max_artifacts = 0) = (max_bytes = 0)) AND ((max_bytes = 0) = (max_operations = 0))))),
    CONSTRAINT access_grant_review_check CHECK (((octet_length(review) >= 2) AND (octet_length(review) <=
CASE
    WHEN (kind = 'rawQuery'::text) THEN 131072
    ELSE 32768
END))),
    CONSTRAINT access_grant_review_digest_check CHECK ((octet_length(review_digest) = 32)),
    CONSTRAINT access_grant_revision_check CHECK (((revision >= 1) AND (revision <= 3))),
    CONSTRAINT access_grant_revoke_key_check CHECK (((octet_length(revoke_key) >= 1) AND (octet_length(revoke_key) <= 128))),
    CONSTRAINT access_grant_revoker_client_check CHECK (((octet_length(revoker_client) >= 1) AND (octet_length(revoker_client) <= 256))),
    CONSTRAINT access_grant_revoker_issuer_check CHECK (((octet_length(revoker_issuer) >= 1) AND (octet_length(revoker_issuer) <= 2048))),
    CONSTRAINT access_grant_revoker_subject_check CHECK (((octet_length(revoker_subject) >= 1) AND (octet_length(revoker_subject) <= 256))),
    CONSTRAINT access_grant_scope_check CHECK (((octet_length(scope) >= 2) AND (octet_length(scope) <= 65536))),
    CONSTRAINT access_grant_scope_kind CHECK ((
CASE
    WHEN (kind = 'rawQuery'::text) THEN ((kind = 'rawQuery'::text) AND (requester_kind = 'human'::text) AND (request_operation = 'requestRawAccess'::text) AND (requester_key IS NOT NULL) AND (octet_length(requester_key) = 32) AND (requester_key = sha256((((((((int4send(octet_length(convert_to(requester_issuer, 'UTF8'::name))) || convert_to(requester_issuer, 'UTF8'::name)) || int4send(octet_length(convert_to(requester_subject, 'UTF8'::name)))) || convert_to(requester_subject, 'UTF8'::name)) || int4send(octet_length(convert_to(requester_client, 'UTF8'::name)))) || convert_to(requester_client, 'UTF8'::name)) || int4send(5)) || convert_to('human'::text, 'UTF8'::name)))) AND (preview_id IS NULL) AND (capture_id IS NULL) AND (cluster_id IS NULL) AND (namespace_uid IS NULL) AND (workload_uid IS NULL) AND (pod_uid IS NULL) AND (policy_uid IS NULL) AND (policy_acceptance_id IS NULL) AND (policy_scope IS NULL) AND (policy_not_after IS NULL) AND (policy_executions_spent = 0) AND (policy_bytes_spent = 0) AND (policy_observed_bytes_spent = 0) AND (policy_observed_events_spent = 0) AND (data_class = 'raw'::text) AND (lifetime_seconds >= 1) AND (result_access IS NULL) AND (result_access_digest IS NULL) AND (not_after IS NOT NULL) AND (jsonb_typeof(raw_query) = 'object'::text) AND ((convert_from(scope, 'UTF8'::name))::jsonb = jsonb_build_object('Version', 'raw-query/v1', 'Scope', raw_query)) AND (jsonb_typeof((raw_query -> 'Artifacts'::text)) = 'array'::text) AND (jsonb_array_length((raw_query -> 'Artifacts'::text)) >= 1) AND ((raw_query -> 'Operations'::text) = ANY (ARRAY['["download_artifact"]'::jsonb, '["get_logs"]'::jsonb, '["pcap_query"]'::jsonb, '["syscall_query"]'::jsonb, '["download_artifact", "get_logs"]'::jsonb, '["download_artifact", "pcap_query"]'::jsonb, '["download_artifact", "syscall_query"]'::jsonb, '["get_logs", "pcap_query"]'::jsonb, '["get_logs", "syscall_query"]'::jsonb, '["pcap_query", "syscall_query"]'::jsonb, '["download_artifact", "get_logs", "pcap_query"]'::jsonb, '["download_artifact", "get_logs", "syscall_query"]'::jsonb, '["download_artifact", "pcap_query", "syscall_query"]'::jsonb, '["get_logs", "pcap_query", "syscall_query"]'::jsonb, '["download_artifact", "get_logs", "pcap_query", "syscall_query"]'::jsonb])) AND (max_artifacts = jsonb_array_length((raw_query -> 'Artifacts'::text))) AND (max_bytes = ((raw_query ->> 'MaxBytes'::text))::bigint) AND (max_bytes >= 1) AND (max_operations = ((raw_query ->> 'MaxOperations'::text))::bigint) AND (max_operations >= 1) AND (not_after = ((raw_query ->> 'NotAfter'::text))::timestamp with time zone))
    ELSE ((raw_query IS NULL) AND (cluster_id IS NOT NULL) AND (namespace_uid IS NOT NULL) AND (workload_uid IS NOT NULL) AND ((((kind = 'adHocCapture'::text) AND (requester_kind = 'human'::text) AND (request_operation = 'requestGrant'::text) AND (requester_key IS NULL) AND (preview_id IS NOT NULL) AND (capture_id IS NOT NULL) AND (pod_uid IS NOT NULL) AND (policy_uid IS NULL) AND (policy_acceptance_id IS NULL) AND (policy_scope IS NULL) AND (policy_not_after IS NULL) AND (lifetime_seconds >= 60) AND (policy_executions_spent = 0) AND (policy_bytes_spent = 0) AND (policy_observed_bytes_spent = 0)) OR ((kind = 'policy'::text) AND (request_operation = 'requestPolicyGrant'::text) AND (requester_key IS NOT NULL) AND (octet_length(requester_key) = 32) AND (requester_key = sha256((((((((int4send(octet_length(convert_to(requester_issuer, 'UTF8'::name))) || convert_to(requester_issuer, 'UTF8'::name)) || int4send(octet_length(convert_to(requester_subject, 'UTF8'::name)))) || convert_to(requester_subject, 'UTF8'::name)) || int4send(octet_length(convert_to(requester_client, 'UTF8'::name)))) || convert_to(requester_client, 'UTF8'::name)) || int4send(octet_length(convert_to(requester_kind, 'UTF8'::name)))) || convert_to(requester_kind, 'UTF8'::name)))) AND (preview_id IS NULL) AND (capture_id IS NULL) AND (pod_uid IS NULL) AND (policy_uid IS NOT NULL) AND ((octet_length(policy_uid) >= 1) AND (octet_length(policy_uid) <= 64)) AND (policy_acceptance_id IS NOT NULL) AND (policy_scope IS NOT NULL) AND (jsonb_typeof(policy_scope) = 'object'::text) AND (octet_length((policy_scope)::text) <= 65536) AND (policy_scope ?& ARRAY['Authority'::text, 'Limits'::text, 'ApprovalPolicyRef'::text, 'ApprovalMaxAge'::text, 'RecipeDigest'::text]) AND ((policy_scope #>> '{Authority,PolicyUID}'::text[]) = policy_uid) AND ((policy_scope #>> '{Authority,ClusterID}'::text[]) = (cluster_id)::text) AND ((policy_scope #>> '{Authority,NamespaceUID}'::text[]) = namespace_uid) AND ((policy_scope #>> '{Authority,WorkloadUID}'::text[]) = workload_uid) AND ((lifetime_seconds >= 1) AND (lifetime_seconds <= 31536000)) AND ((((policy_scope ->> 'ApprovalMaxAge'::text))::bigint >= ((lifetime_seconds)::bigint * 1000000000)) AND (((policy_scope ->> 'ApprovalMaxAge'::text))::bigint <= '31536000000000000'::bigint)) AND (policy_not_after IS NOT NULL) AND (policy_not_after > requested_at) AND (policy_not_after <= (requested_at + make_interval(secs => (lifetime_seconds)::double precision))) AND (policy_not_after <= ((policy_scope #>> '{Authority,NotAfter}'::text[]))::timestamp with time zone) AND (result_access IS NULL) AND (result_access_digest IS NULL) AND (not_after IS NULL) AND (max_artifacts = 0) AND (max_bytes = 0) AND (max_operations = 0) AND (artifacts_spent = 0) AND (bytes_spent = 0) AND (operations_spent = 0) AND (policy_max_executions IS NOT NULL) AND (policy_max_executions > 0) AND (policy_max_bytes IS NOT NULL) AND (policy_max_bytes > 0) AND (policy_max_observed_bytes IS NOT NULL) AND (policy_max_observed_bytes >= 0))) IS TRUE))
END IS TRUE)),
    CONSTRAINT access_grant_workload_uid_check CHECK (((octet_length(workload_uid) >= 1) AND (octet_length(workload_uid) <= 64)))
);

ALTER TABLE ONLY access_grant ADD CONSTRAINT access_grant_child_scope UNIQUE (root_id, id, capture_id);

ALTER TABLE access_grant ADD CONSTRAINT access_grant_expiry_kind CHECK (((decision IS DISTINCT FROM 'approved'::text) OR (((decision_auth_time IS NULL) OR (decision_auth_time <= decided_at)) AND (((kind = ANY (ARRAY['adHocCapture'::text, 'rawQuery'::text])) AND (expires_at = COALESCE(not_after, (decided_at + make_interval(secs => (lifetime_seconds)::double precision))))) OR ((kind = 'policy'::text) AND (expires_at = policy_not_after)))))) NOT VALID;

ALTER TABLE ONLY access_grant ADD CONSTRAINT access_grant_pkey PRIMARY KEY (id);

ALTER TABLE ONLY access_grant ADD CONSTRAINT access_grant_policy_parent UNIQUE (root_id, id, policy_acceptance_id, policy_uid);

ALTER TABLE ONLY access_grant ADD CONSTRAINT access_grant_root_id_capture_id_key UNIQUE (root_id, capture_id);

ALTER TABLE ONLY access_grant ADD CONSTRAINT access_grant_root_parent UNIQUE (root_id, id);

CREATE UNIQUE INDEX access_grant_legacy_request ON access_grant USING btree (root_id, requester_issuer, requester_subject, idempotency_key) WHERE (kind = 'adHocCapture'::text);

CREATE INDEX access_grant_pending ON access_grant USING btree (root_id, requested_at DESC, id) WHERE ((decision IS NULL) AND (revoked_at IS NULL));

CREATE INDEX access_grant_policy_deadline ON access_grant USING btree (root_id, policy_not_after) WHERE ((kind = 'policy'::text) AND ((decision IS NULL) OR (decision = 'approved'::text)));

CREATE UNIQUE INDEX access_grant_policy_request ON access_grant USING btree (root_id, requester_key, request_operation, idempotency_key) WHERE (kind = 'policy'::text);

CREATE INDEX access_grant_raw_member ON access_grant USING gin (raw_query jsonb_path_ops) WHERE (kind = 'rawQuery'::text);

CREATE UNIQUE INDEX access_grant_raw_request ON access_grant USING btree (root_id, requester_key, request_operation, idempotency_key) WHERE (kind = 'rawQuery'::text);

CREATE INDEX access_grant_raw_requester ON access_grant USING btree (root_id, requester_key, requested_at, id) WHERE (kind = 'rawQuery'::text);

CREATE INDEX access_grant_requester ON access_grant USING btree (root_id, requester_issuer, requester_subject, requested_at DESC);

CREATE TABLE access_grant_child (
    id uuid NOT NULL,
    root_id uuid NOT NULL,
    parent_id uuid NOT NULL,
    capture_id uuid NOT NULL,
    action_id text NOT NULL,
    artifact_id uuid NOT NULL,
    artifact_digest bytea NOT NULL,
    created_at timestamp with time zone DEFAULT clock_timestamp() NOT NULL,
    CONSTRAINT access_grant_child_action_id_check CHECK (((octet_length(action_id) >= 1) AND (octet_length(action_id) <= 64))),
    CONSTRAINT access_grant_child_artifact_digest_check CHECK ((octet_length(artifact_digest) = 32))
);

ALTER TABLE ONLY access_grant_child ADD CONSTRAINT access_grant_child_parent_artifact UNIQUE (parent_id, artifact_id);

ALTER TABLE ONLY access_grant_child ADD CONSTRAINT access_grant_child_pkey PRIMARY KEY (id);

CREATE TABLE access_grant_use (
    id uuid NOT NULL,
    root_id uuid NOT NULL,
    parent_id uuid NOT NULL,
    child_id uuid NOT NULL,
    operation text NOT NULL,
    bytes bigint NOT NULL,
    operations bigint NOT NULL,
    created_at timestamp with time zone DEFAULT clock_timestamp() NOT NULL,
    CONSTRAINT access_grant_use_bytes_check CHECK ((bytes >= 0)),
    CONSTRAINT access_grant_use_check CHECK (((bytes + operations) > 0)),
    CONSTRAINT access_grant_use_operation_check CHECK ((operation = ANY (ARRAY['download_artifact'::text, 'get_logs'::text, 'pcap_query'::text, 'syscall_query'::text]))),
    CONSTRAINT access_grant_use_operations_check CHECK ((operations >= 0))
);

ALTER TABLE ONLY access_grant_use ADD CONSTRAINT access_grant_use_pkey PRIMARY KEY (id);

CREATE TABLE adhoc_observation_spend (
    root_id uuid NOT NULL,
    grant_id uuid NOT NULL,
    spent bigint NOT NULL,
    events_spent bigint DEFAULT 0 NOT NULL,
    CONSTRAINT adhoc_observation_spend_events_spent_check CHECK ((events_spent >= 0)),
    CONSTRAINT adhoc_observation_spend_spent_check CHECK ((spent >= 0))
);

ALTER TABLE ONLY adhoc_observation_spend ADD CONSTRAINT adhoc_observation_spend_pkey PRIMARY KEY (root_id, grant_id);

CREATE TABLE artifact_download (
    id uuid NOT NULL,
    root_id uuid NOT NULL,
    allocation_id uuid NOT NULL,
    artifact_id uuid NOT NULL,
    principal_key bytea NOT NULL,
    actor_key bytea NOT NULL,
    idempotency_digest bytea NOT NULL,
    request_digest bytea NOT NULL,
    scope_json jsonb NOT NULL,
    state text DEFAULT 'Preparing'::text NOT NULL,
    created_at timestamp with time zone DEFAULT clock_timestamp() NOT NULL,
    deadline timestamp with time zone NOT NULL,
    output_limit bigint NOT NULL,
    read_limit bigint NOT NULL,
    charged_output bigint DEFAULT 0 NOT NULL,
    charged_read bigint DEFAULT 0 NOT NULL,
    emitted_bytes bigint DEFAULT 0 NOT NULL,
    generation bigint DEFAULT 0 NOT NULL,
    active_batch uuid,
    CONSTRAINT artifact_download_actor_key_check CHECK ((octet_length(actor_key) = 32)),
    CONSTRAINT artifact_download_check1 CHECK (((charged_read >= 0) AND (charged_read <= read_limit))),
    CONSTRAINT artifact_download_check3 CHECK (((emitted_bytes >= 0) AND (emitted_bytes <= charged_output))),
    CONSTRAINT artifact_download_check4 CHECK (((deadline > created_at) AND (deadline <= (created_at + '08:00:00'::interval)))),
    CONSTRAINT artifact_download_deadline_check CHECK ((deadline > created_at)),
    CONSTRAINT artifact_download_generation_check CHECK ((generation >= 0)),
    CONSTRAINT artifact_download_idempotency_digest_check CHECK ((octet_length(idempotency_digest) = 32)),
    CONSTRAINT artifact_download_output_limit_check CHECK (((output_limit >= 1) AND (output_limit <= '17592186044416'::bigint))),
    CONSTRAINT artifact_download_principal_key_check CHECK ((octet_length(principal_key) = 32)),
    CONSTRAINT artifact_download_read_limit_check CHECK (((read_limit >= 1) AND (read_limit <= '70368744177664'::bigint))),
    CONSTRAINT artifact_download_request_digest_check CHECK ((octet_length(request_digest) = 32)),
    CONSTRAINT artifact_download_scope_json_check CHECK (((jsonb_typeof(scope_json) = 'object'::text) AND (octet_length((scope_json)::text) <= 8192))),
    CONSTRAINT artifact_download_state_check CHECK ((state = ANY (ARRAY['Preparing'::text, 'Ready'::text, 'Streaming'::text, 'Interrupted'::text, 'Completed'::text, 'Cancelled'::text, 'Expired'::text, 'Denied'::text, 'Failed'::text])))
);

ALTER TABLE ONLY artifact_download ADD CONSTRAINT artifact_download_id_root_id_key UNIQUE (id, root_id);

ALTER TABLE ONLY artifact_download ADD CONSTRAINT artifact_download_pkey PRIMARY KEY (id);

ALTER TABLE ONLY artifact_download ADD CONSTRAINT artifact_download_root_id_actor_key_idempotency_digest_key UNIQUE (root_id, actor_key, idempotency_digest);

CREATE INDEX artifact_download_by_artifact ON artifact_download USING btree (artifact_id);

CREATE INDEX processing_report_downloads ON artifact_download USING btree (root_id, id);

CREATE TABLE artifact_download_stop (
    download_id uuid NOT NULL,
    root_id uuid NOT NULL,
    request_id uuid NOT NULL,
    key_digest bytea NOT NULL,
    state text NOT NULL,
    stopped_at timestamp with time zone DEFAULT clock_timestamp() NOT NULL,
    CONSTRAINT artifact_download_stop_key_digest_check CHECK ((octet_length(key_digest) = 32)),
    CONSTRAINT artifact_download_stop_state_check CHECK ((state = ANY (ARRAY['Cancelled'::text, 'AlreadyTerminal'::text])))
);

ALTER TABLE ONLY artifact_download_stop ADD CONSTRAINT artifact_download_stop_pkey PRIMARY KEY (download_id);

CREATE TABLE audit_event (
    event_id uuid NOT NULL,
    recorded_at timestamp with time zone DEFAULT clock_timestamp() NOT NULL,
    operation_id uuid NOT NULL,
    kind text NOT NULL,
    operation text NOT NULL,
    issuer text NOT NULL,
    subject text NOT NULL,
    client_id text NOT NULL,
    identity_type text NOT NULL,
    input_digest bytea,
    status text NOT NULL,
    reason text DEFAULT ''::text NOT NULL,
    effect text DEFAULT 'none'::text NOT NULL,
    case_ids text[] DEFAULT '{}'::text[] NOT NULL,
    artifact_ids text[] DEFAULT '{}'::text[] NOT NULL,
    capture_ids text[] DEFAULT '{}'::text[] NOT NULL,
    share_ids text[] DEFAULT '{}'::text[] NOT NULL,
    grant_ids text[] DEFAULT '{}'::text[] NOT NULL,
    reservation_id uuid,
    output_bytes bigint DEFAULT 0 NOT NULL,
    output_digest bytea
)
PARTITION BY RANGE (recorded_at);

ALTER TABLE ONLY audit_event ADD CONSTRAINT audit_event_pkey PRIMARY KEY (event_id, recorded_at);

CREATE INDEX audit_event_operation ON ONLY audit_event USING btree (operation_id);

CREATE INDEX audit_event_recorded ON ONLY audit_event USING btree (recorded_at);

CREATE TABLE audit_event_default (
    event_id uuid CONSTRAINT audit_event_event_id_not_null NOT NULL,
    recorded_at timestamp with time zone DEFAULT clock_timestamp() CONSTRAINT audit_event_recorded_at_not_null NOT NULL,
    operation_id uuid CONSTRAINT audit_event_operation_id_not_null NOT NULL,
    kind text CONSTRAINT audit_event_kind_not_null NOT NULL,
    operation text CONSTRAINT audit_event_operation_not_null NOT NULL,
    issuer text CONSTRAINT audit_event_issuer_not_null NOT NULL,
    subject text CONSTRAINT audit_event_subject_not_null NOT NULL,
    client_id text CONSTRAINT audit_event_client_id_not_null NOT NULL,
    identity_type text CONSTRAINT audit_event_identity_type_not_null NOT NULL,
    input_digest bytea,
    status text CONSTRAINT audit_event_status_not_null NOT NULL,
    reason text DEFAULT ''::text CONSTRAINT audit_event_reason_not_null NOT NULL,
    effect text DEFAULT 'none'::text CONSTRAINT audit_event_effect_not_null NOT NULL,
    case_ids text[] DEFAULT '{}'::text[] CONSTRAINT audit_event_case_ids_not_null NOT NULL,
    artifact_ids text[] DEFAULT '{}'::text[] CONSTRAINT audit_event_artifact_ids_not_null NOT NULL,
    capture_ids text[] DEFAULT '{}'::text[] CONSTRAINT audit_event_capture_ids_not_null NOT NULL,
    share_ids text[] DEFAULT '{}'::text[] CONSTRAINT audit_event_share_ids_not_null NOT NULL,
    grant_ids text[] DEFAULT '{}'::text[] CONSTRAINT audit_event_grant_ids_not_null NOT NULL,
    reservation_id uuid,
    output_bytes bigint DEFAULT 0 CONSTRAINT audit_event_output_bytes_not_null NOT NULL,
    output_digest bytea
);

ALTER TABLE ONLY audit_event_default ADD CONSTRAINT audit_event_default_pkey PRIMARY KEY (event_id, recorded_at);

CREATE INDEX audit_event_default_operation_id_idx ON audit_event_default USING btree (operation_id);

CREATE INDEX audit_event_default_recorded_at_idx ON audit_event_default USING btree (recorded_at);

CREATE TABLE authority_audit (
    id uuid NOT NULL,
    stream_id uuid NOT NULL,
    epoch uuid NOT NULL,
    sequence bigint NOT NULL,
    event_kind text NOT NULL,
    event_digest bytea NOT NULL,
    created_at timestamp with time zone DEFAULT clock_timestamp() NOT NULL,
    record jsonb NOT NULL,
    acknowledged_at timestamp with time zone,
    object_key text,
    object_version text,
    object_etag text,
    object_bytes bigint,
    object_sha256 bytea,
    CONSTRAINT authority_audit_check CHECK (((acknowledged_at IS NULL) = (object_key IS NULL))),
    CONSTRAINT authority_audit_check1 CHECK (((acknowledged_at IS NULL) = (object_version IS NULL))),
    CONSTRAINT authority_audit_check2 CHECK (((acknowledged_at IS NULL) = (object_etag IS NULL))),
    CONSTRAINT authority_audit_check3 CHECK (((acknowledged_at IS NULL) = (object_bytes IS NULL))),
    CONSTRAINT authority_audit_check4 CHECK (((acknowledged_at IS NULL) = (object_sha256 IS NULL))),
    CONSTRAINT authority_audit_event_digest_check CHECK ((octet_length(event_digest) = 32)),
    CONSTRAINT authority_audit_event_kind_check CHECK ((event_kind = ANY (ARRAY['permission-reset'::text, 'permission-change'::text, 'permission-suspend'::text, 'permission-review'::text]))),
    CONSTRAINT authority_audit_object_bytes_check CHECK (((object_bytes IS NULL) OR ((object_bytes >= 1) AND (object_bytes <= 16777216)))),
    CONSTRAINT authority_audit_object_etag_check CHECK (((object_etag IS NULL) OR ((octet_length(object_etag) >= 1) AND (octet_length(object_etag) <= 256)))),
    CONSTRAINT authority_audit_object_key_check CHECK (((object_key IS NULL) OR ((octet_length(object_key) >= 1) AND (octet_length(object_key) <= 256)))),
    CONSTRAINT authority_audit_object_sha256_check CHECK (((object_sha256 IS NULL) OR (octet_length(object_sha256) = 32))),
    CONSTRAINT authority_audit_object_version_check CHECK (((object_version IS NULL) OR (octet_length(object_version) <= 1024))),
    CONSTRAINT authority_audit_record_check CHECK ((octet_length((record)::text) <= 12582912))
);

ALTER TABLE ONLY authority_audit ADD CONSTRAINT authority_audit_pkey PRIMARY KEY (id);

CREATE INDEX authority_audit_pending ON authority_audit USING btree (created_at, id) WHERE (acknowledged_at IS NULL);

CREATE TABLE browser_login (
    id bytea NOT NULL,
    browser bytea NOT NULL,
    ciphertext bytea NOT NULL,
    created_at timestamp with time zone NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    CONSTRAINT browser_login_browser_check CHECK ((octet_length(browser) = 32)),
    CONSTRAINT browser_login_check CHECK (((expires_at > created_at) AND (expires_at <= (created_at + '00:05:00'::interval)))),
    CONSTRAINT browser_login_ciphertext_check CHECK (((octet_length(ciphertext) >= 1) AND (octet_length(ciphertext) <= 262144))),
    CONSTRAINT browser_login_id_check CHECK ((octet_length(id) = 32))
);

ALTER TABLE ONLY browser_login ADD CONSTRAINT browser_login_pkey PRIMARY KEY (id);

CREATE INDEX browser_login_expiry ON browser_login USING btree (expires_at);

CREATE TABLE browser_logout (
    id bytea NOT NULL,
    issuer text NOT NULL,
    client_id text NOT NULL,
    subject text NOT NULL,
    provider_session text NOT NULL,
    issued_at timestamp with time zone NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    CONSTRAINT browser_logout_check CHECK (((subject <> ''::text) OR (provider_session <> ''::text))),
    CONSTRAINT browser_logout_check1 CHECK ((expires_at > issued_at)),
    CONSTRAINT browser_logout_client_id_check CHECK (((octet_length(client_id) >= 1) AND (octet_length(client_id) <= 256))),
    CONSTRAINT browser_logout_id_check CHECK ((octet_length(id) = 32)),
    CONSTRAINT browser_logout_issuer_check CHECK (((octet_length(issuer) >= 1) AND (octet_length(issuer) <= 2048))),
    CONSTRAINT browser_logout_provider_session_check CHECK ((octet_length(provider_session) <= 256)),
    CONSTRAINT browser_logout_subject_check CHECK ((octet_length(subject) <= 256))
);

ALTER TABLE ONLY browser_logout ADD CONSTRAINT browser_logout_pkey PRIMARY KEY (id);

CREATE INDEX browser_logout_expiry ON browser_logout USING btree (expires_at);

CREATE TABLE browser_session (
    id bytea NOT NULL,
    issuer text NOT NULL,
    client_id text NOT NULL,
    subject text NOT NULL,
    provider_session text NOT NULL,
    ciphertext bytea NOT NULL,
    created_at timestamp with time zone NOT NULL,
    authenticated_at timestamp with time zone NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    last_used_at timestamp with time zone NOT NULL,
    refresh_at timestamp with time zone NOT NULL,
    version bigint NOT NULL,
    refresh_claim bytea,
    claim_until timestamp with time zone,
    CONSTRAINT browser_session_check CHECK ((expires_at > created_at)),
    CONSTRAINT browser_session_check1 CHECK ((authenticated_at <= created_at)),
    CONSTRAINT browser_session_check2 CHECK (((refresh_at > created_at) AND (refresh_at <= expires_at))),
    CONSTRAINT browser_session_check3 CHECK (((refresh_claim IS NULL) = (claim_until IS NULL))),
    CONSTRAINT browser_session_ciphertext_check CHECK (((octet_length(ciphertext) >= 1) AND (octet_length(ciphertext) <= 262144))),
    CONSTRAINT browser_session_client_id_check CHECK (((octet_length(client_id) >= 1) AND (octet_length(client_id) <= 256))),
    CONSTRAINT browser_session_id_check CHECK ((octet_length(id) = 32)),
    CONSTRAINT browser_session_issuer_check CHECK (((octet_length(issuer) >= 1) AND (octet_length(issuer) <= 2048))),
    CONSTRAINT browser_session_provider_session_check CHECK (((octet_length(provider_session) >= 1) AND (octet_length(provider_session) <= 256))),
    CONSTRAINT browser_session_refresh_claim_check CHECK (((refresh_claim IS NULL) OR (octet_length(refresh_claim) = 32))),
    CONSTRAINT browser_session_subject_check CHECK (((octet_length(subject) >= 1) AND (octet_length(subject) <= 256))),
    CONSTRAINT browser_session_version_check CHECK ((version > 0))
);

ALTER TABLE ONLY browser_session ADD CONSTRAINT browser_session_pkey PRIMARY KEY (id);

CREATE INDEX browser_session_expiry ON browser_session USING btree (expires_at);

CREATE INDEX browser_session_provider ON browser_session USING btree (issuer, client_id, provider_session);

CREATE INDEX browser_session_subject ON browser_session USING btree (issuer, client_id, subject);

CREATE TABLE capacity_account (
    allocation_id uuid NOT NULL,
    download_allocation_id uuid NOT NULL,
    root_id uuid NOT NULL,
    cluster_id uuid NOT NULL,
    namespace_uid text NOT NULL,
    workload_uid text NOT NULL,
    protected_bytes bigint NOT NULL,
    CONSTRAINT capacity_account_protected_bytes_check CHECK ((protected_bytes > 0))
);

ALTER TABLE ONLY capacity_account ADD CONSTRAINT capacity_account_download_allocation_id_key UNIQUE (download_allocation_id);

ALTER TABLE ONLY capacity_account ADD CONSTRAINT capacity_account_pkey PRIMARY KEY (allocation_id);

ALTER TABLE ONLY capacity_account ADD CONSTRAINT capacity_account_root_id_cluster_id_namespace_uid_workload__key UNIQUE (root_id, cluster_id, namespace_uid, workload_uid);

CREATE TABLE capacity_settings (
    root_id uuid NOT NULL,
    installation_id uuid NOT NULL,
    account_version text NOT NULL,
    qualification jsonb NOT NULL,
    pool_id uuid NOT NULL,
    evidence_bytes bigint NOT NULL,
    reserve_bytes bigint NOT NULL,
    share_bytes bigint,
    limit_bytes bigint NOT NULL,
    namespace_limit_bytes bigint,
    max_concurrent_expensive integer NOT NULL,
    revision bigint NOT NULL,
    CONSTRAINT capacity_settings_check CHECK (((reserve_bytes >= 0) AND (reserve_bytes < evidence_bytes))),
    CONSTRAINT capacity_settings_evidence_bytes_check CHECK ((evidence_bytes > 0)),
    CONSTRAINT capacity_settings_limit_bytes_check CHECK ((limit_bytes > 0)),
    CONSTRAINT capacity_settings_max_concurrent_expensive_check CHECK ((max_concurrent_expensive > 0)),
    CONSTRAINT capacity_settings_namespace_limit_bytes_check CHECK ((namespace_limit_bytes > 0)),
    CONSTRAINT capacity_settings_revision_check CHECK ((revision > 0)),
    CONSTRAINT capacity_settings_share_bytes_check CHECK ((share_bytes > 0))
);

ALTER TABLE ONLY capacity_settings ADD CONSTRAINT capacity_settings_pkey PRIMARY KEY (root_id);

ALTER TABLE ONLY capacity_settings ADD CONSTRAINT capacity_settings_pool_id_key UNIQUE (pool_id);

CREATE TABLE capture_history_parameter (
    root_id uuid NOT NULL,
    capture_id uuid NOT NULL,
    attempt_id uuid NOT NULL,
    selector_key bytea NOT NULL,
    settings_key bytea NOT NULL,
    mac_version text NOT NULL,
    expectation_json bytea NOT NULL,
    retention_json bytea NOT NULL,
    summary_expires_at timestamp with time zone NOT NULL,
    visible boolean DEFAULT true NOT NULL,
    state text DEFAULT 'reserved'::text NOT NULL,
    write_id uuid,
    write_digest bytea,
    write_started_at timestamp with time zone,
    write_until timestamp with time zone,
    write_executor_epoch uuid,
    purge_completion_json bytea,
    delete_id uuid,
    delete_executor_epoch uuid,
    delete_started_at timestamp with time zone,
    delete_until timestamp with time zone,
    delete_fence bigint,
    writer_completion_json bytea,
    copies_digest bytea,
    created_at timestamp with time zone DEFAULT clock_timestamp() NOT NULL,
    CONSTRAINT capture_history_parameter_check CHECK (((summary_expires_at > created_at) AND (summary_expires_at <= (created_at + '3650 days'::interval)))),
    CONSTRAINT capture_history_parameter_check1 CHECK (((write_id IS NULL) = (write_digest IS NULL))),
    CONSTRAINT capture_history_parameter_check2 CHECK (((write_id IS NULL) = (write_started_at IS NULL))),
    CONSTRAINT capture_history_parameter_check3 CHECK (((write_id IS NULL) = (write_until IS NULL))),
    CONSTRAINT capture_history_parameter_check4 CHECK (((write_until IS NULL) OR ((write_until > write_started_at) AND (write_until <= (write_started_at + '00:00:30'::interval))))),
    CONSTRAINT capture_history_parameter_check5 CHECK (((state <> 'available'::text) OR ((writer_completion_json IS NOT NULL) AND (copies_digest IS NOT NULL)))),
    CONSTRAINT capture_history_parameter_check6 CHECK (((state <> ALL (ARRAY['deleting'::text, 'deleted'::text])) OR ((write_id IS NULL) OR (writer_completion_json IS NOT NULL)))),
    CONSTRAINT capture_history_parameter_copies_digest_check CHECK (((copies_digest IS NULL) OR (octet_length(copies_digest) = 32))),
    CONSTRAINT capture_history_parameter_expectation_json_check CHECK (((octet_length(expectation_json) >= 1) AND (octet_length(expectation_json) <= 8192))),
    CONSTRAINT capture_history_parameter_mac_version_check CHECK (((octet_length(mac_version) >= 1) AND (octet_length(mac_version) <= 64))),
    CONSTRAINT capture_history_parameter_purge_completion_json_check CHECK (((purge_completion_json IS NULL) OR ((octet_length(purge_completion_json) >= 1) AND (octet_length(purge_completion_json) <= 8192)))),
    CONSTRAINT capture_history_parameter_retention_json_check CHECK (((octet_length(retention_json) >= 1) AND (octet_length(retention_json) <= 16384))),
    CONSTRAINT capture_history_parameter_selector_key_check CHECK ((octet_length(selector_key) = 32)),
    CONSTRAINT capture_history_parameter_settings_key_check CHECK ((octet_length(settings_key) = 32)),
    CONSTRAINT capture_history_parameter_state_check CHECK ((state = ANY (ARRAY['reserved'::text, 'write_claimed'::text, 'available'::text, 'deleting'::text, 'deleted'::text]))),
    CONSTRAINT capture_history_parameter_write_digest_check CHECK (((write_digest IS NULL) OR (octet_length(write_digest) = 32))),
    CONSTRAINT capture_history_parameter_writer_completion_json_check CHECK (((writer_completion_json IS NULL) OR ((octet_length(writer_completion_json) >= 1) AND (octet_length(writer_completion_json) <= 8192))))
);

ALTER TABLE ONLY capture_history_parameter ADD CONSTRAINT capture_history_parameter_attempt_id_key UNIQUE (attempt_id);

ALTER TABLE ONLY capture_history_parameter ADD CONSTRAINT capture_history_parameter_pkey PRIMARY KEY (capture_id);

CREATE INDEX capture_history_parameter_hidden ON capture_history_parameter USING btree (root_id, capture_id) WHERE ((NOT visible) AND (state = ANY (ARRAY['reserved'::text, 'available'::text, 'deleting'::text])));

CREATE INDEX capture_history_parameter_reserved ON capture_history_parameter USING btree (root_id, capture_id) INCLUDE (attempt_id) WHERE (state = 'reserved'::text);

CREATE INDEX capture_history_parameter_retirement ON capture_history_parameter USING btree (root_id, summary_expires_at, capture_id);

CREATE INDEX capture_history_parameter_selector ON capture_history_parameter USING btree (root_id, selector_key, created_at DESC, capture_id DESC) WHERE visible;

CREATE TABLE capture_history_quota (
    root_id uuid NOT NULL,
    selector_key bytea NOT NULL,
    used integer DEFAULT 0 NOT NULL,
    CONSTRAINT capture_history_quota_selector_key_check CHECK ((octet_length(selector_key) = 32)),
    CONSTRAINT capture_history_quota_used_check CHECK ((used >= 0))
);

ALTER TABLE ONLY capture_history_quota ADD CONSTRAINT capture_history_quota_pkey PRIMARY KEY (root_id, selector_key);

CREATE TABLE context_capture (
    id uuid NOT NULL,
    root_id uuid NOT NULL,
    request_key bytea NOT NULL,
    submission_digest bytea NOT NULL,
    scope_digest bytea NOT NULL,
    scope_json bytea NOT NULL,
    expectation_json bytea NOT NULL,
    pod_pin_json bytea NOT NULL,
    attempt_id uuid NOT NULL,
    permission_epoch uuid NOT NULL,
    permission_sequence bigint NOT NULL,
    identity_policy_uid text NOT NULL,
    identity_policy_generation bigint NOT NULL,
    identity_policy_digest bytea NOT NULL,
    created_at timestamp with time zone DEFAULT clock_timestamp() NOT NULL,
    deadline timestamp with time zone NOT NULL,
    progress_revision bigint DEFAULT 1 NOT NULL,
    deadline_observed_at timestamp with time zone,
    preview_id uuid,
    intent_operation_id uuid,
    share_instruction jsonb,
    history_cluster_id uuid,
    history_namespace_uid text,
    history_workload_uid text,
    history_origin text,
    history_parameters_required boolean DEFAULT true NOT NULL,
    repeated_from_capture_id uuid,
    repeated_from_expires_at timestamp with time zone,
    snapshot_coverage bytea,
    snapshot_coverage_digest bytea,
    snapshot_expectation_digest bytea,
    snapshot_cancel_key bytea,
    snapshot_cancel_actor bytea,
    snapshot_cancel_requested_at timestamp with time zone,
    snapshot_cancel_joined_at timestamp with time zone,
    snapshot_cancel_proof bytea,
    snapshot_cancel_proof_digest bytea,
    group_id uuid,
    group_ordinal smallint,
    reason text,
    target_labels jsonb,
    CONSTRAINT context_capture_check CHECK ((deadline > created_at)),
    CONSTRAINT context_capture_check1 CHECK (((deadline_observed_at IS NULL) OR (isfinite(deadline_observed_at) AND (deadline_observed_at >= deadline)))),
    CONSTRAINT context_capture_check2 CHECK (((intent_operation_id IS NULL) OR (intent_operation_id = id))),
    CONSTRAINT context_capture_expectation_json_check CHECK (((octet_length(expectation_json) >= 1) AND (octet_length(expectation_json) <= 65536))),
    CONSTRAINT context_capture_group_position CHECK ((((group_id IS NULL) AND (group_ordinal IS NULL)) OR ((group_id IS NOT NULL) AND ((group_ordinal >= 0) AND (group_ordinal <= 15))))),
    CONSTRAINT context_capture_history_identity CHECK ((((history_cluster_id IS NULL) AND (history_namespace_uid IS NULL) AND (history_workload_uid IS NULL) AND (history_origin IS NULL)) OR ((history_cluster_id IS NOT NULL) AND ((octet_length(history_namespace_uid) >= 1) AND (octet_length(history_namespace_uid) <= 64)) AND ((octet_length(history_workload_uid) >= 1) AND (octet_length(history_workload_uid) <= 64)) AND (history_origin = ANY (ARRAY['manual'::text, 'policy'::text]))))),
    CONSTRAINT context_capture_identity_policy_digest_check CHECK ((octet_length(identity_policy_digest) = 32)),
    CONSTRAINT context_capture_identity_policy_generation_check CHECK (((identity_policy_generation >= 1) AND (identity_policy_generation <= 2147483647))),
    CONSTRAINT context_capture_identity_policy_uid_check CHECK (((octet_length(identity_policy_uid) >= 1) AND (octet_length(identity_policy_uid) <= 64))),
    CONSTRAINT context_capture_pod_pin_json_check CHECK (((octet_length(pod_pin_json) >= 1) AND (octet_length(pod_pin_json) <= 4096))),
    CONSTRAINT context_capture_progress_revision_check CHECK (((progress_revision >= 1) AND (progress_revision <= 1000000001))),
    CONSTRAINT context_capture_reason_check CHECK (((reason IS NULL) OR ((char_length(reason) >= 1) AND (char_length(reason) <= 512)))),
    CONSTRAINT context_capture_repeat_lineage CHECK (((repeated_from_capture_id IS NULL) = (repeated_from_expires_at IS NULL))),
    CONSTRAINT context_capture_request_key_check CHECK ((octet_length(request_key) = 32)),
    CONSTRAINT context_capture_scope_digest_check CHECK ((octet_length(scope_digest) = 32)),
    CONSTRAINT context_capture_scope_json_check CHECK (((octet_length(scope_json) >= 1) AND (octet_length(scope_json) <= 65536))),
    CONSTRAINT context_capture_share_instruction_check CHECK (((share_instruction IS NULL) OR ((jsonb_typeof(share_instruction) = 'object'::text) AND (octet_length((share_instruction)::text) <= 65536)))),
    CONSTRAINT context_capture_submission_digest_check CHECK ((octet_length(submission_digest) = 32)),
    CONSTRAINT context_snapshot_completion_shape CHECK ((((snapshot_coverage IS NULL) AND (snapshot_coverage_digest IS NULL) AND (snapshot_expectation_digest IS NULL)) OR ((snapshot_coverage IS NOT NULL) AND ((octet_length(snapshot_coverage) >= 1) AND (octet_length(snapshot_coverage) <= 8192)) AND (snapshot_coverage_digest IS NOT NULL) AND (octet_length(snapshot_coverage_digest) = 32) AND (snapshot_expectation_digest IS NOT NULL) AND (octet_length(snapshot_expectation_digest) = 32)))),
    CONSTRAINT snapshot_cancel_shape CHECK ((((snapshot_cancel_key IS NULL) AND (snapshot_cancel_actor IS NULL) AND (snapshot_cancel_requested_at IS NULL) AND (snapshot_cancel_joined_at IS NULL) AND (snapshot_cancel_proof IS NULL) AND (snapshot_cancel_proof_digest IS NULL)) OR ((snapshot_cancel_key IS NOT NULL) AND (octet_length(snapshot_cancel_key) = 32) AND (snapshot_cancel_actor IS NOT NULL) AND ((octet_length(snapshot_cancel_actor) >= 1) AND (octet_length(snapshot_cancel_actor) <= 8192)) AND (snapshot_cancel_requested_at IS NOT NULL) AND isfinite(snapshot_cancel_requested_at) AND (((snapshot_cancel_joined_at IS NULL) AND (snapshot_cancel_proof IS NULL) AND (snapshot_cancel_proof_digest IS NULL)) OR ((snapshot_cancel_joined_at IS NOT NULL) AND isfinite(snapshot_cancel_joined_at) AND (((snapshot_cancel_proof IS NULL) AND (snapshot_cancel_proof_digest IS NULL)) OR ((snapshot_cancel_proof IS NOT NULL) AND ((octet_length(snapshot_cancel_proof) >= 1) AND (octet_length(snapshot_cancel_proof) <= 8192)) AND (snapshot_cancel_proof_digest IS NOT NULL) AND (octet_length(snapshot_cancel_proof_digest) = 32))))))))
);

ALTER TABLE ONLY context_capture ADD CONSTRAINT context_capture_attempt_id_key UNIQUE (attempt_id);

ALTER TABLE ONLY context_capture ADD CONSTRAINT context_capture_pkey PRIMARY KEY (id);

ALTER TABLE ONLY context_capture ADD CONSTRAINT context_capture_root_id_request_key_key UNIQUE (root_id, request_key);

ALTER TABLE ONLY context_capture ADD CONSTRAINT context_capture_root_identity UNIQUE (id, root_id);

CREATE INDEX context_capture_deadline_observation ON context_capture USING btree (root_id, deadline, id) WHERE (deadline_observed_at IS NULL);

CREATE UNIQUE INDEX context_capture_group_ordinal ON context_capture USING btree (group_id, group_ordinal) WHERE (group_id IS NOT NULL);

CREATE INDEX context_capture_history ON context_capture USING btree (root_id, history_cluster_id, history_namespace_uid, history_workload_uid, history_origin, created_at DESC, id DESC) WHERE (history_workload_uid IS NOT NULL);

CREATE INDEX context_capture_legacy_submission ON context_capture USING btree (root_id, submission_digest) WHERE (preview_id IS NULL);

CREATE UNIQUE INDEX context_capture_preview ON context_capture USING btree (root_id, preview_id) WHERE (preview_id IS NOT NULL);

CREATE TABLE context_case_locator (
    artifact_id uuid NOT NULL,
    capture_id uuid NOT NULL,
    root_id uuid NOT NULL,
    case_id uuid NOT NULL,
    cluster_id uuid NOT NULL,
    namespace_uid text NOT NULL,
    workload_uid text NOT NULL,
    pod_uid text NOT NULL,
    CONSTRAINT context_case_locator_namespace_uid_check CHECK (((octet_length(namespace_uid) >= 1) AND (octet_length(namespace_uid) <= 64))),
    CONSTRAINT context_case_locator_pod_uid_check CHECK (((octet_length(pod_uid) >= 1) AND (octet_length(pod_uid) <= 64))),
    CONSTRAINT context_case_locator_workload_uid_check CHECK (((octet_length(workload_uid) >= 1) AND (octet_length(workload_uid) <= 64)))
);

ALTER TABLE ONLY context_case_locator ADD CONSTRAINT context_case_locator_capture_id_key UNIQUE (capture_id);

ALTER TABLE ONLY context_case_locator ADD CONSTRAINT context_case_locator_pkey PRIMARY KEY (artifact_id);

CREATE INDEX context_case_locator_by_case ON context_case_locator USING btree (root_id, case_id, artifact_id);

CREATE TABLE context_catalog (
    artifact_id uuid NOT NULL,
    capture_id uuid NOT NULL,
    root_id uuid NOT NULL,
    published_at timestamp with time zone DEFAULT clock_timestamp() NOT NULL,
    copies_digest bytea NOT NULL,
    native_bytes bigint,
    acquisition_started_at timestamp with time zone,
    acquisition_completed_at timestamp with time zone,
    CONSTRAINT context_catalog_acquisition_window CHECK ((((acquisition_started_at IS NULL) AND (acquisition_completed_at IS NULL)) OR ((acquisition_started_at IS NOT NULL) AND (acquisition_completed_at IS NOT NULL) AND isfinite(acquisition_started_at) AND isfinite(acquisition_completed_at) AND (acquisition_started_at <= acquisition_completed_at)))),
    CONSTRAINT context_catalog_copies_digest_check CHECK ((octet_length(copies_digest) = 32)),
    CONSTRAINT context_catalog_native_bytes_check CHECK (((native_bytes >= 0) AND (native_bytes <= '1099511627776'::bigint)))
);

ALTER TABLE ONLY context_catalog ADD CONSTRAINT context_catalog_capture_id_key UNIQUE (capture_id);

ALTER TABLE ONLY context_catalog ADD CONSTRAINT context_catalog_pkey PRIMARY KEY (artifact_id);

CREATE INDEX context_catalog_by_root ON context_catalog USING btree (root_id, published_at, artifact_id);

CREATE TABLE context_deletion_checkpoint (
    attempt_id uuid NOT NULL,
    root_id uuid NOT NULL,
    capture_id uuid NOT NULL,
    store_id uuid NOT NULL,
    registration_digest bytea NOT NULL,
    writer_digest bytea NOT NULL,
    record_digest bytea NOT NULL,
    record_json bytea NOT NULL,
    installation_id uuid NOT NULL,
    issuer_epoch uuid NOT NULL,
    postmaster_at timestamp with time zone NOT NULL,
    database_oid oid NOT NULL,
    purge_fence bigint NOT NULL,
    purged_at timestamp with time zone NOT NULL,
    recorded_at timestamp with time zone DEFAULT clock_timestamp() NOT NULL,
    audit_receipt_json bytea,
    audit_acknowledged_at timestamp with time zone,
    finalization_xid xid8,
    CONSTRAINT context_deletion_checkpoint_audit_receipt_json_check CHECK (((audit_receipt_json IS NULL) OR ((octet_length(audit_receipt_json) >= 1) AND (octet_length(audit_receipt_json) <= 8192)))),
    CONSTRAINT context_deletion_checkpoint_check CHECK (((audit_receipt_json IS NULL) = (audit_acknowledged_at IS NULL))),
    CONSTRAINT context_deletion_checkpoint_postmaster_at_check CHECK (isfinite(postmaster_at)),
    CONSTRAINT context_deletion_checkpoint_purge_fence_check CHECK ((purge_fence > 0)),
    CONSTRAINT context_deletion_checkpoint_purged_at_check CHECK (isfinite(purged_at)),
    CONSTRAINT context_deletion_checkpoint_record_digest_check CHECK ((octet_length(record_digest) = 32)),
    CONSTRAINT context_deletion_checkpoint_record_json_check CHECK (((octet_length(record_json) >= 1) AND (octet_length(record_json) <= 8192))),
    CONSTRAINT context_deletion_checkpoint_registration_digest_check CHECK ((octet_length(registration_digest) = 32)),
    CONSTRAINT context_deletion_checkpoint_writer_digest_check CHECK ((octet_length(writer_digest) = 32))
);

ALTER TABLE ONLY context_deletion_checkpoint ADD CONSTRAINT context_deletion_checkpoint_capture_id_key UNIQUE (capture_id);

ALTER TABLE ONLY context_deletion_checkpoint ADD CONSTRAINT context_deletion_checkpoint_pkey PRIMARY KEY (attempt_id);

CREATE TABLE context_execution (
    capture_id uuid NOT NULL,
    root_id uuid NOT NULL,
    attempt_id uuid NOT NULL,
    binding_json bytea NOT NULL,
    process_json bytea NOT NULL,
    expectation_digest bytea NOT NULL,
    created_at timestamp with time zone DEFAULT clock_timestamp() NOT NULL,
    not_before timestamp with time zone NOT NULL,
    not_after timestamp with time zone NOT NULL,
    object_uid uuid,
    phase text DEFAULT 'prepared'::text NOT NULL,
    started_at timestamp with time zone,
    acquired_at timestamp with time zone,
    completed_at timestamp with time zone,
    copies_json bytea,
    copies_digest bytea,
    writer_protocol text,
    CONSTRAINT context_execution_binding_json_check CHECK (((octet_length(binding_json) >= 1) AND (octet_length(binding_json) <= 8192))),
    CONSTRAINT context_execution_check CHECK ((isfinite(not_after) AND (not_after > not_before) AND (not_after <= (not_before + '00:00:30'::interval)))),
    CONSTRAINT context_execution_check1 CHECK (COALESCE((((phase = 'prepared'::text) AND (started_at IS NULL) AND (acquired_at IS NULL) AND (completed_at IS NULL) AND (copies_json IS NULL) AND (copies_digest IS NULL)) OR ((phase = 'started'::text) AND (object_uid IS NOT NULL) AND (started_at >= not_before) AND (started_at < not_after) AND (acquired_at IS NULL) AND (completed_at IS NULL) AND (copies_json IS NULL) AND (copies_digest IS NULL)) OR ((phase = ANY (ARRAY['stored'::text, 'captureFailed'::text, 'targetGone'::text, 'denied'::text, 'storeUnconfirmed'::text, 'cancelled'::text, 'peerMembershipChanged'::text, 'peerMembershipStale'::text, 'profilerBusy'::text, 'profileUnavailable'::text])) AND (object_uid IS NOT NULL) AND (started_at >= not_before) AND (started_at < not_after) AND isfinite(completed_at) AND (completed_at >= started_at) AND (((phase = ANY (ARRAY['captureFailed'::text, 'targetGone'::text, 'denied'::text, 'cancelled'::text, 'peerMembershipChanged'::text, 'peerMembershipStale'::text, 'profilerBusy'::text, 'profileUnavailable'::text])) AND (acquired_at IS NULL) AND (copies_json IS NULL) AND (copies_digest IS NULL)) OR ((acquired_at >= started_at) AND (acquired_at < not_after) AND (completed_at >= acquired_at) AND (((phase = 'stored'::text) AND (copies_json IS NOT NULL) AND (copies_digest IS NOT NULL)) OR ((phase = 'storeUnconfirmed'::text) AND (copies_json IS NULL) AND (copies_digest IS NULL))))))), false)),
    CONSTRAINT context_execution_copies_digest_check CHECK (((copies_digest IS NULL) OR (octet_length(copies_digest) = 32))),
    CONSTRAINT context_execution_copies_json_check CHECK (((copies_json IS NULL) OR ((octet_length(copies_json) >= 1) AND (octet_length(copies_json) <= 16384)))),
    CONSTRAINT context_execution_expectation_digest_check CHECK ((octet_length(expectation_digest) = 32)),
    CONSTRAINT context_execution_not_before_check CHECK (isfinite(not_before)),
    CONSTRAINT context_execution_phase_check CHECK ((phase = ANY (ARRAY['prepared'::text, 'started'::text, 'stored'::text, 'captureFailed'::text, 'targetGone'::text, 'denied'::text, 'storeUnconfirmed'::text, 'cancelled'::text, 'peerMembershipChanged'::text, 'peerMembershipStale'::text, 'profilerBusy'::text, 'profileUnavailable'::text]))),
    CONSTRAINT context_execution_process_json_check CHECK (((octet_length(process_json) >= 1) AND (octet_length(process_json) <= 4096))),
    CONSTRAINT context_execution_writer_protocol_check CHECK (((writer_protocol IS NULL) OR (writer_protocol = 'closed-small-context/v1'::text)))
);

ALTER TABLE ONLY context_execution ADD CONSTRAINT context_execution_attempt_id_key UNIQUE (attempt_id);

ALTER TABLE ONLY context_execution ADD CONSTRAINT context_execution_pkey PRIMARY KEY (capture_id);

CREATE TABLE context_key_wrap (
    attempt_id uuid NOT NULL,
    root_id uuid NOT NULL,
    certificate_sha256 bytea NOT NULL,
    used_roles smallint NOT NULL,
    created_at timestamp with time zone DEFAULT clock_timestamp() NOT NULL,
    CONSTRAINT context_key_wrap_certificate_sha256_check CHECK ((octet_length(certificate_sha256) = 32)),
    CONSTRAINT context_key_wrap_used_roles_check CHECK (((used_roles >= 1) AND (used_roles <= 7)))
);

ALTER TABLE ONLY context_key_wrap ADD CONSTRAINT context_key_wrap_pkey PRIMARY KEY (attempt_id);

CREATE TABLE context_processing (
    artifact_id uuid NOT NULL,
    root_id uuid NOT NULL,
    capture_id uuid NOT NULL,
    attempt_id uuid NOT NULL,
    cluster_id uuid NOT NULL,
    namespace_uid text NOT NULL,
    workload_uid text NOT NULL,
    pod_uid text NOT NULL,
    anchor_at timestamp with time zone NOT NULL,
    delete_by timestamp with time zone NOT NULL,
    retire_by timestamp with time zone NOT NULL,
    origin text NOT NULL,
    parents jsonb NOT NULL,
    CONSTRAINT context_processing_anchor_at_check CHECK (isfinite(anchor_at)),
    CONSTRAINT context_processing_check CHECK ((isfinite(delete_by) AND (delete_by > anchor_at))),
    CONSTRAINT context_processing_check1 CHECK ((isfinite(retire_by) AND (retire_by > delete_by))),
    CONSTRAINT context_processing_check2 CHECK ((((origin = 'capture'::text) AND (parents = '[]'::jsonb)) OR ((origin = 'derived'::text) AND (jsonb_array_length(parents) > 0)))),
    CONSTRAINT context_processing_namespace_uid_check CHECK (((octet_length(namespace_uid) >= 1) AND (octet_length(namespace_uid) <= 64))),
    CONSTRAINT context_processing_origin_check CHECK ((origin = ANY (ARRAY['capture'::text, 'derived'::text]))),
    CONSTRAINT context_processing_parents_check CHECK (((jsonb_typeof(parents) = 'array'::text) AND (jsonb_array_length(parents) <= 16) AND (octet_length((parents)::text) <= 4096))),
    CONSTRAINT context_processing_pod_uid_check CHECK (((octet_length(pod_uid) >= 1) AND (octet_length(pod_uid) <= 64))),
    CONSTRAINT context_processing_workload_uid_check CHECK (((octet_length(workload_uid) >= 1) AND (octet_length(workload_uid) <= 64)))
);

ALTER TABLE ONLY context_processing ADD CONSTRAINT context_processing_capture_id_key UNIQUE (capture_id);

ALTER TABLE ONLY context_processing ADD CONSTRAINT context_processing_pkey PRIMARY KEY (artifact_id);

ALTER TABLE ONLY context_processing ADD CONSTRAINT context_processing_root_id_cluster_id_artifact_id_attempt_i_key UNIQUE (root_id, cluster_id, artifact_id, attempt_id);

CREATE INDEX context_processing_scope ON context_processing USING btree (root_id, cluster_id, namespace_uid, workload_uid, anchor_at);

CREATE TABLE context_query (
    id uuid NOT NULL,
    root_id uuid NOT NULL,
    allocation_id uuid CONSTRAINT context_query_allocation_id_not_null1 NOT NULL,
    account_id uuid NOT NULL,
    principal_key bytea NOT NULL,
    actor jsonb NOT NULL,
    query jsonb NOT NULL,
    initial_request jsonb NOT NULL,
    operation_id uuid NOT NULL,
    worker_id uuid NOT NULL,
    created_at timestamp with time zone NOT NULL,
    deadline timestamp with time zone NOT NULL,
    cleanup_until timestamp with time zone NOT NULL,
    retire_by timestamp with time zone NOT NULL,
    issuer_epoch uuid NOT NULL,
    postmaster_at timestamp with time zone NOT NULL,
    database_oid oid NOT NULL,
    generation smallint DEFAULT 0 NOT NULL,
    active_batch uuid,
    polls bigint DEFAULT 0 NOT NULL,
    controls bigint DEFAULT 0 NOT NULL,
    uncertain boolean DEFAULT false NOT NULL,
    baseline_allocation_id uuid,
    invocation_key text,
    request_digest bytea,
    CONSTRAINT context_query_actor_check CHECK (((jsonb_typeof(actor) = 'object'::text) AND (octet_length((actor)::text) <= 4096))),
    CONSTRAINT context_query_check CHECK ((isfinite(created_at) AND isfinite(deadline) AND (deadline > created_at) AND (deadline <= (created_at + '00:01:00'::interval)))),
    CONSTRAINT context_query_check1 CHECK ((isfinite(cleanup_until) AND isfinite(retire_by) AND (cleanup_until >= deadline) AND (retire_by >= cleanup_until))),
    CONSTRAINT context_query_controls_check CHECK (((controls >= 0) AND (controls <= 1000000))),
    CONSTRAINT context_query_generation_check CHECK (((generation >= 0) AND (generation <= 2))),
    CONSTRAINT context_query_initial_request_check CHECK (((jsonb_typeof(initial_request) = 'object'::text) AND ((octet_length((initial_request)::text) >= 2) AND (octet_length((initial_request)::text) <= 8192)))),
    CONSTRAINT context_query_invocation_pair CHECK ((((invocation_key IS NULL) AND (request_digest IS NULL)) OR ((invocation_key IS NOT NULL) AND ((octet_length(invocation_key) >= 1) AND (octet_length(invocation_key) <= 128)) AND (invocation_key !~ '[[:cntrl:]]'::text) AND (request_digest IS NOT NULL) AND (octet_length(request_digest) = 32) AND (request_digest <> decode(repeat('00'::text, 32), 'hex'::text))))),
    CONSTRAINT context_query_polls_check CHECK (((polls >= 0) AND (polls <= 1000000))),
    CONSTRAINT context_query_postmaster_at_check CHECK (isfinite(postmaster_at)),
    CONSTRAINT context_query_principal_key_check CHECK ((octet_length(principal_key) = 32)),
    CONSTRAINT context_query_query_check CHECK (((jsonb_typeof(query) = 'object'::text) AND ((octet_length((query)::text) >= 2) AND (octet_length((query)::text) <=
CASE
    WHEN ((query #> '{Scope,Comparison}'::text[]) IS NOT NULL) THEN 98304
    ELSE 65536
END))))
);

ALTER TABLE ONLY context_query ADD CONSTRAINT context_query_id_root_id_key UNIQUE (id, root_id);

ALTER TABLE ONLY context_query ADD CONSTRAINT context_query_operation_id_key UNIQUE (operation_id);

ALTER TABLE ONLY context_query ADD CONSTRAINT context_query_pkey PRIMARY KEY (id);

ALTER TABLE ONLY context_query ADD CONSTRAINT context_query_worker_id_key UNIQUE (worker_id);

CREATE UNIQUE INDEX context_query_invocation ON context_query USING btree (root_id, principal_key, ((actor ->> 'ClientID'::text)), invocation_key) WHERE (invocation_key IS NOT NULL);

CREATE TABLE context_query_allocation (
    id uuid NOT NULL,
    root_id uuid NOT NULL,
    cluster_id uuid NOT NULL,
    namespace_uid text NOT NULL,
    workload_uid text NOT NULL,
    revision bigint NOT NULL,
    pool_source jsonb NOT NULL,
    policy_source jsonb NOT NULL,
    query_limit bigint NOT NULL,
    allocated bigint DEFAULT 0 NOT NULL,
    CONSTRAINT context_query_allocation_check CHECK (((allocated >= 0) AND (allocated <= query_limit))),
    CONSTRAINT context_query_allocation_namespace_uid_check CHECK (((octet_length(namespace_uid) >= 1) AND (octet_length(namespace_uid) <= 64))),
    CONSTRAINT context_query_allocation_policy_source_check CHECK (((jsonb_typeof(policy_source) = 'object'::text) AND (octet_length((policy_source)::text) <= 4096))),
    CONSTRAINT context_query_allocation_pool_source_check CHECK (((jsonb_typeof(pool_source) = 'object'::text) AND (octet_length((pool_source)::text) <= 4096))),
    CONSTRAINT context_query_allocation_query_limit_check CHECK (((query_limit >= 1) AND (query_limit <= 1000000))),
    CONSTRAINT context_query_allocation_revision_check CHECK (((revision >= 1) AND (revision <= '1152921504606846976'::bigint))),
    CONSTRAINT context_query_allocation_workload_uid_check CHECK (((octet_length(workload_uid) >= 1) AND (octet_length(workload_uid) <= 64)))
);

ALTER TABLE ONLY context_query_allocation ADD CONSTRAINT context_query_allocation_id_root_id_key UNIQUE (id, root_id);

ALTER TABLE ONLY context_query_allocation ADD CONSTRAINT context_query_allocation_pkey PRIMARY KEY (id);

ALTER TABLE ONLY context_query_allocation ADD CONSTRAINT context_query_allocation_root_id_cluster_id_namespace_uid_w_key UNIQUE (root_id, cluster_id, namespace_uid, workload_uid);

CREATE TABLE context_query_backing (
    root_id uuid NOT NULL,
    installation_id uuid NOT NULL,
    acceptance_id uuid NOT NULL,
    profile jsonb NOT NULL,
    qualification jsonb NOT NULL,
    envelope jsonb NOT NULL,
    query_limit bigint NOT NULL,
    principal_query_limit bigint NOT NULL,
    principal_account_limit bigint NOT NULL,
    allocation_limit bigint NOT NULL,
    allocated bigint DEFAULT 0 NOT NULL,
    principals bigint DEFAULT 0 NOT NULL,
    allocations bigint DEFAULT 0 NOT NULL,
    observed_at timestamp with time zone NOT NULL,
    fresh_until timestamp with time zone NOT NULL,
    hard_until timestamp with time zone NOT NULL,
    effects_until timestamp with time zone NOT NULL,
    cleanup_until timestamp with time zone NOT NULL,
    retire_by timestamp with time zone NOT NULL,
    suspended boolean DEFAULT true NOT NULL,
    CONSTRAINT context_query_backing_allocation_limit_check CHECK (((allocation_limit >= 1) AND (allocation_limit <= 1000000))),
    CONSTRAINT context_query_backing_check CHECK (((principal_query_limit >= 1) AND (principal_query_limit <= query_limit))),
    CONSTRAINT context_query_backing_check1 CHECK (((principal_account_limit >= 1) AND (principal_account_limit <= query_limit))),
    CONSTRAINT context_query_backing_check2 CHECK (((allocated >= 0) AND (allocated <= query_limit))),
    CONSTRAINT context_query_backing_check3 CHECK (((principals >= 0) AND (principals <= principal_account_limit))),
    CONSTRAINT context_query_backing_check4 CHECK (((allocations >= 0) AND (allocations <= allocation_limit))),
    CONSTRAINT context_query_backing_check5 CHECK ((isfinite(observed_at) AND isfinite(fresh_until) AND (fresh_until > observed_at) AND (fresh_until <= (observed_at + '00:00:05'::interval)))),
    CONSTRAINT context_query_backing_check6 CHECK ((isfinite(hard_until) AND isfinite(effects_until) AND isfinite(cleanup_until) AND isfinite(retire_by) AND (effects_until >= hard_until) AND (cleanup_until > effects_until) AND (retire_by >= cleanup_until))),
    CONSTRAINT context_query_backing_envelope_check CHECK (((jsonb_typeof(envelope) = 'object'::text) AND ((octet_length((envelope)::text) >= 2) AND (octet_length((envelope)::text) <= 8192)))),
    CONSTRAINT context_query_backing_profile_check CHECK (((jsonb_typeof(profile) = 'object'::text) AND ((octet_length((profile)::text) >= 2) AND (octet_length((profile)::text) <= 32768)))),
    CONSTRAINT context_query_backing_qualification_check CHECK (((jsonb_typeof(qualification) = 'object'::text) AND ((octet_length((qualification)::text) >= 2) AND (octet_length((qualification)::text) <= 32768)))),
    CONSTRAINT context_query_backing_query_limit_check CHECK (((query_limit >= 1) AND (query_limit <= 1000000)))
);

ALTER TABLE ONLY context_query_backing ADD CONSTRAINT context_query_backing_acceptance_id_key UNIQUE (acceptance_id);

ALTER TABLE ONLY context_query_backing ADD CONSTRAINT context_query_backing_pkey PRIMARY KEY (root_id);

CREATE TABLE context_query_batch (
    id uuid NOT NULL,
    query_id uuid NOT NULL,
    operation_id uuid NOT NULL,
    generation smallint NOT NULL,
    batch jsonb NOT NULL,
    claim_id uuid,
    closed boolean DEFAULT false NOT NULL,
    native_operation jsonb,
    native_authority jsonb,
    native_closed boolean DEFAULT false NOT NULL,
    CONSTRAINT context_query_batch_batch_check CHECK (((jsonb_typeof(batch) = 'object'::text) AND ((octet_length((batch)::text) >= 2) AND (octet_length((batch)::text) <=
CASE
    WHEN ((batch #>> '{Request,Call,Tool}'::text[]) = 'compare_profiles'::text) THEN 32768
    ELSE 16384
END)))),
    CONSTRAINT context_query_batch_generation_check CHECK (((generation >= 1) AND (generation <= 2))),
    CONSTRAINT query_native_pair CHECK ((((native_operation IS NULL) AND (native_authority IS NULL) AND (NOT native_closed)) OR COALESCE(((jsonb_typeof(native_operation) = 'object'::text) AND ((octet_length((native_operation)::text) >= 2) AND (octet_length((native_operation)::text) <= 16384)) AND (jsonb_typeof(native_authority) = 'object'::text) AND ((octet_length((native_authority)::text) >= 2) AND (octet_length((native_authority)::text) <=
CASE
    WHEN ((native_authority #> '{Scope,Comparison}'::text[]) IS NOT NULL) THEN 131072
    ELSE 65536
END))), false)))
);

ALTER TABLE ONLY context_query_batch ADD CONSTRAINT context_query_batch_id_query_id_key UNIQUE (id, query_id);

ALTER TABLE ONLY context_query_batch ADD CONSTRAINT context_query_batch_operation_id_key UNIQUE (operation_id);

ALTER TABLE ONLY context_query_batch ADD CONSTRAINT context_query_batch_pkey PRIMARY KEY (id);

ALTER TABLE ONLY context_query_batch ADD CONSTRAINT context_query_batch_query_id_generation_key UNIQUE (query_id, generation);

CREATE TABLE context_query_call (
    operation_id uuid NOT NULL,
    query_id uuid NOT NULL,
    request jsonb NOT NULL,
    is_poll boolean NOT NULL,
    CONSTRAINT context_query_call_request_check CHECK (((jsonb_typeof(request) = 'object'::text) AND ((octet_length((request)::text) >= 2) AND (octet_length((request)::text) <= 8192))))
);

ALTER TABLE ONLY context_query_call ADD CONSTRAINT context_query_call_pkey PRIMARY KEY (operation_id);

CREATE TABLE context_query_capacity (
    root_id uuid NOT NULL,
    acceptance_id uuid NOT NULL,
    capacity_id uuid NOT NULL,
    plan jsonb NOT NULL,
    source_digest bytea NOT NULL,
    issuer_epoch uuid NOT NULL,
    postmaster_at timestamp with time zone NOT NULL,
    database_oid oid NOT NULL,
    accepted_at timestamp with time zone NOT NULL,
    observations bigint DEFAULT 0 NOT NULL,
    observation_id uuid,
    observation_ordinal bigint,
    observation_started_at timestamp with time zone,
    observation_until timestamp with time zone,
    observation_accepted boolean DEFAULT false NOT NULL,
    observation_completed boolean DEFAULT false NOT NULL,
    negative_observed_at timestamp with time zone,
    CONSTRAINT context_query_capacity_accepted_at_check CHECK (isfinite(accepted_at)),
    CONSTRAINT context_query_capacity_check CHECK ((((observation_id IS NULL) AND (observation_ordinal IS NULL) AND (observation_started_at IS NULL) AND (observation_until IS NULL) AND (NOT observation_accepted) AND (NOT observation_completed)) OR ((observation_id IS NOT NULL) AND (observation_ordinal IS NOT NULL) AND (observation_started_at IS NOT NULL) AND (observation_until IS NOT NULL) AND ((observation_ordinal >= 1) AND (observation_ordinal <= observations)) AND isfinite(observation_started_at) AND isfinite(observation_until) AND (observation_started_at < observation_until) AND (observation_until <= (observation_started_at + '00:00:05'::interval))))),
    CONSTRAINT context_query_capacity_negative_observed_at_check CHECK (((negative_observed_at IS NULL) OR isfinite(negative_observed_at))),
    CONSTRAINT context_query_capacity_observations_check CHECK (((observations >= 0) AND (observations <= 1000001))),
    CONSTRAINT context_query_capacity_plan_check CHECK (((jsonb_typeof(plan) = 'object'::text) AND (octet_length((plan)::text) <= 131072))),
    CONSTRAINT context_query_capacity_source_digest_check CHECK ((octet_length(source_digest) = 32))
);

ALTER TABLE ONLY context_query_capacity ADD CONSTRAINT context_query_capacity_acceptance_id_key UNIQUE (acceptance_id);

ALTER TABLE ONLY context_query_capacity ADD CONSTRAINT context_query_capacity_capacity_id_key UNIQUE (capacity_id);

ALTER TABLE ONLY context_query_capacity ADD CONSTRAINT context_query_capacity_pkey PRIMARY KEY (root_id);

CREATE TABLE context_query_key_binding (
    batch_id uuid NOT NULL,
    query_id uuid NOT NULL,
    binding jsonb NOT NULL,
    used_roles smallint DEFAULT 0 NOT NULL,
    child_id uuid NOT NULL,
    source_ordinal smallint,
    CONSTRAINT context_query_key_binding_binding_check CHECK (((jsonb_typeof(binding) = 'object'::text) AND ((octet_length((binding)::text) >= 2) AND (octet_length((binding)::text) <=
CASE
    WHEN (source_ordinal IS NOT NULL) THEN 4096
    WHEN ((binding #>> '{Authority,Scope,NativeType}'::text[]) = ANY (ARRAY['syscallRecords'::text, 'syscallArguments'::text])) THEN 49152
    WHEN (((binding #>> '{Authority,Scope,NativeType}'::text[]) = ANY (ARRAY['pcapng'::text, 'rawPcapng'::text])) AND ((binding #>> '{Authority,Scope,DisplayVersion}'::text[]) = 'approved-pcap-query/v1'::text) AND ((binding #>> '{Authority,Scope,SourceFormat}'::text[]) =
    CASE (binding #>> '{Authority,Scope,NativeType}'::text[])
        WHEN 'pcapng'::text THEN 'pcapng'::text
        ELSE 'pcapng-raw'::text
    END) AND (jsonb_typeof((binding #> '{Authority,Scope,PacketQuery}'::text[])) = 'object'::text)) THEN 49152
    ELSE 16384
END)))),
    CONSTRAINT context_query_key_binding_source_ordinal_check CHECK ((source_ordinal = ANY (ARRAY[0, 1]))),
    CONSTRAINT context_query_key_binding_used_roles_check CHECK (((used_roles >= 0) AND (used_roles <= 7)))
);

ALTER TABLE ONLY context_query_key_binding ADD CONSTRAINT context_query_key_binding_pkey PRIMARY KEY (child_id);

CREATE UNIQUE INDEX context_query_comparison_key_child ON context_query_key_binding USING btree (batch_id, source_ordinal) WHERE (source_ordinal IS NOT NULL);

CREATE UNIQUE INDEX context_query_legacy_key_child ON context_query_key_binding USING btree (batch_id) WHERE (source_ordinal IS NULL);

CREATE TABLE context_query_principal (
    id uuid NOT NULL,
    root_id uuid NOT NULL,
    principal_key bytea NOT NULL,
    allocated bigint NOT NULL,
    CONSTRAINT context_query_principal_allocated_check CHECK (((allocated >= 0) AND (allocated <= 1000000))),
    CONSTRAINT context_query_principal_principal_key_check CHECK ((octet_length(principal_key) = 32))
);

ALTER TABLE ONLY context_query_principal ADD CONSTRAINT context_query_principal_id_root_id_key UNIQUE (id, root_id);

ALTER TABLE ONLY context_query_principal ADD CONSTRAINT context_query_principal_pkey PRIMARY KEY (id);

ALTER TABLE ONLY context_query_principal ADD CONSTRAINT context_query_principal_root_id_principal_key_key UNIQUE (root_id, principal_key);

CREATE TABLE context_query_worker (
    query_id uuid NOT NULL,
    worker_id uuid NOT NULL,
    binding jsonb NOT NULL,
    proof jsonb NOT NULL,
    CONSTRAINT context_query_worker_binding_check CHECK (((jsonb_typeof(binding) = 'object'::text) AND ((octet_length((binding)::text) >= 2) AND (octet_length((binding)::text) <= 16384)))),
    CONSTRAINT context_query_worker_proof_check CHECK (((jsonb_typeof(proof) = 'object'::text) AND ((octet_length((proof)::text) >= 2) AND (octet_length((proof)::text) <= 16384))))
);

ALTER TABLE ONLY context_query_worker ADD CONSTRAINT context_query_worker_pkey PRIMARY KEY (query_id);

ALTER TABLE ONLY context_query_worker ADD CONSTRAINT context_query_worker_worker_id_key UNIQUE (worker_id);

CREATE TABLE context_storage_binding (
    root_id uuid NOT NULL,
    cluster_id uuid NOT NULL,
    namespace_uid text NOT NULL,
    workload_uid text NOT NULL,
    allocation_id uuid NOT NULL,
    source_uid text NOT NULL,
    source_generation bigint NOT NULL,
    source_digest bytea NOT NULL,
    observed_at timestamp with time zone NOT NULL,
    fresh_until timestamp with time zone NOT NULL,
    CONSTRAINT context_storage_binding_namespace_uid_check CHECK (((octet_length(namespace_uid) >= 1) AND (octet_length(namespace_uid) <= 64))),
    CONSTRAINT context_storage_binding_source_digest_check CHECK ((octet_length(source_digest) = 32)),
    CONSTRAINT context_storage_binding_source_generation_check CHECK (((source_generation >= 1) AND (source_generation <= 2147483647))),
    CONSTRAINT context_storage_binding_source_uid_check CHECK (((octet_length(source_uid) >= 1) AND (octet_length(source_uid) <= 64))),
    CONSTRAINT context_storage_binding_workload_uid_check CHECK (((octet_length(workload_uid) >= 1) AND (octet_length(workload_uid) <= 64)))
);

ALTER TABLE ONLY context_storage_binding ADD CONSTRAINT context_storage_binding_allocation_id_key UNIQUE (allocation_id);

ALTER TABLE ONLY context_storage_binding ADD CONSTRAINT context_storage_binding_pkey PRIMARY KEY (root_id, cluster_id, namespace_uid, workload_uid);

CREATE TABLE context_writer_completion (
    capture_id uuid NOT NULL,
    root_id uuid NOT NULL,
    attempt_id uuid NOT NULL,
    registration_digest bytea NOT NULL,
    expectation_digest bytea NOT NULL,
    copies_digest bytea NOT NULL,
    execution_digest bytea NOT NULL,
    completion_digest bytea NOT NULL,
    installation_id uuid NOT NULL,
    issuer_epoch uuid NOT NULL,
    postmaster_at timestamp with time zone NOT NULL,
    database_oid oid NOT NULL,
    stored_at timestamp with time zone NOT NULL,
    closed_at timestamp with time zone NOT NULL,
    recorded_at timestamp with time zone DEFAULT clock_timestamp() NOT NULL,
    CONSTRAINT context_writer_completion_check CHECK ((isfinite(closed_at) AND (closed_at >= stored_at))),
    CONSTRAINT context_writer_completion_completion_digest_check CHECK ((octet_length(completion_digest) = 32)),
    CONSTRAINT context_writer_completion_copies_digest_check CHECK ((octet_length(copies_digest) = 32)),
    CONSTRAINT context_writer_completion_execution_digest_check CHECK ((octet_length(execution_digest) = 32)),
    CONSTRAINT context_writer_completion_expectation_digest_check CHECK ((octet_length(expectation_digest) = 32)),
    CONSTRAINT context_writer_completion_postmaster_at_check CHECK (isfinite(postmaster_at)),
    CONSTRAINT context_writer_completion_registration_digest_check CHECK ((octet_length(registration_digest) = 32)),
    CONSTRAINT context_writer_completion_stored_at_check CHECK (isfinite(stored_at))
);

ALTER TABLE ONLY context_writer_completion ADD CONSTRAINT context_writer_completion_attempt_id_key UNIQUE (attempt_id);

ALTER TABLE ONLY context_writer_completion ADD CONSTRAINT context_writer_completion_pkey PRIMARY KEY (capture_id);

CREATE TABLE custody_allocation (
    id uuid NOT NULL,
    pool_id uuid NOT NULL,
    scope_id uuid NOT NULL,
    service_class text NOT NULL,
    revision bigint NOT NULL,
    valid_until timestamp with time zone NOT NULL,
    paused boolean DEFAULT false NOT NULL,
    byte_limit bigint NOT NULL,
    object_limit bigint NOT NULL,
    charged_bytes bigint DEFAULT 0 NOT NULL,
    charged_objects bigint DEFAULT 0 NOT NULL,
    CONSTRAINT custody_allocation_byte_limit_check CHECK ((byte_limit >= 0)),
    CONSTRAINT custody_allocation_check CHECK (((charged_bytes >= 0) AND (charged_bytes <= byte_limit))),
    CONSTRAINT custody_allocation_check1 CHECK (((charged_objects >= 0) AND (charged_objects <= object_limit))),
    CONSTRAINT custody_allocation_object_limit_check CHECK ((object_limit >= 0)),
    CONSTRAINT custody_allocation_revision_check CHECK ((revision > 0)),
    CONSTRAINT custody_allocation_service_class_check CHECK ((service_class = ANY (ARRAY['context'::text, 'evidence'::text])))
);

ALTER TABLE ONLY custody_allocation ADD CONSTRAINT custody_allocation_pkey PRIMARY KEY (id);

ALTER TABLE ONLY custody_allocation ADD CONSTRAINT custody_allocation_pool_id_scope_id_service_class_key UNIQUE (pool_id, scope_id, service_class);

CREATE TABLE custody_attempt (
    id uuid NOT NULL,
    cluster_id uuid NOT NULL,
    artifact_id uuid NOT NULL,
    allocation_id uuid NOT NULL,
    request_digest bytea NOT NULL,
    pool_revision bigint NOT NULL,
    allocation_revision bigint NOT NULL,
    native_limit bigint NOT NULL,
    reserved_bytes bigint NOT NULL,
    anchor_at timestamp with time zone NOT NULL,
    write_until timestamp with time zone NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    delete_by timestamp with time zone NOT NULL,
    state text DEFAULT 'reserved'::text NOT NULL,
    copies_digest bytea,
    deletion_fence bigint DEFAULT 0 NOT NULL,
    lease_until timestamp with time zone,
    deleted_at timestamp with time zone,
    effective_expires_at timestamp with time zone NOT NULL,
    effective_delete_by timestamp with time zone NOT NULL,
    retention_sequence bigint DEFAULT 0 NOT NULL,
    CONSTRAINT custody_attempt_check CHECK (((anchor_at < write_until) AND (write_until <= expires_at) AND (expires_at < delete_by))),
    CONSTRAINT custody_attempt_check1 CHECK (((state = 'deleted'::text) = (deleted_at IS NOT NULL))),
    CONSTRAINT custody_attempt_copies_digest_check CHECK ((octet_length(copies_digest) = 32)),
    CONSTRAINT custody_attempt_deletion_fence_check CHECK ((deletion_fence >= 0)),
    CONSTRAINT custody_attempt_native_limit_check CHECK (((native_limit >= 0) AND (native_limit <= '83231768576'::bigint))),
    CONSTRAINT custody_attempt_request_digest_check CHECK ((octet_length(request_digest) = 32)),
    CONSTRAINT custody_attempt_reserved_bytes_check CHECK ((reserved_bytes > 0)),
    CONSTRAINT custody_attempt_retention_sequence_check CHECK ((retention_sequence >= 0)),
    CONSTRAINT custody_attempt_state_check CHECK ((state = ANY (ARRAY['reserved'::text, 'stored_unpublished'::text, 'deleting'::text, 'deleted'::text]))),
    CONSTRAINT custody_retention_bounds CHECK (((anchor_at <= effective_expires_at) AND (effective_expires_at < effective_delete_by) AND (effective_expires_at <= expires_at) AND (effective_delete_by <= delete_by)))
);

ALTER TABLE ONLY custody_attempt ADD CONSTRAINT custody_attempt_artifact_id_key UNIQUE (artifact_id);

ALTER TABLE ONLY custody_attempt ADD CONSTRAINT custody_attempt_pkey PRIMARY KEY (id);

CREATE INDEX custody_due ON custody_attempt USING btree (expires_at, id) WHERE (state <> 'deleted'::text);

CREATE INDEX custody_effective_due ON custody_attempt USING btree (effective_expires_at, id) WHERE (state <> 'deleted'::text);

CREATE INDEX custody_effective_overdue ON custody_attempt USING btree (allocation_id, effective_delete_by) WHERE (state <> 'deleted'::text);

CREATE INDEX custody_overdue ON custody_attempt USING btree (allocation_id, delete_by) WHERE (state <> 'deleted'::text);

CREATE TABLE custody_copy (
    attempt_id uuid NOT NULL,
    role smallint NOT NULL,
    byte_limit bigint NOT NULL,
    ciphertext_bytes bigint,
    ciphertext_sha256 bytea,
    etag text,
    version_id text,
    CONSTRAINT custody_copy_byte_limit_check CHECK ((byte_limit > 0)),
    CONSTRAINT custody_copy_check CHECK (((ciphertext_bytes > 0) AND (ciphertext_bytes <= byte_limit))),
    CONSTRAINT custody_copy_check1 CHECK (((ciphertext_bytes IS NULL) = (ciphertext_sha256 IS NULL))),
    CONSTRAINT custody_copy_check2 CHECK (((ciphertext_bytes IS NULL) = (etag IS NULL))),
    CONSTRAINT custody_copy_ciphertext_sha256_check CHECK ((octet_length(ciphertext_sha256) = 32)),
    CONSTRAINT custody_copy_etag_check CHECK (((octet_length(etag) >= 1) AND (octet_length(etag) <= 1024))),
    CONSTRAINT custody_copy_role_check CHECK (((role >= 0) AND (role <= 3))),
    CONSTRAINT custody_copy_version_id_check CHECK (((octet_length(version_id) >= 1) AND (octet_length(version_id) <= 1024)))
);

ALTER TABLE ONLY custody_copy ADD CONSTRAINT custody_copy_pkey PRIMARY KEY (attempt_id, role);

CREATE TABLE custody_event (
    attempt_id uuid NOT NULL,
    phase text NOT NULL,
    created_at timestamp with time zone DEFAULT clock_timestamp() NOT NULL,
    CONSTRAINT custody_event_phase_check CHECK ((phase = ANY (ARRAY['registered'::text, 'stored'::text, 'deleted'::text])))
);

ALTER TABLE ONLY custody_event ADD CONSTRAINT custody_event_pkey PRIMARY KEY (attempt_id, phase);

CREATE TABLE custody_pool (
    id uuid NOT NULL,
    store_id uuid NOT NULL,
    revision bigint NOT NULL,
    valid_until timestamp with time zone NOT NULL,
    paused boolean DEFAULT false NOT NULL,
    byte_limit bigint NOT NULL,
    object_limit bigint NOT NULL,
    allocated_bytes bigint DEFAULT 0 NOT NULL,
    allocated_objects bigint DEFAULT 0 NOT NULL,
    CONSTRAINT custody_pool_byte_limit_check CHECK ((byte_limit >= 0)),
    CONSTRAINT custody_pool_check CHECK (((allocated_bytes >= 0) AND (allocated_bytes <= byte_limit))),
    CONSTRAINT custody_pool_check1 CHECK (((allocated_objects >= 0) AND (allocated_objects <= object_limit))),
    CONSTRAINT custody_pool_object_limit_check CHECK ((object_limit >= 0)),
    CONSTRAINT custody_pool_revision_check CHECK ((revision > 0))
);

ALTER TABLE ONLY custody_pool ADD CONSTRAINT custody_pool_pkey PRIMARY KEY (id);

ALTER TABLE ONLY custody_pool ADD CONSTRAINT custody_pool_store_id_key UNIQUE (store_id);

CREATE TABLE custody_stream (
    attempt_id uuid NOT NULL,
    writer_epoch uuid,
    plan_digest bytea,
    temporary_bytes bigint NOT NULL,
    temporary_objects bigint NOT NULL,
    state jsonb NOT NULL,
    revision bigint DEFAULT 1 NOT NULL,
    released_at timestamp with time zone,
    CONSTRAINT custody_stream_binding_pair CHECK (((writer_epoch IS NULL) = (plan_digest IS NULL))),
    CONSTRAINT custody_stream_plan_digest_check CHECK ((octet_length(plan_digest) = 32)),
    CONSTRAINT custody_stream_revision_check CHECK ((revision >= 1)),
    CONSTRAINT custody_stream_state_check CHECK (((jsonb_typeof(state) = 'object'::text) AND (octet_length((state)::text) <= 16384))),
    CONSTRAINT custody_stream_temporary_bytes_check CHECK (((temporary_bytes >= 1) AND (temporary_bytes <= '83882016768'::bigint))),
    CONSTRAINT custody_stream_temporary_objects_check CHECK (((temporary_objects >= 2) AND (temporary_objects <= 10001)))
);

ALTER TABLE ONLY custody_stream ADD CONSTRAINT custody_stream_pkey PRIMARY KEY (attempt_id);

CREATE TABLE download_allocation (
    id uuid NOT NULL,
    root_id uuid NOT NULL,
    cluster_id uuid NOT NULL,
    namespace_uid text NOT NULL,
    workload_uid text NOT NULL,
    output_limit bigint NOT NULL,
    read_limit bigint NOT NULL,
    reserved_output bigint DEFAULT 0 NOT NULL,
    reserved_read bigint DEFAULT 0 NOT NULL,
    valid_until timestamp with time zone NOT NULL,
    CONSTRAINT download_allocation_check CHECK (((reserved_output >= 0) AND (reserved_output <= output_limit))),
    CONSTRAINT download_allocation_check1 CHECK (((reserved_read >= 0) AND (reserved_read <= read_limit))),
    CONSTRAINT download_allocation_namespace_uid_check CHECK (((octet_length(namespace_uid) >= 1) AND (octet_length(namespace_uid) <= 64))),
    CONSTRAINT download_allocation_output_limit_check CHECK (((output_limit >= 1) AND (output_limit <= '17592186044416'::bigint))),
    CONSTRAINT download_allocation_read_limit_check CHECK (((read_limit >= 1) AND (read_limit <= '70368744177664'::bigint))),
    CONSTRAINT download_allocation_workload_uid_check CHECK (((octet_length(workload_uid) >= 1) AND (octet_length(workload_uid) <= 64)))
);

ALTER TABLE ONLY download_allocation ADD CONSTRAINT download_allocation_id_root_id_key UNIQUE (id, root_id);

ALTER TABLE ONLY download_allocation ADD CONSTRAINT download_allocation_pkey PRIMARY KEY (id);

CREATE TABLE download_batch (
    id uuid NOT NULL,
    session_id uuid NOT NULL,
    generation bigint NOT NULL,
    intent_json jsonb NOT NULL,
    lease_until timestamp with time zone NOT NULL,
    audit_acknowledged_at timestamp with time zone,
    audit_receipt_json jsonb,
    outcome_json jsonb,
    outcome_acknowledged_at timestamp with time zone,
    outcome_receipt_json jsonb,
    CONSTRAINT download_batch_audit_receipt_json_check CHECK (((audit_receipt_json IS NULL) OR ((jsonb_typeof(audit_receipt_json) = 'object'::text) AND (octet_length((audit_receipt_json)::text) <= 4096)))),
    CONSTRAINT download_batch_check CHECK (((audit_acknowledged_at IS NULL) = (audit_receipt_json IS NULL))),
    CONSTRAINT download_batch_check1 CHECK (((outcome_acknowledged_at IS NULL) = (outcome_receipt_json IS NULL))),
    CONSTRAINT download_batch_check2 CHECK (((outcome_acknowledged_at IS NULL) OR (outcome_json IS NOT NULL))),
    CONSTRAINT download_batch_generation_check CHECK ((generation > 0)),
    CONSTRAINT download_batch_intent_json_check CHECK (((jsonb_typeof(intent_json) = 'object'::text) AND (octet_length((intent_json)::text) <= 16384))),
    CONSTRAINT download_batch_outcome_json_check CHECK (((outcome_json IS NULL) OR ((jsonb_typeof(outcome_json) = 'object'::text) AND (octet_length((outcome_json)::text) <= 24576)))),
    CONSTRAINT download_batch_outcome_receipt_json_check CHECK (((outcome_receipt_json IS NULL) OR ((jsonb_typeof(outcome_receipt_json) = 'object'::text) AND (octet_length((outcome_receipt_json)::text) <= 4096))))
);

ALTER TABLE ONLY download_batch ADD CONSTRAINT download_batch_pkey PRIMARY KEY (id);

ALTER TABLE ONLY download_batch ADD CONSTRAINT download_batch_session_id_generation_key UNIQUE (session_id, generation);

CREATE INDEX download_active_leases ON download_batch USING btree (lease_until) WHERE (outcome_json IS NULL);

CREATE TABLE download_control_allocation (
    id uuid NOT NULL,
    root_id uuid NOT NULL,
    audit_store_id uuid NOT NULL,
    window_limit bigint NOT NULL,
    audit_byte_limit bigint NOT NULL,
    reserved_windows bigint DEFAULT 0 NOT NULL,
    reserved_audit_bytes bigint DEFAULT 0 NOT NULL,
    valid_until timestamp with time zone NOT NULL,
    audit_write_until timestamp with time zone NOT NULL,
    CONSTRAINT download_control_allocation_audit_byte_limit_check CHECK (((audit_byte_limit >= 1) AND (audit_byte_limit <= '68987912192'::bigint))),
    CONSTRAINT download_control_allocation_audit_write_until_check CHECK (isfinite(audit_write_until)),
    CONSTRAINT download_control_allocation_check1 CHECK (((reserved_windows >= 0) AND (reserved_windows <= window_limit))),
    CONSTRAINT download_control_allocation_check2 CHECK (((reserved_audit_bytes >= 0) AND (reserved_audit_bytes <= audit_byte_limit))),
    CONSTRAINT download_control_allocation_check3 CHECK (((audit_write_until > valid_until) AND (audit_write_until <= (valid_until + '00:05:00'::interval)))),
    CONSTRAINT download_control_allocation_valid_until_check CHECK (isfinite(valid_until)),
    CONSTRAINT download_control_allocation_window_limit_check CHECK (((window_limit >= 1) AND (window_limit <= 263168)))
);

ALTER TABLE ONLY download_control_allocation ADD CONSTRAINT download_control_allocation_id_root_id_key UNIQUE (id, root_id);

ALTER TABLE ONLY download_control_allocation ADD CONSTRAINT download_control_allocation_pkey PRIMARY KEY (id);

CREATE TABLE download_key_binding (
    batch_id uuid NOT NULL,
    session_id uuid NOT NULL,
    root_id uuid NOT NULL,
    installation_id uuid NOT NULL,
    key_id text NOT NULL,
    peer_id uuid NOT NULL,
    certificate_sha256 bytea NOT NULL,
    authority_json bytea NOT NULL,
    created_at timestamp with time zone DEFAULT clock_timestamp() NOT NULL,
    valid_until timestamp with time zone NOT NULL,
    used_roles smallint DEFAULT 0 NOT NULL,
    worker_proof_json bytea,
    CONSTRAINT download_key_binding_authority_json_check CHECK (((octet_length(authority_json) >= 1) AND (octet_length(authority_json) <= 65536))),
    CONSTRAINT download_key_binding_certificate_sha256_check CHECK ((octet_length(certificate_sha256) = 32)),
    CONSTRAINT download_key_binding_check CHECK (((valid_until > created_at) AND (valid_until <= (created_at + '00:00:05'::interval)))),
    CONSTRAINT download_key_binding_key_id_check CHECK ((key_id ~ '^[a-zA-Z0-9_-]{1,128}$'::text)),
    CONSTRAINT download_key_binding_used_roles_check CHECK (((used_roles >= 0) AND (used_roles <= 7))),
    CONSTRAINT download_key_binding_worker_proof_json_check CHECK (((worker_proof_json IS NULL) OR ((octet_length(worker_proof_json) >= 1) AND (octet_length(worker_proof_json) <= 16384))))
);

ALTER TABLE ONLY download_key_binding ADD CONSTRAINT download_key_binding_pkey PRIMARY KEY (batch_id);

CREATE TABLE download_native_backing (
    allocation_id uuid NOT NULL,
    root_id uuid NOT NULL,
    policy_json jsonb NOT NULL,
    rows_limit bigint NOT NULL,
    keys_limit bigint NOT NULL,
    transitions_per_row bigint NOT NULL,
    charged_rows bigint DEFAULT 0 NOT NULL,
    charged_keys bigint DEFAULT 0 NOT NULL,
    backup_horizon_seconds bigint NOT NULL,
    cleanup_seconds bigint NOT NULL,
    valid_until timestamp with time zone NOT NULL,
    retire_by timestamp with time zone NOT NULL,
    residual_until timestamp with time zone NOT NULL,
    overdue boolean DEFAULT false NOT NULL,
    CONSTRAINT download_native_backing_backup_horizon_seconds_check CHECK (((backup_horizon_seconds >= 0) AND (backup_horizon_seconds <= 316224000))),
    CONSTRAINT download_native_backing_check CHECK (((charged_rows >= 0) AND (charged_rows <= rows_limit))),
    CONSTRAINT download_native_backing_check1 CHECK (((charged_keys >= 0) AND (charged_keys <= keys_limit))),
    CONSTRAINT download_native_backing_check2 CHECK ((isfinite(residual_until) AND (residual_until >= retire_by))),
    CONSTRAINT download_native_backing_check3 CHECK ((retire_by = (valid_until + make_interval(secs => (((2 * backup_horizon_seconds) + cleanup_seconds))::double precision)))),
    CONSTRAINT download_native_backing_cleanup_seconds_check CHECK (((cleanup_seconds >= 1) AND (cleanup_seconds <= 86400))),
    CONSTRAINT download_native_backing_keys_limit_check CHECK (((keys_limit >= 1) AND (keys_limit <= 263168))),
    CONSTRAINT download_native_backing_policy_json_check CHECK (((jsonb_typeof(policy_json) = 'object'::text) AND (octet_length((policy_json)::text) <= 4096))),
    CONSTRAINT download_native_backing_retire_by_check CHECK (isfinite(retire_by)),
    CONSTRAINT download_native_backing_rows_limit_check CHECK (((rows_limit >= 1) AND (rows_limit <= 100000))),
    CONSTRAINT download_native_backing_transitions_per_row_check CHECK (((transitions_per_row >= 8) AND (transitions_per_row <= 65536))),
    CONSTRAINT download_native_backing_valid_until_check CHECK (isfinite(valid_until))
);

ALTER TABLE ONLY download_native_backing ADD CONSTRAINT download_native_backing_pkey PRIMARY KEY (allocation_id);

CREATE TABLE download_native_key (
    window_id uuid NOT NULL,
    worker_id uuid NOT NULL,
    root_id uuid NOT NULL,
    allocation_id uuid NOT NULL,
    operation_id uuid NOT NULL,
    operation_fence bigint NOT NULL,
    authority_json jsonb NOT NULL,
    proof_json jsonb NOT NULL,
    installation_id uuid NOT NULL,
    key_id text NOT NULL,
    peer_id uuid NOT NULL,
    certificate_sha256 bytea NOT NULL,
    valid_until timestamp with time zone NOT NULL,
    used_roles smallint DEFAULT 0 NOT NULL,
    created_at timestamp with time zone NOT NULL,
    CONSTRAINT download_native_key_authority_json_check CHECK (((jsonb_typeof(authority_json) = 'object'::text) AND (octet_length((authority_json)::text) <= 16384))),
    CONSTRAINT download_native_key_certificate_sha256_check CHECK ((octet_length(certificate_sha256) = 32)),
    CONSTRAINT download_native_key_check CHECK (((valid_until > created_at) AND (valid_until <= (created_at + '00:00:05'::interval)))),
    CONSTRAINT download_native_key_key_id_check CHECK (((length(key_id) >= 1) AND (length(key_id) <= 128))),
    CONSTRAINT download_native_key_operation_fence_check CHECK ((operation_fence > 0)),
    CONSTRAINT download_native_key_proof_json_check CHECK (((jsonb_typeof(proof_json) = 'object'::text) AND (octet_length((proof_json)::text) <= 16384))),
    CONSTRAINT download_native_key_used_roles_check CHECK (((used_roles >= 0) AND (used_roles <= 7))),
    CONSTRAINT download_native_key_valid_until_check CHECK (isfinite(valid_until))
);

ALTER TABLE ONLY download_native_key ADD CONSTRAINT download_native_key_pkey PRIMARY KEY (window_id);

CREATE TABLE download_native_owner (
    worker_id uuid NOT NULL,
    root_id uuid NOT NULL,
    allocation_id uuid NOT NULL,
    operation_id uuid NOT NULL,
    fence bigint NOT NULL,
    operation_json jsonb NOT NULL,
    authority_json jsonb NOT NULL,
    lease_sequence bigint NOT NULL,
    lease_started timestamp with time zone NOT NULL,
    lease_until timestamp with time zone NOT NULL,
    updates bigint DEFAULT 1 NOT NULL,
    closed boolean DEFAULT false NOT NULL,
    updated_at timestamp with time zone NOT NULL,
    retired_at timestamp with time zone,
    CONSTRAINT download_native_owner_authority_json_check CHECK (((jsonb_typeof(authority_json) = 'object'::text) AND (octet_length((authority_json)::text) <= 16384))),
    CONSTRAINT download_native_owner_check CHECK ((isfinite(lease_started) AND (lease_until > lease_started) AND (lease_until <= (lease_started + '00:00:05'::interval)))),
    CONSTRAINT download_native_owner_check1 CHECK (((retired_at IS NULL) OR closed)),
    CONSTRAINT download_native_owner_fence_check CHECK (((fence >= 1) AND (fence <= '1152921504606846976'::bigint))),
    CONSTRAINT download_native_owner_lease_sequence_check CHECK (((lease_sequence >= 1) AND (lease_sequence <= '1152921504606846976'::bigint))),
    CONSTRAINT download_native_owner_operation_json_check CHECK (((jsonb_typeof(operation_json) = 'object'::text) AND (octet_length((operation_json)::text) <= 8192))),
    CONSTRAINT download_native_owner_updates_check CHECK (((updates >= 1) AND (updates <= 65536)))
);

ALTER TABLE ONLY download_native_owner ADD CONSTRAINT download_native_owner_operation_id_key UNIQUE (operation_id);

ALTER TABLE ONLY download_native_owner ADD CONSTRAINT download_native_owner_pkey PRIMARY KEY (worker_id);

CREATE TABLE download_response (
    id uuid NOT NULL,
    root_id uuid NOT NULL,
    session_id uuid NOT NULL,
    owner_id uuid NOT NULL,
    generation bigint NOT NULL,
    plan_json jsonb NOT NULL,
    reserved_windows bigint NOT NULL,
    started_at timestamp with time zone NOT NULL,
    until_at timestamp with time zone NOT NULL,
    window_count bigint DEFAULT 0 NOT NULL,
    completed_windows bigint DEFAULT 0 NOT NULL,
    emitted_bytes bigint DEFAULT 0 NOT NULL,
    active_window uuid,
    lease_sequence bigint DEFAULT 0 NOT NULL,
    lease_until timestamp with time zone NOT NULL,
    closed boolean DEFAULT false NOT NULL,
    CONSTRAINT download_response_check1 CHECK (((completed_windows >= 0) AND (completed_windows <= window_count))),
    CONSTRAINT download_response_check2 CHECK ((isfinite(started_at) AND (until_at > started_at) AND (until_at <= (started_at + '08:00:00'::interval)) AND (lease_until <= until_at))),
    CONSTRAINT download_response_emitted_bytes_check CHECK (((emitted_bytes >= 0) AND (emitted_bytes <= '1099511627776'::bigint))),
    CONSTRAINT download_response_generation_check CHECK ((generation > 0)),
    CONSTRAINT download_response_lease_sequence_check CHECK ((lease_sequence >= 0)),
    CONSTRAINT download_response_plan_json_check CHECK (((jsonb_typeof(plan_json) = 'object'::text) AND (octet_length((plan_json)::text) <= 4096))),
    CONSTRAINT download_response_reserved_windows_check CHECK (((reserved_windows >= 1) AND (reserved_windows <= 16384))),
    CONSTRAINT download_response_until_check CHECK ((isfinite(started_at) AND (until_at > started_at) AND (lease_until <= until_at)))
);

ALTER TABLE ONLY download_response ADD CONSTRAINT download_response_id_session_id_key UNIQUE (id, session_id);

ALTER TABLE ONLY download_response ADD CONSTRAINT download_response_pkey PRIMARY KEY (id);

ALTER TABLE ONLY download_response ADD CONSTRAINT download_response_session_id_generation_key UNIQUE (session_id, generation);

CREATE INDEX download_response_leases ON download_response USING btree (root_id, lease_until) WHERE (NOT closed);

CREATE TABLE download_window (
    id uuid NOT NULL,
    response_id uuid NOT NULL,
    session_id uuid NOT NULL,
    ordinal bigint NOT NULL,
    intent_json jsonb NOT NULL,
    intent_receipt jsonb,
    intent_completion jsonb,
    outcome_json jsonb,
    outcome_receipt jsonb,
    outcome_completion jsonb,
    CONSTRAINT download_window_check CHECK (((intent_completion IS NULL) OR ((intent_receipt IS NOT NULL) AND (jsonb_typeof(intent_completion) = 'object'::text) AND (octet_length((intent_completion)::text) <= 8192)))),
    CONSTRAINT download_window_check1 CHECK (((outcome_json IS NULL) OR ((intent_receipt IS NOT NULL) AND (jsonb_typeof(outcome_json) = 'object'::text) AND (octet_length((outcome_json)::text) <= 2048)))),
    CONSTRAINT download_window_check2 CHECK (((outcome_receipt IS NULL) OR ((outcome_json IS NOT NULL) AND (jsonb_typeof(outcome_receipt) = 'object'::text) AND (octet_length((outcome_receipt)::text) <= 4096)))),
    CONSTRAINT download_window_check3 CHECK (((outcome_completion IS NULL) OR ((outcome_receipt IS NOT NULL) AND (jsonb_typeof(outcome_completion) = 'object'::text) AND (octet_length((outcome_completion)::text) <= 8192)))),
    CONSTRAINT download_window_intent_json_check CHECK (((jsonb_typeof(intent_json) = 'object'::text) AND (octet_length((intent_json)::text) <= 16384))),
    CONSTRAINT download_window_intent_receipt_check CHECK (((intent_receipt IS NULL) OR ((jsonb_typeof(intent_receipt) = 'object'::text) AND (octet_length((intent_receipt)::text) <= 4096)))),
    CONSTRAINT download_window_ordinal_check CHECK (((ordinal >= 1) AND (ordinal <= 16384)))
);

ALTER TABLE ONLY download_window ADD CONSTRAINT download_window_pkey PRIMARY KEY (id);

ALTER TABLE ONLY download_window ADD CONSTRAINT download_window_response_id_ordinal_key UNIQUE (response_id, ordinal);

CREATE TABLE download_worker (
    id uuid NOT NULL,
    session_id uuid,
    root_id uuid NOT NULL,
    installation_id uuid NOT NULL,
    allocation_id uuid,
    generation bigint NOT NULL,
    intent_json bytea NOT NULL,
    run_until timestamp with time zone NOT NULL,
    audit_receipt_json bytea,
    claimed_at timestamp with time zone,
    job_json bytea,
    binding_json bytea,
    termination_json bytea,
    retired_proof_json bytea,
    query_id uuid,
    query_allocation_id uuid,
    abandoned_at timestamp with time zone,
    baseline_query_allocation_id uuid,
    CONSTRAINT acquisition_parent_exact CHECK ((((session_id IS NOT NULL) AND (allocation_id IS NOT NULL) AND (query_id IS NULL) AND (query_allocation_id IS NULL)) OR ((session_id IS NULL) AND (allocation_id IS NULL) AND (query_id IS NOT NULL) AND (query_allocation_id IS NOT NULL) AND (generation = 1)))),
    CONSTRAINT download_worker_audit_receipt_json_check CHECK (((octet_length(audit_receipt_json) >= 1) AND (octet_length(audit_receipt_json) <= 8192))),
    CONSTRAINT download_worker_binding_json_check CHECK (((octet_length(binding_json) >= 1) AND (octet_length(binding_json) <= 16384))),
    CONSTRAINT download_worker_check CHECK (((claimed_at IS NULL) OR (audit_receipt_json IS NOT NULL))),
    CONSTRAINT download_worker_check1 CHECK (((job_json IS NULL) OR (claimed_at IS NOT NULL))),
    CONSTRAINT download_worker_check2 CHECK (((binding_json IS NULL) OR (job_json IS NOT NULL))),
    CONSTRAINT download_worker_check3 CHECK (((termination_json IS NULL) OR (binding_json IS NOT NULL))),
    CONSTRAINT download_worker_check4 CHECK (((retired_proof_json IS NULL) OR (termination_json IS NOT NULL))),
    CONSTRAINT download_worker_generation_check CHECK (((generation >= 1) AND (generation <= 1024))),
    CONSTRAINT download_worker_intent_json_check CHECK (((octet_length(intent_json) >= 1) AND (octet_length(intent_json) <=
CASE
    WHEN (baseline_query_allocation_id IS NOT NULL) THEN 98304
    ELSE 65536
END))),
    CONSTRAINT download_worker_job_json_check CHECK (((octet_length(job_json) >= 1) AND (octet_length(job_json) <= 8192))),
    CONSTRAINT download_worker_retired_proof_json_check CHECK (((octet_length(retired_proof_json) >= 1) AND (octet_length(retired_proof_json) <= 32768))),
    CONSTRAINT download_worker_termination_json_check CHECK (((octet_length(termination_json) >= 1) AND (octet_length(termination_json) <= 32768))),
    CONSTRAINT query_unclaimed_abandoned CHECK (((abandoned_at IS NULL) OR ((query_id IS NOT NULL) AND (abandoned_at >= run_until) AND (claimed_at IS NULL) AND (job_json IS NULL) AND (binding_json IS NULL) AND (termination_json IS NULL) AND (retired_proof_json IS NULL))))
);

ALTER TABLE ONLY download_worker ADD CONSTRAINT download_worker_pkey PRIMARY KEY (id);

ALTER TABLE ONLY download_worker ADD CONSTRAINT download_worker_session_id_generation_key UNIQUE (session_id, generation);

CREATE UNIQUE INDEX one_live_download_worker ON download_worker USING btree (session_id) WHERE (retired_proof_json IS NULL);

CREATE UNIQUE INDEX one_query_acquisition_worker ON download_worker USING btree (query_id) WHERE (query_id IS NOT NULL);

CREATE TABLE download_worker_certificate (
    id uuid NOT NULL,
    worker_id uuid NOT NULL,
    epoch integer NOT NULL,
    ordinal integer NOT NULL,
    attempt_json bytea NOT NULL,
    certificate_json bytea,
    certificate_sha256 bytea,
    audit_receipt_json bytea,
    activated_at timestamp with time zone,
    CONSTRAINT download_worker_certificate_attempt_json_check CHECK (((octet_length(attempt_json) >= 1) AND (octet_length(attempt_json) <= 65536))),
    CONSTRAINT download_worker_certificate_audit_receipt_json_check CHECK (((octet_length(audit_receipt_json) >= 1) AND (octet_length(audit_receipt_json) <= 8192))),
    CONSTRAINT download_worker_certificate_certificate_json_check CHECK (((octet_length(certificate_json) >= 1) AND (octet_length(certificate_json) <= 49152))),
    CONSTRAINT download_worker_certificate_certificate_sha256_check CHECK ((octet_length(certificate_sha256) = 32)),
    CONSTRAINT download_worker_certificate_check CHECK (((certificate_json IS NULL) = (certificate_sha256 IS NULL))),
    CONSTRAINT download_worker_certificate_check1 CHECK (((audit_receipt_json IS NULL) OR (certificate_json IS NOT NULL))),
    CONSTRAINT download_worker_certificate_check2 CHECK (((activated_at IS NULL) OR (audit_receipt_json IS NOT NULL))),
    CONSTRAINT download_worker_certificate_epoch_check CHECK (((epoch >= 0) AND (epoch <= 23))),
    CONSTRAINT download_worker_certificate_ordinal_check CHECK (((ordinal >= 1) AND (ordinal <= 2)))
);

ALTER TABLE ONLY download_worker_certificate ADD CONSTRAINT download_worker_certificate_pkey PRIMARY KEY (id);

ALTER TABLE ONLY download_worker_certificate ADD CONSTRAINT download_worker_certificate_worker_id_epoch_ordinal_key UNIQUE (worker_id, epoch, ordinal);

CREATE UNIQUE INDEX download_worker_certificate_digest ON download_worker_certificate USING btree (certificate_sha256) WHERE (certificate_sha256 IS NOT NULL);

CREATE TABLE download_worker_configuration (
    installation_id uuid NOT NULL,
    cluster_id uuid NOT NULL,
    source_uid uuid NOT NULL,
    generation bigint NOT NULL,
    observed_at timestamp with time zone NOT NULL,
    fresh_until timestamp with time zone NOT NULL,
    CONSTRAINT download_worker_configuration_check CHECK ((fresh_until <= (observed_at + '00:00:05'::interval))),
    CONSTRAINT download_worker_configuration_generation_check CHECK (((generation >= 1) AND (generation <= 2147483647)))
);

ALTER TABLE ONLY download_worker_configuration ADD CONSTRAINT download_worker_configuration_pkey PRIMARY KEY (installation_id, cluster_id, source_uid);

CREATE TABLE download_worker_configuration_revision (
    installation_id uuid NOT NULL,
    cluster_id uuid NOT NULL,
    source_uid uuid NOT NULL,
    generation bigint NOT NULL,
    snapshot_json bytea NOT NULL,
    audit_receipt_json bytea,
    CONSTRAINT download_worker_configuration_revision_audit_receipt_json_check CHECK (((octet_length(audit_receipt_json) >= 1) AND (octet_length(audit_receipt_json) <= 8192))),
    CONSTRAINT download_worker_configuration_revision_generation_check CHECK (((generation >= 1) AND (generation <= 2147483647))),
    CONSTRAINT download_worker_configuration_revision_snapshot_json_check CHECK (((octet_length(snapshot_json) >= 1) AND (octet_length(snapshot_json) <= 16384)))
);

ALTER TABLE ONLY download_worker_configuration_revision ADD CONSTRAINT download_worker_configuration_revision_pkey PRIMARY KEY (installation_id, cluster_id, source_uid, generation);

CREATE TABLE download_worker_enrollment (
    worker_id uuid NOT NULL,
    enrollment_json bytea NOT NULL,
    audit_receipt_json bytea,
    CONSTRAINT download_worker_enrollment_audit_receipt_json_check CHECK (((octet_length(audit_receipt_json) >= 1) AND (octet_length(audit_receipt_json) <= 8192))),
    CONSTRAINT download_worker_enrollment_enrollment_json_check CHECK (((octet_length(enrollment_json) >= 1) AND (octet_length(enrollment_json) <= 32768)))
);

ALTER TABLE ONLY download_worker_enrollment ADD CONSTRAINT download_worker_enrollment_pkey PRIMARY KEY (worker_id);

CREATE TABLE download_worker_owner (
    worker_id uuid NOT NULL,
    request_id uuid NOT NULL,
    pod_uid uuid NOT NULL,
    process_epoch uuid NOT NULL,
    fence bigint NOT NULL,
    started_at timestamp with time zone NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    released_at timestamp with time zone,
    CONSTRAINT download_worker_owner_check CHECK (((expires_at > started_at) AND (expires_at <= (started_at + '00:00:30'::interval)))),
    CONSTRAINT download_worker_owner_check1 CHECK (((released_at IS NULL) OR (released_at >= started_at))),
    CONSTRAINT download_worker_owner_fence_check CHECK (((fence >= 1) AND (fence <= '9007199254740991'::bigint)))
);

ALTER TABLE ONLY download_worker_owner ADD CONSTRAINT download_worker_owner_pkey PRIMARY KEY (worker_id);

CREATE UNIQUE INDEX download_worker_owner_request ON download_worker_owner USING btree (request_id);

CREATE TABLE evidence_share (
    id uuid NOT NULL,
    root_id uuid NOT NULL,
    artifact_id uuid NOT NULL,
    case_id uuid NOT NULL,
    cluster_id uuid NOT NULL,
    namespace_uid text NOT NULL,
    workload_uid text NOT NULL,
    pod_uid text NOT NULL,
    version bytea NOT NULL,
    creator_issuer text NOT NULL,
    creator_subject text NOT NULL,
    creator_client text NOT NULL,
    management jsonb NOT NULL,
    recipients jsonb NOT NULL,
    recipient_keys text[] NOT NULL,
    idempotency_key text NOT NULL,
    request_digest bytea NOT NULL,
    created_at timestamp with time zone DEFAULT clock_timestamp() NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    revoked_at timestamp with time zone,
    revoke_key text,
    revision bigint DEFAULT 1 NOT NULL,
    transfer_key text,
    transfer_digest bytea,
    policy_acceptance_id uuid,
    CONSTRAINT evidence_share_check1 CHECK (((revoked_at IS NULL) = (revoke_key IS NULL))),
    CONSTRAINT evidence_share_creator_client_check CHECK (((octet_length(creator_client) >= 1) AND (octet_length(creator_client) <= 256))),
    CONSTRAINT evidence_share_creator_issuer_check CHECK (((octet_length(creator_issuer) >= 1) AND (octet_length(creator_issuer) <= 2048))),
    CONSTRAINT evidence_share_creator_subject_check CHECK (((octet_length(creator_subject) >= 1) AND (octet_length(creator_subject) <= 256))),
    CONSTRAINT evidence_share_idempotency_key_check CHECK (((octet_length(idempotency_key) >= 1) AND (octet_length(idempotency_key) <= 128))),
    CONSTRAINT evidence_share_lifetime CHECK ((expires_at > created_at)),
    CONSTRAINT evidence_share_management_shape CHECK (((jsonb_typeof(management) = 'array'::text) AND (jsonb_array_length(management) >= 1))),
    CONSTRAINT evidence_share_namespace_uid_check CHECK (((octet_length(namespace_uid) >= 1) AND (octet_length(namespace_uid) <= 64))),
    CONSTRAINT evidence_share_pod_uid_check CHECK (((octet_length(pod_uid) >= 1) AND (octet_length(pod_uid) <= 64))),
    CONSTRAINT evidence_share_recipients_shape CHECK (((jsonb_typeof(recipients) = 'array'::text) AND (jsonb_array_length(recipients) >= 1) AND (cardinality(recipient_keys) >= 1))),
    CONSTRAINT evidence_share_request_digest_check CHECK ((octet_length(request_digest) = 32)),
    CONSTRAINT evidence_share_revision CHECK ((((revision >= 1) AND (revision <= 1000000000)) AND ((revoked_at IS NULL) OR (revision >= 2)))),
    CONSTRAINT evidence_share_revoke_key_check CHECK (((octet_length(revoke_key) >= 1) AND (octet_length(revoke_key) <= 128))),
    CONSTRAINT evidence_share_transfer_digest_check CHECK ((octet_length(transfer_digest) = 32)),
    CONSTRAINT evidence_share_transfer_key_check CHECK (((octet_length(transfer_key) >= 1) AND (octet_length(transfer_key) <= 128))),
    CONSTRAINT evidence_share_transfer_pair CHECK (((transfer_key IS NULL) = (transfer_digest IS NULL))),
    CONSTRAINT evidence_share_version_check CHECK ((octet_length(version) = 32)),
    CONSTRAINT evidence_share_workload_uid_check CHECK (((octet_length(workload_uid) >= 1) AND (octet_length(workload_uid) <= 64)))
);

ALTER TABLE ONLY evidence_share ADD CONSTRAINT evidence_share_pkey PRIMARY KEY (id);

ALTER TABLE ONLY evidence_share ADD CONSTRAINT evidence_share_root_id_creator_issuer_creator_subject_idemp_key UNIQUE (root_id, creator_issuer, creator_subject, idempotency_key);

CREATE INDEX evidence_share_administered ON evidence_share USING btree (root_id, created_at DESC, id DESC);

CREATE INDEX evidence_share_artifact ON evidence_share USING btree (root_id, artifact_id) WHERE (revoked_at IS NULL);

CREATE INDEX evidence_share_creator ON evidence_share USING btree (root_id, creator_issuer, creator_subject, created_at DESC);

CREATE INDEX evidence_share_policy_acceptance ON evidence_share USING btree (root_id, policy_acceptance_id) WHERE (policy_acceptance_id IS NOT NULL);

CREATE INDEX evidence_share_recipient ON evidence_share USING gin (recipient_keys) WHERE (revoked_at IS NULL);

CREATE TABLE fleet_initial_activation (
    singleton boolean DEFAULT true NOT NULL,
    installation_id uuid NOT NULL,
    claim_id uuid NOT NULL,
    record_json bytea NOT NULL,
    audit_receipt_json bytea,
    activated_at timestamp with time zone,
    CONSTRAINT fleet_initial_activation_audit_receipt_json_check CHECK (((octet_length(audit_receipt_json) >= 1) AND (octet_length(audit_receipt_json) <= 8192))),
    CONSTRAINT fleet_initial_activation_check CHECK (((activated_at IS NULL) OR (audit_receipt_json IS NOT NULL))),
    CONSTRAINT fleet_initial_activation_record_json_check CHECK (((octet_length(record_json) >= 1) AND (octet_length(record_json) <= 8192))),
    CONSTRAINT fleet_initial_activation_singleton_check CHECK (singleton)
);

ALTER TABLE ONLY fleet_initial_activation ADD CONSTRAINT fleet_initial_activation_claim_id_key UNIQUE (claim_id);

ALTER TABLE ONLY fleet_initial_activation ADD CONSTRAINT fleet_initial_activation_installation_id_key UNIQUE (installation_id);

ALTER TABLE ONLY fleet_initial_activation ADD CONSTRAINT fleet_initial_activation_pkey PRIMARY KEY (singleton);

CREATE TABLE fleet_trust (
    installation_id uuid NOT NULL,
    issuer_epoch uuid NOT NULL,
    source_uid text NOT NULL,
    source_generation bigint NOT NULL,
    source_digest bytea NOT NULL,
    activated_postmaster_at timestamp with time zone,
    activated_database_oid oid,
    CONSTRAINT fleet_activation_pair CHECK (((activated_postmaster_at IS NULL) = (activated_database_oid IS NULL))),
    CONSTRAINT fleet_trust_source_digest_check CHECK ((octet_length(source_digest) = 32)),
    CONSTRAINT fleet_trust_source_generation_check CHECK (((source_generation >= 1) AND (source_generation <= 2147483647))),
    CONSTRAINT fleet_trust_source_uid_check CHECK (((octet_length(source_uid) >= 1) AND (octet_length(source_uid) <= 64)))
);

ALTER TABLE ONLY fleet_trust ADD CONSTRAINT fleet_trust_pkey PRIMARY KEY (installation_id);

CREATE TABLE hub_owner_certificate (
    id uuid NOT NULL,
    enrollment_id uuid NOT NULL,
    epoch bigint NOT NULL,
    ordinal integer NOT NULL,
    not_after timestamp with time zone NOT NULL,
    attempt_json bytea NOT NULL,
    certificate_json bytea,
    certificate_sha256 bytea,
    audit_receipt_json bytea,
    activated_at timestamp with time zone,
    CONSTRAINT hub_owner_certificate_attempt_json_check CHECK (((octet_length(attempt_json) >= 1) AND (octet_length(attempt_json) <= 65536))),
    CONSTRAINT hub_owner_certificate_audit_receipt_json_check CHECK (((octet_length(audit_receipt_json) >= 1) AND (octet_length(audit_receipt_json) <= 8192))),
    CONSTRAINT hub_owner_certificate_certificate_json_check CHECK (((octet_length(certificate_json) >= 1) AND (octet_length(certificate_json) <= 65536))),
    CONSTRAINT hub_owner_certificate_certificate_sha256_check CHECK ((octet_length(certificate_sha256) = 32)),
    CONSTRAINT hub_owner_certificate_check CHECK (((certificate_json IS NULL) = (certificate_sha256 IS NULL))),
    CONSTRAINT hub_owner_certificate_check1 CHECK (((audit_receipt_json IS NULL) OR (certificate_json IS NOT NULL))),
    CONSTRAINT hub_owner_certificate_check2 CHECK (((activated_at IS NULL) OR (audit_receipt_json IS NOT NULL))),
    CONSTRAINT hub_owner_certificate_epoch_check CHECK ((epoch >= 0)),
    CONSTRAINT hub_owner_certificate_ordinal_check CHECK (((ordinal >= 1) AND (ordinal <= 2)))
);

ALTER TABLE ONLY hub_owner_certificate ADD CONSTRAINT hub_owner_certificate_certificate_sha256_key UNIQUE (certificate_sha256);

ALTER TABLE ONLY hub_owner_certificate ADD CONSTRAINT hub_owner_certificate_enrollment_id_epoch_ordinal_key UNIQUE (enrollment_id, epoch, ordinal);

ALTER TABLE ONLY hub_owner_certificate ADD CONSTRAINT hub_owner_certificate_pkey PRIMARY KEY (id);

CREATE TABLE hub_owner_configuration (
    installation_id uuid NOT NULL,
    cluster_id uuid NOT NULL,
    source_uid uuid NOT NULL,
    generation bigint DEFAULT 0 NOT NULL,
    observed_at timestamp with time zone NOT NULL,
    fresh_until timestamp with time zone NOT NULL,
    CONSTRAINT hub_owner_configuration_check CHECK ((fresh_until <= (observed_at + '00:00:05'::interval))),
    CONSTRAINT hub_owner_configuration_generation_check CHECK (((generation >= 0) AND (generation <= 2147483647)))
);

ALTER TABLE ONLY hub_owner_configuration ADD CONSTRAINT hub_owner_configuration_installation_id_cluster_id_source_u_key UNIQUE (installation_id, cluster_id, source_uid);

ALTER TABLE ONLY hub_owner_configuration ADD CONSTRAINT hub_owner_configuration_pkey PRIMARY KEY (installation_id, cluster_id);

CREATE TABLE hub_owner_configuration_revision (
    installation_id uuid NOT NULL,
    cluster_id uuid NOT NULL,
    source_uid uuid NOT NULL,
    generation bigint NOT NULL,
    snapshot_json bytea NOT NULL,
    audit_receipt_json bytea,
    CONSTRAINT hub_owner_configuration_revision_audit_receipt_json_check CHECK (((octet_length(audit_receipt_json) >= 1) AND (octet_length(audit_receipt_json) <= 8192))),
    CONSTRAINT hub_owner_configuration_revision_generation_check CHECK (((generation >= 1) AND (generation <= 2147483647))),
    CONSTRAINT hub_owner_configuration_revision_snapshot_json_check CHECK (((octet_length(snapshot_json) >= 1) AND (octet_length(snapshot_json) <= 65536)))
);

ALTER TABLE ONLY hub_owner_configuration_revision ADD CONSTRAINT hub_owner_configuration_revision_pkey PRIMARY KEY (installation_id, cluster_id, source_uid, generation);

CREATE TABLE hub_owner_enrollment (
    id uuid NOT NULL,
    installation_id uuid NOT NULL,
    cluster_id uuid NOT NULL,
    issuer_epoch uuid NOT NULL,
    pod_uid uuid NOT NULL,
    process_epoch uuid NOT NULL,
    usage text NOT NULL,
    enrollment_json bytea NOT NULL,
    audit_receipt_json bytea,
    created_at timestamp with time zone NOT NULL,
    hold_until timestamp with time zone NOT NULL,
    highest_epoch bigint DEFAULT '-1'::integer NOT NULL,
    retired_at timestamp with time zone,
    CONSTRAINT hub_owner_enrollment_audit_receipt_json_check CHECK (((octet_length(audit_receipt_json) >= 1) AND (octet_length(audit_receipt_json) <= 8192))),
    CONSTRAINT hub_owner_enrollment_check CHECK ((hold_until > created_at)),
    CONSTRAINT hub_owner_enrollment_enrollment_json_check CHECK (((octet_length(enrollment_json) >= 1) AND (octet_length(enrollment_json) <= 16384))),
    CONSTRAINT hub_owner_enrollment_highest_epoch_check CHECK ((highest_epoch >= '-1'::integer)),
    CONSTRAINT hub_owner_enrollment_usage_check CHECK ((usage = ANY (ARRAY['server'::text, 'client'::text])))
);

ALTER TABLE ONLY hub_owner_enrollment ADD CONSTRAINT hub_owner_enrollment_installation_id_cluster_id_issuer_epoc_key UNIQUE (installation_id, cluster_id, issuer_epoch, pod_uid, process_epoch, usage);

ALTER TABLE ONLY hub_owner_enrollment ADD CONSTRAINT hub_owner_enrollment_pkey PRIMARY KEY (id);

CREATE TABLE live_watch_account (
    root_id uuid NOT NULL,
    kind text NOT NULL,
    account_key bytea NOT NULL,
    tokens_micro bigint NOT NULL,
    refilled_at timestamp with time zone NOT NULL,
    CONSTRAINT live_watch_account_account_key_check CHECK ((octet_length(account_key) = 32)),
    CONSTRAINT live_watch_account_kind_check CHECK ((kind = ANY (ARRAY['installation'::text, 'principal'::text, 'workload'::text]))),
    CONSTRAINT live_watch_account_refilled_at_check CHECK (isfinite(refilled_at)),
    CONSTRAINT live_watch_account_tokens_micro_check CHECK ((tokens_micro >= 0))
);

ALTER TABLE ONLY live_watch_account ADD CONSTRAINT live_watch_account_pkey PRIMARY KEY (root_id, kind, account_key);

CREATE TABLE live_watch_control (
    root_id uuid NOT NULL,
    id uuid NOT NULL,
    owner_id uuid NOT NULL,
    fence uuid NOT NULL,
    principal_key bytea NOT NULL,
    workload_key bytea NOT NULL,
    request_digest bytea NOT NULL,
    key_hash bytea NOT NULL,
    revision bigint NOT NULL,
    state text NOT NULL,
    accepted_at timestamp with time zone NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    idle_until timestamp with time zone NOT NULL,
    spent bigint NOT NULL,
    bytes_per_second bigint NOT NULL,
    tokens_micro bigint NOT NULL,
    refilled_at timestamp with time zone NOT NULL,
    cluster_key bytea,
    CONSTRAINT live_watch_control_accepted_at_check CHECK (isfinite(accepted_at)),
    CONSTRAINT live_watch_control_bytes_per_second_check CHECK ((bytes_per_second >= 1)),
    CONSTRAINT live_watch_control_check1 CHECK ((isfinite(idle_until) AND (idle_until > accepted_at) AND (idle_until <= expires_at))),
    CONSTRAINT live_watch_control_cluster_key_check CHECK ((octet_length(cluster_key) = 32)),
    CONSTRAINT live_watch_control_expires_at_check CHECK ((isfinite(expires_at) AND (expires_at > accepted_at))),
    CONSTRAINT live_watch_control_key_hash_check CHECK ((octet_length(key_hash) = 32)),
    CONSTRAINT live_watch_control_principal_key_check CHECK ((octet_length(principal_key) = 32)),
    CONSTRAINT live_watch_control_refilled_at_check CHECK (isfinite(refilled_at)),
    CONSTRAINT live_watch_control_request_digest_check CHECK ((octet_length(request_digest) = 32)),
    CONSTRAINT live_watch_control_revision_check CHECK (((revision >= 1) AND (revision <= 1000000000))),
    CONSTRAINT live_watch_control_spent_check CHECK ((spent >= 0)),
    CONSTRAINT live_watch_control_state_check CHECK ((state = ANY (ARRAY['Active'::text, 'Paused'::text, 'Closed'::text, 'Expired'::text, 'AccessLost'::text, 'Disconnected'::text, 'SourceEnded'::text]))),
    CONSTRAINT live_watch_control_tokens_micro_check CHECK ((tokens_micro >= 0)),
    CONSTRAINT live_watch_control_workload_key_check CHECK ((octet_length(workload_key) = 32))
);

ALTER TABLE ONLY live_watch_control ADD CONSTRAINT live_watch_control_pkey PRIMARY KEY (id);

ALTER TABLE ONLY live_watch_control ADD CONSTRAINT live_watch_control_root_id_key_hash_key UNIQUE (root_id, key_hash);

CREATE INDEX live_watch_expiry ON live_watch_control USING btree (root_id, expires_at);

CREATE INDEX live_watch_principal ON live_watch_control USING btree (root_id, principal_key);

CREATE INDEX live_watch_workload ON live_watch_control USING btree (root_id, workload_key);

CREATE TABLE live_watch_root (
    root_id uuid NOT NULL,
    installation_id uuid NOT NULL,
    issuer_epoch uuid NOT NULL,
    limits_digest bytea NOT NULL,
    limits jsonb NOT NULL,
    CONSTRAINT live_watch_root_limits_check CHECK (((jsonb_typeof(limits) = 'object'::text) AND (octet_length((limits)::text) <= 4096))),
    CONSTRAINT live_watch_root_limits_digest_check CHECK ((octet_length(limits_digest) = 32))
);

ALTER TABLE ONLY live_watch_root ADD CONSTRAINT live_watch_root_installation_id_key UNIQUE (installation_id);

ALTER TABLE ONLY live_watch_root ADD CONSTRAINT live_watch_root_pkey PRIMARY KEY (root_id);

CREATE TABLE local_key_configuration (
    installation_id uuid NOT NULL,
    purpose text NOT NULL,
    key_id text NOT NULL,
    snapshot_json bytea NOT NULL,
    CONSTRAINT local_key_configuration_key_id_check CHECK ((key_id ~ '^[A-Za-z0-9_-]{1,128}$'::text)),
    CONSTRAINT local_key_configuration_purpose_check CHECK ((purpose = ANY (ARRAY['artifact'::text, 'audit'::text, 'browser-credentials'::text, 'policy-submission'::text]))),
    CONSTRAINT local_key_configuration_snapshot_json_check CHECK (((octet_length(snapshot_json) >= 1) AND (octet_length(snapshot_json) <= 16384)))
);

ALTER TABLE ONLY local_key_configuration ADD CONSTRAINT local_key_configuration_pkey PRIMARY KEY (installation_id, purpose, key_id);

CREATE TABLE local_key_version (
    installation_id uuid NOT NULL,
    purpose text NOT NULL,
    key_id text NOT NULL,
    version integer NOT NULL,
    fingerprint bytea NOT NULL,
    CONSTRAINT local_key_version_fingerprint_check CHECK ((octet_length(fingerprint) = 32)),
    CONSTRAINT local_key_version_version_check CHECK ((version > 0))
);

ALTER TABLE ONLY local_key_version ADD CONSTRAINT local_key_version_installation_id_fingerprint_key UNIQUE (installation_id, fingerprint);

ALTER TABLE ONLY local_key_version ADD CONSTRAINT local_key_version_pkey PRIMARY KEY (installation_id, purpose, key_id, version);

CREATE TABLE permission_acceptance (
    request_id uuid NOT NULL,
    stream_id uuid NOT NULL,
    epoch uuid NOT NULL,
    sequence bigint NOT NULL,
    request_digest bytea NOT NULL,
    audit_id uuid NOT NULL,
    assignments integer NOT NULL,
    retired integer NOT NULL,
    CONSTRAINT permission_acceptance_request_digest_check CHECK ((octet_length(request_digest) = 32))
);

ALTER TABLE ONLY permission_acceptance ADD CONSTRAINT permission_acceptance_pkey PRIMARY KEY (request_id);

ALTER TABLE ONLY permission_acceptance ADD CONSTRAINT permission_acceptance_stream_id_epoch_sequence_key UNIQUE (stream_id, epoch, sequence);

CREATE TABLE permission_assignment (
    id uuid NOT NULL,
    stream_id uuid NOT NULL,
    basis_key text NOT NULL,
    subject_kind text NOT NULL,
    issuer text NOT NULL,
    subject_id text NOT NULL,
    role text NOT NULL,
    basis_digest bytea NOT NULL,
    created_at timestamp with time zone DEFAULT clock_timestamp() NOT NULL,
    retired_at timestamp with time zone,
    activation_audit_id uuid NOT NULL,
    retirement_audit_id uuid,
    CONSTRAINT permission_assignment_basis_digest_check CHECK ((octet_length(basis_digest) = 32)),
    CONSTRAINT permission_assignment_check CHECK (((retired_at IS NULL) = (retirement_audit_id IS NULL))),
    CONSTRAINT permission_assignment_issuer_check CHECK (((octet_length(issuer) >= 1) AND (octet_length(issuer) <= 2048))),
    CONSTRAINT permission_assignment_role_check CHECK ((role = ANY (ARRAY['workload-maintainer'::text, 'evidence-reader'::text, 'evidence-owner'::text, 'action-approver'::text]))),
    CONSTRAINT permission_assignment_subject_id_check CHECK (((octet_length(subject_id) >= 1) AND (octet_length(subject_id) <= 256))),
    CONSTRAINT permission_assignment_subject_kind_check CHECK ((subject_kind = ANY (ARRAY['User'::text, 'Group'::text, 'Workload'::text])))
);

ALTER TABLE ONLY permission_assignment ADD CONSTRAINT permission_assignment_pkey PRIMARY KEY (id);

CREATE UNIQUE INDEX permission_current_assignment ON permission_assignment USING btree (stream_id, basis_key, subject_kind, issuer, subject_id, role) WHERE (retired_at IS NULL);

CREATE TABLE permission_basis (
    stream_id uuid NOT NULL,
    basis_key text NOT NULL,
    uid text NOT NULL,
    kind text NOT NULL,
    generation bigint NOT NULL,
    resource_version text NOT NULL,
    observation_version text NOT NULL,
    spec_digest bytea NOT NULL,
    scope_digest bytea NOT NULL,
    cluster_id uuid NOT NULL,
    namespace_uid text NOT NULL,
    workload_uids text[] NOT NULL,
    effect text NOT NULL,
    not_after timestamp with time zone,
    seen_sequence bigint NOT NULL,
    automation_json jsonb,
    automation_audit_id uuid,
    CONSTRAINT automation_envelope_complete CHECK ((((automation_json IS NULL) = (automation_audit_id IS NULL)) AND ((automation_json IS NULL) OR ((kind = 'AccessBinding'::text) AND (effect = 'Allow'::text) AND (jsonb_typeof(automation_json) = 'object'::text) AND (octet_length((automation_json)::text) <= 4096))))),
    CONSTRAINT permission_basis_basis_key_check CHECK (((octet_length(basis_key) >= 1) AND (octet_length(basis_key) <= 256))),
    CONSTRAINT permission_basis_effect_check CHECK ((effect = ANY (ARRAY['Allow'::text, 'Deny'::text]))),
    CONSTRAINT permission_basis_generation_check CHECK (((generation >= 1) AND (generation <= 2147483647))),
    CONSTRAINT permission_basis_kind_check CHECK ((kind = ANY (ARRAY['AccessBinding'::text, 'PermissionSource'::text, 'ClusterAccessBinding'::text]))),
    CONSTRAINT permission_basis_namespace_uid_check CHECK (((octet_length(namespace_uid) >= 1) AND (octet_length(namespace_uid) <= 64))),
    CONSTRAINT permission_basis_observation_version_check CHECK ((octet_length(observation_version) <= 128)),
    CONSTRAINT permission_basis_resource_version_check CHECK (((octet_length(resource_version) >= 1) AND (octet_length(resource_version) <= 128))),
    CONSTRAINT permission_basis_scope_digest_check CHECK ((octet_length(scope_digest) = 32)),
    CONSTRAINT permission_basis_seen_sequence_check CHECK ((seen_sequence > 0)),
    CONSTRAINT permission_basis_spec_digest_check CHECK ((octet_length(spec_digest) = 32)),
    CONSTRAINT permission_basis_uid_check CHECK (((octet_length(uid) >= 1) AND (octet_length(uid) <= 64)))
);

ALTER TABLE ONLY permission_basis ADD CONSTRAINT permission_basis_pkey PRIMARY KEY (stream_id, basis_key);

CREATE INDEX permission_scope ON permission_basis USING btree (cluster_id, namespace_uid, stream_id);

CREATE TABLE permission_review_assignment (
    id uuid NOT NULL,
    stream_id uuid NOT NULL,
    source_uid text NOT NULL,
    issuer text NOT NULL,
    subject_id text NOT NULL,
    role text NOT NULL,
    basis_digest bytea NOT NULL,
    created_at timestamp with time zone DEFAULT clock_timestamp() NOT NULL,
    retired_at timestamp with time zone,
    retirement_audit_id uuid,
    CONSTRAINT permission_review_assignment_basis_digest_check CHECK ((octet_length(basis_digest) = 32)),
    CONSTRAINT permission_review_assignment_check CHECK (((retired_at IS NULL) = (retirement_audit_id IS NULL))),
    CONSTRAINT permission_review_assignment_issuer_check CHECK (((octet_length(issuer) >= 1) AND (octet_length(issuer) <= 2048))),
    CONSTRAINT permission_review_assignment_role_check CHECK ((role = ANY (ARRAY['workload-maintainer'::text, 'evidence-reader'::text, 'evidence-owner'::text, 'action-approver'::text]))),
    CONSTRAINT permission_review_assignment_source_uid_check CHECK (((octet_length(source_uid) >= 1) AND (octet_length(source_uid) <= 64))),
    CONSTRAINT permission_review_assignment_subject_id_check CHECK (((octet_length(subject_id) >= 1) AND (octet_length(subject_id) <= 256)))
);

ALTER TABLE ONLY permission_review_assignment ADD CONSTRAINT permission_review_assignment_pkey PRIMARY KEY (id);

CREATE UNIQUE INDEX permission_review_current ON permission_review_assignment USING btree (stream_id, source_uid, issuer, subject_id) WHERE (retired_at IS NULL);

CREATE TABLE permission_review_decision (
    assignment_id uuid NOT NULL,
    pod_uid text NOT NULL,
    cluster_id uuid NOT NULL,
    namespace_name text NOT NULL,
    namespace_uid text NOT NULL,
    workload_kind text NOT NULL,
    workload_name text NOT NULL,
    workload_uid text NOT NULL,
    pod_name text NOT NULL,
    decided_at timestamp with time zone NOT NULL,
    fresh_until timestamp with time zone NOT NULL,
    CONSTRAINT permission_review_decision_check CHECK (((fresh_until >= decided_at) AND (fresh_until <= (decided_at + '00:01:00'::interval)))),
    CONSTRAINT permission_review_decision_namespace_name_check CHECK (((octet_length(namespace_name) >= 1) AND (octet_length(namespace_name) <= 63))),
    CONSTRAINT permission_review_decision_namespace_uid_check CHECK (((octet_length(namespace_uid) >= 1) AND (octet_length(namespace_uid) <= 64))),
    CONSTRAINT permission_review_decision_pod_name_check CHECK (((octet_length(pod_name) >= 1) AND (octet_length(pod_name) <= 253))),
    CONSTRAINT permission_review_decision_pod_uid_check CHECK (((octet_length(pod_uid) >= 1) AND (octet_length(pod_uid) <= 64))),
    CONSTRAINT permission_review_decision_workload_kind_check CHECK ((workload_kind = ANY (ARRAY['Deployment'::text, 'StatefulSet'::text, 'Pod'::text]))),
    CONSTRAINT permission_review_decision_workload_name_check CHECK (((octet_length(workload_name) >= 1) AND (octet_length(workload_name) <= 253))),
    CONSTRAINT permission_review_decision_workload_uid_check CHECK (((octet_length(workload_uid) >= 1) AND (octet_length(workload_uid) <= 64)))
);

ALTER TABLE ONLY permission_review_decision ADD CONSTRAINT permission_review_decision_pkey PRIMARY KEY (assignment_id, pod_uid);

CREATE INDEX permission_review_pod ON permission_review_decision USING btree (cluster_id, namespace_uid, workload_uid, pod_uid);

CREATE TABLE permission_review_source (
    stream_id uuid NOT NULL,
    uid text NOT NULL,
    epoch uuid NOT NULL,
    seen_sequence bigint NOT NULL,
    generation bigint NOT NULL,
    resource_version text NOT NULL,
    spec_digest bytea NOT NULL,
    authority_digest bytea NOT NULL,
    cluster_id uuid NOT NULL,
    role text NOT NULL,
    source_json jsonb NOT NULL,
    accepted_audit_id uuid NOT NULL,
    CONSTRAINT permission_review_source_authority_digest_check CHECK ((octet_length(authority_digest) = 32)),
    CONSTRAINT permission_review_source_generation_check CHECK (((generation >= 1) AND (generation <= 2147483647))),
    CONSTRAINT permission_review_source_resource_version_check CHECK (((octet_length(resource_version) >= 1) AND (octet_length(resource_version) <= 128))),
    CONSTRAINT permission_review_source_role_check CHECK ((role = ANY (ARRAY['workload-maintainer'::text, 'evidence-reader'::text, 'evidence-owner'::text, 'action-approver'::text]))),
    CONSTRAINT permission_review_source_seen_sequence_check CHECK ((seen_sequence > 0)),
    CONSTRAINT permission_review_source_source_json_check CHECK (((jsonb_typeof(source_json) = 'object'::text) AND (octet_length((source_json)::text) <= 16384))),
    CONSTRAINT permission_review_source_spec_digest_check CHECK ((octet_length(spec_digest) = 32)),
    CONSTRAINT permission_review_source_uid_check CHECK (((octet_length(uid) >= 1) AND (octet_length(uid) <= 64)))
);

ALTER TABLE ONLY permission_review_source ADD CONSTRAINT permission_review_source_pkey PRIMARY KEY (stream_id, uid);

CREATE INDEX permission_review_source_cluster ON permission_review_source USING btree (stream_id, cluster_id);

CREATE TABLE permission_stream (
    id uuid NOT NULL,
    epoch uuid NOT NULL,
    sequence bigint DEFAULT 0 NOT NULL,
    trust_digest bytea NOT NULL,
    projection_digest bytea,
    lease_until timestamp with time zone NOT NULL,
    observed_at timestamp with time zone,
    fresh_until timestamp with time zone,
    suspended boolean DEFAULT true NOT NULL,
    initial_audit_id uuid,
    CONSTRAINT permission_stream_check CHECK (((observed_at IS NULL) = (fresh_until IS NULL))),
    CONSTRAINT permission_stream_observation_lifetime CHECK (((fresh_until IS NULL) OR ((fresh_until > observed_at) AND (fresh_until <= (observed_at + '00:00:30'::interval))))),
    CONSTRAINT permission_stream_projection_digest_check CHECK ((octet_length(projection_digest) = 32)),
    CONSTRAINT permission_stream_sequence_check CHECK ((sequence >= 0)),
    CONSTRAINT permission_stream_trust_digest_check CHECK ((octet_length(trust_digest) = 32))
);

ALTER TABLE ONLY permission_stream ADD CONSTRAINT permission_stream_pkey PRIMARY KEY (id);

CREATE TABLE policy_acceptance (
    id uuid NOT NULL,
    root_id uuid NOT NULL,
    policy_uid text NOT NULL,
    generation bigint NOT NULL,
    nonce uuid NOT NULL,
    scope_digest bytea NOT NULL,
    request_digest bytea NOT NULL,
    record_digest bytea NOT NULL,
    record jsonb NOT NULL,
    accepted_at timestamp with time zone NOT NULL,
    acknowledged_at timestamp with time zone,
    receipt_json jsonb,
    executions_spent bigint DEFAULT 0 NOT NULL,
    shares_spent integer DEFAULT 0 NOT NULL,
    sharing_revoked_at timestamp with time zone,
    sharing_revoke_key text,
    sharing_stopped_at timestamp with time zone,
    sharing_stop_key text,
    collected_bytes_spent bigint DEFAULT 0 NOT NULL,
    observed_bytes_spent bigint DEFAULT 0 NOT NULL,
    observed_events_spent bigint DEFAULT 0 NOT NULL,
    CONSTRAINT policy_acceptance_byte_pools CHECK ((((collected_bytes_spent >= 0) AND (collected_bytes_spent <= COALESCE(((record #>> '{Authority,Limits,MaxBytes}'::text[]))::bigint, (0)::bigint))) AND ((observed_bytes_spent >= 0) AND (observed_bytes_spent <= COALESCE(((record #>> '{Authority,Limits,MaxObservedBytes}'::text[]))::bigint, (0)::bigint))))),
    CONSTRAINT policy_acceptance_check CHECK (((acknowledged_at IS NULL) = (receipt_json IS NULL))),
    CONSTRAINT policy_acceptance_check1 CHECK (((observed_events_spent >= 0) AND (observed_events_spent <= COALESCE(((record #>> '{Authority,Limits,MaxObservedEvents}'::text[]))::bigint, (0)::bigint)))),
    CONSTRAINT policy_acceptance_executions CHECK (((executions_spent >= 0) AND (executions_spent <= COALESCE(((record #>> '{Authority,Limits,MaxExecutions}'::text[]))::bigint, (0)::bigint)))),
    CONSTRAINT policy_acceptance_generation_check CHECK (((generation >= 1) AND (generation <= 2147483647))),
    CONSTRAINT policy_acceptance_receipt_json_check CHECK (((receipt_json IS NULL) OR ((jsonb_typeof(receipt_json) = 'object'::text) AND (octet_length((receipt_json)::text) <= 4096)))),
    CONSTRAINT policy_acceptance_record_check CHECK (((jsonb_typeof(record) = 'object'::text) AND (octet_length((record)::text) <= 65536))),
    CONSTRAINT policy_acceptance_record_digest_check CHECK ((octet_length(record_digest) = 32)),
    CONSTRAINT policy_acceptance_request_digest_check CHECK ((octet_length(request_digest) = 32)),
    CONSTRAINT policy_acceptance_scope_digest_check CHECK ((octet_length(scope_digest) = 32)),
    CONSTRAINT policy_acceptance_shares CHECK (((shares_spent >= 0) AND (((COALESCE(((record #>> '{Sharing,MaxCaptures}'::text[]))::integer, 0) = 0) AND ((shares_spent = 0) OR (record ? 'Sharing'::text))) OR (shares_spent <= ((record #>> '{Sharing,MaxCaptures}'::text[]))::integer)))),
    CONSTRAINT policy_acceptance_sharing_revocation CHECK ((((sharing_revoked_at IS NULL) = (sharing_revoke_key IS NULL)) AND ((sharing_revoked_at IS NULL) OR (record ? 'Sharing'::text)))),
    CONSTRAINT policy_acceptance_sharing_revoke_key_check CHECK (((octet_length(sharing_revoke_key) >= 1) AND (octet_length(sharing_revoke_key) <= 128))),
    CONSTRAINT policy_acceptance_sharing_stop CHECK ((((sharing_stopped_at IS NULL) = (sharing_stop_key IS NULL)) AND ((sharing_stopped_at IS NULL) OR (record ? 'Sharing'::text)))),
    CONSTRAINT policy_acceptance_sharing_stop_key_check CHECK (((octet_length(sharing_stop_key) >= 1) AND (octet_length(sharing_stop_key) <= 128)))
);

ALTER TABLE ONLY policy_acceptance ADD CONSTRAINT policy_acceptance_grant_scope UNIQUE (root_id, id, policy_uid);

ALTER TABLE ONLY policy_acceptance ADD CONSTRAINT policy_acceptance_pkey PRIMARY KEY (id);

ALTER TABLE ONLY policy_acceptance ADD CONSTRAINT policy_acceptance_root_id_nonce_key UNIQUE (root_id, nonce);

ALTER TABLE ONLY policy_acceptance ADD CONSTRAINT policy_acceptance_root_id_policy_uid_scope_digest_key UNIQUE (root_id, policy_uid, scope_digest);

CREATE INDEX policy_acceptance_pending ON policy_acceptance USING btree (root_id, accepted_at, id) WHERE (acknowledged_at IS NULL);

CREATE TABLE policy_grant_attachment (
    id uuid NOT NULL,
    root_id uuid NOT NULL,
    installation_id uuid NOT NULL,
    policy_uid text NOT NULL,
    acceptance_id uuid NOT NULL,
    grant_id uuid NOT NULL,
    authority_digest bytea NOT NULL,
    authored_grant_ref text NOT NULL,
    actor_issuer text NOT NULL,
    actor_subject text NOT NULL,
    actor_client text NOT NULL,
    actor_key bytea NOT NULL,
    idempotency_key text NOT NULL,
    request_digest bytea NOT NULL,
    attached_at timestamp with time zone DEFAULT clock_timestamp() NOT NULL,
    CONSTRAINT policy_grant_attachment_actor_client_check CHECK (((octet_length(actor_client) >= 1) AND (octet_length(actor_client) <= 256))),
    CONSTRAINT policy_grant_attachment_actor_issuer_check CHECK (((octet_length(actor_issuer) >= 1) AND (octet_length(actor_issuer) <= 2048))),
    CONSTRAINT policy_grant_attachment_actor_subject_check CHECK (((octet_length(actor_subject) >= 1) AND (octet_length(actor_subject) <= 256))),
    CONSTRAINT policy_grant_attachment_authority_digest_check CHECK ((octet_length(authority_digest) = 32)),
    CONSTRAINT policy_grant_attachment_check CHECK (((authored_grant_ref = ''::text) OR (authored_grant_ref = (grant_id)::text))),
    CONSTRAINT policy_grant_attachment_check1 CHECK (((octet_length(actor_key) = 32) AND (actor_key = sha256((((((((int4send(octet_length(convert_to(actor_issuer, 'UTF8'::name))) || convert_to(actor_issuer, 'UTF8'::name)) || int4send(octet_length(convert_to(actor_subject, 'UTF8'::name)))) || convert_to(actor_subject, 'UTF8'::name)) || int4send(octet_length(convert_to(actor_client, 'UTF8'::name)))) || convert_to(actor_client, 'UTF8'::name)) || int4send(5)) || convert_to('human'::text, 'UTF8'::name)))))),
    CONSTRAINT policy_grant_attachment_idempotency_key_check CHECK (((octet_length(idempotency_key) >= 1) AND (octet_length(idempotency_key) <= 128))),
    CONSTRAINT policy_grant_attachment_request_digest_check CHECK ((octet_length(request_digest) = 32))
);

ALTER TABLE ONLY policy_grant_attachment ADD CONSTRAINT policy_grant_attachment_pkey PRIMARY KEY (id);

ALTER TABLE ONLY policy_grant_attachment ADD CONSTRAINT policy_grant_attachment_root_id_actor_key_idempotency_key_key UNIQUE (root_id, actor_key, idempotency_key);

ALTER TABLE ONLY policy_grant_attachment ADD CONSTRAINT policy_grant_attachment_root_id_policy_uid_id_key UNIQUE (root_id, policy_uid, id);

CREATE TABLE policy_grant_settings (
    root_id uuid NOT NULL,
    installation_id uuid NOT NULL,
    issuer text NOT NULL,
    source_uid text NOT NULL,
    source_generation bigint NOT NULL,
    source_digest bytea NOT NULL,
    observed_at timestamp with time zone NOT NULL,
    fresh_until timestamp with time zone NOT NULL,
    default_age_seconds integer NOT NULL,
    max_age_seconds integer NOT NULL,
    renewal_notice_seconds integer NOT NULL,
    CONSTRAINT policy_grant_settings_check CHECK (((max_age_seconds >= default_age_seconds) AND (max_age_seconds <= 31536000))),
    CONSTRAINT policy_grant_settings_check1 CHECK (((renewal_notice_seconds >= 1) AND (renewal_notice_seconds <= max_age_seconds))),
    CONSTRAINT policy_grant_settings_check2 CHECK (((fresh_until > observed_at) AND (fresh_until <= (observed_at + '00:00:30'::interval)))),
    CONSTRAINT policy_grant_settings_default_age_seconds_check CHECK (((default_age_seconds >= 1) AND (default_age_seconds <= 31536000))),
    CONSTRAINT policy_grant_settings_issuer_check CHECK (((octet_length(issuer) >= 1) AND (octet_length(issuer) <= 2048))),
    CONSTRAINT policy_grant_settings_source_digest_check CHECK ((octet_length(source_digest) = 32)),
    CONSTRAINT policy_grant_settings_source_generation_check CHECK (((source_generation >= 1) AND (source_generation <= 2147483647))),
    CONSTRAINT policy_grant_settings_source_uid_check CHECK (((octet_length(source_uid) >= 1) AND (octet_length(source_uid) <= 64)))
);

ALTER TABLE ONLY policy_grant_settings ADD CONSTRAINT policy_grant_settings_pkey PRIMARY KEY (root_id);

CREATE TABLE policy_observation_session (
    id uuid NOT NULL,
    root_id uuid NOT NULL,
    policy_uid text,
    acceptance_id uuid,
    grant_id uuid NOT NULL,
    capture_id uuid NOT NULL,
    attempt_id uuid NOT NULL,
    fence uuid NOT NULL,
    action_id text NOT NULL,
    pod_uid text NOT NULL,
    node_uid text NOT NULL,
    boot_id text NOT NULL,
    collector_pod_uid text NOT NULL,
    collector_epoch text NOT NULL,
    expectation_digest bytea NOT NULL,
    program_digest bytea NOT NULL,
    binding_scope bytea NOT NULL,
    accounting_rule bytea NOT NULL,
    source_observed_at timestamp with time zone NOT NULL,
    source_fresh_until timestamp with time zone NOT NULL,
    started_at timestamp with time zone NOT NULL,
    session_until timestamp with time zone NOT NULL,
    lease_until timestamp with time zone NOT NULL,
    start_by timestamp with time zone NOT NULL,
    duration_millis bigint NOT NULL,
    sequence bigint NOT NULL,
    credit bigint NOT NULL,
    max_bytes_per_second bigint NOT NULL,
    ended_at timestamp with time zone,
    adhoc_capture_id uuid GENERATED ALWAYS AS (
CASE
    WHEN (acceptance_id IS NULL) THEN capture_id
    ELSE NULL::uuid
END) STORED,
    argument_definition_digest bytea,
    event_credit bigint DEFAULT 0 NOT NULL,
    max_events_per_second bigint DEFAULT 0 NOT NULL,
    max_probe_bytes bigint DEFAULT 0 NOT NULL,
    max_bytes_per_event bigint DEFAULT 0 NOT NULL,
    max_tracked_threads bigint DEFAULT 0 NOT NULL,
    capture_buffers boolean DEFAULT false NOT NULL,
    CONSTRAINT policy_observation_argument_tuple CHECK ((((accounting_rule = decode('4d3f2eea2ed280bd7017ea2398a4cde18d94daacbcc4c8741a98d52c56697453'::text, 'hex'::text)) AND (argument_definition_digest IS NULL) AND (event_credit = 0) AND (max_events_per_second = 0) AND (max_probe_bytes = 0) AND (max_bytes_per_event = 0) AND (max_tracked_threads = 0) AND (NOT capture_buffers) AND (duration_millis >= 1000) AND (session_until > started_at) AND (session_until <= (started_at + (((duration_millis + 10000))::double precision * '00:00:00.001'::interval)))) OR ((accounting_rule = decode('833bafd01122a099b6a41751e9c545dccd925d54f94faabdfba9f8f9bcd7eef6'::text, 'hex'::text)) AND (argument_definition_digest IS NOT NULL) AND (octet_length(argument_definition_digest) = 32) AND ((event_credit >= 1) AND (event_credit <= 1000000000)) AND ((max_events_per_second >= 1) AND (max_events_per_second <= 100000)) AND (max_probe_bytes = ANY (ARRAY[(256)::bigint, (512)::bigint])) AND ((max_bytes_per_event >= 1) AND (max_bytes_per_event <= 4096)) AND ((max_probe_bytes = 256) OR (max_bytes_per_event >= 128)) AND ((max_tracked_threads >= 1) AND (max_tracked_threads <= 16384)) AND (credit >= max_probe_bytes) AND (max_bytes_per_second >= max_probe_bytes) AND (duration_millis >= 1000) AND (session_until > started_at) AND (session_until <= (started_at + (((duration_millis + 10000))::double precision * '00:00:00.001'::interval)))))),
    CONSTRAINT policy_observation_session_action_id_check CHECK (((octet_length(action_id) >= 1) AND (octet_length(action_id) <= 128))),
    CONSTRAINT policy_observation_session_binding_scope_check CHECK ((octet_length(binding_scope) = 32)),
    CONSTRAINT policy_observation_session_boot_id_check CHECK (((octet_length(boot_id) >= 1) AND (octet_length(boot_id) <= 128))),
    CONSTRAINT policy_observation_session_check1 CHECK ((lease_until = session_until)),
    CONSTRAINT policy_observation_session_check2 CHECK (((start_by > started_at) AND (start_by <= (started_at + '00:00:10'::interval)) AND ((start_by + ((duration_millis)::double precision * '00:00:00.001'::interval)) <= lease_until))),
    CONSTRAINT policy_observation_session_check3 CHECK (((source_observed_at <= started_at) AND (source_fresh_until > started_at) AND (source_fresh_until <= (source_observed_at + '00:00:05'::interval)))),
    CONSTRAINT policy_observation_session_check4 CHECK (((ended_at IS NULL) OR (ended_at >= started_at))),
    CONSTRAINT policy_observation_session_collector_epoch_check CHECK (((octet_length(collector_epoch) >= 1) AND (octet_length(collector_epoch) <= 128))),
    CONSTRAINT policy_observation_session_collector_pod_uid_check CHECK (((octet_length(collector_pod_uid) >= 1) AND (octet_length(collector_pod_uid) <= 128))),
    CONSTRAINT policy_observation_session_credit_check CHECK (((credit >= 1) AND (credit <= '1099511627776'::bigint))),
    CONSTRAINT policy_observation_session_expectation_digest_check CHECK ((octet_length(expectation_digest) = 32)),
    CONSTRAINT policy_observation_session_kind CHECK (((policy_uid IS NULL) = (acceptance_id IS NULL))),
    CONSTRAINT policy_observation_session_max_bytes_per_second_check CHECK (((max_bytes_per_second >= 1) AND (max_bytes_per_second <= 1073741824))),
    CONSTRAINT policy_observation_session_node_uid_check CHECK (((octet_length(node_uid) >= 1) AND (octet_length(node_uid) <= 128))),
    CONSTRAINT policy_observation_session_pod_uid_check CHECK (((octet_length(pod_uid) >= 1) AND (octet_length(pod_uid) <= 128))),
    CONSTRAINT policy_observation_session_program_digest_check CHECK ((octet_length(program_digest) = 32)),
    CONSTRAINT policy_observation_session_sequence_check CHECK ((sequence = 1))
);

ALTER TABLE ONLY policy_observation_session ADD CONSTRAINT policy_observation_session_capture_id_key UNIQUE (capture_id);

ALTER TABLE ONLY policy_observation_session ADD CONSTRAINT policy_observation_session_pkey PRIMARY KEY (id);

CREATE INDEX policy_observation_active ON policy_observation_session USING btree (root_id, acceptance_id, lease_until) WHERE (ended_at IS NULL);

CREATE INDEX policy_observation_adhoc_active ON policy_observation_session USING btree (root_id, grant_id, lease_until) WHERE ((ended_at IS NULL) AND (acceptance_id IS NULL));

CREATE TABLE policy_occurrence (
    id uuid NOT NULL,
    root_id uuid NOT NULL,
    policy_uid text NOT NULL,
    acceptance_id uuid NOT NULL,
    cluster_id uuid NOT NULL,
    workload_uid text NOT NULL,
    pod_uid text NOT NULL,
    restarts bigint NOT NULL,
    created_at timestamp with time zone DEFAULT clock_timestamp() NOT NULL,
    capture_id uuid,
    outcome text,
    detector text DEFAULT 'exit'::text NOT NULL,
    reserved_capture_id uuid,
    grant_id uuid,
    reserved_bytes bigint DEFAULT 0 NOT NULL,
    CONSTRAINT policy_occurrence_check CHECK (((capture_id IS NULL) OR (outcome = 'captured'::text))),
    CONSTRAINT policy_occurrence_detector_check CHECK ((detector = ANY (ARRAY['exit'::text, 'probe'::text, 'alert'::text, 'log'::text, 'resource'::text]))),
    CONSTRAINT policy_occurrence_outcome_check CHECK ((outcome = ANY (ARRAY['captured'::text, 'refused'::text]))),
    CONSTRAINT policy_occurrence_pod_uid_check CHECK (((octet_length(pod_uid) >= 1) AND (octet_length(pod_uid) <= 64))),
    CONSTRAINT policy_occurrence_probe_second CHECK (((detector <> ALL (ARRAY['probe'::text, 'alert'::text, 'log'::text, 'resource'::text])) OR (restarts >= 1000000000))),
    CONSTRAINT policy_occurrence_reservation CHECK ((((reserved_capture_id IS NULL) AND (grant_id IS NULL) AND (reserved_bytes = 0)) OR ((reserved_capture_id IS NOT NULL) AND ((reserved_bytes >= 1) AND (reserved_bytes <= '1099511627776'::bigint))))),
    CONSTRAINT policy_occurrence_restarts_check CHECK (((restarts >= 1) AND (restarts <= '2147483648'::bigint))),
    CONSTRAINT policy_occurrence_workload_uid_check CHECK (((octet_length(workload_uid) >= 1) AND (octet_length(workload_uid) <= 64)))
);

ALTER TABLE ONLY policy_occurrence ADD CONSTRAINT policy_occurrence_capture_id_key UNIQUE (capture_id);

ALTER TABLE ONLY policy_occurrence ADD CONSTRAINT policy_occurrence_pkey PRIMARY KEY (id);

ALTER TABLE ONLY policy_occurrence ADD CONSTRAINT policy_occurrence_reserved_capture_id_key UNIQUE (reserved_capture_id);

ALTER TABLE ONLY policy_occurrence ADD CONSTRAINT policy_occurrence_root_id_policy_uid_pod_uid_restarts_key UNIQUE (root_id, policy_uid, pod_uid, restarts);

CREATE INDEX policy_occurrence_open ON policy_occurrence USING btree (root_id, created_at) WHERE (outcome IS NULL);

CREATE INDEX policy_occurrence_recent ON policy_occurrence USING btree (root_id, policy_uid, created_at DESC);

CREATE TABLE policy_occurrence_capture (
    root_id uuid NOT NULL,
    occurrence_id uuid NOT NULL,
    action_id text NOT NULL,
    capture_id uuid NOT NULL,
    grant_id uuid,
    reserved_bytes bigint NOT NULL,
    CONSTRAINT policy_occurrence_capture_action_id_check CHECK (((octet_length(action_id) >= 1) AND (octet_length(action_id) <= 64))),
    CONSTRAINT policy_occurrence_capture_reserved_bytes_check CHECK (((reserved_bytes >= 1) AND (reserved_bytes <= '1099511627776'::bigint)))
);

ALTER TABLE ONLY policy_occurrence_capture ADD CONSTRAINT policy_occurrence_capture_capture_id_key UNIQUE (capture_id);

ALTER TABLE ONLY policy_occurrence_capture ADD CONSTRAINT policy_occurrence_capture_pkey PRIMARY KEY (occurrence_id, action_id);

CREATE TABLE policy_pod_watermark (
    root_id uuid NOT NULL,
    policy_uid text NOT NULL,
    pod_uid text NOT NULL,
    restarts bigint NOT NULL,
    last_seen timestamp with time zone NOT NULL,
    detector text DEFAULT 'exit'::text NOT NULL,
    armed boolean DEFAULT true NOT NULL,
    CONSTRAINT policy_pod_watermark_detector_check CHECK ((detector = ANY (ARRAY['exit'::text, 'probe'::text, 'alert'::text, 'log'::text, 'resource'::text]))),
    CONSTRAINT policy_pod_watermark_pod_uid_check CHECK (((octet_length(pod_uid) >= 1) AND (octet_length(pod_uid) <= 64))),
    CONSTRAINT policy_pod_watermark_restarts_check CHECK (((restarts >= 0) AND (restarts <= '2147483648'::bigint)))
);

ALTER TABLE ONLY policy_pod_watermark ADD CONSTRAINT policy_pod_watermark_pkey PRIMARY KEY (root_id, policy_uid, pod_uid);

CREATE TABLE policy_recording_source (
    root_id uuid NOT NULL,
    id uuid NOT NULL,
    fence uuid NOT NULL,
    policy_uid text NOT NULL,
    acceptance_id uuid NOT NULL,
    action_id text NOT NULL,
    cluster_id uuid NOT NULL,
    namespace_uid text NOT NULL,
    workload_uid text NOT NULL,
    pod_uid text NOT NULL,
    allocation_id uuid NOT NULL,
    binding_json jsonb NOT NULL,
    started_at timestamp with time zone NOT NULL,
    hard_until timestamp with time zone NOT NULL,
    start_by timestamp with time zone NOT NULL,
    initial_leaf_until timestamp with time zone NOT NULL,
    initial_credit bigint NOT NULL,
    credit bigint NOT NULL,
    bytes_per_second bigint NOT NULL,
    ended_at timestamp with time zone,
    slot_released_at timestamp with time zone,
    source_audience_json jsonb,
    source_audience_digest bytea,
    source_target_json jsonb,
    CONSTRAINT policy_recording_source_action_id_check CHECK (((octet_length(action_id) >= 1) AND (octet_length(action_id) <= 128))),
    CONSTRAINT policy_recording_source_binding_json_check CHECK (((jsonb_typeof(binding_json) = 'object'::text) AND ((octet_length((binding_json)::text) >= 2) AND (octet_length((binding_json)::text) <= 8192)))),
    CONSTRAINT policy_recording_source_bytes_per_second_check CHECK (((bytes_per_second >= 1) AND (bytes_per_second <= '10737418240'::bigint))),
    CONSTRAINT policy_recording_source_check CHECK ((credit >= initial_credit)),
    CONSTRAINT policy_recording_source_check1 CHECK ((isfinite(started_at) AND isfinite(hard_until) AND isfinite(start_by) AND (hard_until > started_at) AND (start_by > started_at) AND (start_by <= (started_at + '00:00:05'::interval)) AND (start_by <= hard_until))),
    CONSTRAINT policy_recording_source_check2 CHECK ((isfinite(initial_leaf_until) AND (initial_leaf_until > started_at) AND (initial_leaf_until <= (started_at + '00:00:30'::interval)) AND (initial_leaf_until <= hard_until))),
    CONSTRAINT policy_recording_source_check3 CHECK (((ended_at IS NULL) OR (isfinite(ended_at) AND (ended_at >= started_at)))),
    CONSTRAINT policy_recording_source_check4 CHECK (((slot_released_at IS NULL) OR ((ended_at IS NOT NULL) AND isfinite(slot_released_at) AND (slot_released_at >= (ended_at + '00:00:30'::interval))))),
    CONSTRAINT policy_recording_source_initial_credit_check CHECK ((initial_credit > 0)),
    CONSTRAINT policy_recording_source_namespace_uid_check CHECK (((octet_length(namespace_uid) >= 1) AND (octet_length(namespace_uid) <= 64))),
    CONSTRAINT policy_recording_source_pod_uid_check CHECK (((octet_length(pod_uid) >= 1) AND (octet_length(pod_uid) <= 64))),
    CONSTRAINT policy_recording_source_policy_uid_check CHECK (((octet_length(policy_uid) >= 1) AND (octet_length(policy_uid) <= 128))),
    CONSTRAINT policy_recording_source_workload_uid_check CHECK (((octet_length(workload_uid) >= 1) AND (octet_length(workload_uid) <= 64))),
    CONSTRAINT policy_source_original_provenance_shape CHECK ((((source_audience_json IS NULL) AND (source_audience_digest IS NULL) AND (source_target_json IS NULL)) OR ((source_audience_json IS NOT NULL) AND (jsonb_typeof(source_audience_json) = 'array'::text) AND ((jsonb_array_length(source_audience_json) >= 1) AND (jsonb_array_length(source_audience_json) <= 32)) AND (octet_length((source_audience_json)::text) <= 98304) AND (source_audience_digest IS NOT NULL) AND (octet_length(source_audience_digest) = 32) AND (source_audience_digest <> decode(repeat('00'::text, 32), 'hex'::text)) AND (source_target_json IS NOT NULL) AND (jsonb_typeof(source_target_json) = 'object'::text) AND ((octet_length((source_target_json)::text) >= 2) AND (octet_length((source_target_json)::text) <= 8192)))))
);

ALTER TABLE ONLY policy_recording_source ADD CONSTRAINT policy_recording_source_pkey PRIMARY KEY (root_id, id);

CREATE INDEX policy_recording_source_account ON policy_recording_source USING btree (root_id, allocation_id) WHERE (slot_released_at IS NULL);

CREATE INDEX policy_recording_source_ended ON policy_recording_source USING btree (root_id, ended_at, id) WHERE ((ended_at IS NOT NULL) AND (slot_released_at IS NULL));

CREATE UNIQUE INDEX policy_recording_source_slot ON policy_recording_source USING btree (root_id, policy_uid, action_id, pod_uid) WHERE (slot_released_at IS NULL);

CREATE TABLE policy_source (
    root_id uuid NOT NULL,
    policy_uid text NOT NULL,
    installation_id uuid NOT NULL,
    cluster_id uuid NOT NULL,
    namespace_uid text NOT NULL,
    name text NOT NULL,
    generation bigint NOT NULL,
    spec_digest bytea NOT NULL,
    resource_version text NOT NULL,
    observed_at timestamp with time zone NOT NULL,
    fresh_until timestamp with time zone NOT NULL,
    deleted boolean NOT NULL,
    suspended boolean NOT NULL,
    collection_digest bytea NOT NULL,
    intent_version bigint DEFAULT 1 NOT NULL,
    active_id uuid,
    creator_json jsonb,
    authored_grant_ref text DEFAULT ''::text NOT NULL,
    grant_attachment_id uuid,
    CONSTRAINT policy_source_authored_grant_ref_check CHECK (((authored_grant_ref = ''::text) OR (authored_grant_ref ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'::text))),
    CONSTRAINT policy_source_collection_digest_check CHECK ((octet_length(collection_digest) = 32)),
    CONSTRAINT policy_source_creator_json_check CHECK (((creator_json IS NULL) OR ((jsonb_typeof(creator_json) = 'object'::text) AND (octet_length((creator_json)::text) <= 8192)))),
    CONSTRAINT policy_source_fresh CHECK (((fresh_until > observed_at) AND (fresh_until <= (observed_at + '00:00:30'::interval)))),
    CONSTRAINT policy_source_generation_check CHECK (((generation >= 1) AND (generation <= 2147483647))),
    CONSTRAINT policy_source_intent_version_check CHECK ((intent_version > 0)),
    CONSTRAINT policy_source_name_check CHECK (((octet_length(name) >= 1) AND (octet_length(name) <= 253))),
    CONSTRAINT policy_source_namespace_uid_check CHECK (((octet_length(namespace_uid) >= 1) AND (octet_length(namespace_uid) <= 64))),
    CONSTRAINT policy_source_policy_uid_check CHECK (((octet_length(policy_uid) >= 1) AND (octet_length(policy_uid) <= 64))),
    CONSTRAINT policy_source_resource_version_check CHECK (((octet_length(resource_version) >= 1) AND (octet_length(resource_version) <= 128))),
    CONSTRAINT policy_source_spec_digest_check CHECK ((octet_length(spec_digest) = 32))
);

ALTER TABLE ONLY policy_source ADD CONSTRAINT policy_source_pkey PRIMARY KEY (root_id, policy_uid);

CREATE TABLE policy_suppression (
    root_id uuid NOT NULL,
    policy_uid text NOT NULL,
    reason text NOT NULL,
    first_at timestamp with time zone NOT NULL,
    last_at timestamp with time zone NOT NULL,
    count bigint NOT NULL,
    CONSTRAINT policy_suppression_check CHECK ((last_at >= first_at)),
    CONSTRAINT policy_suppression_count_check CHECK (((count >= 1) AND (count <= 2147483647))),
    CONSTRAINT policy_suppression_reason_check CHECK ((reason = ANY (ARRAY['cooldown'::text, 'budget'::text, 'coalesced'::text, 'capacity'::text, 'authority'::text, 'unavailable'::text, 'overlong'::text])))
);

ALTER TABLE ONLY policy_suppression ADD CONSTRAINT policy_suppression_pkey PRIMARY KEY (root_id, policy_uid, reason);

CREATE TABLE policy_workload_window (
    root_id uuid NOT NULL,
    cluster_id uuid NOT NULL,
    workload_uid text NOT NULL,
    policy_uid text NOT NULL,
    tat timestamp with time zone NOT NULL,
    CONSTRAINT policy_workload_window_policy_uid_check CHECK ((octet_length(policy_uid) <= 64)),
    CONSTRAINT policy_workload_window_workload_uid_check CHECK (((octet_length(workload_uid) >= 1) AND (octet_length(workload_uid) <= 64)))
);

ALTER TABLE ONLY policy_workload_window ADD CONSTRAINT policy_workload_window_pkey PRIMARY KEY (root_id, cluster_id, workload_uid, policy_uid);

CREATE TABLE processing_decision (
    id uuid NOT NULL,
    root_id uuid NOT NULL,
    rule_id uuid,
    expected_revision bigint NOT NULL,
    actor_digest bytea NOT NULL,
    request_digest bytea NOT NULL,
    scope jsonb NOT NULL,
    action text NOT NULL,
    created_at timestamp with time zone NOT NULL,
    request_until timestamp with time zone NOT NULL,
    valid_until timestamp with time zone NOT NULL,
    retire_by timestamp with time zone NOT NULL,
    applied_at timestamp with time zone,
    result_revision bigint,
    result_sequence bigint,
    erasure_decision bytea,
    CONSTRAINT processing_decision_action_check CHECK ((action = ANY (ARRAY['initialize_processing'::text, 'restrict_processing'::text, 'release_processing'::text, 'request_early_erasure'::text]))),
    CONSTRAINT processing_decision_actor_digest_check CHECK ((octet_length(actor_digest) = 32)),
    CONSTRAINT processing_decision_applied_result CHECK ((((applied_at IS NULL) = (result_revision IS NULL)) AND ((applied_at IS NULL) = (result_sequence IS NULL)))),
    CONSTRAINT processing_decision_check CHECK ((isfinite(retire_by) AND (retire_by > valid_until))),
    CONSTRAINT processing_decision_check1 CHECK ((isfinite(created_at) AND isfinite(request_until) AND (request_until > created_at) AND (request_until <= (created_at + '00:00:05'::interval)) AND (request_until <= valid_until))),
    CONSTRAINT processing_decision_erasure_payload_check CHECK ((((action = 'request_early_erasure'::text) = (erasure_decision IS NOT NULL)) AND ((erasure_decision IS NULL) OR ((octet_length(erasure_decision) >= 1) AND (octet_length(erasure_decision) <= 32768))))),
    CONSTRAINT processing_decision_expected_revision_check CHECK (((expected_revision >= 0) AND (expected_revision <= 15))),
    CONSTRAINT processing_decision_request_digest_check CHECK ((octet_length(request_digest) = 32)),
    CONSTRAINT processing_decision_rule_action CHECK (((rule_id IS NULL) = (action = ANY (ARRAY['initialize_processing'::text, 'request_early_erasure'::text])))),
    CONSTRAINT processing_decision_scope_check CHECK (((jsonb_typeof(scope) = 'object'::text) AND (octet_length((scope)::text) <= 2048))),
    CONSTRAINT processing_decision_valid_until_check CHECK (isfinite(valid_until))
);

ALTER TABLE ONLY processing_decision ADD CONSTRAINT processing_decision_pkey PRIMARY KEY (id);

CREATE UNIQUE INDEX processing_decision_revision ON processing_decision USING btree (root_id, rule_id, expected_revision) WHERE (applied_at IS NOT NULL);

CREATE UNIQUE INDEX processing_erasure_applied ON processing_decision USING btree (root_id, ((scope #>> '{Location,AttemptID}'::text[]))) WHERE ((action = 'request_early_erasure'::text) AND (applied_at IS NOT NULL));

CREATE INDEX processing_erasure_attempt ON processing_decision USING btree (root_id, ((scope #>> '{Location,AttemptID}'::text[])), request_until) WHERE (action = 'request_early_erasure'::text);

CREATE INDEX processing_report_rule_created ON processing_decision USING btree (root_id, rule_id, created_at);

CREATE TABLE processing_root (
    root_id uuid NOT NULL,
    installation_id uuid NOT NULL,
    issuer_epoch uuid NOT NULL,
    epoch uuid NOT NULL,
    source_uid uuid NOT NULL,
    protection_digest bytea NOT NULL,
    backing jsonb NOT NULL,
    backing_revision bigint NOT NULL,
    valid_until timestamp with time zone NOT NULL,
    retire_by timestamp with time zone NOT NULL,
    max_captures bigint NOT NULL,
    max_rules bigint NOT NULL,
    max_root_transitions bigint NOT NULL,
    captures bigint DEFAULT 0 NOT NULL,
    rules bigint DEFAULT 0 NOT NULL,
    root_transitions bigint DEFAULT 0 NOT NULL,
    sequence bigint DEFAULT 1 NOT NULL,
    initialized_at timestamp with time zone,
    initialization_id uuid,
    CONSTRAINT processing_root_backing_check CHECK (((jsonb_typeof(backing) = 'object'::text) AND (octet_length((backing)::text) <= 8192))),
    CONSTRAINT processing_root_backing_revision_check CHECK ((backing_revision > 0)),
    CONSTRAINT processing_root_check CHECK ((isfinite(retire_by) AND (retire_by > valid_until))),
    CONSTRAINT processing_root_check1 CHECK (((captures >= 0) AND (captures <= max_captures))),
    CONSTRAINT processing_root_check2 CHECK (((rules >= 0) AND (rules <= max_rules))),
    CONSTRAINT processing_root_check3 CHECK (((root_transitions >= 0) AND (root_transitions <= max_root_transitions))),
    CONSTRAINT processing_root_check4 CHECK (((initialized_at IS NULL) = (initialization_id IS NULL))),
    CONSTRAINT processing_root_max_captures_check CHECK (((max_captures >= 1) AND (max_captures <= 1000000))),
    CONSTRAINT processing_root_max_root_transitions_check CHECK (((max_root_transitions >= 8) AND (max_root_transitions <= 65536))),
    CONSTRAINT processing_root_max_rules_check CHECK (((max_rules >= 1) AND (max_rules <= 1024))),
    CONSTRAINT processing_root_protection_digest_check CHECK ((octet_length(protection_digest) = 32)),
    CONSTRAINT processing_root_sequence_check CHECK (((sequence >= 1) AND (sequence <= '1152921504606846976'::bigint))),
    CONSTRAINT processing_root_valid_until_check CHECK (isfinite(valid_until))
);

ALTER TABLE ONLY processing_root ADD CONSTRAINT processing_root_epoch_key UNIQUE (epoch);

ALTER TABLE ONLY processing_root ADD CONSTRAINT processing_root_pkey PRIMARY KEY (root_id);

CREATE TABLE processing_rule (
    root_id uuid NOT NULL,
    id uuid NOT NULL,
    scope jsonb NOT NULL,
    revision bigint DEFAULT 0 NOT NULL,
    decisions bigint DEFAULT 0 NOT NULL,
    valid_until timestamp with time zone NOT NULL,
    retire_by timestamp with time zone NOT NULL,
    state text DEFAULT 'reserved'::text NOT NULL,
    current_decision uuid,
    CONSTRAINT processing_rule_check CHECK ((isfinite(retire_by) AND (retire_by > valid_until))),
    CONSTRAINT processing_rule_check1 CHECK ((((revision = 0) AND (state = 'reserved'::text) AND (current_decision IS NULL)) OR ((revision > 0) AND (current_decision IS NOT NULL) AND ((((revision % (2)::bigint) = 1) AND (state = 'restricted'::text)) OR (((revision % (2)::bigint) = 0) AND (state = 'released'::text)))))),
    CONSTRAINT processing_rule_decisions_check CHECK (((decisions >= 0) AND (decisions <= 16))),
    CONSTRAINT processing_rule_revision_check CHECK (((revision >= 0) AND (revision <= 16))),
    CONSTRAINT processing_rule_scope_check CHECK (((jsonb_typeof(scope) = 'object'::text) AND (octet_length((scope)::text) <= 2048))),
    CONSTRAINT processing_rule_state_check CHECK ((state = ANY (ARRAY['reserved'::text, 'restricted'::text, 'released'::text]))),
    CONSTRAINT processing_rule_valid_until_check CHECK (isfinite(valid_until))
);

ALTER TABLE ONLY processing_rule ADD CONSTRAINT processing_rule_pkey PRIMARY KEY (root_id, id);

CREATE INDEX processing_rule_active ON processing_rule USING btree (root_id, id) WHERE (state = 'restricted'::text);

CREATE TABLE recording_save_group (
    id uuid NOT NULL,
    root_id uuid NOT NULL,
    preview_id uuid NOT NULL,
    request_key bytea NOT NULL,
    submission_digest bytea NOT NULL,
    scope_digest bytea NOT NULL,
    scope_json bytea NOT NULL,
    policy_uid text,
    acceptance_id uuid,
    allocation_id uuid NOT NULL,
    child_ids uuid[] NOT NULL,
    accepted_at timestamp with time zone NOT NULL,
    deadline timestamp with time zone NOT NULL,
    progress_revision bigint DEFAULT 1 NOT NULL,
    cancel_requested_at timestamp with time zone,
    cancel_request_key bytea,
    group_kind text DEFAULT 'recordingSave'::text NOT NULL,
    CONSTRAINT recording_save_group_cancel_request_key_check CHECK ((octet_length(cancel_request_key) = 32)),
    CONSTRAINT recording_save_group_check CHECK ((sha256(scope_json) = scope_digest)),
    CONSTRAINT recording_save_group_check1 CHECK ((isfinite(accepted_at) AND isfinite(deadline) AND (deadline > accepted_at))),
    CONSTRAINT recording_save_group_check2 CHECK (((cancel_requested_at IS NULL) = (cancel_request_key IS NULL))),
    CONSTRAINT recording_save_group_child_ids_check CHECK ((((cardinality(child_ids) >= 2) AND (cardinality(child_ids) <= 16)) AND (array_position(child_ids, NULL::uuid) IS NULL))),
    CONSTRAINT recording_save_group_group_kind_check CHECK ((group_kind = ANY (ARRAY['recordingSave'::text, 'composition'::text]))),
    CONSTRAINT recording_save_group_kind_policy CHECK ((((group_kind = 'recordingSave'::text) AND (policy_uid IS NOT NULL) AND (acceptance_id IS NOT NULL)) OR ((group_kind = 'composition'::text) AND (policy_uid IS NULL) AND (acceptance_id IS NULL)))),
    CONSTRAINT recording_save_group_policy_uid_check CHECK (((octet_length(policy_uid) >= 1) AND (octet_length(policy_uid) <= 64))),
    CONSTRAINT recording_save_group_progress_revision_check CHECK (((progress_revision >= 1) AND (progress_revision <= 1000000000))),
    CONSTRAINT recording_save_group_request_key_check CHECK ((octet_length(request_key) = 32)),
    CONSTRAINT recording_save_group_scope_digest_check CHECK ((octet_length(scope_digest) = 32)),
    CONSTRAINT recording_save_group_scope_json_check CHECK (((octet_length(scope_json) >= 1) AND (octet_length(scope_json) <= 65536))),
    CONSTRAINT recording_save_group_submission_digest_check CHECK ((octet_length(submission_digest) = 32))
);

ALTER TABLE ONLY recording_save_group ADD CONSTRAINT recording_save_group_pkey PRIMARY KEY (id);

ALTER TABLE ONLY recording_save_group ADD CONSTRAINT recording_save_group_root_id_id_key UNIQUE (root_id, id);

ALTER TABLE ONLY recording_save_group ADD CONSTRAINT recording_save_group_root_id_preview_id_key UNIQUE (root_id, preview_id);

ALTER TABLE ONLY recording_save_group ADD CONSTRAINT recording_save_group_root_id_request_key_key UNIQUE (root_id, request_key);

CREATE TABLE recording_save_reservation (
    capture_id uuid NOT NULL,
    root_id uuid NOT NULL,
    policy_uid text NOT NULL,
    acceptance_id uuid NOT NULL,
    grant_id uuid,
    reserved_bytes bigint NOT NULL,
    accepted_at timestamp with time zone NOT NULL,
    processing_until timestamp with time zone NOT NULL,
    CONSTRAINT recording_save_reservation_check CHECK ((isfinite(accepted_at) AND isfinite(processing_until) AND (processing_until > accepted_at))),
    CONSTRAINT recording_save_reservation_policy_uid_check CHECK (((octet_length(policy_uid) >= 1) AND (octet_length(policy_uid) <= 64))),
    CONSTRAINT recording_save_reservation_reserved_bytes_check CHECK (((reserved_bytes >= 65536) AND (reserved_bytes <= 8388608)))
);

ALTER TABLE ONLY recording_save_reservation ADD CONSTRAINT recording_save_reservation_pkey PRIMARY KEY (capture_id);

CREATE TABLE recording_selection_set (
    id uuid NOT NULL,
    root_id uuid NOT NULL,
    actor_key bytea NOT NULL,
    principal_key bytea NOT NULL,
    cluster_id uuid NOT NULL,
    namespace_uid text NOT NULL,
    workload_uid text NOT NULL,
    policy_uid text DEFAULT ''::text NOT NULL,
    after_source_id uuid,
    has_more boolean DEFAULT false NOT NULL,
    references_json bytea NOT NULL,
    created_at timestamp with time zone NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    CONSTRAINT recording_selection_set_actor_key_check CHECK ((octet_length(actor_key) = 32)),
    CONSTRAINT recording_selection_set_check CHECK (((NOT has_more) OR (after_source_id IS NOT NULL))),
    CONSTRAINT recording_selection_set_check1 CHECK ((isfinite(created_at) AND isfinite(expires_at) AND (created_at >= '2020-01-01 00:00:00+00'::timestamp with time zone) AND (expires_at < '10000-01-01 00:00:00+00'::timestamp with time zone))),
    CONSTRAINT recording_selection_set_check2 CHECK (((expires_at > created_at) AND (expires_at <= (created_at + '00:01:00'::interval)))),
    CONSTRAINT recording_selection_set_namespace_uid_check CHECK (((length(namespace_uid) >= 1) AND (length(namespace_uid) <= 64))),
    CONSTRAINT recording_selection_set_policy_uid_check CHECK ((length(policy_uid) <= 64)),
    CONSTRAINT recording_selection_set_principal_key_check CHECK ((octet_length(principal_key) = 32)),
    CONSTRAINT recording_selection_set_references_json_check CHECK (((octet_length(references_json) >= 2) AND (octet_length(references_json) <= 65536))),
    CONSTRAINT recording_selection_set_workload_uid_check CHECK (((length(workload_uid) >= 1) AND (length(workload_uid) <= 64)))
);

ALTER TABLE ONLY recording_selection_set ADD CONSTRAINT recording_selection_set_pkey PRIMARY KEY (id);

CREATE INDEX recording_selection_expiry ON recording_selection_set USING btree (root_id, expires_at, id);

CREATE INDEX recording_selection_principal ON recording_selection_set USING btree (root_id, principal_key, expires_at);

CREATE TABLE remote_access_binding_delivery (
    root_id uuid NOT NULL,
    cluster_id uuid NOT NULL,
    observed_at timestamp with time zone NOT NULL,
    digest bytea NOT NULL,
    bindings bytea NOT NULL,
    CONSTRAINT remote_access_binding_delivery_bindings_check CHECK (((octet_length(bindings) >= 2) AND (octet_length(bindings) <= 33554432))),
    CONSTRAINT remote_access_binding_delivery_digest_check CHECK ((octet_length(digest) = 32)),
    CONSTRAINT remote_access_binding_delivery_observed_at_check CHECK ((isfinite(observed_at) AND (observed_at >= '2020-01-01 00:00:00+00'::timestamp with time zone) AND (observed_at < '10000-01-01 00:00:00+00'::timestamp with time zone)))
);

ALTER TABLE ONLY remote_access_binding_delivery ADD CONSTRAINT remote_access_binding_delivery_pkey PRIMARY KEY (root_id, cluster_id);

CREATE TABLE retention_decision (
    id uuid NOT NULL,
    root_id uuid NOT NULL,
    attempt_id uuid NOT NULL,
    sequence bigint NOT NULL,
    previous_expires_at timestamp with time zone NOT NULL,
    previous_delete_by timestamp with time zone NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    delete_by timestamp with time zone NOT NULL,
    decision_digest bytea NOT NULL,
    decision_json bytea NOT NULL,
    recorded_at timestamp with time zone DEFAULT clock_timestamp() NOT NULL,
    audit_acknowledged_at timestamp with time zone,
    audit_receipt_json bytea,
    CONSTRAINT retention_decision_audit_receipt_json_check CHECK (((octet_length(audit_receipt_json) >= 1) AND (octet_length(audit_receipt_json) <= 4096))),
    CONSTRAINT retention_decision_check CHECK (((expires_at < delete_by) AND (expires_at <= previous_expires_at) AND (delete_by <= previous_delete_by) AND ((expires_at < previous_expires_at) OR (delete_by < previous_delete_by)))),
    CONSTRAINT retention_decision_check1 CHECK (((audit_acknowledged_at IS NULL) = (audit_receipt_json IS NULL))),
    CONSTRAINT retention_decision_decision_digest_check CHECK ((octet_length(decision_digest) = 32)),
    CONSTRAINT retention_decision_decision_json_check CHECK (((octet_length(decision_json) >= 1) AND (octet_length(decision_json) <= 32768))),
    CONSTRAINT retention_decision_sequence_check CHECK ((sequence > 0))
);

ALTER TABLE ONLY retention_decision ADD CONSTRAINT retention_decision_attempt_id_sequence_key UNIQUE (attempt_id, sequence);

ALTER TABLE ONLY retention_decision ADD CONSTRAINT retention_decision_pkey PRIMARY KEY (id);

CREATE INDEX retention_pending_audit ON retention_decision USING btree (root_id, recorded_at, id) WHERE (audit_acknowledged_at IS NULL);

CREATE TABLE retention_policy (
    uid text NOT NULL,
    name text NOT NULL,
    generation bigint NOT NULL,
    digest bytea NOT NULL,
    policy jsonb NOT NULL,
    effect jsonb NOT NULL,
    updated_at timestamp with time zone DEFAULT clock_timestamp() NOT NULL,
    CONSTRAINT retention_policy_digest_check CHECK ((octet_length(digest) = 32)),
    CONSTRAINT retention_policy_generation_check CHECK ((generation > 0)),
    CONSTRAINT retention_policy_name_check CHECK (((octet_length(name) >= 1) AND (octet_length(name) <= 253))),
    CONSTRAINT retention_policy_uid_check CHECK (((octet_length(uid) >= 1) AND (octet_length(uid) <= 64)))
);

ALTER TABLE ONLY retention_policy ADD CONSTRAINT retention_policy_pkey PRIMARY KEY (uid);

CREATE TABLE retention_policy_event (
    id bigint NOT NULL,
    uid text NOT NULL,
    name text NOT NULL,
    generation bigint NOT NULL,
    digest bytea NOT NULL,
    change text NOT NULL,
    shortened bigint NOT NULL,
    recorded_at timestamp with time zone DEFAULT clock_timestamp() NOT NULL,
    CONSTRAINT retention_policy_event_change_check CHECK ((change = ANY (ARRAY['applied'::text, 'rejected'::text, 'removed'::text]))),
    CONSTRAINT retention_policy_event_digest_check CHECK ((octet_length(digest) = 32)),
    CONSTRAINT retention_policy_event_shortened_check CHECK ((shortened >= 0))
);

ALTER TABLE retention_policy_event ALTER COLUMN id ADD GENERATED ALWAYS AS IDENTITY (
    SEQUENCE NAME retention_policy_event_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);

ALTER TABLE ONLY retention_policy_event ADD CONSTRAINT retention_policy_event_pkey PRIMARY KEY (id);

CREATE TABLE workload_name (
    cluster_id uuid NOT NULL,
    workload_uid text NOT NULL,
    ref text NOT NULL
);

ALTER TABLE ONLY workload_name ADD CONSTRAINT workload_name_pkey PRIMARY KEY (cluster_id, workload_uid);

ALTER TABLE ONLY audit_event ATTACH PARTITION audit_event_default DEFAULT;
ALTER INDEX audit_event_operation ATTACH PARTITION audit_event_default_operation_id_idx;
ALTER INDEX audit_event_pkey ATTACH PARTITION audit_event_default_pkey;
ALTER INDEX audit_event_recorded ATTACH PARTITION audit_event_default_recorded_at_idx;

-- Views.

CREATE VIEW fleet_current_trust AS
 SELECT installation_id,
    issuer_epoch,
    source_uid,
    source_generation,
    source_digest,
    false AS suspended,
    '-infinity'::timestamp with time zone AS observed_at,
    'infinity'::timestamp with time zone AS fresh_until
   FROM fleet_trust t;

-- Functions. Some SQL function bodies call functions defined later
-- in this file, so bodies are checked when called, not here.
SET LOCAL check_function_bodies = off;

-- +goose StatementBegin
CREATE FUNCTION advance_context_progress() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
BEGIN
 IF TG_WHEN<>'AFTER' OR TG_LEVEL<>'ROW' OR TG_TABLE_SCHEMA<>'public' THEN RAISE EXCEPTION 'invalid context progress source' USING ERRCODE='23514'; END IF;
 IF TG_RELID='public.custody_attempt'::regclass AND TG_OP='UPDATE' THEN
  IF ROW(NEW.state,NEW.copies_digest,NEW.effective_expires_at,NEW.effective_delete_by,NEW.retention_sequence,NEW.deleted_at) IS DISTINCT FROM ROW(OLD.state,OLD.copies_digest,OLD.effective_expires_at,OLD.effective_delete_by,OLD.retention_sequence,OLD.deleted_at) THEN
   UPDATE public.context_capture SET progress_revision=LEAST(progress_revision+1,1000000001) WHERE attempt_id=NEW.id;
  END IF;
 ELSIF TG_RELID='public.context_catalog'::regclass AND TG_OP='INSERT' THEN
  UPDATE public.context_capture SET progress_revision=LEAST(progress_revision+1,1000000001) WHERE id=NEW.capture_id AND root_id=NEW.root_id;
 ELSIF TG_RELID='public.context_execution'::regclass AND TG_OP IN ('INSERT','UPDATE') THEN
  IF TG_OP='INSERT' OR NEW IS DISTINCT FROM OLD THEN UPDATE public.context_capture SET progress_revision=LEAST(progress_revision+1,1000000001) WHERE id=NEW.capture_id AND root_id=NEW.root_id; END IF;
 ELSE RAISE EXCEPTION 'invalid context progress source' USING ERRCODE='23514'; END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION advance_context_progress() FROM PUBLIC;

-- +goose StatementBegin
CREATE FUNCTION apply_retention_policies() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
DECLARE c text;
BEGIN
 PERFORM pg_advisory_xact_lock_shared(hashtext('asservat.retention_policy'));
 SELECT a.cluster_id::text INTO c FROM public.custody_attempt a WHERE a.id=NEW.attempt_id;
 UPDATE public.custody_attempt a SET effective_expires_at=e.expires_at, effective_delete_by=e.delete_by
 FROM (SELECT min(x.expires_at) AS expires_at, min(x.delete_by) AS delete_by
  FROM public.retention_policy r, LATERAL public.retention_policy_effect(r.effect, NEW.attempt_id) x
  WHERE jsonb_typeof(r.effect)='object' AND (jsonb_array_length(r.effect->'clusters')=0 OR r.effect->'clusters' ? c)) e
 WHERE a.id=NEW.attempt_id AND (e.expires_at<a.effective_expires_at OR e.delete_by<a.effective_delete_by);
 RETURN NULL;
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION bump_snapshot_cancel_progress() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
BEGIN
 IF TG_WHEN<>'AFTER' OR TG_LEVEL<>'ROW' OR TG_OP<>'UPDATE' OR TG_TABLE_SCHEMA<>'public' OR TG_RELID<>'public.context_capture'::regclass THEN RAISE EXCEPTION 'invalid cancellation progress source' USING ERRCODE='23514';END IF;
 IF ROW(NEW.snapshot_cancel_requested_at,NEW.snapshot_cancel_joined_at) IS DISTINCT FROM ROW(OLD.snapshot_cancel_requested_at,OLD.snapshot_cancel_joined_at) THEN
  UPDATE public.context_capture SET progress_revision=LEAST(progress_revision+1,1000000001) WHERE root_id=NEW.root_id AND id=NEW.id;
 END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION bump_snapshot_cancel_progress() FROM PUBLIC;

-- +goose StatementBegin
CREATE FUNCTION capacity_apply(r uuid, cluster uuid, namespace_uid text, av text, q jsonb, v jsonb) RETURNS jsonb
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
DECLARE s public.capacity_settings;installation uuid:=(q->'RootBacking'->>'InstallationID')::uuid;i jsonb:=q->'RootBacking';b jsonb:=q->'Backends'->0;
 standing timestamptz:=public.capacity_standing();pool uuid;available bigint;slots bigint;
 retire timestamptz;share bigint;
BEGIN
 IF r IS NULL OR installation IS NULL OR (i->>'RootID')::uuid IS DISTINCT FROM r OR jsonb_array_length(q->'Backends')<>1 OR
  (v->>'EvidenceBytes')::bigint IS NULL OR (v->>'LimitBytes')::bigint IS NULL THEN RAISE EXCEPTION 'capacity settings invalid' USING ERRCODE='23514';END IF;
 PERFORM 1 FROM public.permission_stream WHERE id=r FOR UPDATE;
 SELECT * INTO s FROM public.capacity_settings WHERE root_id=r FOR UPDATE;
 IF NOT FOUND THEN
  pool:=(b->>'PoolID')::uuid;
  INSERT INTO public.custody_pool(id,store_id,revision,valid_until,paused,byte_limit,object_limit)
   VALUES(pool,(b->>'EvidenceStoreID')::uuid,1,standing,false,(v->>'EvidenceBytes')::bigint-(v->>'ReserveBytes')::bigint,1125899906842624);
  retire:=standing+make_interval(secs=>(2*(i->'ProcessingState'->>'BackupHorizonSeconds')::bigint+(i->'ProcessingState'->>'CleanupSeconds')::bigint)::double precision);
  INSERT INTO public.processing_root(root_id,installation_id,issuer_epoch,epoch,source_uid,protection_digest,backing,backing_revision,valid_until,retire_by,max_captures,max_rules,max_root_transitions)
   SELECT r,installation,t.issuer_epoch,(i->>'ProcessingEpoch')::uuid,(i->>'ProcessingSourceUID')::uuid,public.connector_digest(i->'ProcessingProtectionDigest'),
    (i->'ProcessingState')||jsonb_build_object('ValidUntil',standing,'RetireBy',retire),
    1,standing,retire,
    (i->'ProcessingState'->>'MaxCaptures')::bigint,(i->'ProcessingState'->>'MaxRules')::bigint,(i->'ProcessingState'->>'MaxRootTransitions')::bigint
   FROM public.fleet_current_trust t WHERE t.installation_id=installation;
  INSERT INTO public.capacity_settings(root_id,installation_id,account_version,qualification,pool_id,evidence_bytes,reserve_bytes,share_bytes,limit_bytes,namespace_limit_bytes,max_concurrent_expensive,revision)
   VALUES(r,installation,av,q,pool,(v->>'EvidenceBytes')::bigint,(v->>'ReserveBytes')::bigint,NULLIF((v->>'ShareBytes')::bigint,0),(v->>'LimitBytes')::bigint,NULLIF((v->>'NamespaceLimitBytes')::bigint,0),
    (v->>'MaxConcurrentExpensive')::integer,1) RETURNING * INTO s;
  IF q ? 'ContextQuery' THEN PERFORM public.ensure_shared_context_query_capacity(r);END IF;
 ELSE
  available:=(v->>'EvidenceBytes')::bigint-(v->>'ReserveBytes')::bigint;
  PERFORM 1 FROM public.custody_pool WHERE id=s.pool_id FOR UPDATE;
  UPDATE public.capacity_settings SET evidence_bytes=(v->>'EvidenceBytes')::bigint,reserve_bytes=(v->>'ReserveBytes')::bigint,share_bytes=NULLIF((v->>'ShareBytes')::bigint,0),limit_bytes=(v->>'LimitBytes')::bigint,
   namespace_limit_bytes=NULLIF((v->>'NamespaceLimitBytes')::bigint,0),max_concurrent_expensive=(v->>'MaxConcurrentExpensive')::integer,revision=revision+1
   WHERE root_id=r RETURNING * INTO s;
  -- ADR-335 D2/D3: a helm upgrade carries the new share to every enrolled
  -- account. A lower share never drops below the bytes already charged; those
  -- stay used and capacity_charge refuses new charges above the hard limit.
  SELECT count(*) INTO slots FROM public.capacity_account WHERE root_id=r;
  share:=COALESCE(s.share_bytes,available/GREATEST(8,slots));
  UPDATE public.capacity_account SET protected_bytes=share WHERE root_id=r;
  UPDATE public.custody_allocation a SET byte_limit=GREATEST(a.charged_bytes,share)
   FROM public.capacity_account c WHERE c.allocation_id=a.id AND c.root_id=r;
  UPDATE public.custody_pool SET allocated_bytes=(SELECT COALESCE(sum(a.byte_limit),0) FROM public.custody_allocation a WHERE a.pool_id=s.pool_id) WHERE id=s.pool_id;
  UPDATE public.custody_pool SET byte_limit=GREATEST(available,allocated_bytes) WHERE id=s.pool_id;
 END IF;
 RETURN jsonb_build_object('Qualification',s.qualification,'Revision',s.revision);
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION capacity_apply(r uuid, cluster uuid, namespace_uid text, av text, q jsonb, v jsonb) FROM PUBLIC;

-- +goose StatementBegin
CREATE FUNCTION capacity_charge(allocation uuid, bytes bigint, objects bigint) RETURNS boolean
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
DECLARE a public.custody_allocation;s public.capacity_settings;w public.capacity_account;grow bigint;ns bigint;hard bigint;
BEGIN
 SELECT * INTO a FROM public.custody_allocation WHERE id=allocation;
 IF NOT FOUND OR bytes<0 OR objects<0 THEN RETURN false;END IF;
 SELECT * INTO w FROM public.capacity_account WHERE allocation_id=allocation;
 IF FOUND THEN SELECT * INTO STRICT s FROM public.capacity_settings WHERE root_id=w.root_id;PERFORM 1 FROM public.custody_pool WHERE id=a.pool_id FOR UPDATE;END IF;
 SELECT * INTO STRICT a FROM public.custody_allocation WHERE id=allocation FOR UPDATE;
 IF a.charged_objects+objects>a.object_limit THEN RETURN false;END IF;
 IF a.charged_bytes+bytes<=a.byte_limit THEN
  UPDATE public.custody_allocation SET charged_bytes=charged_bytes+bytes,charged_objects=charged_objects+objects WHERE id=allocation;RETURN true;END IF;
 -- The hard limit is the larger of the configured limit and the account's
 -- effective share (specs/capacity.md): a derived share may exceed an
 -- explicit limit, and the protected share is always usable.
 IF w.allocation_id IS NULL THEN RETURN false;END IF;
 hard:=GREATEST(s.limit_bytes,w.protected_bytes);
 IF a.charged_bytes+bytes>hard THEN RETURN false;END IF;
 grow:=a.charged_bytes+bytes-a.byte_limit;
 IF s.namespace_limit_bytes IS NOT NULL THEN
  SELECT COALESCE(sum(x.byte_limit),0) INTO ns FROM public.capacity_account c JOIN public.custody_allocation x ON x.id=c.allocation_id
   WHERE c.root_id=w.root_id AND c.cluster_id=w.cluster_id AND c.namespace_uid=w.namespace_uid;
  IF ns+grow>s.namespace_limit_bytes THEN RETURN false;END IF;
 END IF;
 UPDATE public.custody_pool SET allocated_bytes=allocated_bytes+grow WHERE id=a.pool_id AND allocated_bytes+grow<=byte_limit;
 IF NOT FOUND THEN RETURN false;END IF;
 UPDATE public.custody_allocation SET byte_limit=byte_limit+grow,charged_bytes=charged_bytes+bytes,charged_objects=charged_objects+objects WHERE id=allocation;
 RETURN true;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION capacity_charge(allocation uuid, bytes bigint, objects bigint) FROM PUBLIC;

-- +goose StatementBegin
CREATE FUNCTION capacity_enroll(r uuid, cluster uuid, namespace_id text, workload text, allocation uuid, download uuid, account_digest bytea) RETURNS uuid
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
DECLARE s public.capacity_settings;p public.custody_pool;w public.capacity_account;i jsonb;share bigint;accounts bigint;standing timestamptz:=public.capacity_standing();
 native jsonb;h jsonb;retire timestamptz;ns bigint;
BEGIN
 SELECT * INTO w FROM public.capacity_account WHERE root_id=r AND cluster_id=cluster AND namespace_uid=namespace_id AND workload_uid=workload;
 IF FOUND THEN RETURN w.allocation_id;END IF;
 PERFORM 1 FROM public.permission_stream WHERE id=r FOR UPDATE;
 SELECT * INTO STRICT s FROM public.capacity_settings WHERE root_id=r;
 SELECT * INTO STRICT p FROM public.custody_pool WHERE id=s.pool_id FOR UPDATE;
 SELECT * INTO w FROM public.capacity_account WHERE root_id=r AND cluster_id=cluster AND namespace_uid=namespace_id AND workload_uid=workload;
 IF FOUND THEN RETURN w.allocation_id;END IF;
 IF allocation IS NULL OR download IS NULL OR allocation=download OR octet_length(account_digest)<>32 THEN RAISE EXCEPTION 'capacity enrollment input invalid' USING ERRCODE='23514';END IF;
 SELECT count(*)+1 INTO accounts FROM public.capacity_account WHERE root_id=r;
 share:=COALESCE(s.share_bytes,p.byte_limit/GREATEST(8,accounts));
 IF p.allocated_bytes+share>p.byte_limit THEN
  WITH shrink AS (
   UPDATE public.custody_allocation a SET byte_limit=GREATEST(a.charged_bytes,share)
   FROM public.capacity_account c WHERE c.allocation_id=a.id AND c.root_id=r AND a.byte_limit>GREATEST(a.charged_bytes,share)
   RETURNING a.id, c.protected_bytes)
  UPDATE public.capacity_account c SET protected_bytes=LEAST(c.protected_bytes,GREATEST(share,1)) FROM shrink WHERE c.allocation_id=shrink.id;
  UPDATE public.custody_pool SET allocated_bytes=(SELECT COALESCE(sum(a.byte_limit),0) FROM public.custody_allocation a WHERE a.pool_id=s.pool_id) WHERE id=s.pool_id RETURNING * INTO p;
  IF p.allocated_bytes+share>p.byte_limit THEN RAISE EXCEPTION 'CapacityNotAllocated' USING ERRCODE='23514';END IF;
 END IF;
 IF s.namespace_limit_bytes IS NOT NULL THEN
  SELECT COALESCE(sum(a.byte_limit),0) INTO ns FROM public.capacity_account c JOIN public.custody_allocation a ON a.id=c.allocation_id
   WHERE c.root_id=r AND c.cluster_id=cluster AND c.namespace_uid=namespace_id;
  IF ns+share>s.namespace_limit_bytes THEN RAISE EXCEPTION 'CapacityNotAllocated' USING ERRCODE='23514';END IF;
 END IF;
 i:=s.qualification->'RootBacking';h:=i->'ContextHistory'->'Native';
 UPDATE public.custody_pool SET allocated_bytes=allocated_bytes+share WHERE id=s.pool_id;
 INSERT INTO public.custody_allocation(id,pool_id,scope_id,service_class,revision,valid_until,paused,byte_limit,object_limit)
  VALUES(allocation,s.pool_id,allocation,'context',1,standing,false,share,1099511627776);
 INSERT INTO public.context_storage_binding(root_id,cluster_id,namespace_uid,workload_uid,allocation_id,source_uid,source_generation,source_digest,observed_at,fresh_until)
  VALUES(r,cluster,namespace_id,workload,allocation,'capacity',1,sha256(convert_to('asservat-capacity/'||r::text,'UTF8')),clock_timestamp(),standing);
 INSERT INTO public.download_allocation(id,root_id,cluster_id,namespace_uid,workload_uid,output_limit,read_limit,valid_until)
  VALUES(download,r,cluster,namespace_id,workload,17592186044416,70368744177664,standing);
 INSERT INTO public.download_control_allocation(id,root_id,audit_store_id,window_limit,audit_byte_limit,valid_until,audit_write_until)
  VALUES(download,r,(i->'Capture'->'Policy'->>'StoreID')::uuid,263168,68987912192,standing,standing+interval '30 seconds');
 retire:=standing+make_interval(secs=>(2*(i->'Capture'->'Policy'->>'BackupHorizonSeconds')::bigint+(i->'Capture'->'Policy'->>'CleanupBudgetSeconds')::bigint)::double precision);
 native:=jsonb_build_object('AllocationID',download,'RootID',r,'PolicyID',s.qualification->'ID','PolicyDigest',s.qualification->'Digest',
  'Rows',100000,'Keys',263168,'TransitionsPerRow',267,
  'BackupBytes',2*(h->>'RowBytes')::numeric*(h->>'BackupCopies')::numeric*(100000+263168),
  'WALBytes',(h->>'TransitionWALBytes')::numeric*(h->>'WALCopies')::numeric*((267+4)*100000+8*263168),
  'BackupHorizonSeconds',i->'Capture'->'Policy'->'BackupHorizonSeconds','CleanupSeconds',i->'Capture'->'Policy'->'CleanupBudgetSeconds',
  'ValidUntil',standing,'RetireBy',retire,'History',h);
 INSERT INTO public.download_native_backing(allocation_id,root_id,policy_json,rows_limit,keys_limit,transitions_per_row,backup_horizon_seconds,cleanup_seconds,valid_until,retire_by,residual_until)
  VALUES(download,r,native,100000,263168,267,(native->>'BackupHorizonSeconds')::bigint,(native->>'CleanupSeconds')::bigint,standing,retire,retire);
 INSERT INTO public.capacity_account(allocation_id,download_allocation_id,root_id,cluster_id,namespace_uid,workload_uid,protected_bytes)
  VALUES(allocation,download,r,cluster,namespace_id,workload,share);
 IF s.qualification ? 'ContextQuery' THEN PERFORM public.ensure_shared_context_query_allocation(r,cluster,namespace_id,workload);END IF;
 RETURN allocation;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION capacity_enroll(r uuid, cluster uuid, namespace_id text, workload text, allocation uuid, download uuid, account_digest bytea) FROM PUBLIC;

-- +goose StatementBegin
CREATE FUNCTION capacity_expensive_admits(allocation uuid) RETURNS boolean
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
 SELECT count(*)<COALESCE((SELECT s.max_concurrent_expensive FROM public.capacity_account w JOIN public.capacity_settings s ON s.root_id=w.root_id WHERE w.allocation_id=allocation),2147483647)
 FROM public.custody_attempt a JOIN public.context_capture c ON c.attempt_id=a.id
 WHERE a.allocation_id=allocation AND a.state='reserved' AND a.write_until>clock_timestamp()
  AND convert_from(c.expectation_json,'UTF8')::jsonb ? 'Profile'
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION capacity_expensive_admits(allocation uuid) FROM PUBLIC;

-- +goose StatementBegin
CREATE FUNCTION capacity_json_digest(v jsonb) RETURNS boolean
    LANGUAGE sql IMMUTABLE
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
 SELECT COALESCE(public.connector_digest(v)<>decode(repeat('00',32),'hex'),false)
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION capacity_json_digest(v jsonb) FROM PUBLIC;

-- +goose StatementBegin
CREATE FUNCTION capacity_json_fields(v jsonb, fields text[]) RETURNS boolean
    LANGUAGE sql IMMUTABLE
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
 SELECT COALESCE(jsonb_typeof(v)='object' AND v ?& fields AND (v-fields)='{}'::jsonb,false)
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION capacity_json_fields(v jsonb, fields text[]) FROM PUBLIC;

-- +goose StatementBegin
CREATE FUNCTION capacity_json_integer(v jsonb, lo bigint, hi bigint) RETURNS boolean
    LANGUAGE plpgsql IMMUTABLE
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $_$
BEGIN
 -- Do not let numeric-to-bigint rounding turn a fractional declaration into
 -- a different accepted quantity. JSON strings and missing/null values deny.
 IF jsonb_typeof(v) IS DISTINCT FROM 'number' OR (v#>>'{}') !~ '^(0|[1-9][0-9]*)$' THEN RETURN false;END IF;
 RETURN (v#>>'{}')::bigint BETWEEN lo AND hi;
EXCEPTION WHEN data_exception THEN RETURN false;
END $_$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION capacity_json_integer(v jsonb, lo bigint, hi bigint) FROM PUBLIC;

-- +goose StatementBegin
CREATE FUNCTION capacity_json_text(v jsonb, lo integer, hi integer) RETURNS boolean
    LANGUAGE sql IMMUTABLE
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
 SELECT COALESCE(jsonb_typeof(v)='string' AND octet_length(v#>>'{}') BETWEEN lo AND hi,false)
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION capacity_json_text(v jsonb, lo integer, hi integer) FROM PUBLIC;

-- +goose StatementBegin
CREATE FUNCTION capacity_json_time(v jsonb) RETURNS boolean
    LANGUAGE plpgsql IMMUTABLE
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $_$
DECLARE t timestamptz;
BEGIN
 IF NOT public.capacity_json_text(v,20,40) OR (v#>>'{}')!~'^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,6})?(Z|[+-][0-9]{2}:[0-9]{2})$' THEN RETURN false;END IF;
 t:=(v#>>'{}')::timestamptz;RETURN isfinite(t) AND t<>'0001-01-01 00:00:00+00'::timestamptz;
EXCEPTION WHEN data_exception THEN RETURN false;
END $_$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION capacity_json_time(v jsonb) FROM PUBLIC;

-- +goose StatementBegin
CREATE FUNCTION capacity_json_timestamp(v timestamp with time zone) RETURNS jsonb
    LANGUAGE plpgsql STABLE
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
DECLARE local_value timestamp;fraction text;year_value numeric;
BEGIN
 IF v IS NULL OR NOT isfinite(v) THEN RAISE EXCEPTION 'invalid capacity policy timestamp' USING ERRCODE='23514';END IF;
 local_value:=v AT TIME ZONE 'UTC';year_value:=extract(year FROM local_value);
 IF year_value<1 OR year_value>9999 THEN RAISE EXCEPTION 'invalid capacity policy timestamp' USING ERRCODE='23514';END IF;
 fraction:=rtrim(to_char(local_value,'US'),'0');
 RETURN to_jsonb(to_char(local_value,'YYYY-MM-DD"T"HH24:MI:SS')||CASE WHEN fraction='' THEN '' ELSE '.'||fraction END||'Z');
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION capacity_json_timestamp(v timestamp with time zone) FROM PUBLIC;

-- +goose StatementBegin
CREATE FUNCTION capacity_json_uuid(v jsonb) RETURNS boolean
    LANGUAGE plpgsql IMMUTABLE
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $_$
DECLARE u uuid;
BEGIN
 IF NOT public.capacity_json_text(v,36,36) OR (v#>>'{}')!~'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' THEN RETURN false;END IF;
 u:=(v#>>'{}')::uuid;RETURN u<>'00000000-0000-0000-0000-000000000000'::uuid;
EXCEPTION WHEN data_exception THEN RETURN false;
END $_$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION capacity_json_uuid(v jsonb) FROM PUBLIC;

-- +goose StatementBegin
CREATE FUNCTION capacity_managed_admission_until(r uuid, allocation uuid, kind text, n timestamp with time zone) RETURNS timestamp with time zone
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
 -- A root without capacity settings is unmanaged: its allocations keep their
 -- own byte limits and admission needs no account.
 SELECT 'infinity'::timestamptz WHERE NOT EXISTS(SELECT 1 FROM public.capacity_settings WHERE root_id=r)
 UNION ALL
 SELECT LEAST(a.valid_until,cp.valid_until) FROM public.capacity_account c JOIN public.custody_allocation a ON a.id=c.allocation_id JOIN public.custody_pool cp ON cp.id=a.pool_id
 WHERE c.root_id=r AND CASE WHEN kind='context' THEN c.allocation_id=allocation ELSE c.download_allocation_id=allocation END
  AND NOT a.paused AND NOT cp.paused AND n<a.valid_until AND n<cp.valid_until
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION capacity_managed_admission_until(r uuid, allocation uuid, kind text, n timestamp with time zone) FROM PUBLIC;

-- +goose StatementBegin
CREATE FUNCTION capacity_release(allocation uuid, bytes bigint, objects bigint) RETURNS boolean
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
DECLARE a public.custody_allocation;w public.capacity_account;keep bigint;
BEGIN
 SELECT * INTO a FROM public.custody_allocation WHERE id=allocation;
 IF NOT FOUND THEN RETURN false;END IF;
 SELECT * INTO w FROM public.capacity_account WHERE allocation_id=allocation;
 IF FOUND THEN PERFORM 1 FROM public.custody_pool WHERE id=a.pool_id FOR UPDATE;END IF;
 SELECT * INTO STRICT a FROM public.custody_allocation WHERE id=allocation FOR UPDATE;
 IF a.charged_bytes<bytes OR a.charged_objects<objects OR bytes<0 OR objects<0 THEN RETURN false;END IF;
 keep:=a.byte_limit;
 IF w.allocation_id IS NOT NULL THEN keep:=LEAST(a.byte_limit,GREATEST(w.protected_bytes,a.charged_bytes-bytes));END IF;
 UPDATE public.custody_pool SET allocated_bytes=allocated_bytes-(a.byte_limit-keep) WHERE id=a.pool_id;
 UPDATE public.custody_allocation SET byte_limit=keep,charged_bytes=charged_bytes-bytes,charged_objects=charged_objects-objects WHERE id=allocation;
 RETURN true;
END $$;

SET default_tablespace = '';

SET default_table_access_method = heap;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION capacity_release(allocation uuid, bytes bigint, objects bigint) FROM PUBLIC;

-- +goose StatementBegin
CREATE FUNCTION capacity_session_control(s artifact_download, c download_control_allocation) RETURNS download_control_allocation
    LANGUAGE sql IMMUTABLE
    AS $$ SELECT c $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION capacity_session_native(s artifact_download, b download_native_backing) RETURNS download_native_backing
    LANGUAGE sql IMMUTABLE
    AS $$ SELECT b $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION capacity_standing() RETURNS timestamp with time zone
    LANGUAGE sql IMMUTABLE
    AS $$ SELECT '9970-01-01T00:00:00Z'::timestamptz $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION claim_policy_capture_share() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
DECLARE s jsonb; policy text; src public.policy_source; acc public.policy_acceptance; i jsonb; at timestamptz:=clock_timestamp();
BEGIN
 IF TG_WHEN<>'BEFORE' OR TG_LEVEL<>'ROW' OR TG_OP<>'INSERT' OR TG_TABLE_SCHEMA<>'public' OR TG_RELID<>'public.context_capture'::regclass THEN
  RAISE EXCEPTION 'invalid policy share source' USING ERRCODE='23514';
 END IF;
 IF NEW.share_instruction IS NOT NULL THEN
  RETURN NEW;
 END IF;
 s:=convert_from(NEW.scope_json,'UTF8')::jsonb;
 -- Manual saves never inherit/debit an automatic recurring sharing intent.
 IF s->>'schemaVersion'='recording-save/v1' AND s->>'operation'='recordingSave' THEN RETURN NEW; END IF;
 IF s#>>'{executor,identityType}' IS DISTINCT FROM 'workload' OR s#>>'{executor,clientID}' IS DISTINCT FROM 'policy-executor' OR s#>>'{executor,subject}' NOT LIKE 'policy:%' THEN
  RETURN NEW;
 END IF;
 policy:=substr(s#>>'{executor,subject}',8);
 SELECT * INTO src FROM public.policy_source WHERE root_id=NEW.root_id AND policy_uid=policy;
 IF NOT FOUND OR src.active_id IS NULL OR src.deleted OR src.suspended THEN
  RETURN NEW;
 END IF;
 UPDATE public.policy_acceptance a SET shares_spent=a.shares_spent+1
 WHERE a.id=src.active_id AND a.root_id=NEW.root_id AND a.policy_uid=policy AND a.record ? 'Sharing' AND a.sharing_revoked_at IS NULL AND a.sharing_stopped_at IS NULL
  AND a.generation=src.generation AND (COALESCE((a.record#>>'{Sharing,MaxCaptures}')::integer,0)=0 OR a.shares_spent<(a.record#>>'{Sharing,MaxCaptures}')::integer) AND (a.record#>>'{Sharing,NotAfter}' IS NULL OR (a.record#>>'{Sharing,NotAfter}')::timestamptz>at)
 RETURNING * INTO acc;
 IF NOT FOUND THEN
  RETURN NEW;
 END IF;
 i:=acc.record->'Sharing';
 NEW.share_instruction:=jsonb_build_object(
  'share_id',gen_random_uuid(),
  'creator',jsonb_build_object('issuer',i#>>'{Creator,Issuer}','subject',i#>>'{Creator,Subject}','client',i#>>'{Creator,ClientID}'),
  'management',i->'Management',
  'recipients',(SELECT jsonb_agg(jsonb_build_object('kind',r->>'Kind','issuer',r->>'Issuer','id',r->>'ID') ORDER BY n) FROM jsonb_array_elements(i->'Recipients') WITH ORDINALITY x(r,n)),
  'recipient_keys',(SELECT jsonb_agg((r->>'Kind')||E'\n'||(r->>'Issuer')||E'\n'||(r->>'ID') ORDER BY n) FROM jsonb_array_elements(i->'Recipients') WITH ORDINALITY x(r,n)),
  'not_after',i->'NotAfter',
  'request_digest',encode(sha256(convert_to('policy-share/v1:'||acc.id::text||':'||NEW.id::text,'UTF8')),'hex'),
  'policy_acceptance_id',acc.id);
 RETURN NEW;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION claim_policy_capture_share() FROM PUBLIC;

-- +goose StatementBegin
CREATE FUNCTION connector_digest(v jsonb) RETURNS bytea
    LANGUAGE plpgsql IMMUTABLE
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $_$
DECLARE item record; encoded text:='';
BEGIN
 IF jsonb_typeof(v) IS DISTINCT FROM 'array' OR jsonb_array_length(v)<>32 THEN RAISE EXCEPTION 'invalid connector digest' USING ERRCODE='23514';END IF;
 FOR item IN SELECT value,ordinality FROM jsonb_array_elements_text(v) WITH ORDINALITY LOOP
  IF item.value !~ '^[0-9]{1,3}$' OR item.value::int>255 THEN RAISE EXCEPTION 'invalid connector digest' USING ERRCODE='23514';END IF;
  encoded:=encoded||lpad(to_hex(item.value::int),2,'0');
 END LOOP;
 IF encoded=repeat('0',64) THEN RAISE EXCEPTION 'empty connector digest' USING ERRCODE='23514';END IF;
 RETURN decode(encoded,'hex');
END $_$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION connector_digest(v jsonb) FROM PUBLIC;

-- +goose StatementBegin
CREATE FUNCTION context_packet_query_grant_current(r uuid, qid uuid, batch uuid) RETURNS boolean
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
DECLARE q public.context_query; u public.access_grant_use; grant_operation text;
BEGIN
 SELECT * INTO q FROM public.context_query WHERE root_id=r AND id=qid;
 IF NOT FOUND THEN RETURN false; END IF;
 IF NOT public.context_packet_query_scope_grant_current(r,q.actor,q.query->'Scope',q.query->'Grant') THEN RETURN false; END IF;
 grant_operation:=CASE WHEN q.query#>>'{Scope,DisplayVersion}'='approved-pcap-query/v1' AND q.query#>>'{Scope,NativeType}'='rawPcapng' THEN 'pcap_query'
  WHEN q.query#>>'{Scope,DisplayVersion}'='approved-syscall-query/v1' AND q.query#>>'{Scope,NativeType}'='syscallArguments' THEN 'syscall_query'
  WHEN q.query#>>'{Scope,DisplayVersion}'='approved-logs/v1' AND q.query#>>'{Scope,NativeType}'='logs' THEN 'get_logs' END;
 IF grant_operation IS NULL THEN RETURN true; END IF;
 IF batch IS NULL THEN RETURN true; END IF;
 SELECT * INTO u FROM public.access_grant_use WHERE root_id=r AND id=batch;
 RETURN FOUND AND u.parent_id::text=q.query#>>'{Grant,ParentID}' AND u.child_id::text=q.query#>>'{Grant,ChildID}' AND u.operation=grant_operation AND u.bytes=24576 AND u.operations=1;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION context_packet_query_grant_current(r uuid, qid uuid, batch uuid) FROM PUBLIC;

-- +goose StatementBegin
CREATE FUNCTION context_packet_query_scope_grant_current(r uuid, actor jsonb, s jsonb, binding jsonb) RETURNS boolean
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
DECLARE g public.access_grant; c public.access_grant_child; item jsonb; matched boolean:=false; n timestamptz; grant_operation text;
BEGIN
 grant_operation:=CASE WHEN s->>'DisplayVersion'='approved-pcap-query/v1' AND s->>'NativeType'='rawPcapng' THEN 'pcap_query'
  WHEN s->>'DisplayVersion'='approved-syscall-query/v1' AND s->>'NativeType'='syscallArguments' THEN 'syscall_query'
  WHEN s->>'DisplayVersion'='approved-logs/v1' AND s->>'NativeType'='logs' THEN 'get_logs' END;
 IF grant_operation IS NULL THEN RETURN binding IS NULL AND NOT(s ? 'RawGrantID'); END IF;
 IF NOT public.context_query_scope_source_valid(s) THEN RETURN false; END IF;
 IF NOT public.capacity_json_fields(binding,ARRAY['ParentID','ChildID']) OR NOT public.context_packet_query_uuid(binding->>'ParentID') OR NOT public.context_packet_query_uuid(binding->>'ChildID') OR binding->>'ParentID' IS DISTINCT FROM s->>'RawGrantID' OR actor->>'Kind' IS DISTINCT FROM 'human' THEN RETURN false; END IF;
 SELECT * INTO g FROM public.access_grant WHERE root_id=r AND id=(binding->>'ParentID')::uuid FOR SHARE;
 IF NOT FOUND THEN RETURN false; END IF;
 SELECT * INTO c FROM public.access_grant_child WHERE root_id=r AND id=(binding->>'ChildID')::uuid;
 n:=clock_timestamp();
 IF NOT FOUND OR c.parent_id<>g.id OR c.artifact_id::text IS DISTINCT FROM s->>'ArtifactID' OR c.capture_id::text IS DISTINCT FROM s->>'CaptureID' OR
  to_jsonb(ARRAY(SELECT get_byte(c.artifact_digest,i) FROM generate_series(0,31)i)) IS DISTINCT FROM s->'Version' OR
  g.decision IS DISTINCT FROM 'approved' OR g.revoked_at IS NOT NULL OR NOT COALESCE(n<g.expires_at,false) OR
  g.requester_kind<>'human' OR g.requester_issuer IS DISTINCT FROM actor->>'Issuer' OR g.requester_subject IS DISTINCT FROM actor->>'Subject' OR
  NOT EXISTS(SELECT 1 FROM public.context_case_locator l WHERE l.root_id=r AND l.case_id::text=s->>'CaseID' AND l.capture_id=c.capture_id AND l.artifact_id=c.artifact_id AND l.cluster_id::text=s->>'ClusterID' AND l.namespace_uid=s->>'NamespaceUID' AND l.workload_uid=s->>'WorkloadUID' AND l.pod_uid=s->>'PodUID') THEN RETURN false; END IF;
 IF g.kind='adHocCapture' THEN
  RETURN COALESCE((g.capture_id=c.capture_id OR EXISTS(
   SELECT 1 FROM public.context_capture member
   JOIN public.context_case_locator l ON l.root_id=member.root_id AND l.capture_id=member.id AND l.artifact_id=c.artifact_id
   JOIN public.context_catalog verified ON verified.root_id=member.root_id AND verified.capture_id=member.id AND verified.copies_digest=c.artifact_digest
   JOIN public.recording_save_group rg ON rg.root_id=member.root_id AND rg.id=member.group_id
   WHERE member.root_id=r AND member.id=c.capture_id AND rg.id=g.capture_id AND rg.scope_digest=g.execution_digest AND
   convert_from(member.expectation_json,'UTF8')::jsonb->>'ActionID'=c.action_id AND rg.group_kind='composition' AND member.group_ordinal>=0 AND cardinality(rg.child_ids) BETWEEN 2 AND 16 AND rg.child_ids[member.group_ordinal+1]=member.id AND
 member.created_at=rg.accepted_at AND member.deadline<=rg.deadline AND sha256(member.scope_json)=member.scope_digest AND sha256(rg.scope_json)=rg.scope_digest AND
 convert_from(rg.scope_json,'UTF8')::jsonb->>'schemaVersion'='recorder-group/v1' AND
 convert_from(rg.scope_json,'UTF8')::jsonb->'children'->member.group_ordinal->>'captureID'=member.id::text AND
 convert_from(rg.scope_json,'UTF8')::jsonb->'children'->member.group_ordinal->>'scopeDigest'=encode(member.scope_digest,'hex') AND
 convert_from(rg.scope_json,'UTF8')::jsonb->'children'->member.group_ordinal->>'actionID'=convert_from(member.expectation_json,'UTF8')::jsonb->>'ActionID' AND
 convert_from(member.expectation_json,'UTF8')::jsonb#>>'{Registration,Location,ArtifactID}'=l.artifact_id::text AND
 convert_from(member.expectation_json,'UTF8')::jsonb#>>'{CompositionGroup,ParentCaptureID}'=rg.id::text AND
 (convert_from(member.expectation_json,'UTF8')::jsonb#>>'{CompositionGroup,ChildIndex}')::integer=member.group_ordinal AND
 (convert_from(member.expectation_json,'UTF8')::jsonb#>>'{CompositionGroup,ChildCount}')::integer=cardinality(rg.child_ids))) AND g.result_access->'operations' ? grant_operation AND g.result_access->'actionIDs' ? c.action_id AND g.cluster_id::text=s->>'ClusterID' AND g.namespace_uid=s->>'NamespaceUID' AND g.workload_uid=s->>'WorkloadUID' AND g.pod_uid=s->>'PodUID',false);
 ELSIF g.kind='rawQuery' THEN
  IF g.raw_query->>'CaseID' IS DISTINCT FROM s->>'CaseID' OR NOT(g.raw_query->'Operations' ? grant_operation) THEN RETURN false; END IF;
  FOR item IN SELECT jsonb_array_elements(g.raw_query->'Artifacts') LOOP
   IF COALESCE(item#>>'{Output,ArtifactID}'=c.artifact_id::text AND item#>>'{Output,CaptureID}'=c.capture_id::text AND item#>>'{Output,ActionID}'=c.action_id AND item#>'{Output,ArtifactDigest}'=s->'Version' AND
     item#>>'{Output,Target,ClusterID}'=s->>'ClusterID' AND item#>>'{Output,Target,NamespaceUID}'=s->>'NamespaceUID' AND item#>>'{Output,Target,WorkloadUID}'=s->>'WorkloadUID' AND item#>>'{Output,Target,PodUID}'=s->>'PodUID' AND n<(item->>'ExpiresAt')::timestamptz,false) THEN matched:=true; END IF;
  END LOOP;
  RETURN matched;
 END IF;
 RETURN false;
EXCEPTION WHEN invalid_text_representation OR numeric_value_out_of_range OR datetime_field_overflow THEN RETURN false;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION context_packet_query_scope_grant_current(r uuid, actor jsonb, s jsonb, binding jsonb) FROM PUBLIC;

-- +goose StatementBegin
CREATE FUNCTION context_packet_query_uuid(v text) RETURNS boolean
    LANGUAGE sql IMMUTABLE
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $_$
 SELECT COALESCE(v~'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' AND v<>'00000000-0000-0000-0000-000000000000',false)
$_$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION context_packet_query_uuid(v text) FROM PUBLIC;

-- +goose StatementBegin
CREATE FUNCTION context_packet_query_window_valid(w jsonb, native text) RETURNS boolean
    LANGUAGE plpgsql IMMUTABLE
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
DECLARE i integer; f text; seen text[]:=ARRAY[]::text[]; ins jsonb; code bigint; k bigint; program bytea:=''::bytea; d bytea;
BEGIN
 IF NOT public.capacity_json_fields(w,ARRAY['Fields','FieldCount','Instructions','ProgramCount','CompilerDigest','ProgramDigest','StartTime','EndTime','HasStart','HasEnd','TCPMask','TCPValue','PrefixOffset','PrefixLength','MaxPackets','MaxScanBytes']) OR
  NOT public.capacity_json_integer(w->'FieldCount',1,32) OR NOT public.capacity_json_integer(w->'ProgramCount',0,256) OR
  NOT public.capacity_json_integer(w->'MaxPackets',1,100) OR NOT public.capacity_json_integer(w->'MaxScanBytes',1,1073741824) OR
  jsonb_typeof(w->'Fields') IS DISTINCT FROM 'array' OR jsonb_array_length(w->'Fields')<>32 OR
  jsonb_typeof(w->'Instructions') IS DISTINCT FROM 'array' OR jsonb_array_length(w->'Instructions')<>256 OR
  jsonb_typeof(w->'HasStart') IS DISTINCT FROM 'boolean' OR jsonb_typeof(w->'HasEnd') IS DISTINCT FROM 'boolean' OR
  NOT public.capacity_json_integer(w->'TCPMask',0,511) OR NOT public.capacity_json_integer(w->'TCPValue',0,511) OR
  ((w->>'TCPValue')::integer & ~(w->>'TCPMask')::integer)<>0 OR
  NOT public.capacity_json_integer(w->'PrefixOffset',0,65535) OR NOT public.capacity_json_integer(w->'PrefixLength',0,64) OR
  (w->>'PrefixOffset')::bigint+(w->>'PrefixLength')::bigint>1500 THEN RETURN false; END IF;
 FOR i IN 0..31 LOOP
  IF jsonb_typeof(w->'Fields'->i) IS DISTINCT FROM 'string' THEN RETURN false; END IF;
  f:=w->'Fields'->>i;
  IF i<(w->>'FieldCount')::integer THEN
   IF f<>ALL(ARRAY['packet_index','packet_time','captured_length','wire_length','source_address','destination_address','source_port','destination_port','protocol','tcp_flags','tcp_seq','tcp_ack','tcp_window','icmp_type','icmp_code','frame_prefix_hex']) OR f=ANY(seen) THEN RETURN false; END IF;
   seen:=array_append(seen,f);
  ELSIF f<>'' THEN RETURN false; END IF;
 END LOOP;
 IF ('frame_prefix_hex'=ANY(seen)) IS DISTINCT FROM ((w->>'PrefixLength')::integer>0) OR
  (NOT('frame_prefix_hex'=ANY(seen)) AND (w->>'PrefixOffset')::integer<>0) OR
  (native<>'rawPcapng' AND (w->>'PrefixLength')::integer<>0) THEN RETURN false; END IF;
 IF NOT (w->>'HasStart')::boolean AND w->>'StartTime'<>'0001-01-01T00:00:00Z' OR
    NOT (w->>'HasEnd')::boolean AND w->>'EndTime'<>'0001-01-01T00:00:00Z' OR
    (w->>'HasStart')::boolean AND (NOT isfinite((w->>'StartTime')::timestamptz) OR (w->>'StartTime')::timestamptz='0001-01-01T00:00:00Z'::timestamptz) OR
    (w->>'HasEnd')::boolean AND (NOT isfinite((w->>'EndTime')::timestamptz) OR (w->>'EndTime')::timestamptz='0001-01-01T00:00:00Z'::timestamptz) OR
    (w->>'HasStart')::boolean AND (w->>'HasEnd')::boolean AND (w->>'EndTime')::timestamptz<=(w->>'StartTime')::timestamptz THEN RETURN false; END IF;
 FOR i IN 0..255 LOOP
  ins:=w->'Instructions'->i;
  IF NOT public.capacity_json_fields(ins,ARRAY['Code','Jt','Jf','K']) OR NOT public.capacity_json_integer(ins->'Code',0,65535) OR
   NOT public.capacity_json_integer(ins->'Jt',0,255) OR NOT public.capacity_json_integer(ins->'Jf',0,255) OR NOT public.capacity_json_integer(ins->'K',0,4294967295) THEN RETURN false; END IF;
  IF i>=(w->>'ProgramCount')::integer THEN
   IF ins<>'{"Code":0,"Jt":0,"Jf":0,"K":0}'::jsonb THEN RETURN false; END IF;
  ELSE
   code:=(ins->>'Code')::bigint; k:=(ins->>'K')::bigint;
   program:=program || decode(lpad(to_hex(code&255),2,'0')||lpad(to_hex((code>>8)&255),2,'0')||lpad(to_hex((ins->>'Jt')::integer),2,'0')||lpad(to_hex((ins->>'Jf')::integer),2,'0')||lpad(to_hex(k&255),2,'0')||lpad(to_hex((k>>8)&255),2,'0')||lpad(to_hex((k>>16)&255),2,'0')||lpad(to_hex((k>>24)&255),2,'0'),'hex');
  END IF;
 END LOOP;
 IF (w->>'ProgramCount')::integer=0 THEN RETURN w->'CompilerDigest'=to_jsonb(array_fill(0,ARRAY[32])) AND w->'ProgramDigest'=to_jsonb(array_fill(0,ARRAY[32])); END IF;
 d:=decode('9237f5bae9dcf3a91823d9963ec43b7c0e2e3374ef2ad57d92c8cd39530f4723','hex');
 IF w->'CompilerDigest' IS DISTINCT FROM to_jsonb(ARRAY(SELECT get_byte(d,digest_byte.ordinal) FROM generate_series(0,31) AS digest_byte(ordinal))) THEN RETURN false; END IF;
 d:=sha256(program);
 RETURN w->'ProgramDigest'=to_jsonb(ARRAY(SELECT get_byte(d,digest_byte.ordinal) FROM generate_series(0,31) AS digest_byte(ordinal)));
EXCEPTION WHEN invalid_text_representation OR numeric_value_out_of_range OR datetime_field_overflow THEN RETURN false;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION context_packet_query_window_valid(w jsonb, native text) FROM PUBLIC;

-- +goose StatementBegin
CREATE FUNCTION context_query_begin_tool(s jsonb) RETURNS text
    LANGUAGE sql IMMUTABLE
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
 SELECT CASE WHEN s->>'DisplayVersion'='approved-processes/v1' THEN 'get_target_discovery' WHEN s->>'DisplayVersion'='approved-logs/v1' THEN 'get_logs' WHEN s->>'DisplayVersion'='approved-syscall-query/v1' THEN 'syscall_query' WHEN s->>'DisplayVersion'='approved-pcap-query/v1' THEN 'pcap_query' WHEN s->>'NativeType' IN ('pcapng','rawPcapng') THEN 'get_pcap_summary' WHEN s ? 'Comparison' THEN 'compare_profiles' WHEN s->>'NativeType' IN ('syscallRecords','syscallArguments') THEN CASE s->'Syscalls'->>'View' WHEN 'summary' THEN 'get_syscall_summary' WHEN 'events' THEN 'get_syscall_events' ELSE NULL END WHEN s->>'NativeType'='httpHeaders' THEN 'get_http_headers' WHEN s->>'NativeType'='pprof' THEN 'get_profile_summary' ELSE 'get_file_excerpt' END
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION context_query_begin_tool(s jsonb) FROM PUBLIC;

-- +goose StatementBegin
CREATE FUNCTION context_query_capacity_allocation_current(r uuid, allocation uuid) RETURNS boolean
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
DECLARE a public.context_query_allocation;b public.context_query_backing;c public.context_query_capacity;
BEGIN
 SELECT * INTO STRICT c FROM public.context_query_capacity WHERE root_id=r;
 SELECT * INTO STRICT b FROM public.context_query_backing WHERE root_id=r;
 SELECT * INTO STRICT a FROM public.context_query_allocation WHERE root_id=r AND id=allocation;
 RETURN COALESCE(NOT b.suspended AND a.query_limit=(c.plan->'Qualification'->>'WorkloadQueries')::bigint AND clock_timestamp()<b.hard_until,false);
EXCEPTION WHEN data_exception OR no_data_found OR too_many_rows THEN RETURN false;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION context_query_capacity_allocation_current(r uuid, allocation uuid) FROM PUBLIC;

-- +goose StatementBegin
CREATE FUNCTION context_query_comparison_source(s jsonb, baseline boolean) RETURNS jsonb
    LANGUAGE sql IMMUTABLE
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
 SELECT jsonb_set((s-'Comparison') || CASE WHEN baseline THEN s#>'{Comparison,Baseline}' ELSE '{}'::jsonb END,'{DisplayVersion}','"approved-pprof-summary/v1"'::jsonb)
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION context_query_comparison_source(s jsonb, baseline boolean) FROM PUBLIC;

-- +goose StatementBegin
CREATE FUNCTION context_query_complete_object(j jsonb, required text[]) RETURNS boolean
    LANGUAGE sql IMMUTABLE
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
 SELECT COALESCE(jsonb_typeof(j)='object' AND NOT EXISTS(SELECT 1 FROM unnest(required) k WHERE j->k IS NULL OR j->k='null'::jsonb),false)
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION context_query_complete_object(j jsonb, required text[]) FROM PUBLIC;

-- +goose StatementBegin
CREATE FUNCTION context_query_cost_valid(p jsonb) RETURNS boolean
    LANGUAGE plpgsql IMMUTABLE
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
DECLARE c jsonb:=p->'Cost'; k text; n numeric;
BEGIN
 IF NOT COALESCE(jsonb_typeof(c)='object' AND
  c->>'Workers'='1' AND c->>'ReadBatches'='2' AND c->>'ReadBytes'='8388608' AND
  c->>'StructuredBytes'='49152' AND c->>'WireBytes'='131072' AND c->>'UnwrapAttempts'='6',false) THEN RETURN false; END IF;
 FOREACH k IN ARRAY ARRAY['ProviderRequests','AuthenticationRequests','SigningAttempts','AuditObjects','SQLRows','SQLBytes','WALBytes','BackupBytes'] LOOP
  n:=(c->>k)::numeric;
  IF n IS NULL OR n<1 OR n>1152921504606846976 OR trunc(n)<>n THEN RETURN false; END IF;
 END LOOP;
 RETURN COALESCE((c->>'ProviderRequests')::bigint>=6 AND
  (p->>'PollLimit')::bigint BETWEEN 1 AND 1000000 AND (p->>'ControlTransitionLimit')::bigint BETWEEN 1 AND 1000000 AND
  (c->>'SQLRows')::numeric>=8+(p->>'PollLimit')::numeric AND
  (c->>'AuditObjects')::numeric>=2*(1+(p->>'PollLimit')::numeric) AND
  (p->>'Lifetime')::numeric BETWEEN 1 AND 60000000000 AND p->'Path'->>'Purpose'='context-projection/v1',false);
EXCEPTION WHEN invalid_text_representation OR numeric_value_out_of_range THEN RETURN false;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION context_query_cost_valid(p jsonb) FROM PUBLIC;

-- +goose StatementBegin
CREATE FUNCTION context_query_intent_current(r uuid, op uuid, actor jsonb, epoch uuid, call jsonb) RETURNS boolean
    LANGUAGE sql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
 SELECT COALESCE(call->>'ID'=op::text AND call->>'RootID'=r::text AND call->'Principal'=actor
 AND call->>'Tool' IN ('get_file_excerpt','get_http_headers','get_profile_summary','get_pcap_summary','pcap_query','syscall_query','get_logs','compare_profiles','get_syscall_summary','get_syscall_events','get_query_result')
 AND (call->>'StartedAt')::timestamptz<=clock_timestamp() AND clock_timestamp()<(call->>'Until')::timestamptz
 AND EXISTS(SELECT 1 FROM public.fleet_current_trust t WHERE t.issuer_epoch=epoch
  AND NOT t.suspended AND t.observed_at<=clock_timestamp() AND clock_timestamp()<t.fresh_until),false)
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION context_query_intent_current(r uuid, op uuid, actor jsonb, epoch uuid, call jsonb) FROM PUBLIC;

-- +goose StatementBegin
CREATE FUNCTION context_query_read_batches(s jsonb) RETURNS integer
    LANGUAGE sql IMMUTABLE
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
 SELECT CASE WHEN s->>'DisplayVersion'='approved-processes/v1' THEN 1 WHEN s->>'DisplayVersion'='approved-logs/v1' THEN 2 WHEN s->>'DisplayVersion'='approved-syscall-query/v1' THEN 2 WHEN s->>'DisplayVersion'='approved-pcap-query/v1' THEN 2 WHEN s->>'NativeType' IN ('httpHeaders','pprof','syscallRecords','syscallArguments','pcapng','rawPcapng') THEN 1 ELSE 2 END
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION context_query_read_batches(s jsonb) FROM PUBLIC;

-- +goose StatementBegin
CREATE FUNCTION context_query_scope_source_valid(s jsonb) RETURNS boolean
    LANGUAGE plpgsql IMMUTABLE
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $_$
DECLARE w jsonb:=s->'Comparison'; b jsonb:=w->'Baseline'; k text; i integer;
BEGIN
 IF s->>'DisplayVersion'='approved-processes/v1' THEN
  RETURN COALESCE(s->>'NativeType'='processes' AND s->>'SourceFormat'='asservat-processes/v1' AND
   NOT(s ? 'Headers') AND NOT(s ? 'Profile') AND NOT(s ? 'Syscalls') AND NOT(s ? 'Logs') AND NOT(s ? 'Comparison') AND NOT(s ? 'PacketQuery') AND NOT(s ? 'RawGrantID') AND
   s->'Selection'='{"LineStart":0,"MaxLines":0}'::jsonb AND s->'SourceProjectionDigest'=to_jsonb(array_fill(0,ARRAY[32])) AND
   public.capacity_json_fields(s->'Discovery',ARRAY['Section','Start','Limit','Binding']) AND
   s#>>'{Discovery,Section}' IN ('summary','processes') AND
   public.capacity_json_integer(s#>'{Discovery,Start}',0,256) AND public.capacity_json_integer(s#>'{Discovery,Limit}',1,100) AND
   jsonb_typeof(s#>'{Discovery,Binding}')='string' AND
   ((s#>>'{Discovery,Start}'='0' AND s#>>'{Discovery,Binding}'='') OR
    (s#>>'{Discovery,Start}'<>'0' AND s#>>'{Discovery,Binding}'~'^[0-9a-f]{32}$')) AND
   (s#>>'{Discovery,Section}'<>'summary' OR s#>>'{Discovery,Start}'='0'),false);
 END IF;
 IF s ? 'Discovery' OR s->>'NativeType'='processes' THEN RETURN false; END IF;
 IF s->>'DisplayVersion'='approved-logs/v1' THEN
  RETURN COALESCE(s->>'NativeType'='logs' AND s->>'SourceFormat'='asservat-logs/v1' AND
   public.context_packet_query_uuid(s->>'RawGrantID') AND
   NOT(s ? 'Headers') AND NOT(s ? 'Profile') AND NOT(s ? 'Syscalls') AND NOT(s ? 'Comparison') AND NOT(s ? 'PacketQuery') AND
   s->'Selection'='{"LineStart":0,"MaxLines":0}'::jsonb AND s->'SourceProjectionDigest'=to_jsonb(array_fill(0,ARRAY[32])) AND
   public.capacity_json_fields(s->'Logs',ARRAY['Fragment','Offset','Limit','Binding']) AND
   public.capacity_json_integer(s#>'{Logs,Fragment}',0,67108863) AND public.capacity_json_integer(s#>'{Logs,Offset}',0,4095) AND
   public.capacity_json_integer(s#>'{Logs,Limit}',1,100) AND jsonb_typeof(s#>'{Logs,Binding}')='string' AND
   ((s#>>'{Logs,Fragment}'='0' AND s#>>'{Logs,Offset}'='0' AND s#>>'{Logs,Binding}'='') OR
    ((s#>>'{Logs,Fragment}'<>'0' OR s#>>'{Logs,Offset}'<>'0') AND s#>>'{Logs,Binding}'~'^[0-9a-f]{32}$')),false);
 END IF;
 IF s ? 'Logs' OR s->>'NativeType'='logs' THEN RETURN false; END IF;
 IF s->>'DisplayVersion'='approved-syscall-query/v1' THEN
  RETURN COALESCE(s->>'NativeType'='syscallArguments' AND s->>'SourceFormat'='asservat-syscall-arguments/v1' AND
   public.context_packet_query_uuid(s->>'RawGrantID') AND s#>>'{Syscalls,View}'='raw' AND NOT(s ? 'PacketQuery') AND
   public.context_query_scope_source_valid_legacy133(jsonb_set((s-'RawGrantID') || jsonb_build_object('DisplayVersion','approved-syscall-events/v1'),'{Syscalls,View}','"events"'::jsonb)),false);
 END IF;
 IF s->>'DisplayVersion'='approved-pcap-query/v1' THEN
  RETURN COALESCE(s->>'NativeType' IN ('pcapng','rawPcapng') AND
   ((s->>'NativeType'='pcapng' AND s->>'SourceFormat'='pcapng' AND NOT(s ? 'RawGrantID')) OR
    (s->>'NativeType'='rawPcapng' AND s->>'SourceFormat'='pcapng-raw' AND public.context_packet_query_uuid(s->>'RawGrantID'))) AND
   NOT(s ? 'Headers') AND NOT(s ? 'Profile') AND NOT(s ? 'Syscalls') AND NOT(s ? 'Comparison') AND
   s->'Selection'='{"LineStart":0,"MaxLines":0}'::jsonb AND s->'SourceProjectionDigest'=to_jsonb(array_fill(0,ARRAY[32])) AND
   public.context_packet_query_window_valid(s->'PacketQuery',s->>'NativeType'),false);
 END IF;
 IF s ? 'PacketQuery' OR s ? 'RawGrantID' THEN RETURN false; END IF;
 -- The two fixed saved-packet summaries keep distinct source/display identities.
 IF s->>'NativeType' IN ('pcapng','rawPcapng') THEN
  RETURN COALESCE(NOT (s ? 'Headers') AND NOT (s ? 'Profile') AND NOT (s ? 'Syscalls') AND NOT (s ? 'Comparison') AND
   ((s->>'NativeType'='pcapng' AND s->>'SourceFormat'='pcapng' AND s->>'DisplayVersion'='approved-pcap-summary/v1') OR (s->>'NativeType'='rawPcapng' AND s->>'SourceFormat'='pcapng-raw' AND s->>'DisplayVersion'='approved-raw-pcap-summary/v1')) AND
   s->'Selection'='{"LineStart":0,"MaxLines":0}'::jsonb AND s->'SourceProjectionDigest'=to_jsonb(array_fill(0,ARRAY[32])),false);
 END IF;
 IF NOT (s ? 'Comparison') THEN RETURN public.context_query_scope_source_valid_legacy133(s); END IF;
 IF NOT COALESCE(s->>'NativeType'='pprof' AND s->>'DisplayVersion'='approved-pprof-comparison/v1' AND
  public.capacity_json_fields(w,ARRAY['Normalization','Baseline']) AND w->>'Normalization' IN ('none','perSecond') AND
  public.capacity_json_fields(b,ARRAY['CaseID','ArtifactID','CaptureID','ClusterID','NamespaceUID','WorkloadUID','PodUID','Version']) AND
  public.context_query_scope_source_valid_legacy133(public.context_query_comparison_source(s,false)) AND
  public.context_query_scope_source_valid_legacy133(public.context_query_comparison_source(s,true)),false) THEN RETURN false; END IF;
 FOREACH k IN ARRAY ARRAY['CaseID','ArtifactID','CaptureID','ClusterID'] LOOP
  IF jsonb_typeof(b->k) IS DISTINCT FROM 'string' OR (b->>k)='00000000-0000-0000-0000-000000000000' OR (b->>k)!~'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' THEN RETURN false; END IF;
 END LOOP;
 FOREACH k IN ARRAY ARRAY['NamespaceUID','WorkloadUID','PodUID'] LOOP
  IF jsonb_typeof(b->k) IS DISTINCT FROM 'string' OR octet_length(b->>k) NOT BETWEEN 1 AND 64 OR (b->>k)~'[[:cntrl:]]' THEN RETURN false; END IF;
 END LOOP;
 IF jsonb_typeof(b->'Version') IS DISTINCT FROM 'array' OR jsonb_array_length(b->'Version')<>32 OR b->'Version'=to_jsonb(array_fill(0,ARRAY[32])) THEN RETURN false; END IF;
 FOR i IN 0..31 LOOP IF NOT public.capacity_json_integer(b->'Version'->i,0,255) THEN RETURN false; END IF; END LOOP;
 IF b->>'ArtifactID'=s->>'ArtifactID' AND public.context_query_comparison_source(s,true) IS DISTINCT FROM public.context_query_comparison_source(s,false) THEN RETURN false; END IF;
 RETURN true;
END $_$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION context_query_scope_source_valid(s jsonb) FROM PUBLIC;

-- +goose StatementBegin
CREATE FUNCTION context_query_scope_source_valid_legacy133(s jsonb) RETURNS boolean
    LANGUAGE plpgsql IMMUTABLE
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $_$
DECLARE w jsonb:=s->'Syscalls'; n integer; i integer; name text; previous text;
BEGIN
 IF s ? 'Comparison' THEN RETURN false; END IF;
 IF s->>'NativeType' IN ('syscallRecords','syscallArguments') THEN
  IF NOT COALESCE(NOT (s ? 'Headers') AND NOT (s ? 'Profile') AND
   s->'Selection'='{"LineStart":0,"MaxLines":0}'::jsonb AND s->'SourceProjectionDigest'=to_jsonb(array_fill(0,ARRAY[32])) AND
   s->>'SourceFormat'=CASE s->>'NativeType' WHEN 'syscallRecords' THEN 'asservat-syscall-events/v1' ELSE 'asservat-syscall-arguments/v1' END AND
   public.capacity_json_fields(w,ARRAY['View','Start','Limit','Binding','Names','NameCount','ErrorsOnly']) AND
   w->>'View' IN ('summary','events') AND s->>'DisplayVersion'=CASE w->>'View' WHEN 'summary' THEN 'approved-syscall-summary/v1' WHEN 'events' THEN 'approved-syscall-events/v1' END AND
   public.capacity_json_integer(w->'Start',0,999999) AND public.capacity_json_integer(w->'Limit',1,100) AND
   public.capacity_json_integer(w->'NameCount',0,64) AND jsonb_typeof(w->'Binding')='string' AND jsonb_typeof(w->'ErrorsOnly')='boolean' AND jsonb_typeof(w->'Names')='array',false)
   THEN RETURN false; END IF;
  IF jsonb_array_length(w->'Names')<>64 THEN RETURN false; END IF;
  IF NOT ((w->>'Start'='0' AND w->>'Binding'='') OR (w->>'Start'<>'0' AND w->>'Binding'~'^[0-9a-f]{32}$')) THEN RETURN false; END IF;
  n:=(w->>'NameCount')::integer;
  IF w->>'View'='summary' AND (n<>0 OR (w->>'ErrorsOnly')::boolean) THEN RETURN false; END IF;
  FOR i IN 0..63 LOOP
   IF jsonb_typeof(w->'Names'->i) IS DISTINCT FROM 'string' THEN RETURN false; END IF;
   name:=w->'Names'->>i;
   IF i<n THEN
    IF char_length(name) NOT BETWEEN 1 AND 64 OR previous COLLATE "C">=name COLLATE "C" THEN RETURN false; END IF;
    previous:=name;
   ELSIF name<>'' THEN RETURN false;
   END IF;
  END LOOP;
  RETURN true;
 END IF;
 IF s ? 'Syscalls' THEN RETURN false; END IF;
 RETURN COALESCE(CASE WHEN NOT (s ? 'NativeType') THEN NOT (s ? 'Headers') AND NOT (s ? 'Profile') AND s->>'SourceFormat'='asservat-pod-status/v1' AND s->>'DisplayVersion'='approved-pod-status-display/v1'
  WHEN s->>'NativeType'='httpHeaders' THEN NOT (s ? 'Profile') AND jsonb_typeof(s->'Headers')='object' AND (s->'Headers'->>'Limit')::integer BETWEEN 1 AND 100 AND (s->'Headers'->>'Start')::integer BETWEEN 0 AND 32759 AND
   s->>'SourceFormat'='http-response-headers/v1' AND s->>'DisplayVersion'='approved-http-headers-page/v1' AND s->'Selection'='{"LineStart":0,"MaxLines":0}'::jsonb
  WHEN s->>'NativeType'='pprof' THEN NOT (s ? 'Headers') AND public.capacity_json_fields(s->'Profile',ARRAY['SampleType','TopN']) AND
   jsonb_typeof(s->'Profile'->'SampleType')='string' AND octet_length(s->'Profile'->>'SampleType') BETWEEN 1 AND 64 AND (s->'Profile'->>'SampleType') !~ '[[:cntrl:]]' AND
   public.capacity_json_integer(s->'Profile'->'TopN',1,100) AND s->>'SourceFormat'='pprof' AND s->>'DisplayVersion'='approved-pprof-summary/v1' AND
   s->'Selection'='{"LineStart":0,"MaxLines":0}'::jsonb AND s->'SourceProjectionDigest'=to_jsonb(array_fill(0,ARRAY[32]))
  ELSE false END,false);
END $_$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION context_query_scope_source_valid_legacy133(s jsonb) FROM PUBLIC;

-- +goose StatementBegin
CREATE FUNCTION context_query_shared_profile_current(r uuid, p jsonb) RETURNS boolean
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
DECLARE s public.context_query_backing;t public.fleet_current_trust;h public.download_worker_configuration;v public.download_worker_configuration_revision;path jsonb:=p->'Path';profile jsonb;snapshot jsonb;n timestamptz;
BEGIN
 SELECT * INTO STRICT s FROM public.context_query_backing WHERE root_id=r;
 SELECT * INTO STRICT t FROM public.fleet_current_trust WHERE installation_id=s.installation_id FOR SHARE;
 SELECT * INTO STRICT h FROM public.download_worker_configuration WHERE installation_id=s.installation_id AND cluster_id=(path->>'AcquisitionClusterID')::uuid AND source_uid=(path->'WorkerConfiguration'->>'UID')::uuid FOR SHARE;
 SELECT * INTO STRICT v FROM public.download_worker_configuration_revision WHERE installation_id=h.installation_id AND cluster_id=h.cluster_id AND source_uid=h.source_uid AND generation=h.generation;
 snapshot:=convert_from(v.snapshot_json,'UTF8')::jsonb;profile:=snapshot->'Profile';n:=clock_timestamp();
 RETURN COALESCE(NOT t.suspended AND t.observed_at<=n AND n<t.fresh_until AND
 h.observed_at<=n AND n<h.fresh_until AND NOT (snapshot->>'Suspended')::boolean AND snapshot->>'RecoveryEpoch'=t.issuer_epoch::text AND
 v.audit_receipt_json IS NOT NULL AND profile->'Configuration'=path->'WorkerConfiguration' AND profile->>'InstallationID'=s.installation_id::text AND profile->>'ClusterID'=path->>'AcquisitionClusterID' AND
 profile->>'StoreCredentialSecret'<>'' AND (profile->>'CPUMillis')::numeric=(p->'Worker'->>'CPUMilli')::numeric AND (profile->>'MemoryBytes')::numeric=(p->'Worker'->>'MemoryBytes')::numeric AND
 (p->'Worker'->>'EphemeralStorageBytes')::numeric=4194304 AND (p->'Worker'->>'Runtime')::numeric<=(profile->>'MaxRuntime')::numeric AND
 path->>'Purpose'='context-projection/v1' AND path->>'ConnectorClusterID'=path->>'AcquisitionClusterID' AND clock_timestamp()<LEAST(t.fresh_until,h.fresh_until),false);
EXCEPTION WHEN data_exception OR no_data_found OR too_many_rows THEN RETURN false;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION context_query_shared_profile_current(r uuid, p jsonb) FROM PUBLIC;

-- +goose StatementBegin
CREATE FUNCTION context_query_units(s jsonb) RETURNS integer
    LANGUAGE sql IMMUTABLE
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
 SELECT CASE WHEN s->>'DisplayVersion'='approved-processes/v1' THEN 2 WHEN s->>'DisplayVersion'='approved-logs/v1' THEN 20 WHEN s->>'DisplayVersion'='approved-syscall-query/v1' THEN 4 WHEN s->>'DisplayVersion'='approved-pcap-query/v1' THEN 4 WHEN s ? 'Comparison' THEN 20 WHEN s->>'NativeType' IN ('httpHeaders','syscallRecords','syscallArguments','pcapng','rawPcapng') THEN 2 WHEN s->>'NativeType'='pprof' THEN 10 ELSE 1 END
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION context_query_units(s jsonb) FROM PUBLIC;

-- +goose StatementBegin
CREATE FUNCTION ensure_shared_context_query_allocation(r uuid, cluster uuid, namespace_id text, workload text) RETURNS void
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
DECLARE c public.context_query_capacity;b public.context_query_backing;s public.capacity_settings;limit_value bigint;identity jsonb;
BEGIN
 SELECT * INTO c FROM public.context_query_capacity WHERE root_id=r;
 IF NOT FOUND OR EXISTS(SELECT 1 FROM public.context_query_allocation WHERE root_id=r AND cluster_id=cluster AND namespace_uid=namespace_id AND workload_uid=workload) THEN RETURN;END IF;
 SELECT * INTO STRICT s FROM public.capacity_settings WHERE root_id=r;
 SELECT * INTO STRICT b FROM public.context_query_backing WHERE root_id=r FOR UPDATE;
 limit_value:=(c.plan->'Qualification'->>'WorkloadQueries')::bigint;
 IF (b.allocations+1)::numeric*limit_value>b.query_limit OR b.allocations>=b.allocation_limit THEN RETURN;END IF;
 identity:=jsonb_build_object('UID','capacity','Generation',1,'Digest',to_jsonb(ARRAY(SELECT get_byte(sha256(convert_to('asservat-capacity/'||r::text,'UTF8')),k) FROM generate_series(0,31) k)));
 INSERT INTO public.context_query_allocation(id,root_id,cluster_id,namespace_uid,workload_uid,revision,pool_source,policy_source,query_limit)
  VALUES(gen_random_uuid(),r,cluster,namespace_id,workload,1,identity,identity,limit_value);
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION ensure_shared_context_query_allocation(r uuid, cluster uuid, namespace_id text, workload text) FROM PUBLIC;

-- +goose StatementBegin
CREATE FUNCTION ensure_shared_context_query_capacity(r uuid) RETURNS void
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
DECLARE s public.capacity_settings;t public.fleet_current_trust;q jsonb;e jsonb;w jsonb;acceptance uuid;n timestamptz:=clock_timestamp();
 hard timestamptz:=public.capacity_standing();effects timestamptz;cleanup timestamptz;retire timestamptz;plan jsonb;object_count numeric;keys numeric;
BEGIN
 SELECT * INTO STRICT s FROM public.capacity_settings WHERE root_id=r;
 IF NOT (s.qualification ? 'ContextQuery') OR EXISTS(SELECT 1 FROM public.context_query_capacity WHERE root_id=r) THEN RETURN;END IF;
 SELECT * INTO STRICT t FROM public.fleet_current_trust WHERE installation_id=s.installation_id;
 q:=s.qualification->'ContextQuery';e:=q->'Envelope';w:=q->'Profile'->'Worker';acceptance:=(q->>'CapacityID')::uuid;
 effects:=hard+(GREATEST((w->>'Runtime')::numeric,(w->>'CredentialLifetime')::numeric,(w->>'ProviderEffectLifetime')::numeric)/1000)*interval '1 microsecond';
 cleanup:=effects+((w->>'Cleanup')::numeric/1000)*interval '1 microsecond';
 retire:=cleanup+((2*(q->'History'->>'BackupHorizon')::numeric+(q->'History'->>'RetirementCleanup')::numeric)/1000)*interval '1 microsecond';
 object_count:=(e->>'AuditObjects')::numeric;keys:=(e->>'UnwrapAttempts')::numeric+(e->>'SigningAttempts')::numeric+(e->>'ProviderRequests')::numeric;
 plan:=jsonb_build_object('RootID',r,'InstallationID',s.installation_id,'AcceptanceID',acceptance,'Qualification',q,
  'Reservation',jsonb_build_object('SystemObjects',jsonb_build_object('Bytes',(object_count*(q->'History'->>'AuditCipherBytes')::numeric)::bigint,'Objects',object_count::bigint),'SQLBytes',e->'SQLBytes','BackupBytes',e->'BackupBytes','WALBytes',e->'WALBytes','KeyAttempts',keys::bigint),
  'HardUntil',public.capacity_json_timestamp(hard),'EffectsUntil',public.capacity_json_timestamp(effects),'CleanupUntil',public.capacity_json_timestamp(cleanup),'RetireBy',public.capacity_json_timestamp(retire));
 INSERT INTO public.context_query_capacity(root_id,acceptance_id,capacity_id,plan,source_digest,issuer_epoch,postmaster_at,database_oid,accepted_at)
  VALUES(r,acceptance,acceptance,plan,sha256(convert_to(s.qualification::text,'UTF8')),t.issuer_epoch,pg_postmaster_start_time(),(SELECT oid FROM pg_database WHERE datname=current_database()),n);
 INSERT INTO public.context_query_backing(root_id,installation_id,acceptance_id,profile,qualification,envelope,query_limit,principal_query_limit,principal_account_limit,allocation_limit,observed_at,fresh_until,hard_until,effects_until,cleanup_until,retire_by,suspended)
  VALUES(r,s.installation_id,acceptance,q->'Profile',q->'Profile'->'Qualification',e,(q->>'RootQueries')::bigint,(q->>'PrincipalQueries')::bigint,(q->>'PrincipalAccounts')::bigint,(q->>'WorkloadAccounts')::bigint,n,n+interval '5 seconds',hard,effects,cleanup,retire,false);
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION ensure_shared_context_query_capacity(r uuid) FROM PUBLIC;

-- +goose StatementBegin
CREATE FUNCTION fill_context_capture_history() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
DECLARE e jsonb;s jsonb;
BEGIN
 IF TG_OP='UPDATE' THEN
  IF ROW(NEW.history_cluster_id,NEW.history_namespace_uid,NEW.history_workload_uid,NEW.history_origin) IS DISTINCT FROM ROW(OLD.history_cluster_id,OLD.history_namespace_uid,OLD.history_workload_uid,OLD.history_origin) THEN
   RAISE EXCEPTION 'capture history identity is immutable' USING ERRCODE='23514';
  END IF;
  RETURN NEW;
 END IF;
 -- Caller-supplied values are ignored: the accepted record is the only source.
 e:=convert_from(NEW.expectation_json,'UTF8')::jsonb;
 s:=convert_from(NEW.scope_json,'UTF8')::jsonb;
 NEW.history_cluster_id:=(e#>>'{Registration,Location,ClusterID}')::uuid;
 NEW.history_namespace_uid:=e->>'NamespaceUID';
 NEW.history_workload_uid:=e->>'WorkloadUID';
 -- capture_audit_actor_valid admits only a human or the policy executor.
 NEW.history_origin:=CASE WHEN s->>'schemaVersion'='recording-save/v1' AND s->>'operation'='recordingSave' THEN 'manual' WHEN s#>>'{executor,identityType}'='human' THEN 'manual' ELSE 'policy' END;
 RETURN NEW;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION fill_context_capture_history() FROM PUBLIC;

-- +goose StatementBegin
CREATE FUNCTION guard_access_grant_child_scope() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
DECLARE parent public.access_grant%ROWTYPE; item jsonb; matched boolean:=false;
BEGIN
 SELECT * INTO STRICT parent FROM public.access_grant WHERE root_id=NEW.root_id AND id=NEW.parent_id;
 IF parent.kind='adHocCapture' THEN
  IF NEW.capture_id IS DISTINCT FROM parent.capture_id THEN RAISE EXCEPTION 'child capture differs from parent' USING ERRCODE='23514'; END IF;
 ELSIF parent.kind='rawQuery' THEN
  FOR item IN SELECT jsonb_array_elements(parent.raw_query->'Artifacts') LOOP
   IF item#>>'{Output,ArtifactID}'=NEW.artifact_id::text
    AND item#>>'{Output,CaptureID}'=NEW.capture_id::text
    AND item#>>'{Output,ActionID}'=NEW.action_id
    AND item#>'{Output,ArtifactDigest}'=to_jsonb(ARRAY(SELECT get_byte(NEW.artifact_digest,i)::integer FROM generate_series(0,31) i)) THEN matched:=true; END IF;
  END LOOP;
  IF NOT matched THEN RAISE EXCEPTION 'raw child is not an exact reviewed member' USING ERRCODE='23514'; END IF;
 ELSE RAISE EXCEPTION 'grant cannot parent artifact children' USING ERRCODE='23514'; END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION guard_access_grant_child_scope() FROM PUBLIC;

-- +goose StatementBegin
CREATE FUNCTION guard_capture_history_parameter() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
DECLARE c public.context_capture;g public.recording_save_group;e jsonb;a public.custody_attempt;
 owner_root uuid;owner_id uuid;owner_scope bytea;owner_created timestamptz;owner_allocation uuid;owner_cluster uuid;
BEGIN
 IF TG_OP='DELETE' THEN
  SELECT * INTO STRICT a FROM public.custody_attempt WHERE id=OLD.attempt_id;
  IF a.state<>'deleted' OR clock_timestamp()<OLD.summary_expires_at THEN RAISE EXCEPTION 'retained history obligation' USING ERRCODE='23514';END IF;
  RETURN OLD;
 END IF;
 IF TG_OP='UPDATE' THEN
  IF ROW(NEW.root_id,NEW.capture_id,NEW.attempt_id,NEW.selector_key,NEW.settings_key,NEW.mac_version,NEW.expectation_json,NEW.retention_json,NEW.summary_expires_at,NEW.created_at)
   IS DISTINCT FROM ROW(OLD.root_id,OLD.capture_id,OLD.attempt_id,OLD.selector_key,OLD.settings_key,OLD.mac_version,OLD.expectation_json,OLD.retention_json,OLD.summary_expires_at,OLD.created_at) OR (NOT OLD.visible AND NEW.visible) OR
   (OLD.write_id IS NOT NULL AND ROW(NEW.write_id,NEW.write_digest,NEW.write_started_at,NEW.write_until,NEW.write_executor_epoch) IS DISTINCT FROM ROW(OLD.write_id,OLD.write_digest,OLD.write_started_at,OLD.write_until,OLD.write_executor_epoch)) OR
   (OLD.writer_completion_json IS NOT NULL AND ROW(NEW.writer_completion_json,NEW.copies_digest) IS DISTINCT FROM ROW(OLD.writer_completion_json,OLD.copies_digest)) THEN
    RAISE EXCEPTION 'immutable history parameters' USING ERRCODE='23514';END IF;
  RETURN NEW;
 END IF;
 SELECT * INTO c FROM public.context_capture WHERE id=NEW.capture_id;
 IF FOUND THEN
  owner_root:=c.root_id;owner_id:=c.id;owner_scope:=c.scope_digest;owner_created:=c.created_at;
  owner_allocation:=(convert_from(c.expectation_json,'UTF8')::jsonb#>>'{Registration,AllocationID}')::uuid;
  owner_cluster:=c.history_cluster_id;
 ELSE
  SELECT * INTO STRICT g FROM public.recording_save_group WHERE id=NEW.capture_id;
  owner_root:=g.root_id;owner_id:=g.id;owner_scope:=g.scope_digest;owner_created:=g.accepted_at;owner_allocation:=g.allocation_id;
  owner_cluster:=(convert_from(g.scope_json,'UTF8')::jsonb#>>'{policy,clusterID}')::uuid;
 END IF;
 SELECT * INTO STRICT a FROM public.custody_attempt WHERE id=NEW.attempt_id;
 e:=convert_from(NEW.expectation_json,'UTF8')::jsonb;
 IF NEW.root_id<>owner_root OR (e->>'RootID')::uuid<>owner_root OR (e->>'CaptureID')::uuid<>owner_id OR
   (e#>>'{Registration,Location,AttemptID}')::uuid<>a.id OR (e#>>'{Registration,Location,ArtifactID}')::uuid<>a.artifact_id OR
   (e#>>'{Registration,Location,ClusterID}')::uuid<>a.cluster_id OR (e#>>'{Registration,AllocationID}')::uuid<>a.allocation_id OR a.native_limit<>131072 OR
   public.connector_digest(e->'OriginalExecutionDigest')<>owner_scope OR
   (e#>>'{Registration,StoreID}')::uuid<>(SELECT p.store_id FROM public.custody_pool p JOIN public.custody_allocation x ON x.pool_id=p.id WHERE x.id=a.allocation_id) OR
   (e#>>'{Registration,PoolRevision}')::bigint<>a.pool_revision OR (e#>>'{Registration,AllocationRevision}')::bigint<>a.allocation_revision OR
   (e#>>'{Registration,AnchorAt}')::timestamptz<>a.anchor_at OR (e#>>'{Registration,WriteUntil}')::timestamptz<>a.write_until OR
   (e#>>'{Registration,ExpiresAt}')::timestamptz<>a.expires_at OR (e#>>'{Registration,DeleteBy}')::timestamptz<>a.delete_by OR
   a.allocation_id<>owner_allocation OR
   a.cluster_id<>owner_cluster OR NEW.summary_expires_at>owner_created+interval '3650 days' THEN
  RAISE EXCEPTION 'history parameter scope changed' USING ERRCODE='23514';END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION guard_capture_history_parameter() FROM PUBLIC;

-- +goose StatementBegin
CREATE FUNCTION guard_capture_repeat_lineage() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
BEGIN
 IF TG_OP='UPDATE' AND ROW(NEW.repeated_from_capture_id,NEW.repeated_from_expires_at) IS DISTINCT FROM ROW(OLD.repeated_from_capture_id,OLD.repeated_from_expires_at) THEN
  RAISE EXCEPTION 'immutable repeat lineage' USING ERRCODE='23514';END IF;
 IF TG_OP='INSERT' AND NEW.repeated_from_capture_id IS NOT NULL THEN
  IF NEW.repeated_from_capture_id=NEW.id OR clock_timestamp()>=NEW.repeated_from_expires_at THEN RAISE EXCEPTION 'invalid repeat lineage' USING ERRCODE='23514';END IF;
 END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION guard_capture_repeat_lineage() FROM PUBLIC;

-- +goose StatementBegin
CREATE FUNCTION guard_comparison_worker_parent() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
DECLARE q public.context_query;
BEGIN
 IF NEW.query_id IS NULL THEN
  IF NEW.baseline_query_allocation_id IS NOT NULL THEN RAISE EXCEPTION 'download cannot name comparison allocation' USING ERRCODE='23514'; END IF;
 ELSE
  SELECT * INTO STRICT q FROM public.context_query WHERE id=NEW.query_id AND root_id=NEW.root_id;
  IF NEW.query_allocation_id IS DISTINCT FROM q.allocation_id OR NEW.baseline_query_allocation_id IS DISTINCT FROM q.baseline_allocation_id OR convert_from(NEW.intent_json,'UTF8')::jsonb->'Query' IS DISTINCT FROM q.query THEN RAISE EXCEPTION 'comparison worker parent mismatch' USING ERRCODE='23514'; END IF;
 END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION guard_comparison_worker_parent() FROM PUBLIC;

-- +goose StatementBegin
CREATE FUNCTION guard_context_capture_group() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
DECLARE g public.recording_save_group;
BEGIN
 IF TG_OP='UPDATE' THEN
  IF ROW(NEW.group_id,NEW.group_ordinal) IS DISTINCT FROM ROW(OLD.group_id,OLD.group_ordinal) THEN
   RAISE EXCEPTION 'immutable group membership' USING ERRCODE='23514';
  END IF;
 ELSE
  IF EXISTS(SELECT 1 FROM public.recording_save_group WHERE id=NEW.id OR (root_id=NEW.root_id AND request_key=NEW.request_key)) THEN
   RAISE EXCEPTION 'request key already belongs to a group' USING ERRCODE='23514';
  END IF;
  IF NEW.group_id IS NOT NULL THEN
   SELECT * INTO g FROM public.recording_save_group WHERE root_id=NEW.root_id AND id=NEW.group_id;
   IF NOT FOUND OR g.child_ids[NEW.group_ordinal+1] IS DISTINCT FROM NEW.id OR g.accepted_at IS DISTINCT FROM NEW.created_at OR
      (g.group_kind='recordingSave' AND (g.scope_digest IS DISTINCT FROM NEW.scope_digest OR g.scope_json IS DISTINCT FROM NEW.scope_json)) OR
      (g.group_kind='composition' AND convert_from(g.scope_json,'UTF8')::jsonb->'children'->NEW.group_ordinal->>'scopeDigest' IS DISTINCT FROM encode(NEW.scope_digest,'hex')) THEN
    RAISE EXCEPTION 'unlisted group member' USING ERRCODE='23514';
   END IF;
  END IF;
  IF convert_from(NEW.expectation_json,'UTF8')::jsonb ? 'Snapshot' AND (convert_from(NEW.expectation_json,'UTF8')::jsonb#>>'{Snapshot,StartBy}')::timestamptz>NEW.created_at+interval '5 seconds' AND NOT public.recording_save_group_window_valid(NEW,g,(convert_from(NEW.expectation_json,'UTF8')::jsonb#>>'{Snapshot,StartBy}')::timestamptz) THEN
   RAISE EXCEPTION 'long snapshot window requires exact protected manual group' USING ERRCODE='23514';
  END IF;
 END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION guard_context_capture_group() FROM PUBLIC;

-- +goose StatementBegin
CREATE FUNCTION guard_context_deletion_checkpoint() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
DECLARE w public.context_writer_completion; a public.custody_attempt;
BEGIN
 IF TG_WHEN<>'BEFORE' OR TG_LEVEL<>'ROW' OR TG_RELID<>'public.context_deletion_checkpoint'::regclass OR TG_OP='DELETE' THEN RAISE EXCEPTION 'invalid deletion checkpoint change' USING ERRCODE='23514'; END IF;
 IF TG_OP='UPDATE' THEN
  IF ROW(NEW.attempt_id,NEW.root_id,NEW.capture_id,NEW.store_id,NEW.registration_digest,NEW.writer_digest,NEW.record_digest,NEW.record_json,NEW.installation_id,NEW.issuer_epoch,NEW.postmaster_at,NEW.database_oid,NEW.purge_fence,NEW.purged_at,NEW.recorded_at) IS DISTINCT FROM ROW(OLD.attempt_id,OLD.root_id,OLD.capture_id,OLD.store_id,OLD.registration_digest,OLD.writer_digest,OLD.record_digest,OLD.record_json,OLD.installation_id,OLD.issuer_epoch,OLD.postmaster_at,OLD.database_oid,OLD.purge_fence,OLD.purged_at,OLD.recorded_at) OR OLD.audit_acknowledged_at IS NOT NULL AND ROW(NEW.audit_receipt_json,NEW.audit_acknowledged_at) IS DISTINCT FROM ROW(OLD.audit_receipt_json,OLD.audit_acknowledged_at) THEN RAISE EXCEPTION 'immutable deletion result and audit' USING ERRCODE='23514'; END IF;

  IF OLD.finalization_xid IS NOT NULL AND NEW.finalization_xid IS DISTINCT FROM OLD.finalization_xid OR NEW.finalization_xid IS DISTINCT FROM OLD.finalization_xid AND (OLD.audit_acknowledged_at IS NULL OR NEW.finalization_xid IS DISTINCT FROM pg_current_xact_id()) THEN RAISE EXCEPTION 'invalid one-use finalization transaction' USING ERRCODE='23514'; END IF;
 ELSE
  SELECT * INTO STRICT w FROM public.context_writer_completion WHERE attempt_id=NEW.attempt_id;
  SELECT * INTO STRICT a FROM public.custody_attempt WHERE id=NEW.attempt_id;
  IF w.root_id<>NEW.root_id OR w.capture_id<>NEW.capture_id OR w.completion_digest<>NEW.writer_digest OR w.registration_digest<>NEW.registration_digest OR w.installation_id<>NEW.installation_id OR w.issuer_epoch<>NEW.issuer_epoch OR w.postmaster_at<>NEW.postmaster_at OR w.database_oid<>NEW.database_oid OR a.request_digest<>NEW.registration_digest OR a.state<>'deleting' OR a.deletion_fence<>NEW.purge_fence OR a.lease_until<=clock_timestamp() OR NEW.purged_at<a.effective_expires_at OR NEW.purged_at<w.closed_at OR NEW.purged_at>clock_timestamp() OR NEW.audit_acknowledged_at IS NOT NULL OR NEW.audit_receipt_json IS NOT NULL OR NEW.finalization_xid IS NOT NULL OR NOT EXISTS(SELECT 1 FROM public.custody_allocation ca JOIN public.custody_pool cp ON cp.id=ca.pool_id WHERE ca.id=a.allocation_id AND cp.store_id=NEW.store_id) THEN RAISE EXCEPTION 'deletion result lacks exact fenced purge' USING ERRCODE='23514'; END IF;
 END IF;
 IF NOT public.incarnation_current(NEW.postmaster_at) OR NEW.database_oid<>(SELECT oid FROM pg_database WHERE datname=current_database()) OR NOT EXISTS(SELECT 1 FROM public.fleet_current_trust WHERE installation_id=NEW.installation_id AND issuer_epoch=NEW.issuer_epoch AND NOT suspended AND fresh_until>clock_timestamp()) THEN RAISE EXCEPTION 'deletion checkpoint incarnation unavailable' USING ERRCODE='23514'; END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION guard_context_deletion_checkpoint() FROM PUBLIC;

-- +goose StatementBegin
CREATE FUNCTION guard_context_execution() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'context execution deletion requires retention protocol' USING ERRCODE='23514'; END IF;
 IF TG_OP='INSERT' THEN
  IF EXISTS(SELECT 1 FROM public.context_capture WHERE root_id=NEW.root_id AND id=NEW.capture_id AND snapshot_cancel_requested_at IS NOT NULL) THEN RAISE EXCEPTION 'capture cancellation fences preparation' USING ERRCODE='23514';END IF;
  IF NEW.phase<>'prepared' OR NEW.object_uid IS NOT NULL OR NEW.started_at IS NOT NULL OR NEW.completed_at IS NOT NULL OR clock_timestamp()>=NEW.not_after THEN
   RAISE EXCEPTION 'invalid first context preparation' USING ERRCODE='23514';
  END IF;
  RETURN NEW;
 END IF;
 IF ROW(NEW.capture_id,NEW.root_id,NEW.attempt_id,NEW.binding_json,NEW.process_json,NEW.expectation_digest,NEW.created_at,NEW.not_before,NEW.not_after)
 IS DISTINCT FROM ROW(OLD.capture_id,OLD.root_id,OLD.attempt_id,OLD.binding_json,OLD.process_json,OLD.expectation_digest,OLD.created_at,OLD.not_before,OLD.not_after) THEN
  RAISE EXCEPTION 'immutable context execution identity' USING ERRCODE='23514';
 END IF;
 IF OLD.object_uid IS NOT NULL AND NEW.object_uid IS DISTINCT FROM OLD.object_uid OR OLD.object_uid IS NULL AND NEW.object_uid IS NOT NULL AND (OLD.phase<>'prepared' OR NEW.phase<>'prepared' OR clock_timestamp()>=OLD.not_after) THEN
  RAISE EXCEPTION 'immutable context start object' USING ERRCODE='23514';
 END IF;
 IF NEW IS NOT DISTINCT FROM OLD THEN RETURN NEW; END IF;
 IF OLD.phase='prepared' AND NEW.phase='prepared' AND OLD.object_uid IS NULL AND NEW.object_uid IS NOT NULL THEN RETURN NEW; END IF;
 IF OLD.phase='prepared' AND NEW.phase='started' AND EXISTS(SELECT 1 FROM public.context_capture WHERE root_id=NEW.root_id AND id=NEW.capture_id AND snapshot_cancel_requested_at IS NOT NULL) THEN RAISE EXCEPTION 'capture cancellation fences start' USING ERRCODE='23514';END IF;
 IF OLD.phase='prepared' AND NEW.phase='started' AND OLD.object_uid IS NOT NULL AND NEW.started_at<=clock_timestamp() AND clock_timestamp()<OLD.not_after THEN RETURN NEW; END IF;
 IF OLD.phase='started' AND NEW.phase IN ('stored','captureFailed','targetGone','denied','storeUnconfirmed','cancelled','peerMembershipChanged','peerMembershipStale','profilerBusy','profileUnavailable') AND NEW.started_at=OLD.started_at AND NEW.completed_at<=clock_timestamp() THEN RETURN NEW; END IF;
 RAISE EXCEPTION 'context execution cannot repeat or rewrite result' USING ERRCODE='23514';
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION guard_context_execution() FROM PUBLIC;

-- +goose StatementBegin
CREATE FUNCTION guard_context_key_wrap() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'context key wrap spend cannot be deleted' USING ERRCODE='23514'; END IF;
 IF ROW(NEW.attempt_id,NEW.root_id,NEW.certificate_sha256,NEW.created_at) IS DISTINCT FROM ROW(OLD.attempt_id,OLD.root_id,OLD.certificate_sha256,OLD.created_at)
  OR (NEW.used_roles & OLD.used_roles)<>OLD.used_roles THEN
  RAISE EXCEPTION 'context key wrap spend is append-only' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION guard_context_processing() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
BEGIN
 IF TG_OP<>'INSERT' OR pg_trigger_depth()<2 THEN RAISE EXCEPTION 'processing lineage is publication owned' USING ERRCODE='23514'; END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION guard_context_processing() FROM PUBLIC;

-- +goose StatementBegin
CREATE FUNCTION guard_context_progress() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
BEGIN
 IF TG_OP='INSERT' THEN
  IF NEW.progress_revision<>1 OR NEW.deadline_observed_at IS NOT NULL THEN
   RAISE EXCEPTION 'initial context progress mismatch' USING ERRCODE='23514';
  END IF;
  RETURN NEW;
 END IF;
 IF ROW(NEW.id,NEW.root_id,NEW.preview_id,NEW.request_key,NEW.submission_digest,NEW.scope_digest,NEW.scope_json,NEW.expectation_json,NEW.pod_pin_json,NEW.attempt_id,NEW.permission_epoch,NEW.permission_sequence,NEW.identity_policy_uid,NEW.identity_policy_generation,NEW.identity_policy_digest,NEW.created_at,NEW.deadline,NEW.reason)
 IS DISTINCT FROM ROW(OLD.id,OLD.root_id,OLD.preview_id,OLD.request_key,OLD.submission_digest,OLD.scope_digest,OLD.scope_json,OLD.expectation_json,OLD.pod_pin_json,OLD.attempt_id,OLD.permission_epoch,OLD.permission_sequence,OLD.identity_policy_uid,OLD.identity_policy_generation,OLD.identity_policy_digest,OLD.created_at,OLD.deadline,OLD.reason) THEN
  RAISE EXCEPTION 'immutable accepted context' USING ERRCODE='23514';
 END IF;
 IF NEW.progress_revision<>OLD.progress_revision AND
  (pg_trigger_depth()<2 OR NEW.progress_revision<>LEAST(OLD.progress_revision+1,1000000001)) THEN
  RAISE EXCEPTION 'context revision is source managed' USING ERRCODE='23514';
 END IF;
 IF NEW.deadline_observed_at IS DISTINCT FROM OLD.deadline_observed_at THEN
  IF OLD.deadline_observed_at IS NOT NULL OR NEW.deadline_observed_at IS NULL OR clock_timestamp()<OLD.deadline THEN
   RAISE EXCEPTION 'context deadline observation cannot rewind' USING ERRCODE='23514';
  END IF;
  NEW.deadline_observed_at:=clock_timestamp();
  NEW.progress_revision:=LEAST(OLD.progress_revision+1,1000000001);
 END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION guard_context_progress() FROM PUBLIC;

-- +goose StatementBegin
CREATE FUNCTION guard_context_query() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
DECLARE b public.context_query_backing; a public.context_query_allocation; ba public.context_query_allocation; bp jsonb; bs jsonb; pair boolean; aid uuid; p public.context_query_principal; n timestamptz; u integer;
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'query history retirement unavailable' USING ERRCODE='23514'; END IF;
 IF TG_OP='UPDATE' THEN
  IF pg_trigger_depth()<2 OR (to_jsonb(NEW)-ARRAY['generation','active_batch','polls','controls','uncertain']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['generation','active_batch','polls','controls','uncertain']) OR
   NEW.generation<OLD.generation OR NEW.generation>OLD.generation+1 OR NEW.polls<OLD.polls OR NEW.controls<>OLD.controls+1 OR OLD.uncertain AND NOT NEW.uncertain OR
   NEW.polls>(NEW.query->'Plan'->'Profile'->>'PollLimit')::bigint OR NEW.controls>(NEW.query->'Plan'->'Profile'->>'ControlTransitionLimit')::bigint THEN RAISE EXCEPTION 'query counters immutable' USING ERRCODE='23514'; END IF;
  RETURN NEW;
 END IF;
 IF NEW.query#>>'{Scope,DisplayVersion}' IN ('approved-pcap-query/v1','approved-syscall-query/v1','approved-logs/v1') THEN
  IF NOT COALESCE(NEW.invocation_key IS NOT NULL AND NEW.request_digest IS NOT NULL AND
   NEW.query#>>'{InvocationKey,Key}'=NEW.invocation_key AND
   NEW.query#>'{InvocationKey,RequestDigest}'=to_jsonb(ARRAY(SELECT get_byte(NEW.request_digest,i) FROM generate_series(0,31)i)) AND
   public.context_packet_query_scope_grant_current(NEW.root_id,NEW.actor,NEW.query->'Scope',NEW.query->'Grant'),false) THEN
   RAISE EXCEPTION 'packet query invocation or grant mismatch' USING ERRCODE='23514'; END IF;
 ELSIF NEW.invocation_key IS NOT NULL OR NEW.request_digest IS NOT NULL OR NEW.query ? 'InvocationKey' OR NEW.query ? 'Grant' THEN
  RAISE EXCEPTION 'unrelated query invocation or grant' USING ERRCODE='23514';
 END IF;
 SELECT * INTO STRICT b FROM public.context_query_backing WHERE root_id=NEW.root_id FOR UPDATE;
 pair:=NEW.query#>'{Scope,Comparison}' IS NOT NULL;
 IF pair IS DISTINCT FROM (NEW.baseline_allocation_id IS NOT NULL) OR pair IS DISTINCT FROM (NEW.query ? 'BaselinePlan') THEN RAISE EXCEPTION 'comparison plan branch mismatch' USING ERRCODE='23514'; END IF;
 FOR aid IN SELECT id FROM public.context_query_allocation WHERE root_id=NEW.root_id AND id IN (NEW.allocation_id,NEW.baseline_allocation_id) ORDER BY id FOR UPDATE LOOP NULL; END LOOP;
 SELECT * INTO STRICT a FROM public.context_query_allocation WHERE id=NEW.allocation_id AND root_id=NEW.root_id;
 IF pair THEN SELECT * INTO STRICT ba FROM public.context_query_allocation WHERE id=NEW.baseline_allocation_id AND root_id=NEW.root_id; END IF;
 SELECT * INTO STRICT p FROM public.context_query_principal WHERE id=NEW.account_id AND root_id=NEW.root_id FOR UPDATE;
 n:=clock_timestamp();
 u:=public.context_query_units(NEW.query->'Scope');
 IF NOT public.context_query_intent_current(NEW.root_id,NEW.operation_id,NEW.actor,NEW.issuer_epoch,NEW.initial_request->'Call') OR
  NOT public.context_query_complete_object(NEW.query,ARRAY['ID','OperationID','WorkerID','Scope','Plan','CreatedAt','Deadline','WorkerUntil','CredentialUntil','ProviderUntil','CleanupUntil']) OR
  NOT public.context_query_complete_object(NEW.query->'Plan',ARRAY['AcceptanceID','AccountID','AllocationID','RootID','InstallationID','ClusterID','NamespaceUID','WorkloadUID','AllocationRevision','PoolSource','PolicySource','Principal','Profile','ObservedAt','ValidUntil','HardUntil','EffectsUntil','CleanupUntil','RetireBy']) OR
  NOT public.context_query_complete_object(NEW.query->'Scope',ARRAY['RootID','CaseID','ArtifactID','CaptureID','ClusterID','NamespaceUID','WorkloadUID','PodUID','Version','SourceProjectionDigest','SourceFormat','DisplayVersion','Selection','Principal']) OR
  NOT public.context_query_scope_source_valid(NEW.query->'Scope') OR
  (NEW.query->'Scope'->>'NativeType' IN ('pprof','syscallRecords','syscallArguments','pcapng','rawPcapng','logs','processes') AND ((NEW.query->'Plan'->'Profile'->'Worker'->>'MemoryBytes')::bigint<268435456 OR (NEW.query->'Plan'->'Profile'->'Worker'->>'WorkerTransientBytes')::bigint<268435456)) OR
  b.suspended OR p.principal_key<>NEW.principal_key OR NEW.generation<>0 OR NEW.active_batch IS NOT NULL OR NEW.polls<>0 OR NEW.controls<>0 OR NEW.uncertain OR
  ((NEW.query->'Plan'->'Profile')-'Path') IS DISTINCT FROM (b.profile-'Path') OR NEW.query->'Plan'->'Profile'->'Path'->>'TargetClusterID' IS DISTINCT FROM a.cluster_id::text OR NOT public.context_query_shared_profile_current(NEW.root_id,NEW.query->'Plan'->'Profile') OR NOT public.context_query_capacity_allocation_current(NEW.root_id,a.id) OR NEW.query->'Plan'->>'AcceptanceID'<>b.acceptance_id::text OR NEW.query->'Plan'->>'AllocationID'<>a.id::text OR
  NEW.query->'Plan'->>'AccountID'<>p.id::text OR NEW.query->'Plan'->>'ClusterID'<>a.cluster_id::text OR NEW.query->'Plan'->>'NamespaceUID'<>a.namespace_uid OR NEW.query->'Plan'->>'WorkloadUID'<>a.workload_uid OR
  NEW.query->'Plan'->'Principal' IS DISTINCT FROM NEW.actor OR NEW.query->'Scope'->>'RootID' IS DISTINCT FROM NEW.root_id::text OR NEW.query->'Scope'->>'ClusterID' IS DISTINCT FROM a.cluster_id::text OR NEW.query->'Scope'->>'NamespaceUID' IS DISTINCT FROM a.namespace_uid OR NEW.query->'Scope'->>'WorkloadUID' IS DISTINCT FROM a.workload_uid OR
  NEW.query->'Plan'->'PoolSource' IS DISTINCT FROM a.pool_source OR NEW.query->'Plan'->'PolicySource' IS DISTINCT FROM a.policy_source OR
  (NEW.query->'Plan'->>'AllocationRevision')::bigint<>a.revision OR NEW.query->'Scope'->'Principal' IS DISTINCT FROM NEW.actor OR
  NEW.query->>'ID'<>NEW.id::text OR NEW.query->>'WorkerID'<>NEW.worker_id::text OR NEW.query->>'OperationID'<>NEW.operation_id::text OR
  (NEW.query->>'CreatedAt')::timestamptz<>NEW.created_at OR (NEW.query->>'Deadline')::timestamptz<>NEW.deadline OR (NEW.query->>'CleanupUntil')::timestamptz<>NEW.cleanup_until OR
  NEW.deadline>NEW.created_at+make_interval(secs=>(b.profile->>'Lifetime')::double precision/1000000000) OR
  (NEW.query->'Plan'->>'RootID')::uuid<>NEW.root_id OR (NEW.query->'Plan'->>'InstallationID')::uuid<>b.installation_id OR
  (NEW.query->'Plan'->>'RetireBy')::timestamptz<>NEW.retire_by OR NEW.retire_by<>b.retire_by OR
  (NEW.query->'Plan'->>'HardUntil')::timestamptz<>b.hard_until OR (NEW.query->'Plan'->>'EffectsUntil')::timestamptz<>b.effects_until OR (NEW.query->'Plan'->>'CleanupUntil')::timestamptz<>b.cleanup_until OR
  NEW.deadline>b.hard_until OR NEW.cleanup_until>b.cleanup_until OR n>=(NEW.query->'Plan'->>'ValidUntil')::timestamptz OR n<(NEW.query->'Plan'->>'ObservedAt')::timestamptz OR
  (NEW.query->>'WorkerUntil')::timestamptz>b.effects_until OR (NEW.query->>'CredentialUntil')::timestamptz>b.effects_until OR (NEW.query->>'ProviderUntil')::timestamptz>b.effects_until OR
  NEW.created_at>n OR NEW.created_at<(NEW.initial_request->'Call'->>'StartedAt')::timestamptz OR
  NOT public.incarnation_current(NEW.postmaster_at) OR NEW.database_oid<>(SELECT oid FROM pg_database WHERE datname=current_database()) OR n>=NEW.deadline THEN
  RAISE EXCEPTION 'query accepted backing unavailable' USING ERRCODE='23514'; END IF;
 IF pair THEN
  bp:=NEW.query->'BaselinePlan'; bs:=public.context_query_comparison_source(NEW.query->'Scope',true);
  IF (bp#>>'{Profile,Worker,MemoryBytes}')::bigint<402653184 OR (bp#>>'{Profile,Worker,WorkerTransientBytes}')::bigint<402653184 OR (NEW.query#>>'{Plan,Profile,Worker,MemoryBytes}')::bigint<402653184 OR (NEW.query#>>'{Plan,Profile,Worker,WorkerTransientBytes}')::bigint<402653184 OR NOT public.context_query_complete_object(bp,ARRAY['AcceptanceID','AccountID','AllocationID','RootID','InstallationID','ClusterID','NamespaceUID','WorkloadUID','AllocationRevision','PoolSource','PolicySource','Principal','Profile','ObservedAt','ValidUntil','HardUntil','EffectsUntil','CleanupUntil','RetireBy']) OR
   bp->>'AllocationID' IS DISTINCT FROM ba.id::text OR bp->>'RootID' IS DISTINCT FROM NEW.root_id::text OR bp->>'InstallationID' IS DISTINCT FROM b.installation_id::text OR bp->>'AcceptanceID' IS DISTINCT FROM b.acceptance_id::text OR bp->>'AccountID' IS DISTINCT FROM p.id::text OR bp->'Principal' IS DISTINCT FROM NEW.actor OR
   bp->>'ClusterID' IS DISTINCT FROM ba.cluster_id::text OR bp->>'NamespaceUID' IS DISTINCT FROM ba.namespace_uid OR bp->>'WorkloadUID' IS DISTINCT FROM ba.workload_uid OR
   bs->>'ClusterID' IS DISTINCT FROM ba.cluster_id::text OR bs->>'NamespaceUID' IS DISTINCT FROM ba.namespace_uid OR bs->>'WorkloadUID' IS DISTINCT FROM ba.workload_uid OR
   (bp->>'AllocationRevision')::bigint IS DISTINCT FROM ba.revision OR bp->'PoolSource' IS DISTINCT FROM ba.pool_source OR bp->'PolicySource' IS DISTINCT FROM ba.policy_source OR
   ((bp->'Profile')-'Path') IS DISTINCT FROM (b.profile-'Path') OR ((bp#>'{Profile,Path}')-ARRAY['ID','TargetClusterID']) IS DISTINCT FROM ((NEW.query#>'{Plan,Profile,Path}')-ARRAY['ID','TargetClusterID']) OR bp#>>'{Profile,Path,TargetClusterID}' IS DISTINCT FROM ba.cluster_id::text OR
   NOT public.context_query_shared_profile_current(NEW.root_id,bp->'Profile') OR NOT public.context_query_capacity_allocation_current(NEW.root_id,ba.id) OR
   ((ba.cluster_id,ba.namespace_uid,ba.workload_uid)=(a.cluster_id,a.namespace_uid,a.workload_uid)) IS DISTINCT FROM (ba.id=a.id) OR
   (bp->>'HardUntil')::timestamptz IS DISTINCT FROM b.hard_until OR (bp->>'EffectsUntil')::timestamptz IS DISTINCT FROM b.effects_until OR (bp->>'CleanupUntil')::timestamptz IS DISTINCT FROM b.cleanup_until OR (bp->>'RetireBy')::timestamptz IS DISTINCT FROM b.retire_by OR n>=(bp->>'ValidUntil')::timestamptz OR n<(bp->>'ObservedAt')::timestamptz THEN
   RAISE EXCEPTION 'comparison baseline backing unavailable' USING ERRCODE='23514';
  END IF;
 END IF;
 UPDATE public.context_query_backing SET allocated=allocated+u WHERE root_id=NEW.root_id;
 IF pair AND ba.id<>a.id THEN
  UPDATE public.context_query_allocation SET allocated=allocated+10 WHERE id IN (a.id,ba.id);
 ELSE UPDATE public.context_query_allocation SET allocated=allocated+u WHERE id=NEW.allocation_id; END IF;
 UPDATE public.context_query_principal SET allocated=allocated+u WHERE id=NEW.account_id;
 RETURN NEW;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION guard_context_query() FROM PUBLIC;

-- +goose StatementBegin
CREATE FUNCTION guard_context_query_account() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
DECLARE b public.context_query_backing;
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'query account remains charged' USING ERRCODE='23514'; END IF;
 SELECT * INTO STRICT b FROM public.context_query_backing WHERE root_id=NEW.root_id FOR UPDATE;
 IF TG_OP='UPDATE' THEN
  IF pg_trigger_depth()<2 OR (to_jsonb(NEW)-'allocated') IS DISTINCT FROM (to_jsonb(OLD)-'allocated') OR NEW.allocated-OLD.allocated NOT IN (1,2,4,10,20) THEN RAISE EXCEPTION 'query account mutation denied' USING ERRCODE='23514'; END IF;
 ELSIF NEW.allocated<>0 THEN RAISE EXCEPTION 'query initial account spend invalid' USING ERRCODE='23514';
 ELSIF TG_TABLE_NAME='context_query_principal' THEN
  UPDATE public.context_query_backing SET principals=principals+1 WHERE root_id=NEW.root_id;
 ELSE
  IF NEW.query_limit>b.query_limit THEN RAISE EXCEPTION 'query allocation exceeds root' USING ERRCODE='23514'; END IF;
  UPDATE public.context_query_backing SET allocations=allocations+1 WHERE root_id=NEW.root_id;
 END IF;
 IF TG_TABLE_NAME='context_query_principal' AND NEW.allocated>b.principal_query_limit THEN RAISE EXCEPTION 'query principal capacity exhausted' USING ERRCODE='23514'; END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION guard_context_query_account() FROM PUBLIC;

-- +goose StatementBegin
CREATE FUNCTION guard_context_query_backing() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
DECLARE k text; need numeric;
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'query obligations remain backed' USING ERRCODE='23514'; END IF;
 IF NOT public.context_query_cost_valid(NEW.profile) OR NEW.qualification IS DISTINCT FROM NEW.profile->'Qualification' THEN RAISE EXCEPTION 'query profile incomplete' USING ERRCODE='23514'; END IF;
 FOREACH k IN ARRAY ARRAY['Workers','ReadBatches','ReadBytes','StructuredBytes','WireBytes','UnwrapAttempts','ProviderRequests','AuthenticationRequests','SigningAttempts','AuditObjects','SQLRows','SQLBytes','WALBytes','BackupBytes'] LOOP
  need:=(NEW.profile->'Cost'->>k)::numeric*NEW.query_limit;
  IF (NEW.envelope->>k)::numeric IS NULL OR (NEW.envelope->>k)::numeric<need OR (NEW.envelope->>k)::numeric>1152921504606846976 THEN RAISE EXCEPTION 'query envelope insufficient' USING ERRCODE='23514'; END IF;
 END LOOP;
 IF TG_OP='INSERT' THEN
  IF NEW.allocated<>0 OR NEW.principals<>0 OR NEW.allocations<>0 THEN RAISE EXCEPTION 'query initial spend invalid' USING ERRCODE='23514'; END IF;
 ELSIF (to_jsonb(NEW)-ARRAY['allocated','principals','allocations']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['allocated','principals','allocations']) OR
  NEW.allocated<OLD.allocated OR NEW.principals<OLD.principals OR NEW.allocations<OLD.allocations OR
  (ROW(NEW.allocated,NEW.principals,NEW.allocations) IS DISTINCT FROM ROW(OLD.allocated,OLD.principals,OLD.allocations) AND pg_trigger_depth()<2) OR
  NEW.observed_at<OLD.observed_at OR NEW.observed_at=OLD.observed_at AND NEW.fresh_until>OLD.fresh_until THEN
  RAISE EXCEPTION 'immutable query backing and spend' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION guard_context_query_backing() FROM PUBLIC;

-- +goose StatementBegin
CREATE FUNCTION guard_context_query_child() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
DECLARE q public.context_query; n timestamptz; begin_tool text; call_tool text; key_batch public.context_query_batch;
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'query child history remains charged' USING ERRCODE='23514'; END IF;
 SELECT * INTO STRICT q FROM public.context_query WHERE id=NEW.query_id FOR UPDATE;
 n:=clock_timestamp();
 begin_tool:=public.context_query_begin_tool(q.query->'Scope');
 IF TG_TABLE_NAME='context_query_batch' AND TG_OP='UPDATE' THEN
  IF ROW(NEW.native_operation,NEW.native_authority,NEW.native_closed) IS DISTINCT FROM ROW(OLD.native_operation,OLD.native_authority,OLD.native_closed) THEN
   IF (to_jsonb(NEW)-ARRAY['native_operation','native_authority','native_closed']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['native_operation','native_authority','native_closed']) OR
    OLD.closed OR OLD.native_closed OR q.active_batch IS DISTINCT FROM NEW.id OR NEW.claim_id IS DISTINCT FROM NEW.id OR
    n>=(NEW.batch->>'Until')::timestamptz OR n>=q.deadline OR
    NOT public.context_query_intent_current(q.root_id,NEW.operation_id,q.actor,q.issuer_epoch,NEW.batch->'Request'->'Call') THEN
    RAISE EXCEPTION 'query native operation unavailable' USING ERRCODE='23514';
   END IF;
   IF OLD.native_operation IS NULL THEN
    IF NEW.native_closed OR NOT public.context_query_complete_object(NEW.native_operation,ARRAY['Path','Processing','Reference','Kind','HubPodUID','HubProcessEpoch','WorkerPodUID','WorkerPublicKey','SourceVersion','ParentID','Generation','StartedAt','Until']) OR
     NEW.native_operation->>'Kind' IS DISTINCT FROM 'read-approved-context' OR
     NEW.native_operation->'Reference'->>'QueryID' IS DISTINCT FROM q.id::text OR
     COALESCE(NEW.native_operation->'Reference'->>'SessionID','')<>'' OR
     NEW.native_operation->'Reference'->>'WorkerID' IS DISTINCT FROM q.worker_id::text OR
     NEW.native_operation->'Reference'->>'OperationID' IS DISTINCT FROM NEW.id::text OR
     (NEW.native_operation->'Reference'->>'Fence')::bigint IS DISTINCT FROM NEW.generation OR
     NEW.native_operation->>'ParentID' IS DISTINCT FROM NEW.id::text OR
     (NEW.native_operation->>'Generation')::smallint IS DISTINCT FROM NEW.generation OR
     (NEW.native_operation->>'StartedAt')::timestamptz>n OR
     n>=(NEW.native_operation->>'Until')::timestamptz OR
     (NEW.native_operation->>'Until')::timestamptz>(NEW.batch->>'Until')::timestamptz OR
     NEW.native_authority->'Scope' IS DISTINCT FROM q.query->'Scope' OR
     NEW.native_operation->'SourceVersion' IS DISTINCT FROM q.query#>'{Scope,Version}' OR
     NEW.native_operation->'Path' IS DISTINCT FROM ((NEW.native_authority#>'{Environment,Path}')-'Purpose') OR NEW.native_operation->'Processing' IS DISTINCT FROM NEW.native_authority#>'{Environment,Processing}' OR
     (CASE WHEN q.query#>'{Scope,Comparison}' IS NOT NULL THEN
      NOT public.capacity_json_fields(NEW.native_operation->'Baseline',ARRAY['Path','Processing','SourceVersion']) OR
      NEW.native_authority#>'{Baseline,Baseline}' IS NOT NULL OR NEW.native_authority#>'{Baseline,Scope}' IS DISTINCT FROM public.context_query_comparison_source(q.query->'Scope',true) OR
      NEW.native_operation#>'{Baseline,SourceVersion}' IS DISTINCT FROM q.query#>'{Scope,Comparison,Baseline,Version}' OR NEW.native_operation#>'{Baseline,Path}' IS DISTINCT FROM ((NEW.native_authority#>'{Baseline,Environment,Path}')-'Purpose') OR NEW.native_operation#>'{Baseline,Processing}' IS DISTINCT FROM NEW.native_authority#>'{Baseline,Environment,Processing}'
     ELSE NEW.native_operation ? 'Baseline' OR NEW.native_authority ? 'Baseline' END) THEN
     RAISE EXCEPTION 'query native identity mismatch' USING ERRCODE='23514';
    END IF;
   ELSIF NOT NEW.native_closed OR NEW.native_operation IS DISTINCT FROM OLD.native_operation OR NEW.native_authority IS DISTINCT FROM OLD.native_authority THEN
    RAISE EXCEPTION 'query native identity immutable' USING ERRCODE='23514';
   END IF;
   UPDATE public.context_query SET controls=controls+1 WHERE id=q.id;
   RETURN NEW;
  END IF;
 END IF;
 IF TG_TABLE_NAME='context_query_call' THEN
  call_tool:=begin_tool;
  IF NEW.is_poll THEN call_tool:='get_query_result'; END IF;
  IF TG_OP<>'INSERT' OR n>=q.deadline OR NOT public.context_query_complete_object(NEW.request,ARRAY['Call','OwnerID','HubProcessEpoch']) OR NOT public.context_query_intent_current(q.root_id,NEW.operation_id,q.actor,q.issuer_epoch,NEW.request->'Call') OR NEW.request->'Call'->>'ID'<>NEW.operation_id::text OR NEW.request->'Call'->'Principal' IS DISTINCT FROM q.actor OR
   NEW.request->'Call'->>'RootID'<>q.root_id::text OR (NEW.is_poll AND NEW.operation_id=q.operation_id) OR
   (NOT NEW.is_poll AND NEW.operation_id<>q.operation_id AND NOT COALESCE(
    q.query#>>'{Scope,DisplayVersion}' IN ('approved-pcap-query/v1','approved-syscall-query/v1','approved-logs/v1') AND public.context_query_scope_source_valid(q.query->'Scope') AND q.invocation_key IS NOT NULL AND q.request_digest IS NOT NULL,false)) OR NEW.request->'Call'->>'Tool' IS DISTINCT FROM call_tool THEN RAISE EXCEPTION 'query invocation mismatch' USING ERRCODE='23514'; END IF;
  UPDATE public.context_query SET polls=polls+CASE WHEN NEW.is_poll THEN 1 ELSE 0 END,controls=controls+1 WHERE id=q.id;
 ELSIF TG_TABLE_NAME='context_query_batch' THEN
  IF TG_OP='INSERT' THEN
   IF q.query#>>'{Scope,DisplayVersion}' IN ('approved-pcap-query/v1','approved-syscall-query/v1','approved-logs/v1') AND NOT public.context_packet_query_grant_current(q.root_id,q.id,NEW.id) THEN
    RAISE EXCEPTION 'packet query batch disclosure is not reserved' USING ERRCODE='23514'; END IF;
   IF NOT public.context_query_complete_object(NEW.batch,ARRAY['ID','QueryID','OperationID','Generation','Worker','Request','StartedAt','Until','CleanupUntil']) OR
    n>=q.deadline OR (NEW.batch->>'StartedAt')::timestamptz>n OR n>=(NEW.batch->>'Until')::timestamptz OR
    (NEW.batch->>'Until')::timestamptz>q.deadline OR (NEW.batch->>'Until')::timestamptz>(NEW.batch->'Request'->'Call'->>'Until')::timestamptz OR (NEW.batch->>'CleanupUntil')::timestamptz<>q.cleanup_until OR
    NOT public.context_query_intent_current(q.root_id,NEW.operation_id,q.actor,q.issuer_epoch,NEW.batch->'Request'->'Call') OR
    q.active_batch IS NOT NULL OR q.uncertain OR NEW.generation<>q.generation+1 OR NEW.generation>public.context_query_read_batches(q.query->'Scope') OR NEW.claim_id IS NOT NULL OR NEW.closed OR
    NEW.batch->>'OperationID' IS DISTINCT FROM NEW.operation_id::text OR NEW.batch->>'ID'<>NEW.id::text OR NEW.batch->>'QueryID'<>q.id::text OR (NEW.batch->>'Generation')::smallint<>NEW.generation OR
    NOT EXISTS(SELECT 1 FROM public.context_query_call c WHERE c.operation_id=NEW.operation_id AND c.query_id=q.id AND c.request=NEW.batch->'Request' AND (c.is_poll OR c.operation_id=q.operation_id)) OR
    NOT EXISTS(SELECT 1 FROM public.context_query_worker w WHERE w.query_id=q.id AND w.binding=NEW.batch->'Worker') THEN RAISE EXCEPTION 'query batch unavailable' USING ERRCODE='23514'; END IF;
   UPDATE public.context_query SET generation=NEW.generation,active_batch=NEW.id,controls=controls+1 WHERE id=q.id;
  ELSE
   IF (to_jsonb(NEW)-ARRAY['claim_id','closed']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['claim_id','closed']) OR OLD.closed OR q.active_batch IS DISTINCT FROM NEW.id OR
    OLD.claim_id IS NOT NULL AND NEW.claim_id IS DISTINCT FROM OLD.claim_id OR OLD.claim_id IS NULL AND NEW.claim_id IS NULL OR
    OLD.claim_id IS NULL AND NEW.closed OR NEW.claim_id IS DISTINCT FROM NEW.id OR
    NOT NEW.closed AND (OLD.claim_id IS NOT NULL OR n>=(NEW.batch->>'Until')::timestamptz OR n>=q.deadline OR NOT public.context_query_intent_current(q.root_id,NEW.operation_id,q.actor,q.issuer_epoch,NEW.batch->'Request'->'Call')) OR
    NEW.closed AND (NEW.native_operation IS NOT NULL AND NOT NEW.native_closed OR n>=q.cleanup_until OR n>=(NEW.batch->'Request'->'Call'->>'WriteUntil')::timestamptz) THEN RAISE EXCEPTION 'query batch claim or close unavailable' USING ERRCODE='23514'; END IF;
   UPDATE public.context_query SET active_batch=CASE WHEN NEW.closed THEN NULL ELSE active_batch END,controls=controls+1 WHERE id=q.id;
  END IF;
 ELSIF TG_TABLE_NAME='context_query_worker' THEN
  IF TG_OP<>'INSERT' OR NEW.worker_id<>q.worker_id OR NEW.binding->>'QueryID' IS DISTINCT FROM q.id::text OR NEW.binding->>'WorkerID' IS DISTINCT FROM q.worker_id::text THEN RAISE EXCEPTION 'query worker immutable' USING ERRCODE='23514'; END IF;
  UPDATE public.context_query SET controls=controls+1 WHERE id=q.id;
 ELSE
  IF TG_OP='INSERT' AND NEW.source_ordinal IS NULL AND NEW.child_id IS NULL THEN NEW.child_id:=NEW.batch_id; END IF;
  IF q.query#>'{Scope,Comparison}' IS NOT NULL THEN
   SELECT * INTO STRICT key_batch FROM public.context_query_batch WHERE id=NEW.batch_id AND query_id=q.id;
   IF NOT public.capacity_json_fields(NEW.binding,ARRAY['ID','QueryID','BatchID','WorkerID','ProcessEpoch','SourceOrdinal','SourceVersion','AuthorityDigest','PublicKey','Certificate','Scope','CreatedAt','Until']) OR
    key_batch.native_operation IS NULL OR key_batch.native_closed OR key_batch.closed OR key_batch.claim_id IS DISTINCT FROM key_batch.id OR
    NEW.binding->'AuthorityDigest' IS DISTINCT FROM key_batch.native_authority->'DecisionDigest' OR NEW.binding->>'WorkerID' IS DISTINCT FROM q.worker_id::text OR
    NEW.binding->>'ProcessEpoch' IS DISTINCT FROM key_batch.batch#>>'{Worker,ProcessEpoch}' OR NEW.binding->'Certificate' IS DISTINCT FROM key_batch.batch#>'{Worker,Certificate}' OR NEW.binding->'PublicKey' IS DISTINCT FROM key_batch.native_operation->'WorkerPublicKey' OR
    NEW.binding#>>'{Scope,InstallationID}' IS DISTINCT FROM q.query#>>'{Plan,InstallationID}' OR NEW.binding#>>'{Scope,Purpose}' IS DISTINCT FROM 'artifact' OR
    (NEW.binding->>'CreatedAt')::timestamptz<(key_batch.batch->>'StartedAt')::timestamptz OR (NEW.binding->>'CreatedAt')::timestamptz>n OR n>=(NEW.binding->>'Until')::timestamptz OR
    (NEW.binding->>'Until')::timestamptz>(key_batch.batch->>'Until')::timestamptz OR (NEW.binding->>'Until')::timestamptz>(key_batch.native_authority->>'ValidUntil')::timestamptz OR (NEW.binding->>'Until')::timestamptz>(q.query->>'ProviderUntil')::timestamptz THEN RAISE EXCEPTION 'comparison key parent mismatch' USING ERRCODE='23514'; END IF;
   IF NEW.source_ordinal IS NULL OR NEW.child_id=NEW.batch_id OR NEW.binding->>'ID' IS DISTINCT FROM NEW.child_id::text OR NEW.binding->>'QueryID' IS DISTINCT FROM q.id::text OR NEW.binding->>'BatchID' IS DISTINCT FROM NEW.batch_id::text OR (NEW.binding->>'SourceOrdinal')::integer IS DISTINCT FROM NEW.source_ordinal OR
    NEW.binding->'SourceVersion' IS DISTINCT FROM (CASE NEW.source_ordinal WHEN 0 THEN q.query#>'{Scope,Comparison,Baseline,Version}' WHEN 1 THEN q.query#>'{Scope,Version}' END) THEN RAISE EXCEPTION 'comparison key child mismatch' USING ERRCODE='23514'; END IF;
  ELSIF NEW.source_ordinal IS NOT NULL OR NEW.child_id IS DISTINCT FROM NEW.batch_id THEN RAISE EXCEPTION 'legacy key child mismatch' USING ERRCODE='23514'; END IF;
  IF TG_OP='INSERT' THEN
   IF NEW.used_roles<>0 OR q.active_batch IS DISTINCT FROM NEW.batch_id THEN RAISE EXCEPTION 'query key binding unavailable' USING ERRCODE='23514'; END IF;
  ELSIF (to_jsonb(NEW)-'used_roles') IS DISTINCT FROM (to_jsonb(OLD)-'used_roles') OR (NEW.used_roles|OLD.used_roles)<>NEW.used_roles OR
   (NEW.used_roles#OLD.used_roles) NOT IN (1,2,4) OR q.active_batch IS DISTINCT FROM NEW.batch_id THEN RAISE EXCEPTION 'query key role already spent' USING ERRCODE='23514'; END IF;
  UPDATE public.context_query SET controls=controls+1 WHERE id=q.id;
 END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION guard_context_query_child() FROM PUBLIC;

-- +goose StatementBegin
CREATE FUNCTION guard_context_snapshot_completion() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
DECLARE e public.context_execution; w public.context_writer_completion;
BEGIN
 IF TG_WHEN='BEFORE' THEN
  IF TG_OP='INSERT' THEN
   IF NEW.snapshot_coverage IS NOT NULL THEN RAISE EXCEPTION 'snapshot completion cannot precede admission' USING ERRCODE='23514'; END IF;
  ELSIF ROW(NEW.snapshot_coverage,NEW.snapshot_coverage_digest,NEW.snapshot_expectation_digest) IS DISTINCT FROM ROW(OLD.snapshot_coverage,OLD.snapshot_coverage_digest,OLD.snapshot_expectation_digest) THEN
   IF OLD.snapshot_coverage IS NOT NULL OR NEW.snapshot_coverage IS NULL OR
    (convert_from(NEW.expectation_json,'UTF8')::jsonb)->'Snapshot' IS NULL OR
    (convert_from(NEW.expectation_json,'UTF8')::jsonb)->'Snapshot'='null'::jsonb THEN
    RAISE EXCEPTION 'immutable snapshot completion' USING ERRCODE='23514';
   END IF;
   SELECT * INTO STRICT e FROM public.context_execution WHERE root_id=NEW.root_id AND capture_id=NEW.id;
   IF e.phase<>'stored' OR e.attempt_id<>NEW.attempt_id OR e.writer_protocol<>'closed-small-context/v1' THEN
    RAISE EXCEPTION 'snapshot completion requires stored execution' USING ERRCODE='23514';
   END IF;
  END IF;
 ELSE
  IF NEW.snapshot_coverage IS NOT NULL THEN
   SELECT * INTO STRICT w FROM public.context_writer_completion WHERE root_id=NEW.root_id AND capture_id=NEW.id AND attempt_id=NEW.attempt_id;
   IF w.expectation_digest<>NEW.snapshot_expectation_digest THEN RAISE EXCEPTION 'snapshot completion requires joined writer' USING ERRCODE='23514'; END IF;
  END IF;
 END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION guard_context_snapshot_completion() FROM PUBLIC;

-- +goose StatementBegin
CREATE FUNCTION guard_context_writer_completion() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
DECLARE e public.context_execution; a public.custody_attempt; c public.context_capture;
BEGIN
 IF TG_WHEN<>'BEFORE' OR TG_LEVEL<>'ROW' OR TG_RELID<>'public.context_writer_completion'::regclass OR TG_OP<>'INSERT' THEN RAISE EXCEPTION 'immutable writer completion' USING ERRCODE='23514'; END IF;
 SELECT * INTO STRICT e FROM public.context_execution WHERE capture_id=NEW.capture_id AND root_id=NEW.root_id;
 SELECT * INTO STRICT a FROM public.custody_attempt WHERE id=NEW.attempt_id;
 SELECT * INTO STRICT c FROM public.context_capture WHERE id=NEW.capture_id AND root_id=NEW.root_id;
 IF (convert_from(c.expectation_json,'UTF8')::jsonb)->'Snapshot' IS NOT NULL AND (convert_from(c.expectation_json,'UTF8')::jsonb)->'Snapshot'<>'null'::jsonb AND c.snapshot_coverage IS NULL THEN RAISE EXCEPTION 'snapshot writer lacks coverage' USING ERRCODE='23514'; END IF;
 IF e.writer_protocol IS DISTINCT FROM 'closed-small-context/v1' OR e.phase<>'stored' OR a.state IN ('deleting','deleted') OR e.attempt_id<>a.id OR COALESCE(c.snapshot_expectation_digest,e.expectation_digest)<>NEW.expectation_digest OR e.copies_digest<>NEW.copies_digest OR a.request_digest<>NEW.registration_digest OR (convert_from(e.process_json,'UTF8')::jsonb)->>'InstallationID' IS DISTINCT FROM NEW.installation_id::text OR (convert_from(e.process_json,'UTF8')::jsonb)->>'IssuerEpoch' IS DISTINCT FROM NEW.issuer_epoch::text OR e.completed_at<>NEW.stored_at OR NEW.closed_at>clock_timestamp() OR NEW.recorded_at>clock_timestamp() OR NEW.stored_at>=a.write_until OR NOT public.incarnation_current(NEW.postmaster_at) OR NEW.database_oid<>(SELECT oid FROM pg_database WHERE datname=current_database()) OR NOT EXISTS(SELECT 1 FROM public.fleet_current_trust WHERE installation_id=NEW.installation_id AND issuer_epoch=NEW.issuer_epoch AND NOT suspended AND fresh_until>clock_timestamp()) THEN
  RAISE EXCEPTION 'writer completion lacks exact positive execution' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION guard_context_writer_completion() FROM PUBLIC;

-- +goose StatementBegin
CREATE FUNCTION guard_context_writer_protocol() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
BEGIN
 IF TG_OP='INSERT' AND NEW.writer_protocol IS DISTINCT FROM 'closed-small-context/v1' THEN
  RAISE EXCEPTION 'new API executions require positive writer protocol' USING ERRCODE='23514';
 END IF;
 IF TG_OP='UPDATE' AND NEW.writer_protocol IS DISTINCT FROM OLD.writer_protocol THEN
  RAISE EXCEPTION 'immutable writer protocol' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION guard_context_writer_protocol() FROM PUBLIC;

-- +goose StatementBegin
CREATE FUNCTION guard_custody_stream() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'streaming journal is retained with its attempt' USING ERRCODE='23514'; END IF;
 IF ROW(NEW.attempt_id,NEW.temporary_bytes,NEW.temporary_objects) IS DISTINCT FROM ROW(OLD.attempt_id,OLD.temporary_bytes,OLD.temporary_objects)
  OR NEW.revision<>OLD.revision+1 OR OLD.released_at IS NOT NULL
  OR (NEW.state->>'CreateSpent')::boolean IS DISTINCT FROM true AND (OLD.state->>'CreateSpent')::boolean=true
  OR (NEW.state->>'CompleteSpent')::boolean IS DISTINCT FROM true AND (OLD.state->>'CompleteSpent')::boolean=true THEN
  RAISE EXCEPTION 'streaming journal transition unavailable' USING ERRCODE='23514'; END IF;
 IF ROW(NEW.writer_epoch,NEW.plan_digest) IS DISTINCT FROM ROW(OLD.writer_epoch,OLD.plan_digest) THEN
  -- Exactly one immutable process binding, before any remote effect. No
  -- replacement after an unknown start and no binding while releasing.
  IF OLD.writer_epoch IS NOT NULL OR OLD.plan_digest IS NOT NULL OR NEW.writer_epoch IS NULL OR NEW.plan_digest IS NULL OR
   NEW.state IS DISTINCT FROM OLD.state OR NEW.released_at IS NOT NULL OR
   COALESCE((OLD.state->>'CreateSpent')::boolean,false) OR COALESCE((OLD.state->>'CompleteSpent')::boolean,false) THEN
   RAISE EXCEPTION 'streaming writer already bound or spent' USING ERRCODE='23514'; END IF;
 ELSIF NEW.writer_epoch IS NULL AND
   (NEW.released_at IS NULL OR (NEW.state->>'Aborted')::boolean IS DISTINCT FROM true OR COALESCE((NEW.state->>'CreateSpent')::boolean,false) OR COALESCE((NEW.state->>'CompleteSpent')::boolean,false)) THEN
  -- An unbound journal can only be retired after the existing fenced purge.
  RAISE EXCEPTION 'unbound streaming journal cannot start' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION guard_download_control_allocation() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
DECLARE a public.download_allocation;
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'download control lifecycle unavailable' USING ERRCODE='23514';END IF;
 IF TG_OP='INSERT' THEN
  SELECT * INTO STRICT a FROM public.download_allocation WHERE id=NEW.id AND root_id=NEW.root_id;
  IF NEW.reserved_windows<>0 OR NEW.reserved_audit_bytes<>0 OR NEW.valid_until>a.valid_until OR NEW.window_limit>((a.output_limit-1)/67108864+1)+1024 THEN RAISE EXCEPTION 'invalid download control backing' USING ERRCODE='23514';END IF;
 ELSIF pg_trigger_depth()<2 OR (to_jsonb(NEW)-ARRAY['reserved_windows','reserved_audit_bytes']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['reserved_windows','reserved_audit_bytes']) OR NEW.reserved_windows<=OLD.reserved_windows OR NEW.reserved_audit_bytes<>OLD.reserved_audit_bytes+(NEW.reserved_windows-OLD.reserved_windows)*262144 THEN
  RAISE EXCEPTION 'immutable source-managed download control backing' USING ERRCODE='23514';
 END IF;RETURN NEW;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION guard_download_control_allocation() FROM PUBLIC;

-- +goose StatementBegin
CREATE FUNCTION guard_download_key_spend() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
 IF (NEW.used_roles & OLD.used_roles) <> OLD.used_roles THEN
  RAISE EXCEPTION 'download key spend cannot decrease';
 END IF;
 RETURN NEW;
END; $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION guard_download_native_backing() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
DECLARE p jsonb;q jsonb;need_backup numeric;need_wal numeric;a public.download_allocation;
BEGIN
 IF TG_OP='DELETE' THEN
  IF clock_timestamp()<OLD.residual_until OR EXISTS(SELECT 1 FROM public.download_native_owner WHERE allocation_id=OLD.allocation_id) OR EXISTS(SELECT 1 FROM public.download_native_key WHERE allocation_id=OLD.allocation_id) THEN RAISE EXCEPTION 'native residual history still backed' USING ERRCODE='23514';END IF;RETURN OLD;
 END IF;
 IF TG_OP='UPDATE' THEN
  IF pg_trigger_depth()>=2 AND (to_jsonb(NEW)-ARRAY['residual_until','overdue']) IS NOT DISTINCT FROM (to_jsonb(OLD)-ARRAY['residual_until','overdue']) AND NEW.residual_until>=OLD.residual_until AND (NOT OLD.overdue OR NEW.overdue) THEN RETURN NEW;END IF;
  IF pg_trigger_depth()<2 OR (to_jsonb(NEW)-ARRAY['charged_rows','charged_keys']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['charged_rows','charged_keys']) OR NEW.charged_rows<OLD.charged_rows OR NEW.charged_keys<OLD.charged_keys OR (NEW.charged_rows-OLD.charged_rows)+(NEW.charged_keys-OLD.charged_keys)<>1 THEN RAISE EXCEPTION 'immutable native backing' USING ERRCODE='23514';END IF;RETURN NEW;
 END IF;
 SELECT * INTO STRICT a FROM public.download_allocation WHERE id=NEW.allocation_id AND root_id=NEW.root_id;
 p:=NEW.policy_json;q:=p->'History';
 IF NOT(p ?& ARRAY['AllocationID','RootID','PolicyID','PolicyDigest','Rows','Keys','TransitionsPerRow','BackupBytes','WALBytes','BackupHorizonSeconds','CleanupSeconds','ValidUntil','RetireBy','History']) OR jsonb_typeof(q) IS DISTINCT FROM 'object' OR NEW.charged_rows<>0 OR NEW.charged_keys<>0 OR NEW.residual_until<>NEW.retire_by OR NEW.overdue OR NEW.valid_until>a.valid_until OR NEW.valid_until<=clock_timestamp() OR (p->>'AllocationID')::uuid IS DISTINCT FROM NEW.allocation_id OR (p->>'RootID')::uuid IS DISTINCT FROM NEW.root_id OR (p->>'Rows')::bigint IS DISTINCT FROM NEW.rows_limit OR (p->>'Keys')::bigint IS DISTINCT FROM NEW.keys_limit OR (p->>'TransitionsPerRow')::bigint IS DISTINCT FROM NEW.transitions_per_row OR (p->>'BackupHorizonSeconds')::bigint IS DISTINCT FROM NEW.backup_horizon_seconds OR (p->>'CleanupSeconds')::bigint IS DISTINCT FROM NEW.cleanup_seconds OR (p->>'ValidUntil')::timestamptz IS DISTINCT FROM NEW.valid_until OR (p->>'RetireBy')::timestamptz IS DISTINCT FROM NEW.retire_by THEN RAISE EXCEPTION 'invalid native backing' USING ERRCODE='23514';END IF;
 IF NOT(q ?& ARRAY['ID','Digest','RowBytes','TransitionWALBytes','BackupCopies','WALCopies']) OR jsonb_typeof(q->'ID') IS DISTINCT FROM 'string' OR jsonb_typeof(q->'Digest') IS DISTINCT FROM 'array' OR NOT COALESCE((q->>'RowBytes')::bigint BETWEEN 65536 AND 16777216 AND (q->>'TransitionWALBytes')::bigint BETWEEN 65536 AND 67108864 AND (q->>'BackupCopies')::bigint BETWEEN 1 AND 64 AND (q->>'WALCopies')::bigint BETWEEN 1 AND 64,FALSE) THEN RAISE EXCEPTION 'native history qualification missing' USING ERRCODE='23514';END IF;
 need_backup:=2*(q->>'RowBytes')::numeric*(q->>'BackupCopies')::numeric*(NEW.rows_limit+NEW.keys_limit);
 need_wal:=(q->>'TransitionWALBytes')::numeric*(q->>'WALCopies')::numeric*((NEW.transitions_per_row+4)*NEW.rows_limit+8*NEW.keys_limit);
 IF NOT COALESCE((p->>'BackupBytes')::numeric>=need_backup AND (p->>'BackupBytes')::numeric<=9223372036854775807 AND (p->>'WALBytes')::numeric>=need_wal AND (p->>'WALBytes')::numeric<=9223372036854775807,FALSE) THEN RAISE EXCEPTION 'native history backing insufficient' USING ERRCODE='23514';END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION guard_download_native_backing() FROM PUBLIC;

-- +goose StatementBegin
CREATE FUNCTION guard_download_native_key() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
DECLARE b public.download_native_backing;o public.download_native_owner;w public.download_worker;s public.artifact_download;n timestamptz;
BEGIN
 IF TG_OP='DELETE' THEN
  SELECT * INTO STRICT b FROM public.download_native_backing WHERE allocation_id=OLD.allocation_id;
  SELECT * INTO STRICT o FROM public.download_native_owner WHERE worker_id=OLD.worker_id;
  SELECT * INTO STRICT w FROM public.download_worker WHERE id=OLD.worker_id;
  SELECT * INTO STRICT s FROM public.artifact_download WHERE id=w.session_id;
  b:=public.capacity_session_native(s,b);
  n:=clock_timestamp();
  IF o.retired_at IS NULL OR w.retired_proof_json IS NULL OR n<o.retired_at+make_interval(secs=>b.backup_horizon_seconds::double precision) THEN RAISE EXCEPTION 'native key history not quiescent' USING ERRCODE='23514';END IF;
  UPDATE public.download_native_backing SET residual_until=GREATEST(residual_until,n+make_interval(secs=>b.backup_horizon_seconds::double precision)),overdue=overdue OR n+make_interval(secs=>b.backup_horizon_seconds::double precision)>b.retire_by WHERE allocation_id=b.allocation_id;RETURN OLD;
 END IF;
 SELECT * INTO STRICT o FROM public.download_native_owner WHERE worker_id=NEW.worker_id;
 SELECT * INTO STRICT b FROM public.download_native_backing WHERE allocation_id=NEW.allocation_id FOR UPDATE;
 SELECT * INTO STRICT w FROM public.download_worker WHERE id=NEW.worker_id;
 SELECT * INTO STRICT s FROM public.artifact_download WHERE id=w.session_id;
 b:=public.capacity_session_native(s,b);
 n:=clock_timestamp();
 IF o.closed OR o.retired_at IS NOT NULL OR o.root_id<>NEW.root_id OR o.allocation_id<>NEW.allocation_id OR o.operation_id<>NEW.operation_id OR o.fence<>NEW.operation_fence OR NEW.valid_until>o.lease_until OR n>=NEW.valid_until OR NOT EXISTS(SELECT 1 FROM public.download_window win JOIN public.download_response r ON r.id=win.response_id JOIN public.artifact_download current_session ON current_session.id=r.session_id WHERE win.id=NEW.window_id AND r.id=(o.operation_json->>'ParentID')::uuid AND r.generation=(o.operation_json->>'Generation')::bigint AND r.generation=current_session.generation AND r.active_window=win.id AND NOT r.closed AND r.lease_until>=NEW.valid_until AND win.intent_receipt IS NOT NULL AND win.intent_completion IS NOT NULL AND win.outcome_json IS NULL AND NEW.authority_json->'Scope'=current_session.scope_json) THEN RAISE EXCEPTION 'native key current window unavailable' USING ERRCODE='23514';END IF;
 IF TG_OP='INSERT' THEN
  IF jsonb_typeof(NEW.authority_json->'ValidUntil') IS DISTINCT FROM 'string' OR jsonb_typeof(NEW.proof_json->'FreshUntil') IS DISTINCT FROM 'string' OR NEW.used_roles<>0 OR NEW.created_at>n OR NEW.valid_until>(NEW.authority_json->>'ValidUntil')::timestamptz OR NEW.valid_until>(NEW.proof_json->>'FreshUntil')::timestamptz OR NEW.installation_id IS DISTINCT FROM (o.operation_json#>>'{Reference,InstallationID}')::uuid OR NEW.peer_id IS DISTINCT FROM (o.operation_json->>'WorkerPodUID')::uuid THEN RAISE EXCEPTION 'native key identity mismatch' USING ERRCODE='23514';END IF;
  UPDATE public.download_native_backing SET charged_keys=charged_keys+1 WHERE allocation_id=b.allocation_id;
 ELSIF (to_jsonb(NEW)-'used_roles') IS DISTINCT FROM (to_jsonb(OLD)-'used_roles') OR NEW.used_roles=OLD.used_roles OR NEW.used_roles|OLD.used_roles<>NEW.used_roles OR (NEW.used_roles#OLD.used_roles) NOT IN (1,2,4) THEN RAISE EXCEPTION 'native key slots immutable' USING ERRCODE='23514';END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION guard_download_native_key() FROM PUBLIC;

-- +goose StatementBegin
CREATE FUNCTION guard_download_native_owner() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
DECLARE w public.download_worker;s public.artifact_download;b public.download_native_backing;e public.download_worker_enrollment;n timestamptz;o jsonb;ref jsonb;
BEGIN
 IF TG_OP='DELETE' THEN
  SELECT * INTO STRICT b FROM public.download_native_backing WHERE allocation_id=OLD.allocation_id;
  SELECT * INTO STRICT w FROM public.download_worker WHERE id=OLD.worker_id;
  SELECT * INTO STRICT s FROM public.artifact_download WHERE id=w.session_id;
  b:=public.capacity_session_native(s,b);
  n:=clock_timestamp();
  IF OLD.retired_at IS NULL OR w.retired_proof_json IS NULL OR n<OLD.retired_at+make_interval(secs=>b.backup_horizon_seconds::double precision) OR EXISTS(SELECT 1 FROM public.download_native_key WHERE worker_id=OLD.worker_id) THEN RAISE EXCEPTION 'native owner history not quiescent' USING ERRCODE='23514';END IF;
  UPDATE public.download_native_backing SET residual_until=GREATEST(residual_until,n+make_interval(secs=>b.backup_horizon_seconds::double precision)),overdue=overdue OR n+make_interval(secs=>b.backup_horizon_seconds::double precision)>b.retire_by WHERE allocation_id=b.allocation_id;RETURN OLD;
 END IF;
 SELECT * INTO STRICT w FROM public.download_worker WHERE id=NEW.worker_id;
 SELECT * INTO STRICT s FROM public.artifact_download WHERE id=w.session_id;
 SELECT * INTO STRICT b FROM public.download_native_backing WHERE allocation_id=NEW.allocation_id FOR UPDATE;
 b:=public.capacity_session_native(s,b);
 n:=clock_timestamp();o:=NEW.operation_json;ref:=o->'Reference';
 IF TG_OP='UPDATE' AND NEW.retired_at IS NOT NULL THEN
  IF OLD.retired_at IS NOT NULL OR w.retired_proof_json IS NULL OR NOT NEW.closed OR NEW.retired_at<>NEW.updated_at OR NEW.updated_at>n OR NEW.updates<>OLD.updates+1 OR (to_jsonb(NEW)-ARRAY['closed','retired_at','updated_at','updates']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['closed','retired_at','updated_at','updates']) OR NEW.updates>b.transitions_per_row THEN RAISE EXCEPTION 'invalid native owner retirement' USING ERRCODE='23514';END IF;RETURN NEW;
 END IF;
 IF TG_OP='UPDATE' AND NEW.closed THEN
  IF OLD.retired_at IS NOT NULL OR OLD.closed OR NEW.updates<>OLD.updates+1 OR NEW.updated_at>n OR (to_jsonb(NEW)-ARRAY['closed','updated_at','updates']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['closed','updated_at','updates']) OR NEW.updates>b.transitions_per_row-1 THEN RAISE EXCEPTION 'invalid native owner close' USING ERRCODE='23514';END IF;RETURN NEW;
 END IF;
 SELECT * INTO STRICT e FROM public.download_worker_enrollment WHERE worker_id=NEW.worker_id;
 IF jsonb_typeof(o->'StartedAt') IS DISTINCT FROM 'string' OR jsonb_typeof(o->'Until') IS DISTINCT FROM 'string' OR jsonb_typeof(NEW.authority_json->'ValidUntil') IS DISTINCT FROM 'string' OR n>=b.valid_until OR n>=NEW.lease_until OR NEW.lease_started>n OR NEW.updated_at<>NEW.lease_started OR NEW.updates>b.transitions_per_row-2 OR NEW.closed OR NEW.retired_at IS NOT NULL OR w.termination_json IS NOT NULL OR w.retired_proof_json IS NOT NULL OR w.audit_receipt_json IS NULL OR NEW.root_id<>w.root_id OR NEW.allocation_id<>w.allocation_id OR NEW.lease_until>w.run_until OR NEW.lease_until>s.deadline OR (ref->>'WorkerID')::uuid IS DISTINCT FROM NEW.worker_id OR (ref->>'SessionID')::uuid IS DISTINCT FROM s.id OR (ref->>'InstallationID')::uuid IS DISTINCT FROM w.installation_id OR (ref->>'OperationID')::uuid IS DISTINCT FROM NEW.operation_id OR (ref->>'Fence')::bigint IS DISTINCT FROM NEW.fence OR o->'SourceVersion' IS DISTINCT FROM NEW.authority_json#>'{Scope,Version}' OR NEW.authority_json->'Scope' IS DISTINCT FROM s.scope_json OR (NEW.authority_json->>'ValidUntil')::timestamptz<NEW.lease_until OR (o->>'Until')::timestamptz<NEW.lease_until OR (o->>'Until')::timestamptz>w.run_until OR (o->>'WorkerPodUID') IS DISTINCT FROM (convert_from(w.binding_json,'UTF8')::jsonb)->>'PodUID' OR o->'WorkerPublicKey' IS DISTINCT FROM (convert_from(e.enrollment_json,'UTF8')::jsonb)->'PublicKeyDigest' OR e.audit_receipt_json IS NULL THEN RAISE EXCEPTION 'native operation binding mismatch' USING ERRCODE='23514';END IF;
 IF o->>'Kind' IN ('prepare-context','observe-prepared-context') THEN
  IF NEW.lease_sequence<>1 OR (o->>'Until')::timestamptz>(o->>'StartedAt')::timestamptz+interval '5 seconds' OR NOT EXISTS(SELECT 1 FROM public.download_batch p WHERE p.id=(o->>'ParentID')::uuid AND p.session_id=s.id AND p.generation=(o->>'Generation')::bigint AND p.intent_json#>>'{Batch,Purpose}'='prepare' AND p.audit_receipt_json IS NOT NULL) THEN RAISE EXCEPTION 'native preparation parent unavailable' USING ERRCODE='23514';END IF;
 ELSIF o->>'Kind'='read-context-response' THEN
  IF NOT EXISTS(SELECT 1 FROM public.download_response r WHERE r.id=(o->>'ParentID')::uuid AND r.session_id=s.id AND r.generation=(o->>'Generation')::bigint AND r.generation=s.generation AND NOT r.closed AND r.lease_sequence=NEW.lease_sequence AND r.lease_until>=NEW.lease_until AND r.until_at>n) THEN RAISE EXCEPTION 'native response parent unavailable' USING ERRCODE='23514';END IF;
 ELSE RAISE EXCEPTION 'unknown native operation' USING ERRCODE='23514';END IF;
 IF TG_OP='INSERT' THEN
  IF NEW.fence<>1 OR NEW.updates<>1 THEN RAISE EXCEPTION 'native initial fence' USING ERRCODE='23514';END IF;
  UPDATE public.download_native_backing SET charged_rows=charged_rows+1 WHERE allocation_id=b.allocation_id;
 ELSE
  IF OLD.retired_at IS NOT NULL OR NEW.updates<>OLD.updates+1 OR ROW(NEW.worker_id,NEW.root_id,NEW.allocation_id) IS DISTINCT FROM ROW(OLD.worker_id,OLD.root_id,OLD.allocation_id) THEN RAISE EXCEPTION 'native immutable owner' USING ERRCODE='23514';END IF;
  IF NEW.operation_id=OLD.operation_id THEN
   IF OLD.closed OR NEW.operation_json IS DISTINCT FROM OLD.operation_json OR NEW.fence<>OLD.fence OR o->>'Kind'<>'read-context-response' OR NEW.lease_sequence<=OLD.lease_sequence THEN RAISE EXCEPTION 'native operation replay cannot renew' USING ERRCODE='23514';END IF;
  ELSIF NOT OLD.closed OR NEW.fence<>OLD.fence+1 THEN RAISE EXCEPTION 'native previous owner not closed' USING ERRCODE='23514';END IF;
 END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION guard_download_native_owner() FROM PUBLIC;

-- +goose StatementBegin
CREATE FUNCTION guard_download_response() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
DECLARE s public.artifact_download;c public.download_control_allocation;n timestamptz;used bigint;length bigint;off bigint;read_each bigint;win bigint;
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'download response lifecycle unavailable' USING ERRCODE='23514';END IF;
 IF TG_OP='INSERT' THEN
  SELECT * INTO STRICT s FROM public.artifact_download WHERE id=NEW.session_id AND root_id=NEW.root_id FOR UPDATE;
  SELECT * INTO STRICT c FROM public.download_control_allocation WHERE id=s.allocation_id AND root_id=s.root_id FOR UPDATE;
  c:=public.capacity_session_control(s,c);
  IF NOT (NEW.plan_json ?& ARRAY['Version','Selection','WholeFile','WindowReadLimit']) OR (NEW.plan_json-ARRAY['Version','Selection','WholeFile','WindowReadLimit'])<>'{}'::jsonb OR jsonb_typeof(NEW.plan_json->'Selection') IS DISTINCT FROM 'object' OR NOT ((NEW.plan_json->'Selection') ?& ARRAY['Offset','Length','Partial']) OR ((NEW.plan_json->'Selection')-ARRAY['Offset','Length','Partial'])<>'{}'::jsonb OR jsonb_typeof(NEW.plan_json->'WholeFile') IS DISTINCT FROM 'boolean' OR jsonb_typeof(NEW.plan_json#>'{Selection,Partial}') IS DISTINCT FROM 'boolean' THEN RAISE EXCEPTION 'closed native response plan required' USING ERRCODE='23514';END IF;
  n:=clock_timestamp();length:=(NEW.plan_json#>>'{Selection,Length}')::bigint;off:=(NEW.plan_json#>>'{Selection,Offset}')::bigint;read_each:=(NEW.plan_json->>'WindowReadLimit')::bigint;
  IF length IS NULL OR off IS NULL OR read_each IS NULL OR (NEW.plan_json->>'Version') IS DISTINCT FROM '1' OR length<0 OR length>1099511627776 OR off<0 OR off>1099511627776-length OR read_each<1 OR (NEW.plan_json->>'WholeFile')::boolean AND off<>0 OR (NEW.plan_json#>>'{Selection,Partial}')::boolean AND length=0 THEN RAISE EXCEPTION 'invalid native response plan' USING ERRCODE='23514';END IF;
  win:=greatest(1,(length+67108863)/67108864);
  SELECT coalesce(sum(reserved_windows),0) INTO used FROM public.download_response WHERE session_id=s.id;
  IF n>=c.valid_until OR n>=NEW.lease_until OR n>=NEW.until_at OR NEW.until_at>s.deadline OR NEW.until_at>c.valid_until OR NEW.started_at>n OR NEW.lease_until>NEW.started_at+interval '5 seconds' OR NEW.generation<>s.generation+1 OR s.state NOT IN ('Ready','Streaming','Interrupted') OR NEW.window_count<>0 OR NEW.completed_windows<>0 OR NEW.emitted_bytes<>0 OR NEW.active_window IS NOT NULL OR NEW.closed OR NEW.lease_sequence<>0 OR NEW.reserved_windows<>win OR read_each>70368744177664/win OR read_each*win>s.read_limit-s.charged_read OR length>s.output_limit-s.charged_output OR used+win>((s.output_limit-1)/67108864+1)+1024 THEN RAISE EXCEPTION 'download response unavailable' USING ERRCODE='23514';END IF;
  IF EXISTS(SELECT 1 FROM public.download_response WHERE session_id=s.id AND generation=s.generation AND NOT closed AND lease_until>n) OR EXISTS(SELECT 1 FROM public.download_batch WHERE id=s.active_batch AND lease_until>n AND outcome_json IS NULL) THEN RAISE EXCEPTION 'download response busy' USING ERRCODE='23514';END IF;
  UPDATE public.download_control_allocation SET reserved_windows=reserved_windows+win,reserved_audit_bytes=reserved_audit_bytes+win*262144 WHERE id=c.id;
 ELSE
  IF ROW(NEW.id,NEW.root_id,NEW.session_id,NEW.owner_id,NEW.generation,NEW.plan_json,NEW.reserved_windows,NEW.started_at,NEW.until_at) IS DISTINCT FROM ROW(OLD.id,OLD.root_id,OLD.session_id,OLD.owner_id,OLD.generation,OLD.plan_json,OLD.reserved_windows,OLD.started_at,OLD.until_at) OR NEW.window_count<OLD.window_count OR NEW.completed_windows<OLD.completed_windows OR NEW.emitted_bytes<OLD.emitted_bytes OR NEW.lease_sequence<OLD.lease_sequence OR OLD.closed AND NOT NEW.closed THEN RAISE EXCEPTION 'immutable native response' USING ERRCODE='23514';END IF;
  IF NEW.lease_sequence<>OLD.lease_sequence AND (NEW.lease_sequence<>OLD.lease_sequence+1 OR NEW.lease_until>clock_timestamp()+interval '5 seconds' OR OLD.closed) OR pg_trigger_depth()<2 AND NEW.lease_sequence=OLD.lease_sequence AND NEW.lease_until IS DISTINCT FROM OLD.lease_until THEN RAISE EXCEPTION 'invalid response lease transition' USING ERRCODE='23514';END IF;
  IF pg_trigger_depth()<2 AND ROW(NEW.window_count,NEW.completed_windows,NEW.emitted_bytes,NEW.active_window) IS DISTINCT FROM ROW(OLD.window_count,OLD.completed_windows,OLD.emitted_bytes,OLD.active_window) THEN RAISE EXCEPTION 'window-managed response accounting' USING ERRCODE='23514';END IF;
 END IF;RETURN NEW;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION guard_download_response() FROM PUBLIC;

-- +goose StatementBegin
CREATE FUNCTION guard_download_window() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
DECLARE r public.download_response;s public.artifact_download;c public.download_control_allocation;w jsonb;n timestamptz;amount bigint;read_bytes bigint;emitted bigint;success boolean;verified boolean;final boolean;
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'download window lifecycle unavailable' USING ERRCODE='23514';END IF;
 SELECT * INTO STRICT s FROM public.artifact_download WHERE id=NEW.session_id FOR UPDATE;
 SELECT * INTO STRICT r FROM public.download_response WHERE id=NEW.response_id AND session_id=NEW.session_id FOR UPDATE;
 n:=clock_timestamp();w:=NEW.intent_json->'Window';
 IF TG_OP='INSERT' THEN
  SELECT * INTO STRICT c FROM public.download_control_allocation WHERE id=s.allocation_id AND root_id=s.root_id;
  c:=public.capacity_session_control(s,c);
  IF jsonb_typeof(w) IS DISTINCT FROM 'object' OR NOT (w ?& ARRAY['ID','ResponseID','SessionID','OwnerID','AuditStoreID','Generation','Ordinal','Offset','Length','ReadLimit','StartedAt','WriteUntil','Authority','IntentAcknowledged','Outcome','OutcomeAcknowledged']) OR w->'IntentAcknowledged' IS DISTINCT FROM 'false'::jsonb OR w->'OutcomeAcknowledged' IS DISTINCT FROM 'false'::jsonb OR w->'Outcome' IS DISTINCT FROM 'null'::jsonb OR jsonb_typeof(w->'Authority') IS DISTINCT FROM 'object' OR NOT ((w->'Authority') ?& ARRAY['CheckedAt','ValidUntil','Scope']) OR NEW.intent_json#>'{Response,Plan}' IS DISTINCT FROM r.plan_json OR (NEW.intent_json#>>'{Response,ID}') IS DISTINCT FROM r.id::text OR (NEW.intent_json#>>'{Response,OwnerID}') IS DISTINCT FROM r.owner_id::text THEN RAISE EXCEPTION 'closed original window required' USING ERRCODE='23514';END IF;
  IF EXISTS(SELECT 1 FROM jsonb_each(w-'Outcome') AS v WHERE v.value='null'::jsonb) OR (w#>>'{Authority,CheckedAt}') IS NULL OR (w#>>'{Authority,ValidUntil}') IS NULL OR (w->>'StartedAt')::timestamptz>n OR (w#>>'{Authority,ValidUntil}')::timestamptz>(w#>>'{Authority,CheckedAt}')::timestamptz+interval '5 seconds' OR (w#>>'{Authority,Scope,RootID}') IS DISTINCT FROM s.root_id::text OR (w#>'{Authority,Scope}') IS DISTINCT FROM s.scope_json THEN RAISE EXCEPTION 'window scope/interval mismatch' USING ERRCODE='23514';END IF;
  amount:=(w->>'Length')::bigint;read_bytes:=(w->>'ReadLimit')::bigint;
  IF s.generation<>r.generation OR s.state NOT IN ('Ready','Streaming','Interrupted') OR r.closed OR r.active_window IS NOT NULL OR r.window_count<>r.completed_windows OR r.window_count>=r.reserved_windows OR NEW.ordinal<>r.window_count+1 OR (w->>'ID')::uuid<>NEW.id OR (w->>'ResponseID')::uuid<>r.id OR (w->>'SessionID')::uuid<>s.id OR (w->>'OwnerID')::uuid<>r.owner_id OR (w->>'Generation')::bigint<>r.generation OR (w->>'Ordinal')::bigint<>NEW.ordinal OR (w->>'AuditStoreID')::uuid<>c.audit_store_id OR (w->>'WriteUntil')::timestamptz<>c.audit_write_until OR (w->>'Offset')::bigint<>(r.plan_json#>>'{Selection,Offset}')::bigint+r.emitted_bytes OR amount<>least(67108864,(r.plan_json#>>'{Selection,Length}')::bigint-r.emitted_bytes) OR read_bytes<>(r.plan_json->>'WindowReadLimit')::bigint OR n>=r.until_at OR n>=(w#>>'{Authority,ValidUntil}')::timestamptz OR NEW.intent_receipt IS NOT NULL OR NEW.intent_completion IS NOT NULL OR NEW.outcome_completion IS NOT NULL OR NEW.outcome_json IS NOT NULL OR NEW.outcome_receipt IS NOT NULL THEN RAISE EXCEPTION 'download window unavailable' USING ERRCODE='23514';END IF;
  UPDATE public.artifact_download SET charged_output=charged_output+amount,charged_read=charged_read+read_bytes WHERE id=s.id;
  UPDATE public.download_response SET window_count=window_count+1,active_window=NEW.id,lease_until=least(until_at,(w#>>'{Authority,ValidUntil}')::timestamptz) WHERE id=r.id;
 ELSE
  IF ROW(NEW.id,NEW.response_id,NEW.session_id,NEW.ordinal,NEW.intent_json) IS DISTINCT FROM ROW(OLD.id,OLD.response_id,OLD.session_id,OLD.ordinal,OLD.intent_json) OR OLD.intent_receipt IS NOT NULL AND ROW(NEW.intent_receipt,NEW.intent_completion) IS DISTINCT FROM ROW(OLD.intent_receipt,OLD.intent_completion) OR OLD.outcome_json IS NOT NULL AND NEW.outcome_json IS DISTINCT FROM OLD.outcome_json OR OLD.outcome_receipt IS NOT NULL AND ROW(NEW.outcome_receipt,NEW.outcome_completion) IS DISTINCT FROM ROW(OLD.outcome_receipt,OLD.outcome_completion) THEN RAISE EXCEPTION 'immutable window/audit' USING ERRCODE='23514';END IF;
  IF OLD.outcome_json IS NULL AND NEW.outcome_json IS NOT NULL THEN
   emitted:=(NEW.outcome_json->>'EmittedBytes')::bigint;success:=(NEW.outcome_json->>'Success')::boolean;verified:=(NEW.outcome_json->>'VerifiedFinal')::boolean;
   IF NEW.intent_receipt IS NULL OR emitted IS NULL OR success IS NULL OR verified IS NULL OR emitted<0 OR emitted>(w->>'Length')::bigint OR success AND emitted<>(w->>'Length')::bigint OR verified AND (NOT success OR NEW.ordinal<>r.reserved_windows) THEN RAISE EXCEPTION 'invalid window outcome' USING ERRCODE='23514';END IF;
   UPDATE public.artifact_download SET emitted_bytes=emitted_bytes+emitted WHERE id=s.id;
  END IF;
  IF OLD.outcome_receipt IS NULL AND NEW.outcome_receipt IS NOT NULL THEN
   emitted:=(NEW.outcome_json->>'EmittedBytes')::bigint;success:=(NEW.outcome_json->>'Success')::boolean;verified:=(NEW.outcome_json->>'VerifiedFinal')::boolean;final:=NEW.ordinal=r.reserved_windows;
   IF r.active_window IS DISTINCT FROM NEW.id OR r.completed_windows+1<>NEW.ordinal OR (w->>'Offset')::bigint<>(r.plan_json#>>'{Selection,Offset}')::bigint+r.emitted_bytes THEN RAISE EXCEPTION 'noncontiguous outcome acknowledgement' USING ERRCODE='23514';END IF;
   UPDATE public.download_response SET completed_windows=completed_windows+1,emitted_bytes=emitted_bytes+emitted,active_window=NULL,closed=closed OR NOT success OR final OR n>=until_at WHERE id=r.id;
   IF s.generation=r.generation AND s.state NOT IN ('Completed','Cancelled','Expired','Denied','Failed') THEN
    IF n>=s.deadline OR n>=r.until_at THEN UPDATE public.artifact_download SET state='Expired' WHERE id=s.id;
    ELSIF NOT success OR final THEN UPDATE public.artifact_download SET state=CASE WHEN final AND success AND verified AND (r.plan_json->>'WholeFile')::boolean AND r.emitted_bytes+emitted=(r.plan_json#>>'{Selection,Length}')::bigint THEN 'Completed' ELSE 'Interrupted' END WHERE id=s.id;
    END IF;
   END IF;
  END IF;
 END IF;RETURN NEW;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION guard_download_window() FROM PUBLIC;

-- +goose StatementBegin
CREATE FUNCTION guard_download_worker() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
 IF ROW(NEW.id,NEW.session_id,NEW.query_id,NEW.root_id,NEW.installation_id,NEW.allocation_id,NEW.query_allocation_id,NEW.baseline_query_allocation_id,NEW.generation,NEW.intent_json,NEW.run_until)
 IS DISTINCT FROM ROW(OLD.id,OLD.session_id,OLD.query_id,OLD.root_id,OLD.installation_id,OLD.allocation_id,OLD.query_allocation_id,OLD.baseline_query_allocation_id,OLD.generation,OLD.intent_json,OLD.run_until)
 OR (OLD.audit_receipt_json IS NOT NULL AND NEW.audit_receipt_json IS DISTINCT FROM OLD.audit_receipt_json)
 OR (OLD.claimed_at IS NOT NULL AND NEW.claimed_at IS DISTINCT FROM OLD.claimed_at)
 OR (OLD.job_json IS NOT NULL AND NEW.job_json IS DISTINCT FROM OLD.job_json)
 OR (OLD.binding_json IS NOT NULL AND NEW.binding_json IS DISTINCT FROM OLD.binding_json)
 OR (OLD.termination_json IS NOT NULL AND NEW.termination_json IS DISTINCT FROM OLD.termination_json)
 OR (OLD.retired_proof_json IS NOT NULL AND NEW.retired_proof_json IS DISTINCT FROM OLD.retired_proof_json)
 OR (OLD.abandoned_at IS NOT NULL AND NEW.abandoned_at IS DISTINCT FROM OLD.abandoned_at)
 OR (NEW.abandoned_at IS NOT NULL AND clock_timestamp()<NEW.run_until) THEN
  RAISE EXCEPTION 'acquisition worker identity and consumed transitions are immutable';
 END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION guard_download_worker_owner() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
 IF TG_OP='INSERT' OR NEW.fence<>OLD.fence THEN
  IF NEW.started_at>clock_timestamp() OR NEW.expires_at<=clock_timestamp() THEN
   RAISE EXCEPTION 'worker owner starts only within its original finite interval';
  END IF;
 END IF;
 IF NEW.released_at>clock_timestamp() THEN
  RAISE EXCEPTION 'worker owner release cannot be future dated';
 END IF;
 IF TG_OP='INSERT' THEN RETURN NEW; END IF;
 IF NEW.worker_id IS DISTINCT FROM OLD.worker_id THEN
  RAISE EXCEPTION 'worker owner identity is immutable';
 END IF;
 IF NEW.fence = OLD.fence THEN
  IF ROW(NEW.request_id,NEW.pod_uid,NEW.process_epoch,NEW.started_at,NEW.expires_at)
   IS DISTINCT FROM ROW(OLD.request_id,OLD.pod_uid,OLD.process_epoch,OLD.started_at,OLD.expires_at)
   OR (OLD.released_at IS NOT NULL AND NEW.released_at IS DISTINCT FROM OLD.released_at) THEN
   RAISE EXCEPTION 'worker owner lease cannot be renewed or revived';
  END IF;
 ELSE
  IF NEW.fence <> OLD.fence+1 OR NEW.request_id=OLD.request_id
   OR (OLD.released_at IS NULL AND clock_timestamp()<OLD.expires_at)
   OR NEW.started_at<OLD.started_at OR NEW.released_at IS NOT NULL THEN
   RAISE EXCEPTION 'worker owner replacement requires a finished fence and fresh request';
  END IF;
 END IF;
 RETURN NEW;
END; $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION guard_history_custody_settlement() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
DECLARE h public.capture_history_parameter;
BEGIN
 SELECT * INTO h FROM public.capture_history_parameter WHERE attempt_id=OLD.id;
 IF NOT FOUND THEN RETURN NEW;END IF;
 -- Ordinary evidence cleanup must not certify absence under v1/ while these
 -- objects live under history/v1/. Only typed physical purge can settle them.
 IF NEW.state='deleting' AND (h.state<>'deleting' OR h.delete_fence IS DISTINCT FROM NEW.deletion_fence OR h.delete_until IS DISTINCT FROM NEW.lease_until) THEN
  RAISE EXCEPTION 'history deletion claim not bound' USING ERRCODE='23514';END IF;
 IF NEW.state='deleted' AND OLD.state<>'deleted' AND (h.state<>'deleting' OR h.purge_completion_json IS NULL) THEN
  RAISE EXCEPTION 'history physical purge not acknowledged' USING ERRCODE='23514';END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION guard_history_custody_settlement() FROM PUBLIC;

-- +goose StatementBegin
CREATE FUNCTION guard_owner_certificate() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE parent hub_owner_enrollment;
BEGIN
 IF TG_OP='DELETE' THEN
  IF clock_timestamp()<OLD.not_after+interval '1 minute' THEN
   RAISE EXCEPTION 'owner signing spend cannot be refunded before expiry';
  END IF;
  RETURN OLD;
 END IF;
 IF TG_OP='INSERT' THEN
  SELECT * INTO parent FROM hub_owner_enrollment WHERE id=NEW.enrollment_id FOR UPDATE;
  IF NOT FOUND OR parent.retired_at IS NOT NULL OR parent.audit_receipt_json IS NULL
  OR NEW.epoch<parent.highest_epoch OR NEW.epoch<>floor((extract(epoch FROM clock_timestamp())+60)/1200)
  OR NEW.not_after<>to_timestamp((NEW.epoch+1)*1200)
  OR NEW.ordinal<>(SELECT count(*)+1 FROM hub_owner_certificate WHERE enrollment_id=NEW.enrollment_id AND epoch=NEW.epoch)
  OR NEW.certificate_json IS NOT NULL OR NEW.audit_receipt_json IS NOT NULL OR NEW.activated_at IS NOT NULL THEN
   RAISE EXCEPTION 'owner signing attempt must be current, audited and next bounded ordinal';
  END IF;
  UPDATE hub_owner_enrollment SET highest_epoch=NEW.epoch,hold_until=greatest(hold_until,NEW.not_after+interval '1 minute') WHERE id=NEW.enrollment_id;
 ELSE
  IF ROW(NEW.id,NEW.enrollment_id,NEW.epoch,NEW.ordinal,NEW.not_after,NEW.attempt_json)
  IS DISTINCT FROM ROW(OLD.id,OLD.enrollment_id,OLD.epoch,OLD.ordinal,OLD.not_after,OLD.attempt_json)
  OR (OLD.certificate_json IS NOT NULL AND ROW(NEW.certificate_json,NEW.certificate_sha256) IS DISTINCT FROM ROW(OLD.certificate_json,OLD.certificate_sha256))
  OR (OLD.audit_receipt_json IS NOT NULL AND NEW.audit_receipt_json IS DISTINCT FROM OLD.audit_receipt_json)
  OR (OLD.activated_at IS NOT NULL AND NEW.activated_at IS DISTINCT FROM OLD.activated_at) THEN
   RAISE EXCEPTION 'owner certificate attempt and results are immutable';
  END IF;
 END IF;
 RETURN NEW;
END; $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION guard_owner_configuration_head() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
 IF NEW.observed_at>clock_timestamp() THEN
  RAISE EXCEPTION 'owner configuration observation cannot be in the future';
 END IF;
 IF TG_OP='INSERT' THEN
  IF NEW.generation<>0 OR NEW.fresh_until>NEW.observed_at THEN
   RAISE EXCEPTION 'owner configuration starts unavailable';
  END IF;
 ELSE
  IF ROW(NEW.installation_id,NEW.cluster_id,NEW.source_uid) IS DISTINCT FROM ROW(OLD.installation_id,OLD.cluster_id,OLD.source_uid)
  OR NEW.generation<OLD.generation OR NEW.observed_at<OLD.observed_at
  OR (NEW.observed_at=OLD.observed_at AND NEW.fresh_until>OLD.fresh_until) THEN
   RAISE EXCEPTION 'owner configuration identity, revision and original deadline cannot roll back or renew';
  END IF;
  IF NEW.generation>OLD.generation AND NOT EXISTS (
   SELECT FROM hub_owner_configuration_revision WHERE installation_id=NEW.installation_id AND cluster_id=NEW.cluster_id AND source_uid=NEW.source_uid AND generation=NEW.generation
  ) THEN
   RAISE EXCEPTION 'owner configuration revision must be recorded first';
  END IF;
 END IF;
 RETURN NEW;
END; $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION guard_owner_configuration_revision() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
 IF TG_OP='INSERT' THEN
  PERFORM 1 FROM hub_owner_configuration WHERE installation_id=NEW.installation_id AND cluster_id=NEW.cluster_id AND source_uid=NEW.source_uid FOR UPDATE;
  IF NOT FOUND OR NEW.audit_receipt_json IS NOT NULL OR (
   SELECT count(*) FROM hub_owner_configuration_revision WHERE installation_id=NEW.installation_id AND cluster_id=NEW.cluster_id AND source_uid=NEW.source_uid
  )>=1024 THEN
   RAISE EXCEPTION 'owner configuration revision capacity or initial state invalid';
  END IF;
 ELSE
  IF ROW(NEW.installation_id,NEW.cluster_id,NEW.source_uid,NEW.generation,NEW.snapshot_json)
  IS DISTINCT FROM ROW(OLD.installation_id,OLD.cluster_id,OLD.source_uid,OLD.generation,OLD.snapshot_json)
  OR (OLD.audit_receipt_json IS NOT NULL AND NEW.audit_receipt_json IS DISTINCT FROM OLD.audit_receipt_json) THEN
   RAISE EXCEPTION 'owner configuration revision and audit are immutable';
  END IF;
 END IF;
 RETURN NEW;
END; $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION guard_owner_enrollment() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
 IF TG_OP='DELETE' THEN
  IF clock_timestamp()<OLD.hold_until THEN
   RAISE EXCEPTION 'owner registration still holds possible live certificates';
  END IF;
  RETURN OLD;
 END IF;
 IF TG_OP='INSERT' THEN
  PERFORM 1 FROM hub_owner_configuration WHERE installation_id=NEW.installation_id AND cluster_id=NEW.cluster_id FOR UPDATE;
  IF NOT FOUND OR NEW.audit_receipt_json IS NOT NULL OR NEW.retired_at IS NOT NULL OR NEW.highest_epoch<>-1
  OR NEW.created_at>clock_timestamp() OR NEW.created_at<clock_timestamp()-interval '5 seconds'
  OR NEW.hold_until<>to_timestamp((floor((extract(epoch FROM NEW.created_at)+60)/1200)+1)*1200)+interval '1 minute'
  OR (SELECT count(*) FROM hub_owner_enrollment WHERE installation_id=NEW.installation_id AND cluster_id=NEW.cluster_id)>=1024
  OR (SELECT count(*) FROM hub_owner_enrollment WHERE installation_id=NEW.installation_id AND cluster_id=NEW.cluster_id AND pod_uid=NEW.pod_uid)>=32 THEN
   RAISE EXCEPTION 'owner registration capacity or initial state invalid';
  END IF;
 ELSE
  IF ROW(NEW.id,NEW.installation_id,NEW.cluster_id,NEW.issuer_epoch,NEW.pod_uid,NEW.process_epoch,NEW.usage,NEW.enrollment_json,NEW.created_at)
  IS DISTINCT FROM ROW(OLD.id,OLD.installation_id,OLD.cluster_id,OLD.issuer_epoch,OLD.pod_uid,OLD.process_epoch,OLD.usage,OLD.enrollment_json,OLD.created_at)
  OR (OLD.audit_receipt_json IS NOT NULL AND NEW.audit_receipt_json IS DISTINCT FROM OLD.audit_receipt_json)
  OR (OLD.retired_at IS NOT NULL AND NEW.retired_at IS DISTINCT FROM OLD.retired_at)
  OR NEW.highest_epoch<OLD.highest_epoch OR NEW.hold_until<OLD.hold_until
  OR (NEW.hold_until>OLD.hold_until AND (OLD.retired_at IS NOT NULL OR NEW.hold_until>clock_timestamp()+interval '22 minutes')) THEN
   RAISE EXCEPTION 'owner identity, audit, retirement and consumed periods are immutable';
  END IF;
 END IF;
 RETURN NEW;
END; $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION guard_policy_recording_source() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
BEGIN
 IF TG_OP='DELETE' THEN
  RAISE EXCEPTION 'source retirement requires qualified retained metadata protocol' USING ERRCODE='23514';
 ELSIF TG_OP='UPDATE' THEN
  -- Terminal/quarantine clocks belong to the row-owning database operation,
  -- never to a caller-provided timestamp or pre-lock SQL projection.
  IF OLD.ended_at IS NULL AND NEW.ended_at IS NOT NULL THEN NEW.ended_at:=clock_timestamp(); END IF;
  IF OLD.slot_released_at IS NULL AND NEW.slot_released_at IS NOT NULL THEN NEW.slot_released_at:=clock_timestamp(); END IF;
  IF (to_jsonb(NEW)-ARRAY['credit','ended_at','slot_released_at']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['credit','ended_at','slot_released_at']) OR
   NEW.credit<OLD.credit OR (OLD.ended_at IS NOT NULL AND (NEW.credit<>OLD.credit OR NEW.ended_at IS DISTINCT FROM OLD.ended_at)) OR
   (OLD.slot_released_at IS NOT NULL AND NEW.slot_released_at IS DISTINCT FROM OLD.slot_released_at) THEN
   RAISE EXCEPTION 'immutable source binding or decreasing/terminal credit' USING ERRCODE='23514';
  END IF;
  IF NEW.credit<>OLD.credit AND (OLD.ended_at IS NOT NULL OR clock_timestamp()>=OLD.hard_until) THEN
   RAISE EXCEPTION 'ended source cannot gain credit' USING ERRCODE='23514';
  END IF;
  IF NEW.slot_released_at IS NOT NULL AND NEW.slot_released_at>clock_timestamp() THEN
   RAISE EXCEPTION 'source slot release cannot anticipate closure' USING ERRCODE='23514';
  END IF;
 ELSE
  IF NEW.ended_at IS NOT NULL OR NEW.slot_released_at IS NOT NULL OR clock_timestamp()<NEW.started_at OR clock_timestamp()>=NEW.start_by OR
   NOT EXISTS(SELECT 1 FROM public.policy_acceptance a WHERE a.id=NEW.acceptance_id AND a.root_id=NEW.root_id AND a.policy_uid=NEW.policy_uid AND a.acknowledged_at IS NOT NULL) THEN
   RAISE EXCEPTION 'source first start interval unavailable' USING ERRCODE='23514';
  END IF;
 END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION guard_policy_recording_source() FROM PUBLIC;

-- +goose StatementBegin
CREATE FUNCTION guard_policy_source_original_provenance() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
BEGIN
 IF TG_TABLE_SCHEMA<>'public' OR TG_RELID<>'public.policy_recording_source'::regclass OR TG_WHEN<>'BEFORE' OR TG_LEVEL<>'ROW' OR TG_OP<>'INSERT' THEN
  RAISE EXCEPTION 'invalid original source provenance operation' USING ERRCODE='23514';
 END IF;
 -- RootMetadataQualification and SQL54 require at least 128KiB per record.
 -- Keep 16KiB for page/index overhead; this reuses the existing source charge.
 IF NEW.source_audience_json IS NULL OR NEW.source_audience_digest IS NULL OR NEW.source_target_json IS NULL OR
  public.connector_digest(NEW.binding_json->'AudienceDigest') IS DISTINCT FROM NEW.source_audience_digest OR
  NEW.source_target_json->>'SourceID' IS DISTINCT FROM NEW.id::text OR NEW.source_target_json->>'Fence' IS DISTINCT FROM NEW.fence::text OR
  NEW.source_target_json#>>'{Request,ClusterID}' IS DISTINCT FROM NEW.cluster_id::text OR
  NEW.source_target_json#>>'{Request,Namespace,UID}' IS DISTINCT FROM NEW.namespace_uid OR
  NEW.source_target_json#>>'{Request,Workload,UID}' IS DISTINCT FROM NEW.workload_uid OR
  NEW.source_target_json#>>'{Request,PodUID}' IS DISTINCT FROM NEW.pod_uid OR pg_column_size(NEW)>114688 THEN
  RAISE EXCEPTION 'original source provenance or backed record size unavailable' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION guard_policy_source_original_provenance() FROM PUBLIC;

-- +goose StatementBegin
CREATE FUNCTION guard_processing_decision() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
DECLARE p public.processing_root; r public.processing_rule; n timestamptz; a_erasure public.custody_attempt;
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'processing decision retirement requires independent completion' USING ERRCODE='23514'; END IF;
 -- Lock recovery before the permission/processing and storage locks for the erasure action.
 IF NEW.action='request_early_erasure' THEN
  PERFORM 1 FROM public.fleet_current_trust f WHERE f.installation_id=(SELECT installation_id FROM public.processing_root WHERE root_id=NEW.root_id) FOR SHARE;
 END IF;
 PERFORM 1 FROM public.permission_stream WHERE id=NEW.root_id FOR UPDATE;
 SELECT * INTO STRICT p FROM public.processing_root WHERE root_id=NEW.root_id FOR UPDATE;
 IF NEW.rule_id IS NOT NULL THEN SELECT * INTO STRICT r FROM public.processing_rule WHERE root_id=NEW.root_id AND id=NEW.rule_id FOR UPDATE; END IF;
 n:=clock_timestamp();
 IF TG_OP='INSERT' THEN
  IF NEW.valid_until IS NOT NULL OR NEW.retire_by IS NOT NULL THEN RAISE EXCEPTION 'processing decision dates are source owned' USING ERRCODE='23514'; END IF;
  NEW.valid_until:=p.valid_until; NEW.retire_by:=p.retire_by;
  IF NEW.rule_id IS NOT NULL THEN NEW.valid_until:=r.valid_until; NEW.retire_by:=r.retire_by; END IF;
  IF n>=NEW.valid_until OR NEW.request_until>NEW.valid_until OR n<NEW.created_at OR n>=NEW.request_until OR n>=p.valid_until OR NEW.applied_at IS NOT NULL OR NEW.result_revision IS NOT NULL OR NEW.result_sequence IS NOT NULL THEN
   RAISE EXCEPTION 'invalid prepared processing decision' USING ERRCODE='23514'; END IF;
  IF NEW.action='initialize_processing' THEN
   IF p.initialized_at IS NOT NULL OR NEW.expected_revision<>0 OR p.root_transitions>=p.max_root_transitions OR EXISTS(SELECT 1 FROM public.context_catalog WHERE root_id=NEW.root_id) THEN
    RAISE EXCEPTION 'processing completeness needs empty reviewed history' USING ERRCODE='23514'; END IF;
   UPDATE public.processing_root SET root_transitions=root_transitions+1 WHERE root_id=NEW.root_id;
  ELSIF NEW.action='request_early_erasure' THEN
   IF p.root_transitions+2>=p.max_root_transitions THEN RAISE EXCEPTION 'processing erasure capacity unavailable' USING ERRCODE='23514'; END IF;
   IF EXISTS(SELECT 1 FROM public.processing_decision d WHERE d.root_id=NEW.root_id AND d.action=NEW.action
       AND d.scope#>>'{Location,AttemptID}'=NEW.scope#>>'{Location,AttemptID}' AND (d.applied_at IS NOT NULL OR d.request_until>n)) THEN
    RAISE EXCEPTION 'processing erasure already requested' USING ERRCODE='23505'; END IF;
   PERFORM public.processing_erasure_attempt(NEW,p);
   SELECT LEAST(p.retire_by,l.retire_by) INTO STRICT NEW.retire_by FROM public.context_processing l
    WHERE l.root_id=NEW.root_id AND l.artifact_id=(NEW.scope#>>'{Location,ArtifactID}')::uuid;
   NEW.valid_until:=LEAST(p.valid_until,NEW.retire_by-interval '1 microsecond');
   IF NEW.request_until>NEW.valid_until THEN RAISE EXCEPTION 'processing erasure original retention ended' USING ERRCODE='23514'; END IF;
   -- Two backed root-transition units cover the decision and cutoff. Keep one existing unit for backed root renewal.
   UPDATE public.processing_root SET root_transitions=root_transitions+2 WHERE root_id=NEW.root_id;
   IF clock_timestamp()>=NEW.request_until THEN RAISE EXCEPTION 'processing erasure expired after reserve' USING ERRCODE='23514'; END IF;
  ELSE
   IF p.initialized_at IS NULL OR NOT public.processing_scope_valid(NEW.scope) OR NEW.scope IS DISTINCT FROM r.scope OR NEW.expected_revision<>r.revision OR r.decisions>=16 OR
      (NEW.action='restrict_processing' AND (r.revision%2<>0 OR r.decisions>=15)) OR
      (NEW.action='release_processing' AND (r.revision%2<>1 OR r.state<>'restricted')) OR
      (NEW.action='restrict_processing' AND EXISTS(SELECT 1 FROM public.context_processing c WHERE c.root_id=NEW.root_id AND c.delete_by>r.valid_until AND
       ((r.scope->>'Kind'='artifact' AND c.artifact_id=(r.scope#>>'{Location,ArtifactID}')::uuid AND c.attempt_id=(r.scope#>>'{Location,AttemptID}')::uuid AND c.cluster_id=(r.scope#>>'{Location,ClusterID}')::uuid) OR
        (r.scope->>'Kind'='workloadInterval' AND c.cluster_id=(r.scope->>'ClusterID')::uuid AND c.namespace_uid=r.scope->>'NamespaceUID' AND c.workload_uid=r.scope->>'WorkloadUID' AND c.anchor_at>=(r.scope->>'AcquiredFrom')::timestamptz AND c.anchor_at<(r.scope->>'AcquiredUntil')::timestamptz)))) OR
      EXISTS(SELECT 1 FROM public.processing_decision d WHERE d.root_id=NEW.root_id AND d.rule_id=NEW.rule_id AND d.applied_at IS NULL AND d.request_until>n) THEN
    RAISE EXCEPTION 'processing decision scope or capacity unavailable' USING ERRCODE='23514'; END IF;
   UPDATE public.processing_rule SET decisions=decisions+1 WHERE root_id=NEW.root_id AND id=NEW.rule_id;
  END IF;
 ELSE
  IF (to_jsonb(NEW)-ARRAY['applied_at','result_revision','result_sequence']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['applied_at','result_revision','result_sequence']) OR OLD.applied_at IS NOT NULL OR NEW.applied_at IS NULL OR n>=NEW.request_until OR n>=NEW.valid_until OR n>=p.valid_until THEN
   RAISE EXCEPTION 'immutable or expired processing decision' USING ERRCODE='23514'; END IF;
  IF NEW.action='request_early_erasure' THEN a_erasure:=public.processing_erasure_attempt(NEW,p); END IF;
  n:=clock_timestamp();
  IF NEW.action='initialize_processing' THEN
   IF p.initialized_at IS NOT NULL OR EXISTS(SELECT 1 FROM public.context_catalog WHERE root_id=NEW.root_id) THEN RAISE EXCEPTION 'processing history changed during review' USING ERRCODE='23514'; END IF;
   UPDATE public.processing_root SET initialized_at=n,initialization_id=NEW.id,sequence=sequence+1 WHERE root_id=NEW.root_id;
   NEW.result_revision:=0;
  ELSIF NEW.action='request_early_erasure' THEN
   INSERT INTO public.retention_decision(id,root_id,attempt_id,sequence,previous_expires_at,previous_delete_by,expires_at,delete_by,decision_digest,decision_json)
    VALUES(NEW.id,NEW.root_id,a_erasure.id,a_erasure.retention_sequence+1,a_erasure.effective_expires_at,a_erasure.effective_delete_by,
           a_erasure.anchor_at,a_erasure.effective_delete_by,sha256(NEW.erasure_decision),NEW.erasure_decision);
   UPDATE public.custody_attempt SET effective_expires_at=a_erasure.anchor_at,retention_sequence=a_erasure.retention_sequence+1 WHERE id=a_erasure.id;
   NEW.result_revision:=0;
  ELSE
   IF p.initialized_at IS NULL OR r.revision<>NEW.expected_revision OR r.scope IS DISTINCT FROM NEW.scope OR
      (NEW.action='release_processing' AND r.state<>'restricted') OR (NEW.action='restrict_processing' AND r.state NOT IN ('reserved','released')) THEN
    RAISE EXCEPTION 'processing decision CAS changed' USING ERRCODE='23514'; END IF;
   UPDATE public.processing_rule SET revision=revision+1,state=CASE WHEN NEW.action='release_processing' THEN 'released' ELSE 'restricted' END,current_decision=NEW.id WHERE root_id=NEW.root_id AND id=NEW.rule_id;
   UPDATE public.processing_root SET sequence=sequence+1 WHERE root_id=NEW.root_id;
   NEW.result_revision:=r.revision+1;
  END IF;
  -- Nested counter/rule triggers can wait. Recheck the original decision interval after those writes as well;
  -- an expiry rolls back every nested effect in this transaction.
  n:=clock_timestamp();
  IF n>=NEW.request_until OR n>=NEW.valid_until OR n>=p.valid_until THEN RAISE EXCEPTION 'processing decision expired after nested locks' USING ERRCODE='23514'; END IF;
  IF NEW.action='request_early_erasure' AND NOT EXISTS(SELECT 1 FROM public.fleet_current_trust t
      WHERE t.installation_id=p.installation_id AND t.issuer_epoch=p.issuer_epoch AND NOT t.suspended
       AND t.observed_at<=n AND n<t.fresh_until) THEN
   RAISE EXCEPTION 'processing erasure recovery expired after apply' USING ERRCODE='23514'; END IF;
  NEW.applied_at:=n; NEW.result_sequence:=CASE WHEN NEW.action='request_early_erasure' THEN p.sequence ELSE p.sequence+1 END;
 END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION guard_processing_decision() FROM PUBLIC;

-- +goose StatementBegin
CREATE FUNCTION guard_processing_root() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
DECLARE n timestamptz; q jsonb; rows numeric; transitions numeric; h bigint; b bigint;
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'processing retirement requires independent completion' USING ERRCODE='23514'; END IF;
 PERFORM 1 FROM public.permission_stream WHERE id=NEW.root_id FOR UPDATE;
 n:=clock_timestamp(); q:=NEW.backing->'History';
 IF NOT (NEW.backing ?& ARRAY['RootID','InstallationID','PolicyID','BackupIdentity','PolicyDigest','BackupDigest','History','MaxCaptures','MaxRules','MaxRootTransitions','BackupBytes','WALBytes','BackupHorizonSeconds','CleanupSeconds','ValidUntil','RetireBy']) OR
    jsonb_typeof(q) IS DISTINCT FROM 'object' OR NOT (q ?& ARRAY['Format','ID','Digest','RowBytes','TransitionWALBytes','BackupCopies','WALCopies']) OR
    NEW.backing->>'RootID' IS DISTINCT FROM NEW.root_id::text OR NEW.backing->>'InstallationID' IS DISTINCT FROM NEW.installation_id::text OR
    q->>'Format' IS DISTINCT FROM 'context-processing-history/v1' OR
    (q->>'ID')::uuid IS NULL OR (NEW.backing->>'PolicyID')::uuid IS NULL OR (NEW.backing->>'BackupIdentity')::uuid IS NULL OR
    jsonb_array_length(q->'Digest')<>32 OR jsonb_array_length(NEW.backing->'PolicyDigest')<>32 OR jsonb_array_length(NEW.backing->'BackupDigest')<>32 OR
    coalesce((q->>'RowBytes')::bigint,0) NOT BETWEEN 16384 AND 16777216 OR
    coalesce((q->>'TransitionWALBytes')::bigint,0) NOT BETWEEN 65536 AND 67108864 OR
    coalesce((q->>'BackupCopies')::bigint,0) NOT BETWEEN 1 AND 64 OR coalesce((q->>'WALCopies')::bigint,0) NOT BETWEEN 1 AND 64 THEN
  RAISE EXCEPTION 'unqualified processing backing' USING ERRCODE='23514'; END IF;
 h:=(NEW.backing->>'BackupHorizonSeconds')::bigint; b:=(NEW.backing->>'CleanupSeconds')::bigint;
 rows:=1+NEW.max_root_transitions+NEW.max_captures+17*NEW.max_rules;
 transitions:=4*NEW.max_root_transitions+2*NEW.max_captures+130*NEW.max_rules;
 IF h IS NULL OR h NOT BETWEEN 0 AND 316224000 OR b IS NULL OR b NOT BETWEEN 1 AND 86400 OR
    (NEW.backing->>'MaxCaptures')::bigint IS DISTINCT FROM NEW.max_captures OR (NEW.backing->>'MaxRules')::bigint IS DISTINCT FROM NEW.max_rules OR
    (NEW.backing->>'MaxRootTransitions')::bigint IS DISTINCT FROM NEW.max_root_transitions OR
    (NEW.backing->>'ValidUntil')::timestamptz IS DISTINCT FROM NEW.valid_until OR (NEW.backing->>'RetireBy')::timestamptz IS DISTINCT FROM NEW.retire_by OR
    NEW.retire_by<>NEW.valid_until+make_interval(secs=>(2*h+b)::double precision) OR
    coalesce((NEW.backing->>'BackupBytes')::numeric,0)<2*rows*(q->>'RowBytes')::numeric*(q->>'BackupCopies')::numeric OR
    coalesce((NEW.backing->>'WALBytes')::numeric,0)<transitions*(q->>'TransitionWALBytes')::numeric*(q->>'WALCopies')::numeric THEN
  RAISE EXCEPTION 'processing backing below complete history' USING ERRCODE='23514'; END IF;
 IF TG_OP='INSERT' THEN
  IF NEW.backing_revision<>1 OR NEW.captures<>0 OR NEW.rules<>0 OR NEW.root_transitions<>0 OR NEW.sequence<>1 OR NEW.initialized_at IS NOT NULL OR n>=NEW.valid_until THEN
   RAISE EXCEPTION 'invalid initial processing root' USING ERRCODE='23514'; END IF;
 ELSE
  IF ROW(NEW.root_id,NEW.installation_id,NEW.issuer_epoch,NEW.epoch,NEW.source_uid,NEW.protection_digest) IS DISTINCT FROM ROW(OLD.root_id,OLD.installation_id,OLD.issuer_epoch,OLD.epoch,OLD.source_uid,OLD.protection_digest) OR
     NEW.captures<OLD.captures OR NEW.rules<OLD.rules OR NEW.root_transitions<OLD.root_transitions OR NEW.sequence<OLD.sequence OR
     OLD.initialized_at IS NOT NULL AND ROW(NEW.initialized_at,NEW.initialization_id) IS DISTINCT FROM ROW(OLD.initialized_at,OLD.initialization_id) THEN
   RAISE EXCEPTION 'immutable processing history' USING ERRCODE='23514'; END IF;
  IF NEW.backing IS DISTINCT FROM OLD.backing THEN
   IF NEW.backing_revision<>OLD.backing_revision+1 OR NEW.root_transitions<>OLD.root_transitions+1 OR NEW.sequence<>OLD.sequence+1 OR
      ROW(NEW.captures,NEW.rules,NEW.initialized_at,NEW.initialization_id) IS DISTINCT FROM ROW(OLD.captures,OLD.rules,OLD.initialized_at,OLD.initialization_id) OR
      NEW.max_captures<OLD.max_captures OR NEW.max_rules<OLD.max_rules OR NEW.max_root_transitions<OLD.max_root_transitions OR NEW.valid_until<OLD.valid_until OR
      NEW.backing->'History' IS DISTINCT FROM OLD.backing->'History' OR NEW.backing->'PolicyID' IS DISTINCT FROM OLD.backing->'PolicyID' OR
      NEW.backing->'PolicyDigest' IS DISTINCT FROM OLD.backing->'PolicyDigest' OR NEW.backing->'BackupIdentity' IS DISTINCT FROM OLD.backing->'BackupIdentity' OR
      NEW.backing->'BackupDigest' IS DISTINCT FROM OLD.backing->'BackupDigest' OR NEW.backing->'BackupHorizonSeconds' IS DISTINCT FROM OLD.backing->'BackupHorizonSeconds' OR
      NEW.backing->'CleanupSeconds' IS DISTINCT FROM OLD.backing->'CleanupSeconds' OR
      n>=NEW.valid_until THEN
    RAISE EXCEPTION 'processing backing update does not cover history' USING ERRCODE='23514'; END IF;
  ELSE
   IF NEW.backing_revision<>OLD.backing_revision OR ROW(NEW.valid_until,NEW.retire_by,NEW.max_captures,NEW.max_rules,NEW.max_root_transitions) IS DISTINCT FROM ROW(OLD.valid_until,OLD.retire_by,OLD.max_captures,OLD.max_rules,OLD.max_root_transitions) OR pg_trigger_depth()<2 THEN
    RAISE EXCEPTION 'processing counters are source managed' USING ERRCODE='23514'; END IF;
  END IF;
 END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION guard_processing_root() FROM PUBLIC;

-- +goose StatementBegin
CREATE FUNCTION guard_processing_rule() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
DECLARE p public.processing_root;
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'restriction history cannot be erased' USING ERRCODE='23514'; END IF;
 PERFORM 1 FROM public.permission_stream WHERE id=NEW.root_id FOR UPDATE;
 SELECT * INTO STRICT p FROM public.processing_root WHERE root_id=NEW.root_id FOR UPDATE;
 IF NOT public.processing_scope_valid(NEW.scope) THEN RAISE EXCEPTION 'invalid processing scope' USING ERRCODE='23514'; END IF;
 IF TG_OP='INSERT' THEN
  IF NEW.valid_until IS NOT NULL OR NEW.retire_by IS NOT NULL THEN RAISE EXCEPTION 'processing rule dates are source owned' USING ERRCODE='23514'; END IF;
  NEW.valid_until:=p.valid_until; NEW.retire_by:=p.retire_by;
  IF NEW.scope->>'Kind'='workloadInterval' AND (NEW.scope->>'AcquiredUntil')::timestamptz>p.valid_until OR
     NEW.scope->>'Kind'='artifact' AND NOT EXISTS(SELECT 1 FROM public.context_processing n WHERE n.root_id=NEW.root_id AND n.artifact_id=(NEW.scope#>>'{Location,ArtifactID}')::uuid AND n.attempt_id=(NEW.scope#>>'{Location,AttemptID}')::uuid AND n.cluster_id=(NEW.scope#>>'{Location,ClusterID}')::uuid) OR
     p.initialized_at IS NULL OR clock_timestamp()>=p.valid_until OR p.rules>=p.max_rules OR NEW.revision<>0 OR NEW.decisions<>0 OR NEW.state<>'reserved' OR NEW.current_decision IS NOT NULL THEN
   RAISE EXCEPTION 'processing rule capacity unavailable' USING ERRCODE='23514'; END IF;
  UPDATE public.processing_root SET rules=rules+1 WHERE root_id=NEW.root_id;
 ELSE
  IF ROW(NEW.root_id,NEW.id,NEW.scope,NEW.valid_until,NEW.retire_by) IS DISTINCT FROM ROW(OLD.root_id,OLD.id,OLD.scope,OLD.valid_until,OLD.retire_by) OR pg_trigger_depth()<2 THEN
   RAISE EXCEPTION 'processing rule is decision owned' USING ERRCODE='23514'; END IF;
  IF NOT (NEW.decisions=OLD.decisions+1 AND ROW(NEW.revision,NEW.state,NEW.current_decision) IS NOT DISTINCT FROM ROW(OLD.revision,OLD.state,OLD.current_decision)) AND
     NOT (NEW.decisions=OLD.decisions AND NEW.revision=OLD.revision+1 AND NEW.current_decision IS DISTINCT FROM OLD.current_decision AND NEW.state=(CASE WHEN NEW.revision%2=1 THEN 'restricted' ELSE 'released' END)) THEN
   RAISE EXCEPTION 'invalid processing transition' USING ERRCODE='23514'; END IF;
 END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION guard_processing_rule() FROM PUBLIC;

-- +goose StatementBegin
CREATE FUNCTION guard_recording_save_group() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
BEGIN
 IF TG_OP='DELETE' THEN
  RAISE EXCEPTION 'group control retirement requires protocol' USING ERRCODE='23514';
 ELSIF TG_OP='UPDATE' THEN
  IF (to_jsonb(NEW)-ARRAY['progress_revision','cancel_requested_at','cancel_request_key']) IS DISTINCT FROM
     (to_jsonb(OLD)-ARRAY['progress_revision','cancel_requested_at','cancel_request_key']) OR
     NEW.progress_revision<>OLD.progress_revision+1 THEN
   RAISE EXCEPTION 'immutable save group' USING ERRCODE='23514';
  END IF;
  IF ROW(NEW.cancel_requested_at,NEW.cancel_request_key) IS DISTINCT FROM ROW(OLD.cancel_requested_at,OLD.cancel_request_key) THEN
   IF OLD.cancel_requested_at IS NOT NULL OR NEW.cancel_requested_at IS NULL OR NEW.cancel_request_key IS NULL THEN
    RAISE EXCEPTION 'immutable group cancellation' USING ERRCODE='23514';
   END IF;
   NEW.cancel_requested_at:=clock_timestamp();
  ELSIF pg_trigger_depth()<2 THEN
   RAISE EXCEPTION 'group progress derives from children' USING ERRCODE='23514';
  END IF;
  RETURN NEW;
 END IF;
 IF NEW.progress_revision<>1 OR NEW.cancel_requested_at IS NOT NULL OR NEW.cancel_request_key IS NOT NULL OR
    EXISTS(SELECT 1 FROM public.context_capture WHERE id=NEW.id OR (root_id=NEW.root_id AND request_key=NEW.request_key)) OR
    (SELECT count(DISTINCT x) FROM unnest(NEW.child_ids) x)<>cardinality(NEW.child_ids) OR NEW.id=ANY(NEW.child_ids) THEN
  RAISE EXCEPTION 'invalid new save group' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION guard_recording_save_group() FROM PUBLIC;

-- +goose StatementBegin
CREATE FUNCTION guard_recording_save_reservation() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN RAISE EXCEPTION 'manual save reservation is immutable' USING ERRCODE='23514'; END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION guard_recording_save_reservation() FROM PUBLIC;

-- +goose StatementBegin
CREATE FUNCTION guard_recording_selection_set() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
 IF TG_OP='UPDATE' OR OLD.expires_at>clock_timestamp() THEN
  RAISE EXCEPTION 'live recording selection is immutable' USING ERRCODE='23514';
 END IF;
 RETURN OLD;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION guard_recording_selection_set() FROM PUBLIC;

-- +goose StatementBegin
CREATE FUNCTION guard_snapshot_cancel() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
BEGIN
 IF TG_OP='INSERT' THEN
  IF NEW.snapshot_cancel_key IS NOT NULL THEN RAISE EXCEPTION 'cancellation follows committed acceptance' USING ERRCODE='23514';END IF;
  RETURN NEW;
 END IF;
 IF ROW(NEW.snapshot_cancel_key,NEW.snapshot_cancel_actor,NEW.snapshot_cancel_requested_at) IS DISTINCT FROM ROW(OLD.snapshot_cancel_key,OLD.snapshot_cancel_actor,OLD.snapshot_cancel_requested_at) THEN
  IF OLD.snapshot_cancel_key IS NOT NULL OR NEW.snapshot_cancel_key IS NULL OR (jsonb_typeof(convert_from(NEW.expectation_json,'UTF8')::jsonb->'Snapshot') IS DISTINCT FROM 'object' AND jsonb_typeof(convert_from(NEW.expectation_json,'UTF8')::jsonb->'Profile') IS DISTINCT FROM 'object' AND NOT COALESCE(convert_from(NEW.expectation_json,'UTF8')::jsonb->>'NativeType'='processes' AND convert_from(NEW.expectation_json,'UTF8')::jsonb->>'DataClass'='metadata' AND jsonb_typeof(convert_from(NEW.expectation_json,'UTF8')::jsonb->'Processes')='object',false) AND NOT COALESCE(convert_from(NEW.expectation_json,'UTF8')::jsonb->>'NativeType'='logs' AND convert_from(NEW.expectation_json,'UTF8')::jsonb->>'DataClass'='raw' AND jsonb_typeof(convert_from(NEW.expectation_json,'UTF8')::jsonb->'Logs')='object',false) AND jsonb_typeof(convert_from(NEW.expectation_json,'UTF8')::jsonb->'Recording') IS DISTINCT FROM 'object') THEN RAISE EXCEPTION 'immutable cancellation request' USING ERRCODE='23514';END IF;
  NEW.snapshot_cancel_requested_at:=clock_timestamp();
 END IF;
 IF ROW(NEW.snapshot_cancel_joined_at,NEW.snapshot_cancel_proof,NEW.snapshot_cancel_proof_digest) IS DISTINCT FROM ROW(OLD.snapshot_cancel_joined_at,OLD.snapshot_cancel_proof,OLD.snapshot_cancel_proof_digest) THEN
  IF OLD.snapshot_cancel_joined_at IS NOT NULL OR NEW.snapshot_cancel_joined_at IS NULL OR NEW.snapshot_cancel_joined_at>clock_timestamp() THEN RAISE EXCEPTION 'immutable cancellation completion' USING ERRCODE='23514';END IF;
  IF NEW.snapshot_cancel_proof IS NULL THEN
   IF EXISTS(SELECT 1 FROM public.context_execution WHERE root_id=NEW.root_id AND capture_id=NEW.id AND started_at IS NOT NULL) THEN RAISE EXCEPTION 'started cancellation needs joined proof' USING ERRCODE='23514';END IF;
  ELSIF NOT EXISTS(SELECT 1 FROM public.context_execution WHERE root_id=NEW.root_id AND capture_id=NEW.id AND phase='cancelled') THEN RAISE EXCEPTION 'cancellation lacks joined execution' USING ERRCODE='23514';END IF;
 END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION guard_snapshot_cancel() FROM PUBLIC;

-- +goose StatementBegin
CREATE FUNCTION guard_worker_certificate() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
 IF ROW(NEW.id,NEW.worker_id,NEW.epoch,NEW.ordinal,NEW.attempt_json) IS DISTINCT FROM ROW(OLD.id,OLD.worker_id,OLD.epoch,OLD.ordinal,OLD.attempt_json)
 OR (OLD.certificate_json IS NOT NULL AND ROW(NEW.certificate_json,NEW.certificate_sha256) IS DISTINCT FROM ROW(OLD.certificate_json,OLD.certificate_sha256))
 OR (OLD.audit_receipt_json IS NOT NULL AND NEW.audit_receipt_json IS DISTINCT FROM OLD.audit_receipt_json) THEN
  RAISE EXCEPTION 'worker certificate attempt and consumed results are immutable';
 END IF;
 IF OLD.activated_at IS NOT NULL AND NEW.activated_at IS DISTINCT FROM OLD.activated_at THEN
  RAISE EXCEPTION 'worker certificate activation is immutable';
 END IF;
 RETURN NEW;
END; $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION guard_worker_configuration_head() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
 IF ROW(NEW.installation_id,NEW.cluster_id,NEW.source_uid) IS DISTINCT FROM ROW(OLD.installation_id,OLD.cluster_id,OLD.source_uid)
 OR NEW.generation<OLD.generation OR NEW.observed_at<OLD.observed_at THEN
  RAISE EXCEPTION 'worker configuration identity and revision cannot roll back';
 END IF;
 RETURN NEW;
END; $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION guard_worker_configuration_revision() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
 IF ROW(NEW.installation_id,NEW.cluster_id,NEW.source_uid,NEW.generation,NEW.snapshot_json)
 IS DISTINCT FROM ROW(OLD.installation_id,OLD.cluster_id,OLD.source_uid,OLD.generation,OLD.snapshot_json)
 OR (OLD.audit_receipt_json IS NOT NULL AND NEW.audit_receipt_json IS DISTINCT FROM OLD.audit_receipt_json) THEN
  RAISE EXCEPTION 'worker configuration revision and audit are immutable';
 END IF;
 RETURN NEW;
END; $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION guard_worker_enrollment() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
 IF ROW(NEW.worker_id,NEW.enrollment_json) IS DISTINCT FROM ROW(OLD.worker_id,OLD.enrollment_json)
 OR (OLD.audit_receipt_json IS NOT NULL AND NEW.audit_receipt_json IS DISTINCT FROM OLD.audit_receipt_json) THEN
  RAISE EXCEPTION 'worker enrollment and acknowledged audit are immutable';
 END IF;
 RETURN NEW;
END; $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION incarnation_current(x timestamp with time zone) RETURNS boolean
    LANGUAGE sql IMMUTABLE
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$ SELECT x IS NOT NULL $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION incarnation_current(x timestamp with time zone) FROM PUBLIC;

-- +goose StatementBegin
CREATE FUNCTION initialize_processing_root() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
BEGIN
 NEW.initialized_at:=clock_timestamp(); NEW.initialization_id:=NEW.epoch;
 NEW.root_transitions:=NEW.root_transitions+1; NEW.sequence:=NEW.sequence+1;
 RETURN NEW;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION initialize_processing_root() FROM PUBLIC;

-- +goose StatementBegin
CREATE FUNCTION live_watch_change(r uuid, o uuid, d bytea, c jsonb, expected bigint, cost bigint, bound timestamp with time zone) RETURNS jsonb
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
DECLARE p public.live_watch_root; w public.live_watch_control; n timestamptz; k text; a bytea; bucket public.live_watch_account; rate bigint;burst bigint;available bigint;oldjson jsonb;
BEGIN
 SELECT * INTO STRICT p FROM public.live_watch_root WHERE root_id=r FOR UPDATE;
 SELECT * INTO STRICT w FROM public.live_watch_control WHERE root_id=r AND id=(c->>'ID')::uuid FOR UPDATE;
 n:=clock_timestamp();oldjson:=public.live_watch_value(w);
 -- cost: one batch, at most the 24 KiB default MCP result.
 IF o IS NULL OR d IS NULL OR expected IS NULL OR cost IS NULL OR bound IS NULL OR NOT isfinite(bound) OR w.owner_id<>o OR p.limits_digest<>d OR w.revision<>expected OR cost<0 OR cost>24576 OR NOT public.capacity_json_fields(c,ARRAY['ID','OwnerID','Fence','PrincipalKey','WorkloadKey','RequestDigest','Revision','State','AcceptedAt','ExpiresAt','IdleUntil','Spent','BytesPerSecond']) OR
 (oldjson-ARRAY['Revision','State','Spent','IdleUntil','AcceptedAt','ExpiresAt']) IS DISTINCT FROM (c-ARRAY['Revision','State','Spent','IdleUntil','AcceptedAt','ExpiresAt']) OR w.accepted_at IS DISTINCT FROM (c->>'AcceptedAt')::timestamptz OR w.expires_at IS DISTINCT FROM (c->>'ExpiresAt')::timestamptz OR (c->>'Spent')::bigint<>w.spent+cost OR (c->>'Revision')::bigint NOT IN (w.revision,w.revision+1) OR
 ((c->>'Revision')::bigint=w.revision AND (cost=0 OR c->>'State'<>w.state AND NOT(w.state IN ('Active','Paused','Disconnected') AND c->>'State' IN ('Disconnected','SourceEnded')))) OR ((c->>'Revision')::bigint=w.revision+1 AND cost<>0) OR
 (w.state NOT IN ('Active','Paused','Disconnected') AND (c->>'State'<>w.state OR cost<>0)) OR (c->>'IdleUntil')::timestamptz>w.expires_at OR (c->>'IdleUntil')::timestamptz>n+interval '10 minutes' THEN RAISE EXCEPTION 'live revision or control conflict' USING ERRCODE='23505'; END IF;
 IF c->>'State'<>'Closed' AND (n>=bound OR n>=w.expires_at OR n>=w.idle_until OR NOT EXISTS(SELECT 1 FROM public.fleet_current_trust WHERE installation_id=p.installation_id AND issuer_epoch=p.issuer_epoch AND NOT suspended AND observed_at<=n AND n<fresh_until)) THEN RAISE EXCEPTION 'live owner or original bound unavailable' USING ERRCODE='23514'; END IF;
 IF c->>'State'='Closed' AND ((c->>'IdleUntil')::timestamptz<>w.idle_until OR cost<>0) THEN RAISE EXCEPTION 'live close cannot renew or disclose' USING ERRCODE='23514'; END IF;
 IF cost>0 THEN
  IF n<w.refilled_at THEN RAISE EXCEPTION 'live clock unavailable' USING ERRCODE='23514'; END IF;
  available:=public.live_watch_refilled(w.tokens_micro,w.refilled_at,n,w.bytes_per_second,(p.limits->>'WatchBurst')::bigint);
  IF available<cost*1000000 THEN RAISE EXCEPTION 'live watch rate unavailable' USING ERRCODE='54000'; END IF;
  w.tokens_micro:=available-cost*1000000;w.refilled_at:=n;
  FOREACH k IN ARRAY ARRAY['installation','principal','workload'] LOOP
   a:=CASE k WHEN 'installation' THEN decode(replace(r::text,'-','')||repeat('00',16),'hex') WHEN 'principal' THEN w.principal_key ELSE w.workload_key END;
   SELECT * INTO STRICT bucket FROM public.live_watch_account WHERE root_id=r AND kind=k AND account_key=a FOR UPDATE;
   rate:=(p.limits->>(CASE k WHEN 'installation' THEN 'InstallationRate' WHEN 'principal' THEN 'PrincipalRate' ELSE 'WorkloadRate' END))::bigint;
   burst:=(p.limits->>(CASE k WHEN 'installation' THEN 'InstallationBurst' WHEN 'principal' THEN 'PrincipalBurst' ELSE 'WorkloadBurst' END))::bigint;
   IF n<bucket.refilled_at THEN RAISE EXCEPTION 'live clock unavailable' USING ERRCODE='23514'; END IF;
   available:=public.live_watch_refilled(bucket.tokens_micro,bucket.refilled_at,n,rate,burst);
   IF available<cost*1000000 THEN RAISE EXCEPTION 'live aggregate rate unavailable' USING ERRCODE='54000'; END IF;
   UPDATE public.live_watch_account SET tokens_micro=available-cost*1000000,refilled_at=n WHERE root_id=r AND kind=k AND account_key=a;
  END LOOP;
 END IF;
 UPDATE public.live_watch_control SET revision=(c->>'Revision')::bigint,state=c->>'State',spent=(c->>'Spent')::bigint,idle_until=(c->>'IdleUntil')::timestamptz,tokens_micro=w.tokens_micro,refilled_at=w.refilled_at WHERE id=w.id RETURNING * INTO w;
 RETURN public.live_watch_value(w);
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION live_watch_change(r uuid, o uuid, d bytea, c jsonb, expected bigint, cost bigint, bound timestamp with time zone) FROM PUBLIC;

-- +goose StatementBegin
CREATE FUNCTION live_watch_close_control(r uuid, p bytea, i uuid, expected bigint, f uuid) RETURNS jsonb
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
DECLARE w public.live_watch_control;
BEGIN
 IF octet_length(p)<>32 OR i IS NULL OR f IS NULL OR expected IS NULL OR expected<1 THEN RAISE EXCEPTION 'live recovery close invalid' USING ERRCODE='22023'; END IF;
 SELECT * INTO w FROM public.live_watch_control WHERE root_id=r AND principal_key=p AND id=i FOR UPDATE;
 IF NOT FOUND OR w.revision<>expected OR w.fence<>f THEN RAISE EXCEPTION 'live recovery control conflict' USING ERRCODE='23505'; END IF;
 IF w.state IN ('Active','Paused','Disconnected') THEN
  UPDATE public.live_watch_control SET state='Closed' WHERE root_id=r AND id=i RETURNING * INTO w;
 END IF;
 RETURN public.live_watch_value(w);
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION live_watch_close_control(r uuid, p bytea, i uuid, expected bigint, f uuid) FROM PUBLIC;

-- +goose StatementBegin
CREATE FUNCTION live_watch_configure(r uuid, i uuid, e uuid, d bytea, l jsonb) RETURNS boolean
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
DECLARE p public.live_watch_root; k text;
BEGIN
 IF octet_length(d)<>32 OR NOT public.capacity_json_fields(l,ARRAY['InstallationSlots','PrincipalSlots','WorkloadSlots','MemoryBytes','InstallationRate','InstallationBurst','PrincipalRate','PrincipalBurst','WorkloadRate','WorkloadBurst','WatchBurst','MaxRate','MaxAccounts','MaxControlRecords']) THEN RETURN false; END IF;
 FOREACH k IN ARRAY ARRAY['InstallationSlots','PrincipalSlots','WorkloadSlots'] LOOP IF NOT public.capacity_json_integer(l->k,1,4096) THEN RETURN false; END IF; END LOOP;
 FOREACH k IN ARRAY ARRAY['InstallationRate','PrincipalRate','WorkloadRate'] LOOP IF NOT public.capacity_json_integer(l->k,1,268435456) THEN RETURN false; END IF; END LOOP;
 FOREACH k IN ARRAY ARRAY['InstallationBurst','PrincipalBurst','WorkloadBurst'] LOOP IF NOT public.capacity_json_integer(l->k,24576,1073741824) THEN RETURN false; END IF; END LOOP;
 IF NOT public.capacity_json_integer(l->'MemoryBytes',1048576,4294967296) OR NOT public.capacity_json_integer(l->'WatchBurst',24576,9007199254740991) OR NOT public.capacity_json_integer(l->'MaxRate',1,9007199254740991) OR NOT public.capacity_json_integer(l->'MaxAccounts',3,1048576) OR NOT public.capacity_json_integer(l->'MaxControlRecords',1,1048576) OR
 (l->>'PrincipalSlots')::bigint>(l->>'InstallationSlots')::bigint OR (l->>'WorkloadSlots')::bigint>(l->>'InstallationSlots')::bigint OR (l->>'MemoryBytes')::bigint<(l->>'InstallationSlots')::bigint*1048576 OR (l->>'MaxControlRecords')::bigint<(l->>'InstallationSlots')::bigint THEN RETURN false; END IF;
 INSERT INTO public.live_watch_root(root_id,installation_id,issuer_epoch,limits_digest,limits) VALUES(r,i,e,d,l) ON CONFLICT DO NOTHING;
 SELECT * INTO STRICT p FROM public.live_watch_root WHERE root_id=r FOR UPDATE;
 IF NOT EXISTS(SELECT 1 FROM public.fleet_current_trust WHERE installation_id=i AND issuer_epoch=e AND NOT suspended AND observed_at<=clock_timestamp() AND clock_timestamp()<fresh_until) THEN RETURN false; END IF;
 IF p.installation_id<>i THEN RETURN false; END IF;
 IF p.issuer_epoch=e AND p.limits_digest=d AND p.limits=l THEN RETURN true; END IF;
 IF p.limits_digest<>d OR p.limits<>l THEN
  PERFORM public.live_watch_prune(r);
  IF EXISTS(SELECT 1 FROM public.live_watch_control WHERE root_id=r) OR EXISTS(SELECT 1 FROM public.live_watch_account WHERE root_id=r) THEN RETURN false; END IF;
 END IF;
 UPDATE public.live_watch_root SET issuer_epoch=e,limits_digest=d,limits=l WHERE root_id=r;
 RETURN true;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION live_watch_configure(r uuid, i uuid, e uuid, d bytea, l jsonb) FROM PUBLIC;

-- +goose StatementBegin
CREATE FUNCTION live_watch_create(r uuid, o uuid, d bytea, c jsonb, key bytea, bound timestamp with time zone) RETURNS jsonb
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
DECLARE p public.live_watch_root; w public.live_watch_control; n timestamptz; counts record; k text; a bytea; burst bigint; initial_key bytea;
BEGIN
 SELECT * INTO STRICT p FROM public.live_watch_root WHERE root_id=r FOR UPDATE;
 n:=clock_timestamp();
 IF o IS NULL OR d IS NULL OR key IS NULL OR bound IS NULL OR NOT isfinite(bound) OR n>=bound OR p.limits_digest<>d OR octet_length(key)<>32 OR NOT EXISTS(SELECT 1 FROM public.fleet_current_trust WHERE installation_id=p.installation_id AND issuer_epoch=p.issuer_epoch AND NOT suspended AND observed_at<=n AND n<fresh_until) THEN RAISE EXCEPTION 'live owner or limits unavailable' USING ERRCODE='23514'; END IF;
 SELECT * INTO w FROM public.live_watch_control WHERE root_id=r AND key_hash=key;
 IF FOUND THEN
  IF w.principal_key<>public.live_watch_digest(c->'PrincipalKey') OR w.request_digest<>public.live_watch_digest(c->'RequestDigest') THEN RAISE EXCEPTION 'live request conflict' USING ERRCODE='23505'; END IF;
  IF w.owner_id<>o THEN RAISE EXCEPTION 'live owner unavailable' USING ERRCODE='23514'; END IF;
  RETURN jsonb_build_object('control',public.live_watch_value(w),'reused',true);
 END IF;
 PERFORM public.live_watch_prune(r);
 IF NOT public.capacity_json_fields(c,ARRAY['ID','OwnerID','Fence','PrincipalKey','WorkloadKey','RequestDigest','Revision','State','AcceptedAt','ExpiresAt','IdleUntil','OutputLimit','Spent','BytesPerSecond']) OR (c->>'OwnerID')::uuid<>o OR (c->>'Revision')::bigint<>1 OR c->>'State'<>'Active' OR (c->>'Spent')::bigint<>0 OR
 (c->>'AcceptedAt')::timestamptz>n OR (c->>'AcceptedAt')::timestamptz<n-interval '5 seconds' OR (c->>'ExpiresAt')::timestamptz<=n OR (c->>'ExpiresAt')::timestamptz>(c->>'AcceptedAt')::timestamptz+make_interval(secs=>(p.limits->>'MaxDurationSeconds')::integer) OR (c->>'IdleUntil')::timestamptz<=n OR (c->>'IdleUntil')::timestamptz>(c->>'AcceptedAt')::timestamptz+interval '30 seconds' OR (c->>'OutputLimit')::bigint>(p.limits->>'MaxOutputBytes')::bigint OR (c->>'BytesPerSecond')::bigint>(p.limits->>'MaxRate')::bigint THEN RAISE EXCEPTION 'invalid initial live control' USING ERRCODE='23514'; END IF;
 SELECT count(*) AS total,count(*) FILTER(WHERE state IN ('Active','Paused','Disconnected') AND n<expires_at AND n<idle_until) AS active,
 count(*) FILTER(WHERE state IN ('Active','Paused','Disconnected') AND n<expires_at AND n<idle_until AND principal_key=public.live_watch_digest(c->'PrincipalKey')) AS principal,
 count(*) FILTER(WHERE state IN ('Active','Paused','Disconnected') AND n<expires_at AND n<idle_until AND workload_key=public.live_watch_digest(c->'WorkloadKey')) AS workload INTO counts FROM public.live_watch_control WHERE root_id=r;
 IF counts.total>=(p.limits->>'MaxControlRecords')::bigint OR counts.active>=(p.limits->>'InstallationSlots')::bigint OR counts.principal>=(p.limits->>'PrincipalSlots')::bigint OR counts.workload>=(p.limits->>'WorkloadSlots')::bigint THEN RAISE EXCEPTION 'live capacity unavailable' USING ERRCODE='54000'; END IF;
 initial_key:=decode(replace(r::text,'-','')||repeat('00',16),'hex');
 FOREACH k IN ARRAY ARRAY['installation','principal','workload'] LOOP
  a:=CASE k WHEN 'installation' THEN initial_key WHEN 'principal' THEN public.live_watch_digest(c->'PrincipalKey') ELSE public.live_watch_digest(c->'WorkloadKey') END;
  IF NOT EXISTS(SELECT 1 FROM public.live_watch_account WHERE root_id=r AND kind=k AND account_key=a) THEN
   IF (SELECT count(*) FROM public.live_watch_account WHERE root_id=r)>=(p.limits->>'MaxAccounts')::bigint THEN RAISE EXCEPTION 'live accounts unavailable' USING ERRCODE='54000'; END IF;
   burst:=(p.limits->>(CASE k WHEN 'installation' THEN 'InstallationBurst' WHEN 'principal' THEN 'PrincipalBurst' ELSE 'WorkloadBurst' END))::bigint;
   INSERT INTO public.live_watch_account VALUES(r,k,a,burst*1000000,n);
  END IF;
 END LOOP;
 INSERT INTO public.live_watch_control(root_id,id,owner_id,fence,principal_key,workload_key,request_digest,key_hash,revision,state,accepted_at,expires_at,idle_until,output_limit,spent,bytes_per_second,tokens_micro,refilled_at)
 VALUES(r,(c->>'ID')::uuid,o,(c->>'Fence')::uuid,public.live_watch_digest(c->'PrincipalKey'),public.live_watch_digest(c->'WorkloadKey'),public.live_watch_digest(c->'RequestDigest'),key,1,'Active',(c->>'AcceptedAt')::timestamptz,(c->>'ExpiresAt')::timestamptz,(c->>'IdleUntil')::timestamptz,(c->>'OutputLimit')::bigint,0,(c->>'BytesPerSecond')::bigint,(p.limits->>'WatchBurst')::bigint*1000000,n) RETURNING * INTO w;
 RETURN jsonb_build_object('control',public.live_watch_value(w),'reused',false);
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION live_watch_create(r uuid, o uuid, d bytea, c jsonb, key bytea, bound timestamp with time zone) FROM PUBLIC;

-- +goose StatementBegin
CREATE FUNCTION live_watch_create_cluster(r uuid, o uuid, d bytea, c jsonb, key bytea, bound timestamp with time zone, k bytea) RETURNS jsonb
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
DECLARE p public.live_watch_root; w public.live_watch_control; n timestamptz; counts record; knd text; a bytea; burst bigint; initial_key bytea;
BEGIN
 SELECT * INTO STRICT p FROM public.live_watch_root WHERE root_id=r FOR UPDATE;
 n:=clock_timestamp();
 IF o IS NULL OR d IS NULL OR key IS NULL OR bound IS NULL OR k IS NULL OR NOT isfinite(bound) OR n>=bound OR p.limits_digest<>d OR octet_length(key)<>32 OR octet_length(k)<>32 OR NOT EXISTS(SELECT 1 FROM public.fleet_current_trust WHERE installation_id=p.installation_id AND issuer_epoch=p.issuer_epoch AND NOT suspended AND observed_at<=n AND n<fresh_until) THEN RAISE EXCEPTION 'live owner or limits unavailable' USING ERRCODE='23514'; END IF;
 SELECT * INTO w FROM public.live_watch_control WHERE root_id=r AND key_hash=key;
 IF FOUND THEN
  IF w.principal_key<>public.live_watch_digest(c->'PrincipalKey') OR w.request_digest<>public.live_watch_digest(c->'RequestDigest') THEN RAISE EXCEPTION 'live request conflict' USING ERRCODE='23505'; END IF;
  IF w.owner_id<>o OR w.cluster_key IS DISTINCT FROM k THEN RAISE EXCEPTION 'live owner unavailable' USING ERRCODE='23514'; END IF;
  RETURN jsonb_build_object('control',public.live_watch_value(w),'reused',true);
 END IF;
 PERFORM public.live_watch_prune(r);
 IF NOT public.capacity_json_fields(c,ARRAY['ID','OwnerID','Fence','PrincipalKey','WorkloadKey','RequestDigest','Revision','State','AcceptedAt','ExpiresAt','IdleUntil','Spent','BytesPerSecond']) OR (c->>'OwnerID')::uuid<>o OR (c->>'Revision')::bigint<>1 OR c->>'State'<>'Active' OR (c->>'Spent')::bigint<>0 OR
 (c->>'AcceptedAt')::timestamptz>n OR (c->>'AcceptedAt')::timestamptz<n-interval '5 seconds' OR (c->>'ExpiresAt')::timestamptz<=n OR (c->>'IdleUntil')::timestamptz<=n OR (c->>'IdleUntil')::timestamptz>(c->>'AcceptedAt')::timestamptz+interval '10 minutes' OR (c->>'BytesPerSecond')::bigint>(p.limits->>'MaxRate')::bigint THEN RAISE EXCEPTION 'invalid initial live control' USING ERRCODE='23514'; END IF;
 SELECT count(*) AS total,count(*) FILTER(WHERE state IN ('Active','Paused','Disconnected') AND n<expires_at AND n<idle_until) AS active,
 count(*) FILTER(WHERE state IN ('Active','Paused','Disconnected') AND n<expires_at AND n<idle_until AND principal_key=public.live_watch_digest(c->'PrincipalKey')) AS principal,
 count(*) FILTER(WHERE state IN ('Active','Paused','Disconnected') AND n<expires_at AND n<idle_until AND workload_key=public.live_watch_digest(c->'WorkloadKey')) AS workload INTO counts FROM public.live_watch_control WHERE root_id=r;
 IF counts.total>=(p.limits->>'MaxControlRecords')::bigint OR counts.active>=(p.limits->>'InstallationSlots')::bigint OR counts.principal>=(p.limits->>'PrincipalSlots')::bigint OR counts.workload>=(p.limits->>'WorkloadSlots')::bigint THEN RAISE EXCEPTION 'live capacity unavailable' USING ERRCODE='54000'; END IF;
 initial_key:=decode(replace(r::text,'-','')||repeat('00',16),'hex');
 FOREACH knd IN ARRAY ARRAY['installation','principal','workload'] LOOP
  a:=CASE knd WHEN 'installation' THEN initial_key WHEN 'principal' THEN public.live_watch_digest(c->'PrincipalKey') ELSE public.live_watch_digest(c->'WorkloadKey') END;
  IF NOT EXISTS(SELECT 1 FROM public.live_watch_account WHERE root_id=r AND kind=knd AND account_key=a) THEN
   IF (SELECT count(*) FROM public.live_watch_account WHERE root_id=r)>=(p.limits->>'MaxAccounts')::bigint THEN RAISE EXCEPTION 'live accounts unavailable' USING ERRCODE='54000'; END IF;
   burst:=(p.limits->>(CASE knd WHEN 'installation' THEN 'InstallationBurst' WHEN 'principal' THEN 'PrincipalBurst' ELSE 'WorkloadBurst' END))::bigint;
   INSERT INTO public.live_watch_account VALUES(r,knd,a,burst*1000000,n);
  END IF;
 END LOOP;
 INSERT INTO public.live_watch_control(root_id,id,owner_id,fence,principal_key,workload_key,request_digest,key_hash,revision,state,accepted_at,expires_at,idle_until,spent,bytes_per_second,tokens_micro,refilled_at,cluster_key)
 VALUES(r,(c->>'ID')::uuid,o,(c->>'Fence')::uuid,public.live_watch_digest(c->'PrincipalKey'),public.live_watch_digest(c->'WorkloadKey'),public.live_watch_digest(c->'RequestDigest'),key,1,'Active',(c->>'AcceptedAt')::timestamptz,(c->>'ExpiresAt')::timestamptz,(c->>'IdleUntil')::timestamptz,0,(c->>'BytesPerSecond')::bigint,(p.limits->>'WatchBurst')::bigint*1000000,n,k) RETURNING * INTO w;
 RETURN jsonb_build_object('control',public.live_watch_value(w),'reused',false);
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION live_watch_create_cluster(r uuid, o uuid, d bytea, c jsonb, key bytea, bound timestamp with time zone, k bytea) FROM PUBLIC;

-- +goose StatementBegin
CREATE FUNCTION live_watch_current(r uuid, o uuid, d bytea, c jsonb, bound timestamp with time zone) RETURNS boolean
    LANGUAGE sql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
 SELECT COALESCE(EXISTS(SELECT 1 FROM public.live_watch_control w JOIN public.live_watch_root p ON p.root_id=w.root_id JOIN public.fleet_current_trust t ON t.installation_id=p.installation_id AND t.issuer_epoch=p.issuer_epoch
 WHERE w.root_id=r AND w.id=(c->>'ID')::uuid AND w.owner_id=o AND p.limits_digest=d AND w.state IN ('Active','Paused','Disconnected','Closed') AND public.live_watch_matches(w,c) AND clock_timestamp()<w.expires_at AND clock_timestamp()<w.idle_until AND clock_timestamp()<bound AND NOT t.suspended AND t.observed_at<=clock_timestamp() AND clock_timestamp()<t.fresh_until),false)
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION live_watch_current(r uuid, o uuid, d bytea, c jsonb, bound timestamp with time zone) FROM PUBLIC;

-- +goose StatementBegin
CREATE FUNCTION live_watch_digest(v jsonb) RETURNS bytea
    LANGUAGE plpgsql IMMUTABLE
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
DECLARE i integer;out bytea:=decode(repeat('00',32),'hex');
BEGIN
 IF jsonb_typeof(v) IS DISTINCT FROM 'array' OR jsonb_array_length(v)<>32 THEN RAISE EXCEPTION 'invalid live digest' USING ERRCODE='23514'; END IF;
 FOR i IN 0..31 LOOP
  IF NOT public.capacity_json_integer(v->i,0,255) THEN RAISE EXCEPTION 'invalid live digest' USING ERRCODE='23514'; END IF;
  out:=set_byte(out,i,(v->>i)::integer);
 END LOOP;
 RETURN out;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION live_watch_digest(v jsonb) FROM PUBLIC;

-- +goose StatementBegin
CREATE FUNCTION live_watch_matches(w live_watch_control, c jsonb) RETURNS boolean
    LANGUAGE sql IMMUTABLE
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
 SELECT COALESCE((public.live_watch_value(w)-ARRAY['AcceptedAt','ExpiresAt','IdleUntil'])=(c-ARRAY['AcceptedAt','ExpiresAt','IdleUntil']) AND
 w.accepted_at=(c->>'AcceptedAt')::timestamptz AND w.expires_at=(c->>'ExpiresAt')::timestamptz AND w.idle_until=(c->>'IdleUntil')::timestamptz,false)
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION live_watch_matches(w live_watch_control, c jsonb) FROM PUBLIC;

-- +goose StatementBegin
CREATE FUNCTION live_watch_owner(r uuid, p bytea, i uuid, k bytea) RETURNS TABLE(installation_id uuid, cluster_id uuid, issuer_epoch uuid, pod_uid uuid, process_epoch uuid)
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
DECLARE w public.live_watch_control;n timestamptz:=clock_timestamp();found_owners bigint;
BEGIN
 IF octet_length(p)<>32 OR (i IS NULL)=(k IS NULL) OR (k IS NOT NULL AND octet_length(k)<>32) THEN
  RAISE EXCEPTION 'live owner locator invalid' USING ERRCODE='22023';
 END IF;
 IF i IS NOT NULL THEN
  SELECT c.* INTO w FROM public.live_watch_control c WHERE c.root_id=r AND c.principal_key=p AND c.id=i;
 ELSE
  SELECT c.* INTO w FROM public.live_watch_control c WHERE c.root_id=r AND c.principal_key=p AND c.key_hash=k;
 END IF;
 IF NOT FOUND THEN RETURN; END IF;
 -- A retained closed receipt is routable until its original end; an expired
 -- or unavailable owner never becomes an absent key eligible for local Open.
 IF n>=w.expires_at OR n>=w.idle_until THEN
  RAISE EXCEPTION 'live owner unavailable' USING ERRCODE='55000';
 END IF;
 RETURN QUERY SELECT e.installation_id,e.cluster_id,e.issuer_epoch,e.pod_uid,e.process_epoch
 FROM public.live_watch_root b JOIN public.fleet_current_trust t ON t.installation_id=b.installation_id AND t.issuer_epoch=b.issuer_epoch
 JOIN public.hub_owner_enrollment e ON e.installation_id=b.installation_id AND e.issuer_epoch=b.issuer_epoch AND e.process_epoch=w.owner_id AND e.usage='server'
 WHERE b.root_id=r AND NOT t.suspended AND t.observed_at<=n AND n<t.fresh_until
 AND e.audit_receipt_json IS NOT NULL AND e.retired_at IS NULL AND n<e.hold_until
 AND EXISTS(SELECT 1 FROM public.hub_owner_certificate a WHERE a.enrollment_id=e.id AND a.activated_at IS NOT NULL AND n<a.not_after)
 LIMIT 2;
 GET DIAGNOSTICS found_owners=ROW_COUNT;
 IF found_owners<>1 THEN RAISE EXCEPTION 'live owner unavailable' USING ERRCODE='55000'; END IF;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION live_watch_owner(r uuid, p bytea, i uuid, k bytea) FROM PUBLIC;

-- +goose StatementBegin
CREATE FUNCTION live_watch_prune(r uuid) RETURNS jsonb
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
DECLARE p public.live_watch_root;n timestamptz;controls bigint;accounts bigint;
BEGIN
 SELECT * INTO STRICT p FROM public.live_watch_root WHERE root_id=r FOR UPDATE;
 n:=clock_timestamp();
 -- Each bounded candidate set is materialized once; DELETE must not rescan a
 -- volatile limited subquery and exceed its stated cap.
 WITH candidates AS MATERIALIZED(SELECT id FROM public.live_watch_control WHERE root_id=r AND expires_at<=n ORDER BY expires_at,id LIMIT 64 FOR UPDATE SKIP LOCKED)
 DELETE FROM public.live_watch_control w USING candidates c WHERE w.id=c.id;
 GET DIAGNOSTICS controls=ROW_COUNT;
 WITH candidates AS MATERIALIZED(SELECT a.kind,a.account_key FROM public.live_watch_account a WHERE a.root_id=r AND a.refilled_at<=n AND
 public.live_watch_refilled(a.tokens_micro,a.refilled_at,n,(p.limits->>(CASE a.kind WHEN 'installation' THEN 'InstallationRate' WHEN 'principal' THEN 'PrincipalRate' ELSE 'WorkloadRate' END))::bigint,(p.limits->>(CASE a.kind WHEN 'installation' THEN 'InstallationBurst' WHEN 'principal' THEN 'PrincipalBurst' ELSE 'WorkloadBurst' END))::bigint)=(p.limits->>(CASE a.kind WHEN 'installation' THEN 'InstallationBurst' WHEN 'principal' THEN 'PrincipalBurst' ELSE 'WorkloadBurst' END))::bigint*1000000 AND
 NOT EXISTS(SELECT 1 FROM public.live_watch_control w WHERE w.root_id=r AND (a.kind='installation' OR a.kind='principal' AND w.principal_key=a.account_key OR a.kind='workload' AND w.workload_key=a.account_key)) ORDER BY a.kind,a.account_key LIMIT 64 FOR UPDATE SKIP LOCKED)
 DELETE FROM public.live_watch_account a USING candidates c WHERE a.root_id=r AND a.kind=c.kind AND a.account_key=c.account_key;
 GET DIAGNOSTICS accounts=ROW_COUNT;
 RETURN jsonb_build_object('controls',controls,'accounts',accounts);
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION live_watch_prune(r uuid) FROM PUBLIC;

-- +goose StatementBegin
CREATE FUNCTION live_watch_read_control(r uuid, p bytea, i uuid) RETURNS jsonb
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
DECLARE w public.live_watch_control;
BEGIN
 IF octet_length(p)<>32 OR i IS NULL THEN RAISE EXCEPTION 'live recovery locator invalid' USING ERRCODE='22023'; END IF;
 SELECT * INTO w FROM public.live_watch_control WHERE root_id=r AND principal_key=p AND id=i;
 IF NOT FOUND THEN RAISE EXCEPTION 'live recovery unavailable' USING ERRCODE='55000'; END IF;
 RETURN public.live_watch_value(w);
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION live_watch_read_control(r uuid, p bytea, i uuid) FROM PUBLIC;

-- +goose StatementBegin
CREATE FUNCTION live_watch_refilled(t bigint, a timestamp with time zone, n timestamp with time zone, rate bigint, burst bigint) RETURNS bigint
    LANGUAGE sql IMMUTABLE
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
 SELECT least(burst::numeric*1000000,t::numeric+greatest(0,floor(extract(epoch FROM n-a)*1000000))*rate::numeric)::bigint
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION live_watch_refilled(t bigint, a timestamp with time zone, n timestamp with time zone, rate bigint, burst bigint) FROM PUBLIC;

-- +goose StatementBegin
CREATE FUNCTION live_watch_value(w live_watch_control) RETURNS jsonb
    LANGUAGE sql IMMUTABLE
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
 SELECT jsonb_build_object('ID',w.id,'OwnerID',w.owner_id,'Fence',w.fence,
 'PrincipalKey',to_jsonb(ARRAY(SELECT get_byte(w.principal_key,g.idx) FROM generate_series(0,31) AS g(idx))),
 'WorkloadKey',to_jsonb(ARRAY(SELECT get_byte(w.workload_key,g.idx) FROM generate_series(0,31) AS g(idx))),
 'RequestDigest',to_jsonb(ARRAY(SELECT get_byte(w.request_digest,g.idx) FROM generate_series(0,31) AS g(idx))),
 'Revision',w.revision,'State',w.state,'AcceptedAt',w.accepted_at,'ExpiresAt',w.expires_at,'IdleUntil',w.idle_until,
 'Spent',w.spent,'BytesPerSecond',w.bytes_per_second)
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION live_watch_value(w live_watch_control) FROM PUBLIC;

-- +goose StatementBegin
CREATE FUNCTION live_watch_viewers(i uuid, k bytea) RETURNS bigint
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
BEGIN
 IF k IS NULL OR octet_length(k)<>32 OR EXISTS(SELECT 1 FROM public.live_watch_control w JOIN public.live_watch_root b ON b.root_id=w.root_id WHERE b.installation_id=i AND w.cluster_key IS NULL AND w.state IN ('Active','Paused','Disconnected') AND clock_timestamp()<w.expires_at AND clock_timestamp()<w.idle_until) THEN
  RAISE EXCEPTION 'live viewer cluster history unavailable' USING ERRCODE='55000';
 END IF;
 RETURN (SELECT count(DISTINCT w.id)
 FROM public.live_watch_control w
 JOIN public.live_watch_root b ON b.root_id=w.root_id
 JOIN public.fleet_current_trust t ON t.installation_id=b.installation_id AND t.issuer_epoch=b.issuer_epoch
 JOIN public.hub_owner_enrollment e ON e.installation_id=b.installation_id AND e.issuer_epoch=b.issuer_epoch AND e.process_epoch=w.owner_id AND e.usage='server'
 WHERE b.installation_id=i AND w.cluster_key=k
 AND NOT t.suspended AND t.observed_at<=clock_timestamp() AND clock_timestamp()<t.fresh_until
 AND e.audit_receipt_json IS NOT NULL AND e.retired_at IS NULL AND clock_timestamp()<e.hold_until
 AND EXISTS(SELECT 1 FROM public.hub_owner_certificate a WHERE a.enrollment_id=e.id AND a.activated_at IS NOT NULL AND clock_timestamp()<a.not_after)
 AND w.state IN ('Active','Paused','Disconnected')
 AND clock_timestamp()<w.expires_at AND clock_timestamp()<w.idle_until);
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION live_watch_viewers(i uuid, k bytea) FROM PUBLIC;

-- +goose StatementBegin
CREATE FUNCTION lock_approved_context_grant(p_root uuid, p_preview uuid, p_capture uuid, p_issuer text, p_subject text, p_client text, p_digest bytea) RETURNS timestamp with time zone
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
DECLARE g public.access_grant;
BEGIN
 SELECT * INTO g FROM public.access_grant WHERE root_id=p_root AND preview_id=p_preview AND capture_id=p_capture FOR SHARE;
 IF NOT FOUND OR g.requester_issuer<>p_issuer OR g.requester_subject<>p_subject OR g.requester_client<>p_client
 OR g.execution_digest<>p_digest OR g.decision IS DISTINCT FROM 'approved' OR g.revoked_at IS NOT NULL
 OR g.expires_at<=clock_timestamp() OR convert_from(g.scope,'UTF8')::jsonb->>'timing' IS DISTINCT FROM 'approvedAcceptance/v1' THEN
  RETURN NULL;
 END IF;
 RETURN g.expires_at;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION lock_approved_context_grant(p_root uuid, p_preview uuid, p_capture uuid, p_issuer text, p_subject text, p_client text, p_digest bytea) FROM PUBLIC;

-- +goose StatementBegin
CREATE FUNCTION lock_context_query_capacity(r uuid, acceptance uuid) RETURNS boolean
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
DECLARE a public.context_query_capacity;b public.context_query_backing;t public.fleet_current_trust;
BEGIN
 SELECT * INTO STRICT b FROM public.context_query_backing WHERE root_id=r;
 SELECT * INTO STRICT t FROM public.fleet_current_trust WHERE installation_id=b.installation_id FOR SHARE;
 PERFORM 1 FROM public.permission_stream WHERE id=r FOR SHARE;
 SELECT * INTO STRICT a FROM public.context_query_capacity WHERE root_id=r AND acceptance_id=acceptance FOR SHARE;
 RETURN COALESCE(b.acceptance_id=acceptance AND a.capacity_id=(a.plan->'Qualification'->>'CapacityID')::uuid AND a.observations=0 AND a.issuer_epoch=t.issuer_epoch AND
  public.incarnation_current(a.postmaster_at) AND a.database_oid=(SELECT oid FROM pg_database WHERE datname=current_database()) AND
  (a.plan->>'RootID')::uuid=r AND (a.plan->>'HardUntil')::timestamptz=b.hard_until AND clock_timestamp()<b.hard_until,false);
EXCEPTION WHEN data_exception OR no_data_found OR too_many_rows THEN RETURN false;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION lock_context_query_capacity(r uuid, acceptance uuid) FROM PUBLIC;

-- +goose StatementBegin
CREATE FUNCTION materialize_capture_share() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
DECLARE s jsonb; access_until timestamptz; version bytea; ends timestamptz; acceptance uuid; share uuid; at timestamptz:=clock_timestamp();
BEGIN
 IF TG_WHEN<>'AFTER' OR TG_LEVEL<>'ROW' OR TG_OP<>'INSERT' OR TG_TABLE_SCHEMA<>'public' OR TG_RELID<>'public.context_case_locator'::regclass THEN
  RAISE EXCEPTION 'invalid capture share source' USING ERRCODE='23514';
 END IF;
 SELECT c.share_instruction,a.effective_expires_at INTO s,access_until FROM public.context_capture c JOIN public.custody_attempt a ON a.id=c.attempt_id
 WHERE c.id=NEW.capture_id AND c.root_id=NEW.root_id;
 IF s IS NULL THEN
  RETURN NEW;
 END IF;
 BEGIN
  acceptance:=(s->>'policy_acceptance_id')::uuid;
 EXCEPTION WHEN invalid_text_representation THEN
  RETURN NEW;
 END;
 IF acceptance IS NOT NULL THEN
  PERFORM 1 FROM public.policy_acceptance p WHERE p.id=acceptance AND p.root_id=NEW.root_id AND p.sharing_revoked_at IS NULL FOR KEY SHARE;
  IF NOT FOUND THEN
   RETURN NEW;
  END IF;
 END IF;
 SELECT v.copies_digest INTO version FROM public.context_catalog v WHERE v.capture_id=NEW.capture_id AND v.root_id=NEW.root_id;
 ends:=LEAST(COALESCE((s->>'not_after')::timestamptz,access_until),access_until);
 IF version IS NULL OR ends IS NULL OR ends<=at THEN
  RETURN NEW;
 END IF;
 BEGIN
  INSERT INTO public.evidence_share(id,root_id,artifact_id,case_id,cluster_id,namespace_uid,workload_uid,pod_uid,version,creator_issuer,creator_subject,creator_client,
   management,recipients,recipient_keys,idempotency_key,request_digest,created_at,expires_at,policy_acceptance_id)
  VALUES((s->>'share_id')::uuid,NEW.root_id,NEW.artifact_id,NEW.case_id,NEW.cluster_id,NEW.namespace_uid,NEW.workload_uid,NEW.pod_uid,version,
   s#>>'{creator,issuer}',s#>>'{creator,subject}',s#>>'{creator,client}',s->'management',s->'recipients',
   ARRAY(SELECT jsonb_array_elements_text(s->'recipient_keys')),'capture:'||NEW.capture_id::text,decode(s->>'request_digest','hex'),at,ends,acceptance)
  ON CONFLICT DO NOTHING RETURNING id INTO share;
 EXCEPTION WHEN check_violation OR not_null_violation OR invalid_text_representation OR foreign_key_violation THEN
  -- A malformed instruction never blocks publication; the share is
  -- reported unavailable instead.
  RETURN NEW;
 END;
 IF share IS NOT NULL THEN
  INSERT INTO public.audit_event(event_id,operation_id,kind,operation,issuer,subject,client_id,identity_type,status,effect,case_ids,artifact_ids,capture_ids,share_ids)
  VALUES(gen_random_uuid(),NEW.capture_id,'share.create','publish_capture',s#>>'{creator,issuer}',s#>>'{creator,subject}',s#>>'{creator,client}','human','success','accepted',
   ARRAY[NEW.case_id::text],ARRAY[NEW.artifact_id::text],ARRAY[NEW.capture_id::text],ARRAY[share::text]);
 END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION materialize_capture_share() FROM PUBLIC;

-- +goose StatementBegin
CREATE FUNCTION notify_capture_progress() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
BEGIN
 PERFORM pg_notify('asservat_capture_progress',NEW.id::text);
 RETURN NULL;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION notify_capture_progress() FROM PUBLIC;

-- +goose StatementBegin
CREATE FUNCTION notify_grant_capture() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
BEGIN
 PERFORM pg_notify('asservat_capture_progress',NEW.capture_id::text);
 RETURN NULL;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION notify_grant_capture() FROM PUBLIC;

-- +goose StatementBegin
CREATE FUNCTION notify_remote_delivery() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
BEGIN
 PERFORM pg_notify(TG_ARGV[0],NEW.cluster_id::text);
 RETURN NULL;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION notify_remote_delivery() FROM PUBLIC;

-- +goose StatementBegin
CREATE FUNCTION processing_erasure_attempt(d processing_decision, p processing_root) RETURNS custody_attempt
    LANGUAGE plpgsql
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
DECLARE a public.custody_attempt; l public.context_processing; doc jsonb; origins jsonb; storage_pool_id uuid; n timestamptz;
BEGIN
 IF d.action IS DISTINCT FROM 'request_early_erasure' OR d.root_id IS DISTINCT FROM p.root_id OR p.initialized_at IS NULL OR
    d.rule_id IS NOT NULL OR d.expected_revision<>0 OR
    d.scope->>'Kind' IS DISTINCT FROM 'artifact' OR NOT public.processing_scope_valid(d.scope) THEN
  RAISE EXCEPTION 'invalid processing erasure scope' USING ERRCODE='23514'; END IF;
 SELECT * INTO STRICT l FROM public.context_processing WHERE root_id=d.root_id AND
  cluster_id=(d.scope#>>'{Location,ClusterID}')::uuid AND artifact_id=(d.scope#>>'{Location,ArtifactID}')::uuid AND attempt_id=(d.scope#>>'{Location,AttemptID}')::uuid;
 SELECT * INTO STRICT a FROM public.custody_attempt WHERE id=l.attempt_id;
 SELECT ca.pool_id INTO STRICT storage_pool_id FROM public.custody_allocation ca WHERE ca.id=a.allocation_id;
 PERFORM 1 FROM public.custody_pool cp WHERE cp.id=storage_pool_id FOR UPDATE;
 PERFORM 1 FROM public.custody_allocation ca WHERE ca.id=a.allocation_id AND ca.pool_id=storage_pool_id FOR UPDATE;
 SELECT * INTO STRICT a FROM public.custody_attempt WHERE id=l.attempt_id FOR UPDATE;
 n:=clock_timestamp();
 IF n>=d.request_until OR n>=p.valid_until OR d.request_until>=l.retire_by OR
    a.artifact_id<>l.artifact_id OR a.cluster_id<>l.cluster_id OR a.anchor_at<>l.anchor_at OR a.delete_by<>l.delete_by OR
    a.state<>'stored_unpublished' OR n>=a.effective_expires_at OR a.effective_expires_at<=a.anchor_at OR
    NOT EXISTS(SELECT 1 FROM public.context_catalog cat
     JOIN public.context_capture c ON c.root_id=cat.root_id AND c.id=cat.capture_id
     JOIN public.context_writer_completion w ON w.root_id=c.root_id AND w.capture_id=c.id AND w.attempt_id=c.attempt_id
     JOIN public.context_execution x ON x.root_id=w.root_id AND x.capture_id=w.capture_id AND x.attempt_id=w.attempt_id
     JOIN public.fleet_trust f ON f.installation_id=w.installation_id AND f.activated_postmaster_at=w.postmaster_at AND f.activated_database_oid=w.database_oid
     JOIN public.fleet_current_trust t ON t.installation_id=f.installation_id AND t.issuer_epoch=w.issuer_epoch
     WHERE cat.root_id=l.root_id AND cat.artifact_id=l.artifact_id AND cat.capture_id=l.capture_id AND c.attempt_id=a.id
      AND cat.copies_digest=a.copies_digest
      AND x.writer_protocol='closed-small-context/v1' AND x.phase='stored' AND x.copies_digest=w.copies_digest
      AND w.copies_digest=a.copies_digest AND w.registration_digest=a.request_digest AND w.installation_id=p.installation_id AND w.issuer_epoch=p.issuer_epoch
      AND w.closed_at<=n AND public.incarnation_current(w.postmaster_at) AND w.database_oid=(SELECT oid FROM pg_database WHERE datname=current_database())
      AND NOT t.suspended AND t.observed_at<=n AND n<t.fresh_until) THEN
  RAISE EXCEPTION 'processing erasure needs current verified closed writer' USING ERRCODE='23514'; END IF;
 IF a.retention_sequence=0 THEN
  SELECT convert_from(c.expectation_json,'UTF8')::jsonb->'RetentionRules' INTO STRICT origins FROM public.context_capture c WHERE c.root_id=l.root_id AND c.id=l.capture_id;
 ELSE
  SELECT convert_from(r.decision_json,'UTF8')::jsonb->'Origins' INTO STRICT origins FROM public.retention_decision r
   WHERE r.root_id=l.root_id AND r.attempt_id=a.id AND r.sequence=a.retention_sequence;
 END IF;
 doc:=convert_from(d.erasure_decision,'UTF8')::jsonb;
 IF NOT public.capacity_json_fields(doc,ARRAY['ID','RootID','Location','Target','Sequence','RegistrationDigest','PolicyRevision','Policies','Origins','Previous','Effective','ObservedAt','ValidUntil']) OR
    doc->>'ID' IS DISTINCT FROM d.id::text OR doc->>'RootID' IS DISTINCT FROM d.root_id::text OR doc->'Location' IS DISTINCT FROM d.scope->'Location' OR
    doc->'Target' IS DISTINCT FROM jsonb_build_object('ClusterID',l.cluster_id,'NamespaceUID',l.namespace_uid,'WorkloadUID',l.workload_uid,'PodUID',l.pod_uid) OR
    (doc->>'Sequence')::bigint IS DISTINCT FROM a.retention_sequence+1 OR public.connector_digest(doc->'RegistrationDigest') IS DISTINCT FROM a.request_digest OR
    NOT public.capacity_json_fields(doc->'PolicyRevision',ARRAY['UID','Generation','Digest']) OR
    doc#>>'{PolicyRevision,UID}' IS DISTINCT FROM 'erasure:'||d.id::text OR doc#>'{PolicyRevision,Generation}' IS DISTINCT FROM '1'::jsonb OR
    public.connector_digest(doc#>'{PolicyRevision,Digest}') IS DISTINCT FROM d.request_digest OR
    jsonb_typeof(origins) IS DISTINCT FROM 'array' OR jsonb_array_length(origins) NOT BETWEEN 1 AND 64 OR
    doc->'Policies' IS DISTINCT FROM origins OR doc->'Origins' IS DISTINCT FROM origins OR
    NOT public.capacity_json_fields(doc->'Previous',ARRAY['AnchorAt','ExpiresAt','DeleteBy']) OR
    NOT public.capacity_json_fields(doc->'Effective',ARRAY['AnchorAt','ExpiresAt','DeleteBy']) OR
    (doc#>>'{Previous,AnchorAt}')::timestamptz IS DISTINCT FROM a.anchor_at OR (doc#>>'{Previous,ExpiresAt}')::timestamptz IS DISTINCT FROM a.effective_expires_at OR
    (doc#>>'{Previous,DeleteBy}')::timestamptz IS DISTINCT FROM a.effective_delete_by OR
    (doc#>>'{Effective,AnchorAt}')::timestamptz IS DISTINCT FROM a.anchor_at OR (doc#>>'{Effective,ExpiresAt}')::timestamptz IS DISTINCT FROM a.anchor_at OR
    (doc#>>'{Effective,DeleteBy}')::timestamptz IS DISTINCT FROM a.effective_delete_by OR
    (doc->>'ObservedAt')::timestamptz IS DISTINCT FROM d.created_at OR (doc->>'ValidUntil')::timestamptz IS DISTINCT FROM d.request_until THEN
  RAISE EXCEPTION 'processing erasure payload does not match retained custody' USING ERRCODE='23514'; END IF;
 RETURN a;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION processing_erasure_attempt(d processing_decision, p processing_root) FROM PUBLIC;

-- +goose StatementBegin
CREATE FUNCTION processing_scope_valid(s jsonb) RETURNS boolean
    LANGUAGE sql IMMUTABLE
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
 SELECT coalesce(jsonb_typeof(s)='object' AND octet_length(s::text)<=2048 AND
 s ?& ARRAY['Kind','Location','ClusterID','NamespaceUID','WorkloadUID','AcquiredFrom','AcquiredUntil'] AND
 s-ARRAY['Kind','Location','ClusterID','NamespaceUID','WorkloadUID','AcquiredFrom','AcquiredUntil']='{}'::jsonb AND
 jsonb_typeof(s->'Location')='object' AND (s->'Location')-ARRAY['ClusterID','ArtifactID','AttemptID']='{}'::jsonb AND
 CASE s->>'Kind'
 WHEN 'artifact' THEN (s#>>'{Location,ClusterID}')::uuid IS NOT NULL AND (s#>>'{Location,ArtifactID}')::uuid IS NOT NULL AND (s#>>'{Location,AttemptID}')::uuid IS NOT NULL
  AND s->>'ClusterID'='' AND s->>'NamespaceUID'='' AND s->>'WorkloadUID'='' AND s->>'AcquiredFrom'='0001-01-01T00:00:00Z' AND s->>'AcquiredUntil'='0001-01-01T00:00:00Z'
 WHEN 'workloadInterval' THEN s->'Location'='{"ClusterID":"","ArtifactID":"","AttemptID":""}'::jsonb AND (s->>'ClusterID')::uuid IS NOT NULL
  AND octet_length(s->>'NamespaceUID') BETWEEN 1 AND 64 AND octet_length(s->>'WorkloadUID') BETWEEN 1 AND 64
  AND isfinite((s->>'AcquiredFrom')::timestamptz) AND isfinite((s->>'AcquiredUntil')::timestamptz)
  AND (s->>'AcquiredUntil')::timestamptz>(s->>'AcquiredFrom')::timestamptz AND (s->>'AcquiredUntil')::timestamptz<=(s->>'AcquiredFrom')::timestamptz+interval '3660 days'
 ELSE false END,false)
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION processing_scope_valid(s jsonb) FROM PUBLIC;

-- +goose StatementBegin
CREATE FUNCTION project_context_case_locator() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
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

-- +goose StatementBegin
CREATE FUNCTION project_context_processing() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $_$
DECLARE p public.processing_root; e jsonb; n timestamptz;
BEGIN
 IF TG_WHEN<>'AFTER' OR TG_LEVEL<>'ROW' OR TG_OP<>'INSERT' OR TG_TABLE_SCHEMA<>'public' OR TG_RELID<>'public.context_catalog'::regclass THEN
  RAISE EXCEPTION 'invalid processing publication source' USING ERRCODE='23514'; END IF;
 PERFORM 1 FROM public.permission_stream WHERE id=NEW.root_id FOR UPDATE;
 SELECT * INTO STRICT p FROM public.processing_root WHERE root_id=NEW.root_id FOR UPDATE;
 n:=clock_timestamp();
 IF p.initialized_at IS NULL OR n>=p.valid_until THEN RAISE EXCEPTION 'processing completeness unavailable' USING ERRCODE='23514'; END IF;
 SELECT convert_from(c.expectation_json,'UTF8')::jsonb INTO STRICT e FROM public.context_capture c WHERE c.id=NEW.capture_id AND c.root_id=NEW.root_id;
 IF e ? 'Processes' AND e->>'NativeType' IS DISTINCT FROM 'processes' THEN RAISE EXCEPTION 'unqualified process processing lineage' USING ERRCODE='23514'; END IF;
 IF e ? 'Logs' AND e->>'NativeType' IS DISTINCT FROM 'logs' THEN RAISE EXCEPTION 'unqualified logs processing lineage' USING ERRCODE='23514'; END IF;
 IF NOT COALESCE(e->>'ActionID'~'^a[0-9a-f]{24}$' AND e->>'NativeType'='processes' AND e->>'DataClass'='metadata' AND
    jsonb_typeof(e->'Processes')='object' AND e#>>'{Processes,ActionID}'=e->>'ActionID' AND
    e#>>'{Processes,Mode}' IN ('podMainProcesses','allPodProcesses') AND
    public.capacity_json_integer(e#>'{Processes,MaxNativeBytes}',1,2097152) AND e#>'{Processes,MaxNativeBytes}'=e#>'{Registration,NativeLimit}' AND
    public.capacity_json_integer(e#>'{Processes,TimeoutMillis}',1,5000) AND length(e#>>'{Processes,Composition}') BETWEEN 1 AND 65536 AND
    NOT(e ? 'Recording') AND NOT(e ? 'Profile') AND NOT(e ? 'Snapshot') AND NOT(e ? 'Logs') AND NOT(e ? 'Lifecycle') AND NOT(e ? 'CompositionGroup') OR
    e->>'ActionID'~'^a[0-9a-f]{24}$' AND e->>'NativeType'='logs' AND e->>'DataClass'='raw' AND
    jsonb_typeof(e->'Logs')='object' AND e#>>'{Logs,ActionID}'=e->>'ActionID' AND e#>>'{Logs,Streams}'='combined' AND
    NOT(e ? 'Recording') AND NOT(e ? 'Profile') AND NOT(e ? 'Snapshot') AND NOT(e ? 'Lifecycle') AND
    public.capacity_json_integer(e#>'{Logs,BeforeMillis}',0,86400000) AND public.capacity_json_integer(e#>'{Logs,AfterMillis}',0,9007199254740991) AND public.capacity_json_integer(e#>'{Logs,TimeoutMillis}',1,9007199254740991) AND
    (e#>>'{Logs,TimeoutMillis}')::bigint>(e#>>'{Logs,AfterMillis}')::bigint AND
    (e#>>'{Logs,BeforeMillis}')::bigint+(e#>>'{Logs,AfterMillis}')::bigint>0 AND
    public.capacity_json_integer(e#>'{Logs,MaxNativeBytes}',1,67108864) AND e#>'{Logs,MaxNativeBytes}'=e#>'{Registration,NativeLimit}' AND
    (e->>'TriggeredAt')::timestamptz+make_interval(secs=>(e#>>'{Logs,AfterMillis}')::double precision/1000)<(e#>>'{Registration,WriteUntil}')::timestamptz AND
    length(e#>>'{Logs,Composition}')>0 OR
    e->>'ActionID'~'^a[0-9a-f]{24}$' AND e->>'NativeType' IN ('pprof','goTrace') AND jsonb_typeof(e->'Profile')='object' AND e->>'DataClass'='raw' AND
    NOT e ? 'Recording' AND NOT e ? 'Snapshot' AND NOT e ? 'Lifecycle' AND NOT e ? 'CompositionGroup' AND
    (e->>'NativeType'='goTrace' AND e#>>'{Profile,Type}'='runtimeTrace' OR e->>'NativeType'='pprof' AND e#>>'{Profile,Type}' IN ('cpu','heap','allocs','goroutine','block','mutex','threadcreate')) AND
    (e#>>'{Profile,MaxBytes}')::bigint=(e#>>'{Registration,NativeLimit}')::bigint AND
    (e#>>'{Profile,TimeoutMillis}')::bigint BETWEEN (e#>>'{Profile,DurationMillis}')::bigint+5000 AND (e#>>'{Profile,DurationMillis}')::bigint+10000 AND
    length(e#>>'{Profile,Composition}')>0 OR
    e->>'ActionID'='pod-status' AND NOT e ? 'NativeType' AND NOT e ? 'Recording' AND NOT e ? 'Logs' OR
    e->>'ActionID'~'^a[0-9a-f]{24}$' AND jsonb_typeof(e->'Recording')='object' AND (e->>'NativeType'='pcapng' AND e#>>'{Recording,Kind}'='packetCapture' OR e->>'NativeType'='rawPcapng' AND e#>>'{Recording,Kind}'='packetCapture' AND e#>>'{Recording,Profile}'='rawPackets' OR e->>'NativeType'='httpHeaders' AND e#>>'{Recording,Kind}'='packetCapture' AND e#>>'{Recording,Profile}'='httpHeaders' OR e->>'NativeType'='syscallRecords' AND e#>>'{Recording,Kind}'='syscallTrace' OR e->>'NativeType'='syscallArguments' AND e#>>'{Recording,Kind}'='syscallTrace' AND e#>>'{Recording,Profile}'='arguments' AND jsonb_typeof(e#>'{Recording,Arguments}')='object' AND NOT e ? 'Snapshot' AND NOT e ? 'Profile' AND NOT e ? 'Lifecycle') OR
    e->>'ActionID'~'^a[0-9a-f]{24}$' AND e->>'NativeType' IN ('pcapng','syscallRecords') AND jsonb_typeof(e->'Snapshot')='object' AND NOT(e#>'{Snapshot}' ? 'HTTP') AND (NOT e ? 'Recording' OR e->'Recording'='null'::jsonb) OR
    e->>'ActionID'~'^a[0-9a-f]{24}$' AND e->>'NativeType'='httpHeaders' AND e->>'DataClass'='extract' AND jsonb_typeof(e->'Snapshot')='object' AND NOT(e ? 'Recording') AND
    public.capacity_json_fields(e#>'{Snapshot,HTTP}',ARRAY['MaxFlows','MaxHeaderBytes','MaxFlowBytes','MaxTotalBytes','IdleMillis']) AND
    public.capacity_json_integer(e#>'{Snapshot,HTTP,MaxFlows}',1,1024) AND public.capacity_json_integer(e#>'{Snapshot,HTTP,MaxHeaderBytes}',1,32768) AND
    public.capacity_json_integer(e#>'{Snapshot,HTTP,MaxFlowBytes}',1,262144) AND public.capacity_json_integer(e#>'{Snapshot,HTTP,MaxTotalBytes}',1,16777216) AND
    (e#>>'{Snapshot,HTTP,MaxTotalBytes}')::bigint>=(e#>>'{Snapshot,HTTP,MaxFlowBytes}')::bigint AND public.capacity_json_integer(e#>'{Snapshot,HTTP,IdleMillis}',1000,30000) AND
    (CASE WHEN e#>>'{SourceSnapshotManifest,binding}'~'^[A-Za-z0-9+/]+={0,2}$' THEN convert_from(decode(e#>>'{SourceSnapshotManifest,binding}','base64'),'UTF8')::jsonb->>'ObservationGrantID' END)~'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',false) OR NOT COALESCE(e->>'DataClass'='metadata' AND e->>'NativeType' IS DISTINCT FROM 'logs' AND e->>'NativeType' IS DISTINCT FROM 'rawPcapng' AND e->>'NativeType' IS DISTINCT FROM 'httpHeaders' AND e->>'NativeType' IS DISTINCT FROM 'pprof' AND e->>'NativeType' IS DISTINCT FROM 'goTrace' AND e->>'NativeType' IS DISTINCT FROM 'syscallArguments' OR e->>'DataClass'='raw' AND e->>'NativeType' IN ('rawPcapng','pprof','goTrace','syscallArguments','logs') OR e->>'DataClass'='extract' AND e->>'NativeType'='httpHeaders',false) OR
    (e->>'CaptureUID')::uuid IS DISTINCT FROM NEW.capture_id OR (e#>>'{Registration,Location,ArtifactID}')::uuid IS DISTINCT FROM NEW.artifact_id OR
    (e#>>'{Registration,DeleteBy}')::timestamptz>p.valid_until THEN
  RAISE EXCEPTION 'unqualified processing lineage' USING ERRCODE='23514'; END IF;
 -- Renewing installation capacity does not expand an older restrictive rule's
 -- managed-history coverage. The restriction stays effective after its own
 -- administrative deadline; future matching evidence cannot outlive backing.
 IF EXISTS(SELECT 1 FROM public.processing_rule r WHERE r.root_id=NEW.root_id AND r.state='restricted' AND
    (e#>>'{Registration,DeleteBy}')::timestamptz>r.valid_until AND
    ((r.scope->>'Kind'='artifact' AND r.scope#>>'{Location,ArtifactID}'=NEW.artifact_id::text AND r.scope#>>'{Location,AttemptID}'=e#>>'{Registration,Location,AttemptID}' AND r.scope#>>'{Location,ClusterID}'=e#>>'{Registration,Location,ClusterID}') OR
     (r.scope->>'Kind'='workloadInterval' AND r.scope->>'ClusterID'=e#>>'{Registration,Location,ClusterID}' AND r.scope->>'NamespaceUID'=e->>'NamespaceUID' AND r.scope->>'WorkloadUID'=e->>'WorkloadUID' AND
      (e#>>'{Registration,AnchorAt}')::timestamptz>=(r.scope->>'AcquiredFrom')::timestamptz AND (e#>>'{Registration,AnchorAt}')::timestamptz<(r.scope->>'AcquiredUntil')::timestamptz))) THEN
  RAISE EXCEPTION 'retained processing restriction requires coverage reconciliation' USING ERRCODE='23514'; END IF;
 INSERT INTO public.context_processing(artifact_id,root_id,capture_id,attempt_id,cluster_id,namespace_uid,workload_uid,pod_uid,anchor_at,delete_by,retire_by,origin,parents)
 VALUES(NEW.artifact_id,NEW.root_id,NEW.capture_id,(e#>>'{Registration,Location,AttemptID}')::uuid,(e#>>'{Registration,Location,ClusterID}')::uuid,e->>'NamespaceUID',e->>'WorkloadUID',e->>'PodUID',(e#>>'{Registration,AnchorAt}')::timestamptz,(e#>>'{Registration,DeleteBy}')::timestamptz,p.retire_by,'capture','[]');
 RETURN NEW;
END $_$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION project_context_processing() FROM PUBLIC;

-- +goose StatementBegin
CREATE FUNCTION project_recording_save_group_revision() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
BEGIN
 IF NEW.group_id IS NOT NULL AND NEW.progress_revision<>OLD.progress_revision THEN
  UPDATE public.recording_save_group SET progress_revision=progress_revision+1 WHERE id=NEW.group_id;
 END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION project_recording_save_group_revision() FROM PUBLIC;

-- +goose StatementBegin
CREATE FUNCTION protect_access_grant() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
DECLARE
 counters text[] := ARRAY['artifacts_spent','bytes_spent','operations_spent',
  'policy_executions_spent','policy_bytes_spent','policy_observed_bytes_spent','policy_observed_events_spent'];
 mutable text[] := ARRAY['decision','approver_issuer','approver_subject','approver_client','decision_reason','decision_acr','decision_auth_time','decided_at','decision_key','expires_at',
  'revoked_at','revoker_issuer','revoker_subject','revoker_client','revoke_key','revision','policy_not_after',
  'artifacts_spent','bytes_spent','operations_spent','policy_executions_spent','policy_bytes_spent','policy_observed_bytes_spent','policy_observed_events_spent'];
 spent boolean;
 before_row jsonb;
 after_row jsonb;
BEGIN
 -- Stored generated values are computed after BEFORE triggers. Compare the
 -- immutable source columns, never NEW's not-yet-computed generated fields.
 before_row := to_jsonb(OLD)-ARRAY['policy_max_executions','policy_max_bytes','policy_max_observed_bytes'];
 after_row := to_jsonb(NEW)-ARRAY['policy_max_executions','policy_max_bytes','policy_max_observed_bytes'];
 IF TG_OP='DELETE' OR (after_row-mutable)<>(before_row-mutable) THEN
  RAISE EXCEPTION 'access grant is immutable' USING ERRCODE='23514';
 END IF;
 spent := ROW(NEW.artifacts_spent,NEW.bytes_spent,NEW.operations_spent,NEW.policy_executions_spent,NEW.policy_bytes_spent,NEW.policy_observed_bytes_spent,NEW.policy_observed_events_spent)
   IS DISTINCT FROM ROW(OLD.artifacts_spent,OLD.bytes_spent,OLD.operations_spent,OLD.policy_executions_spent,OLD.policy_bytes_spent,OLD.policy_observed_bytes_spent,OLD.policy_observed_events_spent);
 IF NEW.artifacts_spent<OLD.artifacts_spent OR NEW.bytes_spent<OLD.bytes_spent OR NEW.operations_spent<OLD.operations_spent
  OR NEW.policy_executions_spent<OLD.policy_executions_spent OR NEW.policy_bytes_spent<OLD.policy_bytes_spent OR NEW.policy_observed_bytes_spent<OLD.policy_observed_bytes_spent OR NEW.policy_observed_events_spent<OLD.policy_observed_events_spent THEN
  RAISE EXCEPTION 'access grant spend never decreases' USING ERRCODE='23514';
 END IF;
 IF OLD.decision IS NULL AND NEW.decision IS NOT NULL THEN
  IF spent OR NEW.policy_not_after IS DISTINCT FROM OLD.policy_not_after
   OR OLD.revoked_at IS NOT NULL OR NEW.revoked_at IS NOT NULL OR NEW.revision<>OLD.revision+1
   OR clock_timestamp()>=OLD.review_until OR (OLD.kind='policy' AND clock_timestamp()>=OLD.policy_not_after)
   OR (OLD.kind='rawQuery' AND clock_timestamp()>=OLD.not_after) THEN
   RAISE EXCEPTION 'access grant decision refused' USING ERRCODE='23514';
  END IF;
 ELSIF OLD.revoked_at IS NULL AND NEW.revoked_at IS NOT NULL THEN
  IF spent OR NEW.revision<>OLD.revision+1 OR (after_row-ARRAY['revoked_at','revoker_issuer','revoker_subject','revoker_client','revoke_key','revision'])<>(before_row-ARRAY['revoked_at','revoker_issuer','revoker_subject','revoker_client','revoke_key','revision']) THEN
   RAISE EXCEPTION 'access grant revocation refused' USING ERRCODE='23514';
  END IF;
 ELSIF NEW.policy_not_after IS DISTINCT FROM OLD.policy_not_after THEN
  IF OLD.kind<>'policy' OR NEW.policy_not_after IS NULL OR NEW.policy_not_after>=OLD.policy_not_after
   OR (after_row-ARRAY['policy_not_after','expires_at'])<>(before_row-ARRAY['policy_not_after','expires_at'])
   OR NEW.expires_at IS DISTINCT FROM (CASE WHEN OLD.decision='approved' THEN NEW.policy_not_after ELSE NULL END) THEN
   RAISE EXCEPTION 'access grant deadline only shortens' USING ERRCODE='23514';
  END IF;
 ELSIF spent THEN
  IF OLD.decision IS DISTINCT FROM 'approved' OR OLD.revoked_at IS NOT NULL OR clock_timestamp()>=OLD.expires_at
   OR (after_row-counters)<>(before_row-counters) THEN
   RAISE EXCEPTION 'access grant pool is not usable' USING ERRCODE='23514';
  END IF;
 ELSE
  RAISE EXCEPTION 'access grant is immutable' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION protect_access_grant() FROM PUBLIC;

-- +goose StatementBegin
CREATE FUNCTION protect_access_grant_history() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
BEGIN
 RAISE EXCEPTION 'access grant history is append-only' USING ERRCODE='23514';
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION protect_access_grant_history() FROM PUBLIC;

-- +goose StatementBegin
CREATE FUNCTION protect_adhoc_observation_spend() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
BEGIN
 IF TG_OP='DELETE' OR NEW.root_id<>OLD.root_id OR NEW.grant_id<>OLD.grant_id OR NEW.spent<OLD.spent OR NEW.events_spent<OLD.events_spent THEN
  RAISE EXCEPTION 'ad hoc observation spend is monotonic' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION protect_adhoc_observation_spend() FROM PUBLIC;

-- +goose StatementBegin
CREATE FUNCTION protect_capture_share_instruction() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
BEGIN
 IF NEW.share_instruction IS DISTINCT FROM OLD.share_instruction THEN
  RAISE EXCEPTION 'capture sharing instruction is immutable' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION protect_capture_share_instruction() FROM PUBLIC;

-- +goose StatementBegin
CREATE FUNCTION protect_context_case_locator() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
BEGIN
 RAISE EXCEPTION 'immutable context case routing; retirement protocol required' USING ERRCODE='23514';
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION protect_context_case_locator() FROM PUBLIC;

-- +goose StatementBegin
CREATE FUNCTION protect_custody_retention() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
BEGIN
 IF TG_OP='INSERT' THEN
  IF NEW.retention_sequence<>0 OR (NEW.effective_expires_at IS NOT NULL AND NEW.effective_expires_at<>NEW.expires_at) OR (NEW.effective_delete_by IS NOT NULL AND NEW.effective_delete_by<>NEW.delete_by) THEN RAISE EXCEPTION 'initial retention must match registration'; END IF;
  NEW.effective_expires_at:=NEW.expires_at;NEW.effective_delete_by:=NEW.delete_by;RETURN NEW;
 END IF;
 IF (NEW.id,NEW.cluster_id,NEW.artifact_id,NEW.allocation_id,NEW.request_digest,NEW.pool_revision,NEW.allocation_revision,NEW.native_limit,NEW.reserved_bytes,NEW.anchor_at,NEW.write_until,NEW.expires_at,NEW.delete_by) IS DISTINCT FROM
 (OLD.id,OLD.cluster_id,OLD.artifact_id,OLD.allocation_id,OLD.request_digest,OLD.pool_revision,OLD.allocation_revision,OLD.native_limit,OLD.reserved_bytes,OLD.anchor_at,OLD.write_until,OLD.expires_at,OLD.delete_by) THEN RAISE EXCEPTION 'immutable custody registration'; END IF;
 IF NEW.effective_expires_at>OLD.effective_expires_at OR NEW.effective_delete_by>OLD.effective_delete_by THEN RAISE EXCEPTION 'retention deadlines only shorten'; END IF;
 IF NEW.retention_sequence<>OLD.retention_sequence AND (NEW.retention_sequence<>OLD.retention_sequence+1 OR NOT EXISTS(SELECT 1 FROM public.retention_decision d WHERE d.attempt_id=OLD.id AND d.sequence=NEW.retention_sequence AND d.previous_expires_at=OLD.effective_expires_at AND d.previous_delete_by=OLD.effective_delete_by AND d.expires_at=NEW.effective_expires_at AND d.delete_by=NEW.effective_delete_by)) THEN RAISE EXCEPTION 'retention decision mismatch'; END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION protect_download_allocation() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
 IF (to_jsonb(NEW)-ARRAY['reserved_output','reserved_read']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['reserved_output','reserved_read']) OR NEW.reserved_output<OLD.reserved_output OR NEW.reserved_read<OLD.reserved_read THEN
  RAISE EXCEPTION 'immutable download allocation; reservations cannot be refunded' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION protect_download_batch() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
 IF ROW(NEW.id,NEW.session_id,NEW.generation,NEW.intent_json,NEW.lease_until) IS DISTINCT FROM ROW(OLD.id,OLD.session_id,OLD.generation,OLD.intent_json,OLD.lease_until) OR
 (OLD.audit_acknowledged_at IS NOT NULL AND ROW(NEW.audit_acknowledged_at,NEW.audit_receipt_json) IS DISTINCT FROM ROW(OLD.audit_acknowledged_at,OLD.audit_receipt_json)) OR
 (OLD.outcome_json IS NOT NULL AND NEW.outcome_json IS DISTINCT FROM OLD.outcome_json) OR
 (OLD.outcome_acknowledged_at IS NOT NULL AND ROW(NEW.outcome_acknowledged_at,NEW.outcome_receipt_json) IS DISTINCT FROM ROW(OLD.outcome_acknowledged_at,OLD.outcome_receipt_json)) THEN
  RAISE EXCEPTION 'immutable download batch or receipt' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION protect_download_session() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
 IF (to_jsonb(NEW)-ARRAY['state','charged_output','charged_read','emitted_bytes','generation','active_batch']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['state','charged_output','charged_read','emitted_bytes','generation','active_batch']) OR NEW.charged_output<OLD.charged_output OR NEW.charged_read<OLD.charged_read OR NEW.emitted_bytes<OLD.emitted_bytes OR NEW.generation<OLD.generation THEN
  RAISE EXCEPTION 'immutable download session or decreasing spend' USING ERRCODE='23514';
 END IF;
 IF OLD.state IN ('Completed','Cancelled','Expired','Denied','Failed') AND NEW.state<>OLD.state THEN
  RAISE EXCEPTION 'terminal download session' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION protect_evidence_share() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
DECLARE n timestamptz:=clock_timestamp();
BEGIN
 IF TG_OP='DELETE' THEN
  IF n<OLD.expires_at THEN RAISE EXCEPTION 'an unexpired share is revoked, not deleted' USING ERRCODE='23514'; END IF;
  RETURN OLD;
 END IF;
 IF TG_OP='INSERT' THEN
  IF NOT EXISTS(SELECT 1 FROM public.context_case_locator r JOIN public.context_capture source ON source.root_id=r.root_id AND source.id=r.capture_id
   JOIN public.context_catalog v ON v.root_id=r.root_id AND v.capture_id=r.capture_id
   JOIN public.custody_attempt attempt ON attempt.id=source.attempt_id
   WHERE r.root_id=NEW.root_id AND r.artifact_id=NEW.artifact_id AND r.case_id=NEW.case_id AND r.cluster_id=NEW.cluster_id
    AND r.namespace_uid=NEW.namespace_uid AND r.workload_uid=NEW.workload_uid AND r.pod_uid=NEW.pod_uid
    AND v.copies_digest=NEW.version AND NEW.expires_at<=attempt.effective_expires_at) THEN
   RAISE EXCEPTION 'share differs from exact published source' USING ERRCODE='23514';
  END IF;
  RETURN NEW;
 END IF;
 IF OLD.revoked_at IS NOT NULL OR NEW.revision<>OLD.revision+1 THEN
  RAISE EXCEPTION 'share mutation is unavailable or already spent' USING ERRCODE='23514';
 END IF;
 IF ROW(NEW.id,NEW.root_id,NEW.artifact_id,NEW.case_id,NEW.cluster_id,NEW.namespace_uid,NEW.workload_uid,NEW.pod_uid,
   NEW.version,NEW.creator_issuer,NEW.creator_subject,NEW.creator_client,NEW.recipients,NEW.recipient_keys,NEW.idempotency_key,
   NEW.request_digest,NEW.created_at,NEW.expires_at,NEW.policy_acceptance_id)
  IS DISTINCT FROM ROW(OLD.id,OLD.root_id,OLD.artifact_id,OLD.case_id,OLD.cluster_id,OLD.namespace_uid,OLD.workload_uid,OLD.pod_uid,
   OLD.version,OLD.creator_issuer,OLD.creator_subject,OLD.creator_client,OLD.recipients,OLD.recipient_keys,OLD.idempotency_key,
   OLD.request_digest,OLD.created_at,OLD.expires_at,OLD.policy_acceptance_id) THEN
  RAISE EXCEPTION 'share mutation changes immutable source or original bounds' USING ERRCODE='23514';
 END IF;
 IF NEW.revoked_at IS NOT NULL THEN
  IF ROW(NEW.management,NEW.transfer_key,NEW.transfer_digest) IS DISTINCT FROM ROW(OLD.management,OLD.transfer_key,OLD.transfer_digest) THEN
   RAISE EXCEPTION 'share revocation changes only the revocation' USING ERRCODE='23514';
  END IF;
 ELSIF NEW.transfer_key IS NULL OR OLD.expires_at<=n THEN
  RAISE EXCEPTION 'share transfer changes only live management' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION protect_evidence_share() FROM PUBLIC;

-- +goose StatementBegin
CREATE FUNCTION protect_policy_collection_spend() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
BEGIN
 IF NEW.executions_spent<OLD.executions_spent
  OR NEW.collected_bytes_spent<OLD.collected_bytes_spent
  OR NEW.observed_bytes_spent<OLD.observed_bytes_spent
  OR NEW.observed_events_spent<OLD.observed_events_spent THEN
  RAISE EXCEPTION 'policy collection spend never decreases' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION protect_policy_collection_spend() FROM PUBLIC;

-- +goose StatementBegin
CREATE FUNCTION protect_policy_observation_session() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
BEGIN
 IF TG_OP='INSERT' THEN
  IF NEW.ended_at IS NOT NULL OR clock_timestamp()>=NEW.start_by
   OR clock_timestamp()>=NEW.source_fresh_until OR NEW.started_at>clock_timestamp()
   OR NOT EXISTS(SELECT 1 FROM public.context_capture c WHERE c.id=NEW.capture_id
     AND c.root_id=NEW.root_id AND c.attempt_id=NEW.attempt_id) THEN
   RAISE EXCEPTION 'invalid original observation session' USING ERRCODE='23514';
  END IF;
  RETURN NEW;
 END IF;
 IF TG_OP='DELETE' THEN
  -- The same protected finalizer already proved writer/backend quiescence and
  -- acknowledged encrypted deletion audit. An expired lease alone is not enough.
  IF clock_timestamp()<OLD.lease_until OR NOT EXISTS(
   SELECT 1 FROM public.context_deletion_checkpoint d
   JOIN public.custody_attempt a ON a.id=d.attempt_id
   WHERE d.root_id=OLD.root_id AND d.attempt_id=OLD.attempt_id AND d.capture_id=OLD.capture_id
    AND d.audit_acknowledged_at IS NOT NULL AND d.finalization_xid=pg_current_xact_id()
    AND a.state='deleted') THEN
   RAISE EXCEPTION 'observation retirement requires finalized capture' USING ERRCODE='23514';
  END IF;
  RETURN OLD;
 END IF;
 IF OLD.ended_at IS NOT NULL OR NEW.ended_at IS NULL
  OR (to_jsonb(NEW)-'ended_at')<>(to_jsonb(OLD)-'ended_at') THEN
  RAISE EXCEPTION 'original finite observation session is immutable' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION protect_policy_observation_session() FROM PUBLIC;

-- +goose StatementBegin
CREATE FUNCTION protect_policy_occurrence_capture() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
BEGIN
 RAISE EXCEPTION 'policy occurrence captures never change or refund' USING ERRCODE='23514';
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION protect_policy_occurrence_capture() FROM PUBLIC;

-- +goose StatementBegin
CREATE FUNCTION protect_policy_occurrence_reservation() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
BEGIN
 IF OLD.reserved_capture_id IS NOT NULL AND
  (TG_OP='DELETE' OR ROW(NEW.reserved_capture_id,NEW.grant_id,NEW.reserved_bytes)
   IS DISTINCT FROM ROW(OLD.reserved_capture_id,OLD.grant_id,OLD.reserved_bytes)) THEN
  RAISE EXCEPTION 'policy capture reservation never changes or refunds' USING ERRCODE='23514';
 END IF;
 IF TG_OP='DELETE' THEN RETURN OLD; END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION protect_policy_occurrence_reservation() FROM PUBLIC;

-- +goose StatementBegin
CREATE FUNCTION protect_policy_sharing() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
BEGIN
 IF NEW.shares_spent<OLD.shares_spent OR (OLD.sharing_revoked_at IS NOT NULL AND ROW(NEW.sharing_revoked_at,NEW.sharing_revoke_key) IS DISTINCT FROM ROW(OLD.sharing_revoked_at,OLD.sharing_revoke_key))
  OR (OLD.sharing_stopped_at IS NOT NULL AND ROW(NEW.sharing_stopped_at,NEW.sharing_stop_key) IS DISTINCT FROM ROW(OLD.sharing_stopped_at,OLD.sharing_stop_key)) THEN
  RAISE EXCEPTION 'policy sharing spend and revocation are monotonic' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION protect_policy_sharing() FROM PUBLIC;

-- +goose StatementBegin
CREATE FUNCTION protect_retention_decision() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
 IF (NEW.id,NEW.root_id,NEW.attempt_id,NEW.sequence,NEW.previous_expires_at,NEW.previous_delete_by,NEW.expires_at,NEW.delete_by,NEW.decision_digest,NEW.decision_json,NEW.recorded_at) IS DISTINCT FROM
 (OLD.id,OLD.root_id,OLD.attempt_id,OLD.sequence,OLD.previous_expires_at,OLD.previous_delete_by,OLD.expires_at,OLD.delete_by,OLD.decision_digest,OLD.decision_json,OLD.recorded_at) OR
 (OLD.audit_acknowledged_at IS NOT NULL AND (NEW.audit_acknowledged_at,NEW.audit_receipt_json) IS DISTINCT FROM (OLD.audit_acknowledged_at,OLD.audit_receipt_json)) THEN RAISE EXCEPTION 'immutable retention journal';END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION read_capacity_qualification(r uuid) RETURNS jsonb
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
 SELECT qualification FROM public.capacity_settings WHERE root_id=r
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION read_capacity_qualification(r uuid) FROM PUBLIC;

-- +goose StatementBegin
CREATE FUNCTION read_capacity_qualification_pin(r uuid, i uuid) RETURNS jsonb
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
 SELECT jsonb_build_object('qualificationID',s.qualification->>'ID','qualificationDigest',encode(public.connector_digest(s.qualification->'Digest'),'hex'),
  'accountVersion',s.account_version,'capturePolicy',s.qualification->'RootBacking'->'Capture'->'Policy',
  'operationRetentionSeconds',LEAST((s.qualification->'RootBacking'->'Normal'->>'RetainedSeconds')::bigint,(s.qualification->'RootBacking'->'Resolution'->>'RetainedSeconds')::bigint),
  'evidenceStoreID',s.qualification->'Backends'->0->>'EvidenceStoreID')
 FROM public.capacity_settings s WHERE s.root_id=r AND s.installation_id=i
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION read_capacity_qualification_pin(r uuid, i uuid) FROM PUBLIC;

-- +goose StatementBegin
CREATE FUNCTION read_shared_context_query_plan(r uuid, cluster uuid, namespace_id text, workload text, actor jsonb, principal_key_value bytea, proposed_account uuid, path jsonb) RETURNS jsonb
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
DECLARE b public.context_query_backing;a public.context_query_allocation;account uuid;acceptance uuid;profile jsonb;n timestamptz;until_at timestamptz;
BEGIN
 SELECT acceptance_id INTO STRICT acceptance FROM public.context_query_capacity WHERE root_id=r;
 IF NOT public.lock_context_query_capacity(r,acceptance) OR principal_key_value IS NULL OR octet_length(principal_key_value)<>32 OR octet_length(actor::text)>4096 OR proposed_account IS NULL THEN
  RAISE EXCEPTION 'query capacity reader unavailable' USING ERRCODE='23514';END IF;
 SELECT * INTO STRICT b FROM public.context_query_backing WHERE root_id=r FOR SHARE;
 SELECT * INTO STRICT a FROM public.context_query_allocation WHERE root_id=r AND cluster_id=cluster AND namespace_uid=namespace_id AND workload_uid=workload FOR SHARE;
 IF NOT public.context_query_capacity_allocation_current(r,a.id) THEN RAISE EXCEPTION 'query allocation unavailable' USING ERRCODE='23514';END IF;
 profile:=jsonb_set(b.profile,'{Path}',path);
 IF path->>'TargetClusterID' IS DISTINCT FROM cluster::text OR NOT public.context_query_shared_profile_current(r,profile) THEN RAISE EXCEPTION 'shared query placement unavailable' USING ERRCODE='23514';END IF;
 SELECT id INTO account FROM public.context_query_principal WHERE root_id=r AND principal_key=principal_key_value FOR SHARE;
 n:=clock_timestamp();until_at:=LEAST(n+interval '5 seconds',b.hard_until);
 RETURN jsonb_build_object('AcceptanceID',acceptance,'AccountID',COALESCE(account,proposed_account),'AllocationID',a.id,'RootID',r,'InstallationID',b.installation_id,
  'ClusterID',a.cluster_id,'NamespaceUID',a.namespace_uid,'WorkloadUID',a.workload_uid,'AllocationRevision',a.revision,'PoolSource',a.pool_source,'PolicySource',a.policy_source,'Principal',actor,'Profile',profile,
  'ObservedAt',public.capacity_json_timestamp(n),'ValidUntil',public.capacity_json_timestamp(until_at),'HardUntil',public.capacity_json_timestamp(b.hard_until),'EffectsUntil',public.capacity_json_timestamp(b.effects_until),'CleanupUntil',public.capacity_json_timestamp(b.cleanup_until),'RetireBy',public.capacity_json_timestamp(b.retire_by));
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION read_shared_context_query_plan(r uuid, cluster uuid, namespace_id text, workload text, actor jsonb, principal_key_value bytea, proposed_account uuid, path jsonb) FROM PUBLIC;

-- +goose StatementBegin
CREATE FUNCTION record_permission_review_audit(audit_id uuid, stream uuid, event_digest bytea, record jsonb) RETURNS void
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
DECLARE s public.permission_stream;
BEGIN
 SELECT * INTO s FROM public.permission_stream WHERE id=stream FOR SHARE;
 IF NOT FOUND OR octet_length(event_digest)<>32 OR jsonb_typeof(record)<>'object' OR record->>'Kind'<>'permission-review' OR record->>'ID'<>audit_id::text OR
  record->>'RootID'<>stream::text OR record->>'Epoch'<>s.epoch::text OR (record->>'Sequence')::bigint<>s.sequence OR jsonb_typeof(record->'Review')<>'object' OR
  NOT EXISTS (SELECT 1 FROM public.permission_review_assignment a WHERE a.stream_id=stream AND a.id::text=record->'Review'->>'AssignmentID' AND a.retired_at IS NULL) THEN
  RAISE EXCEPTION 'permission review audit refused' USING ERRCODE='23514';
 END IF;
 INSERT INTO public.authority_audit(id,stream_id,epoch,sequence,event_kind,event_digest,record) VALUES(audit_id,stream,s.epoch,s.sequence,'permission-review',event_digest,record);
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION record_permission_review_audit(audit_id uuid, stream uuid, event_digest bytea, record jsonb) FROM PUBLIC;

-- +goose StatementBegin
CREATE FUNCTION recording_save_group_window_valid(c context_capture, g recording_save_group, until_at timestamp with time zone) RETURNS boolean
    LANGUAGE plpgsql STABLE SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
DECLARE s jsonb;e jsonb;q jsonb;
BEGIN
 IF c.group_id IS NULL OR c.group_ordinal IS NULL OR until_at IS NULL OR NOT isfinite(until_at) THEN RETURN false;END IF;
 IF g.id IS DISTINCT FROM c.group_id OR g.root_id IS DISTINCT FROM c.root_id OR cardinality(g.child_ids) NOT BETWEEN 2 AND 16 OR c.group_ordinal<0 OR c.group_ordinal>=cardinality(g.child_ids) THEN RETURN false;END IF;
 s:=convert_from(c.scope_json,'UTF8')::jsonb;e:=convert_from(c.expectation_json,'UTF8')::jsonb;q:=e->'Snapshot';
 RETURN COALESCE(g.child_ids[c.group_ordinal+1]=c.id AND c.scope_json=g.scope_json AND c.scope_digest=g.scope_digest AND sha256(c.scope_json)=c.scope_digest AND
  s->>'schemaVersion'='recording-save/v1' AND s->>'operation'='recordingSave' AND (s->>'captureID')::uuid=g.id AND
  jsonb_typeof(s->'sources')='array' AND jsonb_array_length(s->'sources')=cardinality(g.child_ids) AND
  s->'sources'->c.group_ordinal->>'sourceSessionID'=q->>'SourceID' AND s->'sources'->c.group_ordinal->>'podUID'=e->>'PodUID' AND
  e->'Lifecycle'->>'TriggerKind'='recordingSave' AND (e->>'CaptureUID')::uuid=c.id AND c.created_at=g.accepted_at AND
  (q->>'T0')::timestamptz=g.accepted_at AND (q->>'IssuedAt')::timestamptz=g.accepted_at AND
  (q->>'StartBy')::timestamptz>g.accepted_at AND (q->>'StartBy')::timestamptz<=g.accepted_at+interval '15 seconds' AND
  (q->>'StartBy')::timestamptz<=(q->>'SourceHardUntil')::timestamptz AND (q->>'StartBy')::timestamptz<(q->>'ProcessingUntil')::timestamptz AND
  (q->>'ProcessingUntil')::timestamptz=c.deadline AND (e#>>'{Registration,WriteUntil}')::timestamptz=c.deadline AND
  until_at>c.created_at AND until_at<=(q->>'StartBy')::timestamptz,false);
EXCEPTION WHEN data_exception OR no_data_found OR too_many_rows THEN RETURN false;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION recording_save_group_window_valid(c context_capture, g recording_save_group, until_at timestamp with time zone) FROM PUBLIC;

-- +goose StatementBegin
CREATE FUNCTION require_audited_context_deletion() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
DECLARE d public.context_deletion_checkpoint; f public.fleet_current_trust;
BEGIN
 IF TG_WHEN<>'BEFORE' OR TG_LEVEL<>'ROW' OR TG_RELID<>'public.custody_attempt'::regclass OR TG_OP<>'UPDATE' THEN RAISE EXCEPTION 'invalid deletion source' USING ERRCODE='23514'; END IF;
 IF NEW.state<>'deleted' OR OLD.state='deleted' OR NOT EXISTS(SELECT 1 FROM public.context_execution WHERE attempt_id=NEW.id AND writer_protocol='closed-small-context/v1') THEN RETURN NEW; END IF;
 SELECT * INTO d FROM public.context_deletion_checkpoint WHERE attempt_id=NEW.id AND audit_acknowledged_at IS NOT NULL;
 IF NOT FOUND OR OLD.state<>'deleting' OR d.finalization_xid IS DISTINCT FROM pg_current_xact_id() OR d.registration_digest<>NEW.request_digest OR d.purge_fence>NEW.deletion_fence THEN
  RAISE EXCEPTION 'positive context deletion requires independent acknowledged audit' USING ERRCODE='23514';
 END IF;
 -- Only the dedicated finalizer may set the transaction-local persisted marker.
 -- It holds recovery first; legacy/direct mutation fails above before acquiring
 -- a reverse-order lock. Recheck the exact already-held recovery row here.
 SELECT * INTO f FROM public.fleet_current_trust WHERE installation_id=d.installation_id FOR SHARE;
 IF NOT FOUND OR d.issuer_epoch<>f.issuer_epoch OR f.suspended OR f.fresh_until<=clock_timestamp() OR NOT public.incarnation_current(d.postmaster_at) OR d.database_oid<>(SELECT oid FROM pg_database WHERE datname=current_database()) THEN
  RAISE EXCEPTION 'positive context deletion requires current incarnation' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION require_audited_context_deletion() FROM PUBLIC;

-- +goose StatementBegin
CREATE FUNCTION require_comparison_key_pair() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
BEGIN
 IF NEW.source_ordinal IS NOT NULL AND (SELECT count(*) FROM public.context_query_key_binding WHERE batch_id=NEW.batch_id AND query_id=NEW.query_id AND source_ordinal IS NOT NULL)<>2 THEN
  RAISE EXCEPTION 'comparison requires both key children atomically' USING ERRCODE='23514'; END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION require_comparison_key_pair() FROM PUBLIC;

-- +goose StatementBegin
CREATE FUNCTION require_completed_context_finalization() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
BEGIN
 IF TG_WHEN<>'AFTER' OR TG_LEVEL<>'ROW' OR TG_RELID<>'public.context_deletion_checkpoint'::regclass OR TG_OP<>'UPDATE' THEN RAISE EXCEPTION 'invalid finalization source' USING ERRCODE='23514'; END IF;
 IF NEW.finalization_xid IS NOT NULL AND OLD.finalization_xid IS NULL AND (NEW.finalization_xid IS DISTINCT FROM pg_current_xact_id() OR NOT EXISTS(SELECT 1 FROM public.custody_attempt WHERE id=NEW.attempt_id AND state='deleted')) THEN
  RAISE EXCEPTION 'finalization marker requires same-transaction deletion' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION require_completed_context_finalization() FROM PUBLIC;

-- +goose StatementBegin
CREATE FUNCTION require_context_writer_completion() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
BEGIN
 IF TG_WHEN<>'AFTER' OR TG_LEVEL<>'ROW' OR TG_RELID<>'public.context_execution'::regclass OR TG_OP<>'UPDATE' THEN RAISE EXCEPTION 'invalid writer source' USING ERRCODE='23514'; END IF;
 IF NEW.writer_protocol='closed-small-context/v1' AND NEW.phase='stored' AND NOT EXISTS(SELECT 1 FROM public.context_writer_completion WHERE capture_id=NEW.capture_id AND root_id=NEW.root_id AND attempt_id=NEW.attempt_id AND copies_digest=NEW.copies_digest) THEN
  RAISE EXCEPTION 'positive stored outcome requires joined writer completion' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION require_context_writer_completion() FROM PUBLIC;

-- +goose StatementBegin
CREATE FUNCTION require_custody_stream() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
BEGIN
 IF NEW.native_limit > 8388608 AND NOT EXISTS (SELECT 1 FROM public.custody_stream WHERE attempt_id = NEW.id) THEN
  RAISE EXCEPTION 'streaming attempt requires its journal' USING ERRCODE='23514';
 END IF;
 RETURN NULL;
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION require_recording_save_group_members() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
DECLARE g public.recording_save_group; member record; n integer:=0; e jsonb; s jsonb;
BEGIN
 SELECT * INTO STRICT g FROM public.recording_save_group WHERE id=NEW.id;
 s:=convert_from(g.scope_json,'UTF8')::jsonb;
 IF g.group_kind='composition' THEN
  -- ADR-276: each member is one single manual recording under its own scope,
  -- listed with that scope's digest in the recorder-group/v1 parent.
  IF s->>'schemaVersion' IS DISTINCT FROM 'recorder-group/v1' OR s->>'captureID' IS DISTINCT FROM g.id::text OR
     jsonb_typeof(s->'children') IS DISTINCT FROM 'array' OR jsonb_array_length(s->'children')<>cardinality(g.child_ids) THEN
   RAISE EXCEPTION 'group selection differs from accepted scope' USING ERRCODE='23514';
  END IF;
  FOR member IN SELECT c.*,a.allocation_id AS actual_allocation FROM public.context_capture c
   JOIN public.custody_attempt a ON a.id=c.attempt_id WHERE c.group_id=g.id ORDER BY c.group_ordinal LOOP
   e:=convert_from(member.expectation_json,'UTF8')::jsonb;
   IF member.root_id<>g.root_id OR member.group_ordinal<>n OR member.id<>g.child_ids[n+1] OR
      s->'children'->n->>'captureID' IS DISTINCT FROM member.id::text OR
      s->'children'->n->>'scopeDigest' IS DISTINCT FROM encode(member.scope_digest,'hex') OR
      sha256(member.scope_json)<>member.scope_digest OR member.created_at<>g.accepted_at OR
      member.deadline>g.deadline OR member.actual_allocation<>g.allocation_id OR NOT COALESCE(jsonb_typeof(e->'Recording')='object' OR
       e->>'NativeType'='logs' AND e->>'DataClass'='raw' AND jsonb_typeof(e->'Logs')='object' AND
       e#>>'{Logs,ActionID}'=s->'children'->n->>'actionID' AND e#>>'{Logs,Streams}'='combined' AND
       public.capacity_json_integer(e#>'{Logs,MaxNativeBytes}',1,67108864) AND e#>'{Logs,MaxNativeBytes}'=e#>'{Registration,NativeLimit}' AND
       e#>>'{CompositionGroup,ParentCaptureID}'=g.id::text AND (e#>>'{CompositionGroup,ChildIndex}')::integer=n AND (e#>>'{CompositionGroup,ChildCount}')::integer=cardinality(g.child_ids),false) THEN
    RAISE EXCEPTION 'incomplete or substituted group member' USING ERRCODE='23514';
   END IF;
   n:=n+1;
  END LOOP;
  IF n<>cardinality(g.child_ids) THEN RAISE EXCEPTION 'incomplete composition group' USING ERRCODE='23514'; END IF;
  RETURN NEW;
 END IF;
 IF s->>'schemaVersion' IS DISTINCT FROM 'recording-save/v1' OR s->>'captureID' IS DISTINCT FROM g.id::text OR
    jsonb_typeof(s->'sources') IS DISTINCT FROM 'array' OR jsonb_array_length(s->'sources')<>cardinality(g.child_ids) THEN
  RAISE EXCEPTION 'group selection differs from accepted scope' USING ERRCODE='23514';
 END IF;
 FOR member IN SELECT c.*,a.allocation_id AS actual_allocation FROM public.context_capture c
  JOIN public.custody_attempt a ON a.id=c.attempt_id WHERE c.group_id=g.id ORDER BY c.group_ordinal LOOP
  e:=convert_from(member.expectation_json,'UTF8')::jsonb;
  IF member.root_id<>g.root_id OR member.group_ordinal<>n OR member.id<>g.child_ids[n+1] OR
     member.scope_digest<>g.scope_digest OR member.scope_json<>g.scope_json OR member.created_at<>g.accepted_at OR
     member.deadline>g.deadline OR member.actual_allocation<>g.allocation_id OR
     (e#>>'{Snapshot,T0}')::timestamptz IS DISTINCT FROM g.accepted_at OR
     e#>>'{Snapshot,SourceID}' IS DISTINCT FROM s->'sources'->n->>'sourceSessionID' OR
     NOT EXISTS(SELECT 1 FROM public.recording_save_reservation r WHERE r.capture_id=member.id AND
       r.root_id=g.root_id AND r.acceptance_id=g.acceptance_id AND r.policy_uid=g.policy_uid AND r.accepted_at=g.accepted_at) THEN
   RAISE EXCEPTION 'incomplete or substituted group member' USING ERRCODE='23514';
  END IF;
  n:=n+1;
 END LOOP;
 IF n<>cardinality(g.child_ids) THEN RAISE EXCEPTION 'incomplete save group' USING ERRCODE='23514'; END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION require_recording_save_group_members() FROM PUBLIC;

-- +goose StatementBegin
CREATE FUNCTION require_snapshot_cancel_proof() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
BEGIN
 IF TG_WHEN<>'AFTER' OR TG_LEVEL<>'ROW' OR TG_OP<>'UPDATE' OR TG_TABLE_SCHEMA<>'public' OR TG_RELID<>'public.context_execution'::regclass THEN RAISE EXCEPTION 'invalid cancellation execution source' USING ERRCODE='23514';END IF;
 IF NEW.phase='cancelled' AND NOT EXISTS(SELECT 1 FROM public.context_capture c WHERE c.root_id=NEW.root_id AND c.id=NEW.capture_id AND c.snapshot_cancel_requested_at IS NOT NULL AND c.snapshot_cancel_joined_at IS NOT NULL AND c.snapshot_cancel_proof IS NOT NULL AND c.snapshot_cancel_proof_digest=sha256(c.snapshot_cancel_proof)) THEN RAISE EXCEPTION 'cancelled execution lacks exact joined proof' USING ERRCODE='23514';END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION require_snapshot_cancel_proof() FROM PUBLIC;

-- +goose StatementBegin
CREATE FUNCTION retention_checkpoint_receipt_current(input_root uuid, input_event uuid, input_receipt jsonb) RETURNS boolean
    LANGUAGE plpgsql IMMUTABLE
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $_$
DECLARE receipt_value jsonb; text_value text; text_bytes bytea; field_name text;
 maximum integer; byte_index integer; octet integer; digest_value jsonb; nonzero boolean:=false;
BEGIN
 IF input_receipt IS NULL THEN RETURN false; END IF;
 receipt_value:=input_receipt;

 IF input_root IS NULL OR input_event IS NULL
 OR input_root='00000000-0000-0000-0000-000000000000'::uuid
 OR input_event='00000000-0000-0000-0000-000000000000'::uuid THEN RETURN false; END IF;
 IF jsonb_typeof(receipt_value) IS DISTINCT FROM 'object'
 OR octet_length(convert_to(receipt_value::text,'UTF8'))>4096
 OR NOT receipt_value ?& ARRAY['Key','Version','ETag','Bytes','SHA256']
 OR (receipt_value-ARRAY['Key','Version','ETag','Bytes','SHA256'])<>'{}'::jsonb THEN RETURN false; END IF;
 IF jsonb_typeof(receipt_value->'Key') IS DISTINCT FROM 'string'
 OR (receipt_value->>'Key') COLLATE "C" IS DISTINCT FROM
    ('retention-acceptance/v1/'||input_root::text||'/'||input_event::text||'/record') COLLATE "C" THEN RETURN false; END IF;
 FOREACH field_name IN ARRAY ARRAY['Version','ETag'] LOOP
  IF jsonb_typeof(receipt_value->field_name) IS DISTINCT FROM 'string' THEN RETURN false; END IF;
  text_value:=receipt_value->>field_name;
  IF field_name='Version' AND text_value COLLATE "C"='null' COLLATE "C" THEN RETURN false; END IF;
  text_bytes:=convert_to(text_value,'UTF8');
  maximum:=CASE WHEN field_name='Version' THEN 1024 ELSE 256 END;
  IF octet_length(text_bytes)<1 OR octet_length(text_bytes)>maximum THEN RETURN false; END IF;
  -- Go identity.Text rejects Unicode Cc: U+0000..001F and U+007F..009F.
  -- Inspect fixed UTF-8 octets, independently of database/session collation.
  FOR byte_index IN 0..octet_length(text_bytes)-1 LOOP
   octet:=get_byte(text_bytes,byte_index);
   IF octet<=31 OR octet=127 THEN RETURN false; END IF;
   IF octet=194 AND byte_index+1<octet_length(text_bytes) THEN
    IF get_byte(text_bytes,byte_index+1) BETWEEN 128 AND 159 THEN RETURN false; END IF;
   END IF;
  END LOOP;
 END LOOP;
 IF jsonb_typeof(receipt_value->'Bytes') IS DISTINCT FROM 'number' THEN RETURN false; END IF;
 text_value:=receipt_value->>'Bytes';
 IF text_value COLLATE "C" !~ '^[1-9][0-9]*$' COLLATE "C"
 OR length(text_value)>6 THEN RETURN false; END IF;
 IF text_value::bigint>524288 THEN RETURN false; END IF;
 IF jsonb_typeof(receipt_value->'SHA256') IS DISTINCT FROM 'array' THEN RETURN false; END IF;
 IF jsonb_array_length(receipt_value->'SHA256')<>32 THEN RETURN false; END IF;
 FOR digest_value IN SELECT element.value FROM jsonb_array_elements(receipt_value->'SHA256') AS element(value) LOOP
  IF jsonb_typeof(digest_value) IS DISTINCT FROM 'number' THEN RETURN false; END IF;
  text_value:=digest_value#>>'{}';
  IF text_value COLLATE "C" !~ '^(0|[1-9][0-9]*)$' COLLATE "C"
  OR length(text_value)>3 THEN RETURN false; END IF;
  octet:=text_value::integer;
  IF octet>255 THEN RETURN false; END IF;
  nonzero:=nonzero OR octet>0;
 END LOOP;
 RETURN nonzero;
EXCEPTION WHEN data_exception THEN
 -- Malformed/oversized numeric, JSON, UTF-8 or NUL input denies. Do not catch
 -- cancellation, lock/I/O failure or resource exhaustion as successful input.
 RETURN false;
END;
$_$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION retention_lifecycle_receipt_current(input_root uuid, input_event uuid, input_receipt bytea) RETURNS boolean
    LANGUAGE plpgsql IMMUTABLE
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $_$
DECLARE receipt_value jsonb; text_value text; text_bytes bytea; field_name text;
 maximum integer; byte_index integer; octet integer; digest_value jsonb; nonzero boolean:=false;
 raw_value json; raw_digest json; member_count bigint; distinct_members bigint;
BEGIN
 IF input_receipt IS NULL OR octet_length(input_receipt) NOT BETWEEN 1 AND 4096 THEN RETURN false; END IF;
 raw_value:=convert_from(input_receipt,'UTF8')::json;
 IF json_typeof(raw_value) IS DISTINCT FROM 'object' THEN RETURN false; END IF;
 SELECT count(*),count(DISTINCT member.key COLLATE "C") INTO member_count,distinct_members
 FROM json_each(raw_value) AS member;
 IF member_count<>5 OR distinct_members<>5 THEN RETURN false; END IF;
 -- bytea retains lexical JSON spelling. Reject numeric exponents/fractions
 -- before JSONB normalization; Go's integer decoder rejects these spellings.
 IF json_typeof(raw_value->'Bytes') IS DISTINCT FROM 'number'
 OR (raw_value->>'Bytes') COLLATE "C" !~ '^[1-9][0-9]*$' COLLATE "C"
 OR json_typeof(raw_value->'SHA256') IS DISTINCT FROM 'array' THEN RETURN false; END IF;
 FOR raw_digest IN SELECT element.value FROM json_array_elements(raw_value->'SHA256') AS element(value) LOOP
  IF json_typeof(raw_digest) IS DISTINCT FROM 'number'
  OR (raw_digest#>>'{}') COLLATE "C" !~ '^(0|[1-9][0-9]*)$' COLLATE "C" THEN RETURN false; END IF;
 END LOOP;
 receipt_value:=raw_value::jsonb;

 IF input_root IS NULL OR input_event IS NULL
 OR input_root='00000000-0000-0000-0000-000000000000'::uuid
 OR input_event='00000000-0000-0000-0000-000000000000'::uuid THEN RETURN false; END IF;
 IF jsonb_typeof(receipt_value) IS DISTINCT FROM 'object'
 OR octet_length(convert_to(receipt_value::text,'UTF8'))>4096
 OR NOT receipt_value ?& ARRAY['Key','Version','ETag','Bytes','SHA256']
 OR (receipt_value-ARRAY['Key','Version','ETag','Bytes','SHA256'])<>'{}'::jsonb THEN RETURN false; END IF;
 IF jsonb_typeof(receipt_value->'Key') IS DISTINCT FROM 'string'
 OR (receipt_value->>'Key') COLLATE "C" IS DISTINCT FROM
    ('lifecycle/v1/'||input_root::text||'/'||input_event::text||'/record') COLLATE "C" THEN RETURN false; END IF;
 FOREACH field_name IN ARRAY ARRAY['Version','ETag'] LOOP
  IF jsonb_typeof(receipt_value->field_name) IS DISTINCT FROM 'string' THEN RETURN false; END IF;
  text_value:=receipt_value->>field_name;
  IF field_name='Version' AND text_value COLLATE "C"='null' COLLATE "C" THEN RETURN false; END IF;
  text_bytes:=convert_to(text_value,'UTF8');
  maximum:=CASE WHEN field_name='Version' THEN 1024 ELSE 256 END;
  IF octet_length(text_bytes)<1 OR octet_length(text_bytes)>maximum THEN RETURN false; END IF;
  -- Go identity.Text rejects Unicode Cc: U+0000..001F and U+007F..009F.
  -- Inspect fixed UTF-8 octets, independently of database/session collation.
  FOR byte_index IN 0..octet_length(text_bytes)-1 LOOP
   octet:=get_byte(text_bytes,byte_index);
   IF octet<=31 OR octet=127 THEN RETURN false; END IF;
   IF octet=194 AND byte_index+1<octet_length(text_bytes) THEN
    IF get_byte(text_bytes,byte_index+1) BETWEEN 128 AND 159 THEN RETURN false; END IF;
   END IF;
  END LOOP;
 END LOOP;
 IF jsonb_typeof(receipt_value->'Bytes') IS DISTINCT FROM 'number' THEN RETURN false; END IF;
 text_value:=receipt_value->>'Bytes';
 IF text_value COLLATE "C" !~ '^[1-9][0-9]*$' COLLATE "C"
 OR length(text_value)>6 THEN RETURN false; END IF;
 IF text_value::bigint>131072 THEN RETURN false; END IF;
 IF jsonb_typeof(receipt_value->'SHA256') IS DISTINCT FROM 'array' THEN RETURN false; END IF;
 IF jsonb_array_length(receipt_value->'SHA256')<>32 THEN RETURN false; END IF;
 FOR digest_value IN SELECT element.value FROM jsonb_array_elements(receipt_value->'SHA256') AS element(value) LOOP
  IF jsonb_typeof(digest_value) IS DISTINCT FROM 'number' THEN RETURN false; END IF;
  text_value:=digest_value#>>'{}';
  IF text_value COLLATE "C" !~ '^(0|[1-9][0-9]*)$' COLLATE "C"
  OR length(text_value)>3 THEN RETURN false; END IF;
  octet:=text_value::integer;
  IF octet>255 THEN RETURN false; END IF;
  nonzero:=nonzero OR octet>0;
 END LOOP;
 RETURN nonzero;
EXCEPTION WHEN data_exception THEN
 -- Malformed/oversized numeric, JSON, UTF-8 or NUL input denies. Do not catch
 -- cancellation, lock/I/O failure or resource exhaustion as successful input.
 RETURN false;
END;
$_$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION retention_policy_effect(p jsonb, one_attempt uuid DEFAULT NULL::uuid) RETURNS TABLE(attempt_id uuid, cluster_id uuid, native_type text, case_metadata boolean, old_expires_at timestamp with time zone, old_delete_by timestamp with time zone, expires_at timestamp with time zone, delete_by timestamp with time zone)
    LANGUAGE sql STABLE
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
 WITH scoped AS (
  SELECT a.id, a.cluster_id, a.anchor_at, a.effective_expires_at, a.effective_delete_by,
   coalesce(convert_from(c.expectation_json,'UTF8')::jsonb->>'NativeType','') AS native_type, false AS case_metadata, c.target_labels AS labels
  FROM public.custody_attempt a JOIN public.context_capture c ON c.attempt_id=a.id
  WHERE a.state<>'deleted' AND (one_attempt IS NULL OR a.id=one_attempt)
  UNION ALL
  SELECT a.id, a.cluster_id, a.anchor_at, a.effective_expires_at, a.effective_delete_by, NULL, true, c.target_labels
  FROM public.custody_attempt a JOIN public.capture_history_parameter h ON h.attempt_id=a.id
  LEFT JOIN public.context_capture c ON c.id=h.capture_id
  WHERE a.state<>'deleted' AND (one_attempt IS NULL OR a.id=one_attempt)
 ), limited AS (
  SELECT s.*, (CASE WHEN s.case_metadata THEN (p->>'caseMaximum')::bigint ELSE (p->'maxima'->>s.native_type)::bigint END) AS maximum
  FROM scoped s
  WHERE (jsonb_array_length(p->'clusters')=0 OR p->'clusters' ? s.cluster_id::text)
   AND (s.labels IS NULL OR (coalesce(s.labels->'namespace','{}') @> coalesce(p->'namespaceLabels','{}')
    AND coalesce(s.labels->'workload','{}') @> coalesce(p->'workloadLabels','{}')))
 ), next AS (
  SELECT l.id, l.cluster_id, l.native_type, l.case_metadata,
   least(l.effective_delete_by, l.anchor_at+make_interval(secs=>l.maximum)) AS delete_by,
   least(l.effective_expires_at, greatest(l.anchor_at, l.anchor_at+make_interval(secs=>l.maximum-(p->>'budget')::bigint))) AS expires_at,
   l.effective_expires_at AS old_expires, l.effective_delete_by AS old_delete
  FROM limited l WHERE l.maximum IS NOT NULL
 )
 SELECT n.id, n.cluster_id, n.native_type, n.case_metadata, n.old_expires, n.old_delete,
  least(n.expires_at, n.delete_by-interval '1 microsecond'), n.delete_by
 FROM next n
$$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION retention_preview(effects jsonb) RETURNS jsonb
    LANGUAGE sql STABLE
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
 WITH e AS (
  SELECT r.attempt_id, r.cluster_id, r.native_type, r.case_metadata,
   min(r.old_expires_at) AS old_expires_at, min(r.old_delete_by) AS old_delete_by,
   min(r.expires_at) AS expires_at, min(r.delete_by) AS delete_by
  FROM jsonb_array_elements(effects) p, LATERAL public.retention_policy_effect(p.value) r
  GROUP BY 1,2,3,4
 ), c AS (
  SELECT e.*, (e.expires_at<e.old_expires_at OR e.delete_by<e.old_delete_by) AS changed FROM e
 ), g AS (
  SELECT c.cluster_id, coalesce(c.native_type,'') AS native_type, c.case_metadata, count(*) AS scanned,
   count(*) FILTER (WHERE c.changed) AS affected,
   count(*) FILTER (WHERE c.expires_at<=clock_timestamp() AND c.old_expires_at>clock_timestamp()) AS read_closed,
   count(*) FILTER (WHERE c.changed AND c.delete_by<=clock_timestamp()) AS deletion_due,
   min(c.expires_at) FILTER (WHERE c.changed) AS earliest_expires_at,
   min(c.delete_by) FILTER (WHERE c.changed) AS earliest_delete_by
  FROM c GROUP BY 1,2,3
 )
 SELECT coalesce(jsonb_agg(to_jsonb(g)),'[]'::jsonb) FROM g
$$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION spend_adhoc_observation(r uuid, g uuid, amount bigint, events bigint) RETURNS boolean
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
DECLARE grant_row public.access_grant; byte_ceiling bigint; event_ceiling bigint; used public.adhoc_observation_spend;
BEGIN
 IF amount IS NULL OR events IS NULL OR amount<1 OR events<0 THEN RETURN false; END IF;
 SELECT * INTO grant_row FROM public.access_grant WHERE root_id=r AND id=g FOR SHARE;
 IF NOT FOUND OR grant_row.kind<>'adHocCapture' OR grant_row.decision IS DISTINCT FROM 'approved'
  OR grant_row.revoked_at IS NOT NULL OR grant_row.expires_at<=clock_timestamp() THEN RETURN false; END IF;
 byte_ceiling:=(convert_from(grant_row.scope,'UTF8')::jsonb#>>'{approval,observationLimits,maxObservedBytes}')::bigint;
 event_ceiling:=COALESCE((convert_from(grant_row.scope,'UTF8')::jsonb#>>'{approval,observationLimits,maxObservedEvents}')::bigint,0);
 IF byte_ceiling IS NULL OR byte_ceiling<1 OR event_ceiling<0 THEN RETURN false; END IF;
 INSERT INTO public.adhoc_observation_spend(root_id,grant_id,spent,events_spent) VALUES(r,g,0,0) ON CONFLICT DO NOTHING;
 SELECT * INTO STRICT used FROM public.adhoc_observation_spend WHERE root_id=r AND grant_id=g FOR UPDATE;
 -- The original grant lock prevents revision changes, not passage of time.
 IF grant_row.expires_at<=clock_timestamp() OR amount>byte_ceiling-used.spent OR events>event_ceiling-used.events_spent THEN RETURN false; END IF;
 UPDATE public.adhoc_observation_spend SET spent=spent+amount,events_spent=events_spent+events WHERE root_id=r AND grant_id=g;
 RETURN true;
END $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION spend_adhoc_observation(r uuid, g uuid, amount bigint, events bigint) FROM PUBLIC;

-- +goose StatementBegin
CREATE FUNCTION spend_adhoc_observed_bytes(r uuid, g uuid, amount bigint) RETURNS boolean
    LANGUAGE sql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'pg_temp'
    AS $$
 SELECT public.spend_adhoc_observation(r,g,amount,0);
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION spend_adhoc_observed_bytes(r uuid, g uuid, amount bigint) FROM PUBLIC;

-- Indexes that call functions.

CREATE INDEX retention_decision_invalid_receipt ON retention_decision USING btree (root_id, id) WHERE ((audit_acknowledged_at IS NULL) OR (NOT retention_lifecycle_receipt_current(root_id, id, audit_receipt_json)));

-- Foreign keys.

ALTER TABLE ONLY access_grant_child ADD CONSTRAINT access_grant_child_parent_id_fkey FOREIGN KEY (parent_id) REFERENCES access_grant(id);
ALTER TABLE ONLY access_grant_child ADD CONSTRAINT access_grant_child_root_parent FOREIGN KEY (root_id, parent_id) REFERENCES access_grant(root_id, id);
ALTER TABLE ONLY access_grant ADD CONSTRAINT access_grant_exact_policy_acceptance FOREIGN KEY (root_id, policy_acceptance_id, policy_uid) REFERENCES policy_acceptance(root_id, id, policy_uid);
ALTER TABLE ONLY access_grant ADD CONSTRAINT access_grant_policy_acceptance_id_fkey FOREIGN KEY (policy_acceptance_id) REFERENCES policy_acceptance(id);
ALTER TABLE ONLY access_grant_use ADD CONSTRAINT access_grant_use_child_id_fkey FOREIGN KEY (child_id) REFERENCES access_grant_child(id);
ALTER TABLE ONLY access_grant_use ADD CONSTRAINT access_grant_use_parent_id_fkey FOREIGN KEY (parent_id) REFERENCES access_grant(id);
ALTER TABLE ONLY adhoc_observation_spend ADD CONSTRAINT adhoc_observation_spend_grant_id_fkey FOREIGN KEY (grant_id) REFERENCES access_grant(id);
ALTER TABLE ONLY artifact_download ADD CONSTRAINT artifact_download_allocation_id_root_id_fkey FOREIGN KEY (allocation_id, root_id) REFERENCES download_allocation(id, root_id);
ALTER TABLE ONLY artifact_download ADD CONSTRAINT artifact_download_artifact_id_fkey FOREIGN KEY (artifact_id) REFERENCES context_catalog(artifact_id);
ALTER TABLE ONLY artifact_download_stop ADD CONSTRAINT artifact_download_stop_download_id_root_id_fkey FOREIGN KEY (download_id, root_id) REFERENCES artifact_download(id, root_id) ON DELETE CASCADE;
ALTER TABLE ONLY authority_audit ADD CONSTRAINT authority_audit_stream_id_fkey FOREIGN KEY (stream_id) REFERENCES permission_stream(id);
ALTER TABLE ONLY capacity_account ADD CONSTRAINT capacity_account_allocation_id_fkey FOREIGN KEY (allocation_id) REFERENCES custody_allocation(id);
ALTER TABLE ONLY capacity_account ADD CONSTRAINT capacity_account_download_allocation_id_fkey FOREIGN KEY (download_allocation_id) REFERENCES download_allocation(id);
ALTER TABLE ONLY capacity_account ADD CONSTRAINT capacity_account_root_id_fkey FOREIGN KEY (root_id) REFERENCES capacity_settings(root_id);
ALTER TABLE ONLY capacity_settings ADD CONSTRAINT capacity_settings_pool_id_fkey FOREIGN KEY (pool_id) REFERENCES custody_pool(id);
ALTER TABLE ONLY capacity_settings ADD CONSTRAINT capacity_settings_root_id_fkey FOREIGN KEY (root_id) REFERENCES permission_stream(id);
ALTER TABLE ONLY capture_history_parameter ADD CONSTRAINT capture_history_parameter_attempt_id_fkey FOREIGN KEY (attempt_id) REFERENCES custody_attempt(id);
ALTER TABLE ONLY capture_history_parameter ADD CONSTRAINT capture_history_parameter_root_id_fkey FOREIGN KEY (root_id) REFERENCES permission_stream(id);
ALTER TABLE ONLY capture_history_quota ADD CONSTRAINT capture_history_quota_root_id_fkey FOREIGN KEY (root_id) REFERENCES permission_stream(id);
ALTER TABLE ONLY context_capture ADD CONSTRAINT context_capture_attempt_id_fkey FOREIGN KEY (attempt_id) REFERENCES custody_attempt(id);
ALTER TABLE ONLY context_capture ADD CONSTRAINT context_capture_group_link FOREIGN KEY (root_id, group_id) REFERENCES recording_save_group(root_id, id);
ALTER TABLE ONLY context_capture ADD CONSTRAINT context_capture_root_id_fkey FOREIGN KEY (root_id) REFERENCES permission_stream(id);
ALTER TABLE ONLY context_case_locator ADD CONSTRAINT context_case_locator_artifact_id_fkey FOREIGN KEY (artifact_id) REFERENCES context_catalog(artifact_id);
ALTER TABLE ONLY context_case_locator ADD CONSTRAINT context_case_locator_capture_id_root_id_fkey FOREIGN KEY (capture_id, root_id) REFERENCES context_capture(id, root_id);
ALTER TABLE ONLY context_catalog ADD CONSTRAINT context_catalog_capture_id_root_id_fkey FOREIGN KEY (capture_id, root_id) REFERENCES context_capture(id, root_id);
ALTER TABLE ONLY context_deletion_checkpoint ADD CONSTRAINT context_deletion_checkpoint_attempt_id_fkey FOREIGN KEY (attempt_id) REFERENCES context_writer_completion(attempt_id);
ALTER TABLE ONLY context_deletion_checkpoint ADD CONSTRAINT context_deletion_checkpoint_capture_id_fkey FOREIGN KEY (capture_id) REFERENCES context_writer_completion(capture_id);
ALTER TABLE ONLY context_deletion_checkpoint ADD CONSTRAINT context_deletion_checkpoint_capture_id_root_id_fkey FOREIGN KEY (capture_id, root_id) REFERENCES context_capture(id, root_id);
ALTER TABLE ONLY context_deletion_checkpoint ADD CONSTRAINT context_deletion_checkpoint_installation_id_fkey FOREIGN KEY (installation_id) REFERENCES fleet_trust(installation_id);
ALTER TABLE ONLY context_execution ADD CONSTRAINT context_execution_attempt_id_fkey FOREIGN KEY (attempt_id) REFERENCES custody_attempt(id);
ALTER TABLE ONLY context_execution ADD CONSTRAINT context_execution_capture_id_fkey FOREIGN KEY (capture_id) REFERENCES context_capture(id);
ALTER TABLE ONLY context_execution ADD CONSTRAINT context_execution_capture_id_root_id_fkey FOREIGN KEY (capture_id, root_id) REFERENCES context_capture(id, root_id);
ALTER TABLE ONLY context_execution ADD CONSTRAINT context_execution_root_id_fkey FOREIGN KEY (root_id) REFERENCES permission_stream(id);
ALTER TABLE ONLY context_key_wrap ADD CONSTRAINT context_key_wrap_attempt_id_fkey FOREIGN KEY (attempt_id) REFERENCES context_execution(attempt_id);
ALTER TABLE ONLY context_key_wrap ADD CONSTRAINT context_key_wrap_root_id_fkey FOREIGN KEY (root_id) REFERENCES permission_stream(id);
ALTER TABLE ONLY context_processing ADD CONSTRAINT context_processing_artifact_id_fkey FOREIGN KEY (artifact_id) REFERENCES context_catalog(artifact_id);
ALTER TABLE ONLY context_processing ADD CONSTRAINT context_processing_capture_id_root_id_fkey FOREIGN KEY (capture_id, root_id) REFERENCES context_capture(id, root_id);
ALTER TABLE ONLY context_processing ADD CONSTRAINT context_processing_root_id_fkey FOREIGN KEY (root_id) REFERENCES processing_root(root_id);
ALTER TABLE ONLY context_query ADD CONSTRAINT context_query_account_id_root_id_fkey FOREIGN KEY (account_id, root_id) REFERENCES context_query_principal(id, root_id);
ALTER TABLE ONLY context_query ADD CONSTRAINT context_query_allocation_id_root_id_fkey FOREIGN KEY (allocation_id, root_id) REFERENCES context_query_allocation(id, root_id);
ALTER TABLE ONLY context_query_allocation ADD CONSTRAINT context_query_allocation_root_id_fkey FOREIGN KEY (root_id) REFERENCES context_query_backing(root_id);
ALTER TABLE ONLY context_query_backing ADD CONSTRAINT context_query_backing_installation_id_fkey FOREIGN KEY (installation_id) REFERENCES fleet_trust(installation_id);
ALTER TABLE ONLY context_query_backing ADD CONSTRAINT context_query_backing_root_id_fkey FOREIGN KEY (root_id) REFERENCES permission_stream(id);
ALTER TABLE ONLY context_query ADD CONSTRAINT context_query_baseline_allocation_id_root_id_fkey FOREIGN KEY (baseline_allocation_id, root_id) REFERENCES context_query_allocation(id, root_id);
ALTER TABLE ONLY context_query_batch ADD CONSTRAINT context_query_batch_operation_id_fkey FOREIGN KEY (operation_id) REFERENCES context_query_call(operation_id);
ALTER TABLE ONLY context_query_batch ADD CONSTRAINT context_query_batch_query_id_fkey FOREIGN KEY (query_id) REFERENCES context_query(id);
ALTER TABLE ONLY context_query_call ADD CONSTRAINT context_query_call_query_id_fkey FOREIGN KEY (query_id) REFERENCES context_query(id);
ALTER TABLE ONLY context_query_capacity ADD CONSTRAINT context_query_capacity_settings_fk FOREIGN KEY (root_id) REFERENCES capacity_settings(root_id);
ALTER TABLE ONLY context_query_key_binding ADD CONSTRAINT context_query_key_binding_batch_id_query_id_fkey FOREIGN KEY (batch_id, query_id) REFERENCES context_query_batch(id, query_id);
ALTER TABLE ONLY context_query_principal ADD CONSTRAINT context_query_principal_root_id_fkey FOREIGN KEY (root_id) REFERENCES context_query_backing(root_id);
ALTER TABLE ONLY context_query ADD CONSTRAINT context_query_root_id_fkey FOREIGN KEY (root_id) REFERENCES context_query_backing(root_id);
ALTER TABLE ONLY context_query_worker ADD CONSTRAINT context_query_worker_query_id_fkey FOREIGN KEY (query_id) REFERENCES context_query(id);
ALTER TABLE ONLY context_storage_binding ADD CONSTRAINT context_storage_binding_allocation_id_fkey FOREIGN KEY (allocation_id) REFERENCES custody_allocation(id);
ALTER TABLE ONLY context_storage_binding ADD CONSTRAINT context_storage_binding_root_id_fkey FOREIGN KEY (root_id) REFERENCES permission_stream(id);
ALTER TABLE ONLY context_writer_completion ADD CONSTRAINT context_writer_completion_attempt_id_fkey FOREIGN KEY (attempt_id) REFERENCES custody_attempt(id);
ALTER TABLE ONLY context_writer_completion ADD CONSTRAINT context_writer_completion_capture_id_fkey FOREIGN KEY (capture_id) REFERENCES context_execution(capture_id);
ALTER TABLE ONLY context_writer_completion ADD CONSTRAINT context_writer_completion_capture_id_root_id_fkey FOREIGN KEY (capture_id, root_id) REFERENCES context_capture(id, root_id);
ALTER TABLE ONLY context_writer_completion ADD CONSTRAINT context_writer_completion_installation_id_fkey FOREIGN KEY (installation_id) REFERENCES fleet_trust(installation_id);
ALTER TABLE ONLY custody_allocation ADD CONSTRAINT custody_allocation_pool_id_fkey FOREIGN KEY (pool_id) REFERENCES custody_pool(id);
ALTER TABLE ONLY custody_attempt ADD CONSTRAINT custody_attempt_allocation_id_fkey FOREIGN KEY (allocation_id) REFERENCES custody_allocation(id);
ALTER TABLE ONLY custody_copy ADD CONSTRAINT custody_copy_attempt_id_fkey FOREIGN KEY (attempt_id) REFERENCES custody_attempt(id);
ALTER TABLE ONLY custody_event ADD CONSTRAINT custody_event_attempt_id_fkey FOREIGN KEY (attempt_id) REFERENCES custody_attempt(id);
ALTER TABLE ONLY custody_stream ADD CONSTRAINT custody_stream_attempt_id_fkey FOREIGN KEY (attempt_id) REFERENCES custody_attempt(id);
ALTER TABLE ONLY artifact_download ADD CONSTRAINT download_active_batch FOREIGN KEY (active_batch) REFERENCES download_batch(id);
ALTER TABLE ONLY download_allocation ADD CONSTRAINT download_allocation_root_id_fkey FOREIGN KEY (root_id) REFERENCES permission_stream(id);
ALTER TABLE ONLY download_batch ADD CONSTRAINT download_batch_session_id_fkey FOREIGN KEY (session_id) REFERENCES artifact_download(id);
ALTER TABLE ONLY download_control_allocation ADD CONSTRAINT download_control_allocation_id_root_id_fkey FOREIGN KEY (id, root_id) REFERENCES download_allocation(id, root_id);
ALTER TABLE ONLY download_key_binding ADD CONSTRAINT download_key_binding_batch_id_fkey FOREIGN KEY (batch_id) REFERENCES download_batch(id);
ALTER TABLE ONLY download_key_binding ADD CONSTRAINT download_key_binding_installation_id_fkey FOREIGN KEY (installation_id) REFERENCES fleet_trust(installation_id);
ALTER TABLE ONLY download_key_binding ADD CONSTRAINT download_key_binding_root_id_fkey FOREIGN KEY (root_id) REFERENCES permission_stream(id);
ALTER TABLE ONLY download_key_binding ADD CONSTRAINT download_key_binding_session_id_fkey FOREIGN KEY (session_id) REFERENCES artifact_download(id);
ALTER TABLE ONLY download_native_backing ADD CONSTRAINT download_native_backing_allocation_id_root_id_fkey FOREIGN KEY (allocation_id, root_id) REFERENCES download_allocation(id, root_id);
ALTER TABLE ONLY download_native_key ADD CONSTRAINT download_native_key_allocation_id_fkey FOREIGN KEY (allocation_id) REFERENCES download_native_backing(allocation_id);
ALTER TABLE ONLY download_native_key ADD CONSTRAINT download_native_key_window_id_fkey FOREIGN KEY (window_id) REFERENCES download_window(id);
ALTER TABLE ONLY download_native_key ADD CONSTRAINT download_native_key_worker_id_fkey FOREIGN KEY (worker_id) REFERENCES download_native_owner(worker_id);
ALTER TABLE ONLY download_native_owner ADD CONSTRAINT download_native_owner_allocation_id_fkey FOREIGN KEY (allocation_id) REFERENCES download_native_backing(allocation_id);
ALTER TABLE ONLY download_native_owner ADD CONSTRAINT download_native_owner_worker_id_fkey FOREIGN KEY (worker_id) REFERENCES download_worker(id);
ALTER TABLE ONLY download_response ADD CONSTRAINT download_response_active_window FOREIGN KEY (active_window) REFERENCES download_window(id) DEFERRABLE INITIALLY DEFERRED;
ALTER TABLE ONLY download_response ADD CONSTRAINT download_response_session_id_root_id_fkey FOREIGN KEY (session_id, root_id) REFERENCES artifact_download(id, root_id);
ALTER TABLE ONLY download_window ADD CONSTRAINT download_window_response_id_session_id_fkey FOREIGN KEY (response_id, session_id) REFERENCES download_response(id, session_id);
ALTER TABLE ONLY download_worker ADD CONSTRAINT download_worker_allocation_id_fkey FOREIGN KEY (allocation_id) REFERENCES download_allocation(id);
ALTER TABLE ONLY download_worker ADD CONSTRAINT download_worker_baseline_query_allocation_id_fkey FOREIGN KEY (baseline_query_allocation_id) REFERENCES context_query_allocation(id);
ALTER TABLE ONLY download_worker_certificate ADD CONSTRAINT download_worker_certificate_worker_id_fkey FOREIGN KEY (worker_id) REFERENCES download_worker_enrollment(worker_id);
ALTER TABLE ONLY download_worker_configuration_revision ADD CONSTRAINT download_worker_configuration_installation_id_cluster_id_s_fkey FOREIGN KEY (installation_id, cluster_id, source_uid) REFERENCES download_worker_configuration(installation_id, cluster_id, source_uid);
ALTER TABLE ONLY download_worker_configuration ADD CONSTRAINT download_worker_configuration_installation_id_fkey FOREIGN KEY (installation_id) REFERENCES fleet_trust(installation_id);
ALTER TABLE ONLY download_worker_enrollment ADD CONSTRAINT download_worker_enrollment_worker_id_fkey FOREIGN KEY (worker_id) REFERENCES download_worker(id);
ALTER TABLE ONLY download_worker ADD CONSTRAINT download_worker_installation_id_fkey FOREIGN KEY (installation_id) REFERENCES fleet_trust(installation_id);
ALTER TABLE ONLY download_worker_owner ADD CONSTRAINT download_worker_owner_worker_id_fkey FOREIGN KEY (worker_id) REFERENCES download_worker(id);
ALTER TABLE ONLY download_worker ADD CONSTRAINT download_worker_query_allocation_id_fkey FOREIGN KEY (query_allocation_id) REFERENCES context_query_allocation(id);
ALTER TABLE ONLY download_worker ADD CONSTRAINT download_worker_query_id_fkey FOREIGN KEY (query_id) REFERENCES context_query(id);
ALTER TABLE ONLY download_worker ADD CONSTRAINT download_worker_root_id_fkey FOREIGN KEY (root_id) REFERENCES permission_stream(id);
ALTER TABLE ONLY download_worker ADD CONSTRAINT download_worker_session_id_fkey FOREIGN KEY (session_id) REFERENCES artifact_download(id);
ALTER TABLE ONLY evidence_share ADD CONSTRAINT evidence_share_artifact_id_fkey FOREIGN KEY (artifact_id) REFERENCES context_case_locator(artifact_id);
ALTER TABLE ONLY evidence_share ADD CONSTRAINT evidence_share_policy_acceptance_id_fkey FOREIGN KEY (policy_acceptance_id) REFERENCES policy_acceptance(id);
ALTER TABLE ONLY hub_owner_certificate ADD CONSTRAINT hub_owner_certificate_enrollment_id_fkey FOREIGN KEY (enrollment_id) REFERENCES hub_owner_enrollment(id);
ALTER TABLE ONLY hub_owner_configuration ADD CONSTRAINT hub_owner_configuration_installation_id_fkey FOREIGN KEY (installation_id) REFERENCES fleet_trust(installation_id);
ALTER TABLE ONLY hub_owner_configuration_revision ADD CONSTRAINT hub_owner_configuration_revis_installation_id_cluster_id_s_fkey FOREIGN KEY (installation_id, cluster_id, source_uid) REFERENCES hub_owner_configuration(installation_id, cluster_id, source_uid);
ALTER TABLE ONLY hub_owner_enrollment ADD CONSTRAINT hub_owner_enrollment_installation_id_cluster_id_fkey FOREIGN KEY (installation_id, cluster_id) REFERENCES hub_owner_configuration(installation_id, cluster_id);
ALTER TABLE ONLY live_watch_account ADD CONSTRAINT live_watch_account_root_id_fkey FOREIGN KEY (root_id) REFERENCES live_watch_root(root_id);
ALTER TABLE ONLY live_watch_control ADD CONSTRAINT live_watch_control_root_id_fkey FOREIGN KEY (root_id) REFERENCES live_watch_root(root_id);
ALTER TABLE ONLY live_watch_root ADD CONSTRAINT live_watch_root_installation_id_fkey FOREIGN KEY (installation_id) REFERENCES fleet_trust(installation_id);
ALTER TABLE ONLY live_watch_root ADD CONSTRAINT live_watch_root_root_id_fkey FOREIGN KEY (root_id) REFERENCES permission_stream(id);
ALTER TABLE ONLY local_key_configuration ADD CONSTRAINT local_key_configuration_installation_id_fkey FOREIGN KEY (installation_id) REFERENCES fleet_trust(installation_id);
ALTER TABLE ONLY local_key_version ADD CONSTRAINT local_key_version_installation_id_purpose_key_id_fkey FOREIGN KEY (installation_id, purpose, key_id) REFERENCES local_key_configuration(installation_id, purpose, key_id);
ALTER TABLE ONLY permission_acceptance ADD CONSTRAINT permission_acceptance_audit FOREIGN KEY (audit_id) REFERENCES authority_audit(id) DEFERRABLE INITIALLY DEFERRED;
ALTER TABLE ONLY permission_acceptance ADD CONSTRAINT permission_acceptance_stream_id_fkey FOREIGN KEY (stream_id) REFERENCES permission_stream(id);
ALTER TABLE ONLY permission_assignment ADD CONSTRAINT permission_activation_audit FOREIGN KEY (activation_audit_id) REFERENCES authority_audit(id) DEFERRABLE INITIALLY DEFERRED;
ALTER TABLE ONLY permission_assignment ADD CONSTRAINT permission_assignment_stream_id_basis_key_fkey FOREIGN KEY (stream_id, basis_key) REFERENCES permission_basis(stream_id, basis_key);
ALTER TABLE ONLY permission_basis ADD CONSTRAINT permission_basis_automation_audit_id_fkey FOREIGN KEY (automation_audit_id) REFERENCES authority_audit(id) DEFERRABLE INITIALLY DEFERRED;
ALTER TABLE ONLY permission_basis ADD CONSTRAINT permission_basis_stream_id_fkey FOREIGN KEY (stream_id) REFERENCES permission_stream(id);
ALTER TABLE ONLY permission_assignment ADD CONSTRAINT permission_retirement_audit FOREIGN KEY (retirement_audit_id) REFERENCES authority_audit(id) DEFERRABLE INITIALLY DEFERRED;
ALTER TABLE ONLY permission_review_assignment ADD CONSTRAINT permission_review_assignment_stream_id_fkey FOREIGN KEY (stream_id) REFERENCES permission_stream(id);
ALTER TABLE ONLY permission_review_decision ADD CONSTRAINT permission_review_decision_assignment_id_fkey FOREIGN KEY (assignment_id) REFERENCES permission_review_assignment(id);
ALTER TABLE ONLY permission_review_assignment ADD CONSTRAINT permission_review_retirement_audit FOREIGN KEY (retirement_audit_id) REFERENCES authority_audit(id) DEFERRABLE INITIALLY DEFERRED;
ALTER TABLE ONLY permission_review_source ADD CONSTRAINT permission_review_source_audit FOREIGN KEY (accepted_audit_id) REFERENCES authority_audit(id) DEFERRABLE INITIALLY DEFERRED;
ALTER TABLE ONLY permission_review_source ADD CONSTRAINT permission_review_source_stream_id_fkey FOREIGN KEY (stream_id) REFERENCES permission_stream(id);
ALTER TABLE ONLY permission_stream ADD CONSTRAINT permission_stream_initial_audit_id_fkey FOREIGN KEY (initial_audit_id) REFERENCES authority_audit(id) DEFERRABLE INITIALLY DEFERRED;
ALTER TABLE ONLY policy_acceptance ADD CONSTRAINT policy_acceptance_root_id_policy_uid_fkey FOREIGN KEY (root_id, policy_uid) REFERENCES policy_source(root_id, policy_uid);
ALTER TABLE ONLY policy_source ADD CONSTRAINT policy_active_record FOREIGN KEY (active_id) REFERENCES policy_acceptance(id) DEFERRABLE INITIALLY DEFERRED;
ALTER TABLE ONLY policy_grant_attachment ADD CONSTRAINT policy_grant_attachment_acceptance_id_fkey FOREIGN KEY (acceptance_id) REFERENCES policy_acceptance(id);
ALTER TABLE ONLY policy_grant_attachment ADD CONSTRAINT policy_grant_attachment_grant_id_fkey FOREIGN KEY (grant_id) REFERENCES access_grant(id);
ALTER TABLE ONLY policy_grant_attachment ADD CONSTRAINT policy_grant_attachment_root_id_grant_id_acceptance_id_pol_fkey FOREIGN KEY (root_id, grant_id, acceptance_id, policy_uid) REFERENCES access_grant(root_id, id, policy_acceptance_id, policy_uid);
ALTER TABLE ONLY policy_grant_attachment ADD CONSTRAINT policy_grant_attachment_root_id_policy_uid_fkey FOREIGN KEY (root_id, policy_uid) REFERENCES policy_source(root_id, policy_uid);
ALTER TABLE ONLY policy_grant_settings ADD CONSTRAINT policy_grant_settings_root_id_fkey FOREIGN KEY (root_id) REFERENCES permission_stream(id);
ALTER TABLE ONLY policy_observation_session ADD CONSTRAINT policy_observation_session_adhoc_grant FOREIGN KEY (root_id, grant_id, adhoc_capture_id) REFERENCES access_grant(root_id, id, capture_id);
ALTER TABLE ONLY policy_observation_session ADD CONSTRAINT policy_observation_session_attempt_id_fkey FOREIGN KEY (attempt_id) REFERENCES custody_attempt(id);
ALTER TABLE ONLY policy_observation_session ADD CONSTRAINT policy_observation_session_capture_id_root_id_fkey FOREIGN KEY (capture_id, root_id) REFERENCES context_capture(id, root_id);
ALTER TABLE ONLY policy_observation_session ADD CONSTRAINT policy_observation_session_root_id_grant_id_acceptance_id__fkey FOREIGN KEY (root_id, grant_id, acceptance_id, policy_uid) REFERENCES access_grant(root_id, id, policy_acceptance_id, policy_uid);
ALTER TABLE ONLY policy_occurrence ADD CONSTRAINT policy_occurrence_acceptance_id_fkey FOREIGN KEY (acceptance_id) REFERENCES policy_acceptance(id);
ALTER TABLE ONLY policy_occurrence_capture ADD CONSTRAINT policy_occurrence_capture_capture_id_fkey FOREIGN KEY (capture_id) REFERENCES context_capture(id);
ALTER TABLE ONLY policy_occurrence ADD CONSTRAINT policy_occurrence_capture_id_fkey FOREIGN KEY (capture_id) REFERENCES context_capture(id);
ALTER TABLE ONLY policy_occurrence_capture ADD CONSTRAINT policy_occurrence_capture_occurrence_id_fkey FOREIGN KEY (occurrence_id) REFERENCES policy_occurrence(id);
ALTER TABLE ONLY policy_occurrence ADD CONSTRAINT policy_occurrence_grant_scope FOREIGN KEY (root_id, grant_id, acceptance_id, policy_uid) REFERENCES access_grant(root_id, id, policy_acceptance_id, policy_uid);
ALTER TABLE ONLY policy_occurrence ADD CONSTRAINT policy_occurrence_reserved_capture_id_fkey FOREIGN KEY (reserved_capture_id) REFERENCES context_capture(id);
ALTER TABLE ONLY policy_occurrence ADD CONSTRAINT policy_occurrence_root_id_policy_uid_fkey FOREIGN KEY (root_id, policy_uid) REFERENCES policy_source(root_id, policy_uid);
ALTER TABLE ONLY policy_pod_watermark ADD CONSTRAINT policy_pod_watermark_root_id_policy_uid_fkey FOREIGN KEY (root_id, policy_uid) REFERENCES policy_source(root_id, policy_uid);
ALTER TABLE ONLY policy_recording_source ADD CONSTRAINT policy_recording_source_acceptance_id_fkey FOREIGN KEY (acceptance_id) REFERENCES policy_acceptance(id);
ALTER TABLE ONLY policy_recording_source ADD CONSTRAINT policy_recording_source_root_id_fkey FOREIGN KEY (root_id) REFERENCES permission_stream(id);
ALTER TABLE ONLY policy_source ADD CONSTRAINT policy_source_exact_grant_attachment FOREIGN KEY (root_id, policy_uid, grant_attachment_id) REFERENCES policy_grant_attachment(root_id, policy_uid, id);
ALTER TABLE ONLY policy_source ADD CONSTRAINT policy_source_root_id_fkey FOREIGN KEY (root_id) REFERENCES permission_stream(id);
ALTER TABLE ONLY policy_suppression ADD CONSTRAINT policy_suppression_root_id_policy_uid_fkey FOREIGN KEY (root_id, policy_uid) REFERENCES policy_source(root_id, policy_uid);
ALTER TABLE ONLY processing_decision ADD CONSTRAINT processing_decision_root_id_fkey FOREIGN KEY (root_id) REFERENCES processing_root(root_id);
ALTER TABLE ONLY processing_decision ADD CONSTRAINT processing_decision_root_id_rule_id_fkey FOREIGN KEY (root_id, rule_id) REFERENCES processing_rule(root_id, id);
ALTER TABLE ONLY processing_root ADD CONSTRAINT processing_root_root_id_fkey FOREIGN KEY (root_id) REFERENCES permission_stream(id);
ALTER TABLE ONLY processing_rule ADD CONSTRAINT processing_rule_root_id_fkey FOREIGN KEY (root_id) REFERENCES processing_root(root_id);
ALTER TABLE ONLY recording_save_group ADD CONSTRAINT recording_save_group_acceptance_id_fkey FOREIGN KEY (acceptance_id) REFERENCES policy_acceptance(id);
ALTER TABLE ONLY recording_save_group ADD CONSTRAINT recording_save_group_allocation_id_fkey FOREIGN KEY (allocation_id) REFERENCES custody_allocation(id);
ALTER TABLE ONLY recording_save_group ADD CONSTRAINT recording_save_group_root_id_fkey FOREIGN KEY (root_id) REFERENCES permission_stream(id);
ALTER TABLE ONLY recording_save_reservation ADD CONSTRAINT recording_save_reservation_acceptance_id_fkey FOREIGN KEY (acceptance_id) REFERENCES policy_acceptance(id);
ALTER TABLE ONLY recording_save_reservation ADD CONSTRAINT recording_save_reservation_capture_id_fkey FOREIGN KEY (capture_id) REFERENCES context_capture(id) ON DELETE CASCADE;
ALTER TABLE ONLY recording_save_reservation ADD CONSTRAINT recording_save_reservation_grant_id_fkey FOREIGN KEY (grant_id) REFERENCES access_grant(id);
ALTER TABLE ONLY recording_save_reservation ADD CONSTRAINT recording_save_reservation_root_id_fkey FOREIGN KEY (root_id) REFERENCES permission_stream(id);
ALTER TABLE ONLY recording_selection_set ADD CONSTRAINT recording_selection_set_root_id_fkey FOREIGN KEY (root_id) REFERENCES permission_stream(id);
ALTER TABLE ONLY retention_decision ADD CONSTRAINT retention_decision_attempt_id_fkey FOREIGN KEY (attempt_id) REFERENCES custody_attempt(id);
ALTER TABLE ONLY retention_decision ADD CONSTRAINT retention_decision_root_id_fkey FOREIGN KEY (root_id) REFERENCES permission_stream(id);

-- Triggers.

CREATE TRIGGER access_grant_child_immutable BEFORE DELETE OR UPDATE ON access_grant_child FOR EACH ROW EXECUTE FUNCTION protect_access_grant_history();
CREATE TRIGGER access_grant_child_scope_guard BEFORE INSERT ON access_grant_child FOR EACH ROW EXECUTE FUNCTION guard_access_grant_child_scope();
CREATE TRIGGER access_grant_decision_notify AFTER UPDATE ON access_grant FOR EACH ROW WHEN (((new.capture_id IS NOT NULL) AND (new.decision IS DISTINCT FROM old.decision))) EXECUTE FUNCTION notify_grant_capture();
CREATE TRIGGER access_grant_immutable BEFORE DELETE OR UPDATE ON access_grant FOR EACH ROW EXECUTE FUNCTION protect_access_grant();
CREATE TRIGGER access_grant_use_immutable BEFORE DELETE OR UPDATE ON access_grant_use FOR EACH ROW EXECUTE FUNCTION protect_access_grant_history();
CREATE TRIGGER adhoc_observation_spend_monotonic BEFORE DELETE OR UPDATE ON adhoc_observation_spend FOR EACH ROW EXECUTE FUNCTION protect_adhoc_observation_spend();
CREATE TRIGGER capture_history_parameter_guard BEFORE INSERT OR DELETE OR UPDATE ON capture_history_parameter FOR EACH ROW EXECUTE FUNCTION guard_capture_history_parameter();
CREATE TRIGGER capture_repeat_lineage_guard BEFORE INSERT OR UPDATE ON context_capture FOR EACH ROW EXECUTE FUNCTION guard_capture_repeat_lineage();
CREATE TRIGGER capture_share_from_case_locator AFTER INSERT ON context_case_locator FOR EACH ROW EXECUTE FUNCTION materialize_capture_share();
CREATE CONSTRAINT TRIGGER comparison_key_pair AFTER INSERT ON context_query_key_binding DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION require_comparison_key_pair();
CREATE TRIGGER comparison_worker_parent BEFORE INSERT ON download_worker FOR EACH ROW EXECUTE FUNCTION guard_comparison_worker_parent();
CREATE TRIGGER context_capture_group_guard BEFORE INSERT OR UPDATE ON context_capture FOR EACH ROW EXECUTE FUNCTION guard_context_capture_group();
CREATE TRIGGER context_capture_group_revision AFTER UPDATE OF progress_revision ON context_capture FOR EACH ROW EXECUTE FUNCTION project_recording_save_group_revision();
CREATE TRIGGER context_capture_history_fill BEFORE INSERT OR UPDATE ON context_capture FOR EACH ROW EXECUTE FUNCTION fill_context_capture_history();
CREATE TRIGGER context_capture_policy_share BEFORE INSERT ON context_capture FOR EACH ROW EXECUTE FUNCTION claim_policy_capture_share();
CREATE TRIGGER context_capture_progress_notify AFTER UPDATE ON context_capture FOR EACH ROW WHEN ((new.progress_revision IS DISTINCT FROM old.progress_revision)) EXECUTE FUNCTION notify_capture_progress();
CREATE TRIGGER context_capture_share_instruction_immutable BEFORE UPDATE ON context_capture FOR EACH ROW EXECUTE FUNCTION protect_capture_share_instruction();
CREATE TRIGGER context_case_from_catalog AFTER INSERT ON context_catalog FOR EACH ROW EXECUTE FUNCTION project_context_case_locator();
CREATE TRIGGER context_case_locator_immutable BEFORE DELETE OR UPDATE ON context_case_locator FOR EACH ROW EXECUTE FUNCTION protect_context_case_locator();
CREATE TRIGGER context_deletion_checkpoint_guard BEFORE INSERT OR DELETE OR UPDATE ON context_deletion_checkpoint FOR EACH ROW EXECUTE FUNCTION guard_context_deletion_checkpoint();
CREATE TRIGGER context_execution_guard BEFORE INSERT OR DELETE OR UPDATE ON context_execution FOR EACH ROW EXECUTE FUNCTION guard_context_execution();
CREATE CONSTRAINT TRIGGER context_finalization_completed AFTER UPDATE ON context_deletion_checkpoint DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION require_completed_context_finalization();
CREATE TRIGGER context_processing_from_catalog AFTER INSERT ON context_catalog FOR EACH ROW EXECUTE FUNCTION project_context_processing();
CREATE TRIGGER context_processing_guard BEFORE INSERT OR DELETE OR UPDATE ON context_processing FOR EACH ROW EXECUTE FUNCTION guard_context_processing();
CREATE TRIGGER context_progress_from_catalog AFTER INSERT ON context_catalog FOR EACH ROW EXECUTE FUNCTION advance_context_progress();
CREATE TRIGGER context_progress_from_custody AFTER UPDATE ON custody_attempt FOR EACH ROW EXECUTE FUNCTION advance_context_progress();
CREATE TRIGGER context_progress_from_execution AFTER INSERT OR UPDATE ON context_execution FOR EACH ROW EXECUTE FUNCTION advance_context_progress();
CREATE TRIGGER context_progress_guard BEFORE INSERT OR UPDATE ON context_capture FOR EACH ROW EXECUTE FUNCTION guard_context_progress();
CREATE TRIGGER context_query_allocation_guard BEFORE INSERT OR DELETE OR UPDATE ON context_query_allocation FOR EACH ROW EXECUTE FUNCTION guard_context_query_account();
CREATE TRIGGER context_query_backing_guard BEFORE INSERT OR DELETE OR UPDATE ON context_query_backing FOR EACH ROW EXECUTE FUNCTION guard_context_query_backing();
CREATE TRIGGER context_query_batch_guard BEFORE INSERT OR DELETE OR UPDATE ON context_query_batch FOR EACH ROW EXECUTE FUNCTION guard_context_query_child();
CREATE TRIGGER context_query_call_guard BEFORE INSERT OR DELETE OR UPDATE ON context_query_call FOR EACH ROW EXECUTE FUNCTION guard_context_query_child();
CREATE TRIGGER context_query_guard BEFORE INSERT OR DELETE OR UPDATE ON context_query FOR EACH ROW EXECUTE FUNCTION guard_context_query();
CREATE TRIGGER context_query_key_guard BEFORE INSERT OR DELETE OR UPDATE ON context_query_key_binding FOR EACH ROW EXECUTE FUNCTION guard_context_query_child();
CREATE TRIGGER context_query_principal_guard BEFORE INSERT OR DELETE OR UPDATE ON context_query_principal FOR EACH ROW EXECUTE FUNCTION guard_context_query_account();
CREATE TRIGGER context_query_worker_guard BEFORE INSERT OR DELETE OR UPDATE ON context_query_worker FOR EACH ROW EXECUTE FUNCTION guard_context_query_child();
CREATE TRIGGER context_snapshot_completion_guard BEFORE INSERT OR UPDATE ON context_capture FOR EACH ROW EXECUTE FUNCTION guard_context_snapshot_completion();
CREATE CONSTRAINT TRIGGER context_snapshot_completion_required AFTER UPDATE ON context_capture DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION guard_context_snapshot_completion();
CREATE TRIGGER context_writer_completion_guard BEFORE INSERT OR DELETE OR UPDATE ON context_writer_completion FOR EACH ROW EXECUTE FUNCTION guard_context_writer_completion();
CREATE CONSTRAINT TRIGGER context_writer_completion_required AFTER UPDATE ON context_execution DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION require_context_writer_completion();
CREATE TRIGGER context_writer_protocol_guard BEFORE INSERT OR UPDATE ON context_execution FOR EACH ROW EXECUTE FUNCTION guard_context_writer_protocol();
CREATE CONSTRAINT TRIGGER custody_attempt_stream_required AFTER INSERT ON custody_attempt DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION require_custody_stream();
CREATE TRIGGER custody_context_deletion_guard BEFORE UPDATE ON custody_attempt FOR EACH ROW EXECUTE FUNCTION require_audited_context_deletion();
CREATE TRIGGER custody_retention_immutable BEFORE INSERT OR UPDATE ON custody_attempt FOR EACH ROW EXECUTE FUNCTION protect_custody_retention();
CREATE TRIGGER custody_stream_guard BEFORE DELETE OR UPDATE ON custody_stream FOR EACH ROW EXECUTE FUNCTION guard_custody_stream();
CREATE TRIGGER download_allocation_immutable BEFORE UPDATE ON download_allocation FOR EACH ROW EXECUTE FUNCTION protect_download_allocation();
CREATE TRIGGER download_batch_immutable BEFORE UPDATE ON download_batch FOR EACH ROW EXECUTE FUNCTION protect_download_batch();
CREATE TRIGGER download_control_guard BEFORE INSERT OR DELETE OR UPDATE ON download_control_allocation FOR EACH ROW EXECUTE FUNCTION guard_download_control_allocation();
CREATE TRIGGER download_key_spend BEFORE UPDATE ON download_key_binding FOR EACH ROW EXECUTE FUNCTION guard_download_key_spend();
CREATE TRIGGER download_native_backing_guard BEFORE INSERT OR DELETE OR UPDATE ON download_native_backing FOR EACH ROW EXECUTE FUNCTION guard_download_native_backing();
CREATE TRIGGER download_native_key_guard BEFORE INSERT OR DELETE OR UPDATE ON download_native_key FOR EACH ROW EXECUTE FUNCTION guard_download_native_key();
CREATE TRIGGER download_native_owner_guard BEFORE INSERT OR DELETE OR UPDATE ON download_native_owner FOR EACH ROW EXECUTE FUNCTION guard_download_native_owner();
CREATE TRIGGER download_response_guard BEFORE INSERT OR DELETE OR UPDATE ON download_response FOR EACH ROW EXECUTE FUNCTION guard_download_response();
CREATE TRIGGER download_session_immutable BEFORE UPDATE ON artifact_download FOR EACH ROW EXECUTE FUNCTION protect_download_session();
CREATE TRIGGER download_window_guard BEFORE INSERT OR DELETE OR UPDATE ON download_window FOR EACH ROW EXECUTE FUNCTION guard_download_window();
CREATE TRIGGER download_worker_guard BEFORE UPDATE ON download_worker FOR EACH ROW EXECUTE FUNCTION guard_download_worker();
CREATE TRIGGER download_worker_owner_guard BEFORE INSERT OR UPDATE ON download_worker_owner FOR EACH ROW EXECUTE FUNCTION guard_download_worker_owner();
CREATE TRIGGER evidence_share_immutable BEFORE INSERT OR DELETE OR UPDATE ON evidence_share FOR EACH ROW EXECUTE FUNCTION protect_evidence_share();
CREATE TRIGGER guard_context_key_wrap BEFORE DELETE OR UPDATE ON context_key_wrap FOR EACH ROW EXECUTE FUNCTION guard_context_key_wrap();
CREATE TRIGGER history_custody_settlement_guard BEFORE UPDATE ON custody_attempt FOR EACH ROW EXECUTE FUNCTION guard_history_custody_settlement();
CREATE TRIGGER owner_certificate_guard BEFORE INSERT OR DELETE OR UPDATE ON hub_owner_certificate FOR EACH ROW EXECUTE FUNCTION guard_owner_certificate();
CREATE TRIGGER owner_configuration_head_guard BEFORE INSERT OR UPDATE ON hub_owner_configuration FOR EACH ROW EXECUTE FUNCTION guard_owner_configuration_head();
CREATE TRIGGER owner_configuration_revision_guard BEFORE INSERT OR UPDATE ON hub_owner_configuration_revision FOR EACH ROW EXECUTE FUNCTION guard_owner_configuration_revision();
CREATE TRIGGER owner_enrollment_guard BEFORE INSERT OR DELETE OR UPDATE ON hub_owner_enrollment FOR EACH ROW EXECUTE FUNCTION guard_owner_enrollment();
CREATE TRIGGER policy_acceptance_collection_monotonic BEFORE UPDATE ON policy_acceptance FOR EACH ROW EXECUTE FUNCTION protect_policy_collection_spend();
CREATE TRIGGER policy_acceptance_sharing_monotonic BEFORE UPDATE ON policy_acceptance FOR EACH ROW EXECUTE FUNCTION protect_policy_sharing();
CREATE TRIGGER policy_grant_attachment_immutable BEFORE DELETE OR UPDATE ON policy_grant_attachment FOR EACH ROW EXECUTE FUNCTION protect_access_grant_history();
CREATE TRIGGER policy_observation_session_monotonic BEFORE INSERT OR DELETE OR UPDATE ON policy_observation_session FOR EACH ROW EXECUTE FUNCTION protect_policy_observation_session();
CREATE TRIGGER policy_occurrence_capture_immutable BEFORE DELETE OR UPDATE ON policy_occurrence_capture FOR EACH ROW EXECUTE FUNCTION protect_policy_occurrence_capture();
CREATE TRIGGER policy_occurrence_reservation_immutable BEFORE DELETE OR UPDATE ON policy_occurrence FOR EACH ROW EXECUTE FUNCTION protect_policy_occurrence_reservation();
CREATE TRIGGER policy_recording_source_guard BEFORE INSERT OR DELETE OR UPDATE ON policy_recording_source FOR EACH ROW EXECUTE FUNCTION guard_policy_recording_source();
CREATE TRIGGER policy_source_original_provenance BEFORE INSERT ON policy_recording_source FOR EACH ROW EXECUTE FUNCTION guard_policy_source_original_provenance();
CREATE TRIGGER processing_decision_guard BEFORE INSERT OR DELETE OR UPDATE ON processing_decision FOR EACH ROW EXECUTE FUNCTION guard_processing_decision();
CREATE TRIGGER processing_root_guard BEFORE INSERT OR DELETE OR UPDATE ON processing_root FOR EACH ROW EXECUTE FUNCTION guard_processing_root();
CREATE TRIGGER processing_root_initialize BEFORE INSERT ON processing_root FOR EACH ROW EXECUTE FUNCTION initialize_processing_root();
CREATE TRIGGER processing_rule_guard BEFORE INSERT OR DELETE OR UPDATE ON processing_rule FOR EACH ROW EXECUTE FUNCTION guard_processing_rule();
CREATE CONSTRAINT TRIGGER recording_save_group_complete AFTER INSERT ON recording_save_group DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION require_recording_save_group_members();
CREATE TRIGGER recording_save_group_guard BEFORE INSERT OR DELETE OR UPDATE ON recording_save_group FOR EACH ROW EXECUTE FUNCTION guard_recording_save_group();
CREATE TRIGGER recording_save_reservation_immutable BEFORE UPDATE ON recording_save_reservation FOR EACH ROW EXECUTE FUNCTION guard_recording_save_reservation();
CREATE TRIGGER recording_selection_guard BEFORE DELETE OR UPDATE ON recording_selection_set FOR EACH ROW EXECUTE FUNCTION guard_recording_selection_set();
CREATE TRIGGER remote_access_binding_delivery_notify AFTER INSERT OR UPDATE ON remote_access_binding_delivery FOR EACH ROW EXECUTE FUNCTION notify_remote_delivery('asservat_remote_bindings');
CREATE TRIGGER retention_decision_immutable BEFORE UPDATE ON retention_decision FOR EACH ROW EXECUTE FUNCTION protect_retention_decision();
CREATE CONSTRAINT TRIGGER snapshot_cancel_execution_proof AFTER UPDATE ON context_execution DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION require_snapshot_cancel_proof();
CREATE TRIGGER snapshot_cancel_guard BEFORE INSERT OR UPDATE ON context_capture FOR EACH ROW EXECUTE FUNCTION guard_snapshot_cancel();
CREATE TRIGGER snapshot_cancel_progress AFTER UPDATE ON context_capture FOR EACH ROW EXECUTE FUNCTION bump_snapshot_cancel_progress();
CREATE TRIGGER worker_certificate_guard BEFORE UPDATE ON download_worker_certificate FOR EACH ROW EXECUTE FUNCTION guard_worker_certificate();
CREATE TRIGGER worker_configuration_head_guard BEFORE UPDATE ON download_worker_configuration FOR EACH ROW EXECUTE FUNCTION guard_worker_configuration_head();
CREATE TRIGGER worker_configuration_revision_guard BEFORE UPDATE ON download_worker_configuration_revision FOR EACH ROW EXECUTE FUNCTION guard_worker_configuration_revision();
CREATE TRIGGER worker_enrollment_guard BEFORE UPDATE ON download_worker_enrollment FOR EACH ROW EXECUTE FUNCTION guard_worker_enrollment();
CREATE TRIGGER zz_apply_retention_policies AFTER INSERT ON capture_history_parameter FOR EACH ROW EXECUTE FUNCTION apply_retention_policies();
CREATE TRIGGER zz_apply_retention_policies AFTER INSERT ON context_capture FOR EACH ROW EXECUTE FUNCTION apply_retention_policies();
