// Generated from canonical browser OpenAPI. Run npm run generate; do not edit.
export type paths = Record<string, never>;
export type webhooks = Record<string, never>;
export interface components {
    schemas: {
        McpInput_activate_policy: {
            /**
             * Format: uuid
             * @description Explicit approved grant to attach as a current team manager after acceptance audit; never reissues authority or refills spend.
             */
            grant_id?: string;
            policy_name: string;
            idempotency_key: string;
            /** @description Accept the reviewed recurring sharing of a DebugPolicy with spec.sharing (ADR-239). Without it such a policy is not activated; the reply SharingReviewRequired states that repeated collections will be shared, with whom, how many captures and until when. */
            sharing_reviewed?: boolean;
        };
        /** Asservat mcp-result v1 */
        Contract_mcp_result: {
            /** @constant */
            schema_version: "mcp-result/v1";
            /** Format: uuid */
            request_id: string;
            /** @enum {string} */
            data_class: "metadata" | "extract" | "raw";
            /** @enum {string} */
            status: "ok" | "pending" | "error";
            data: Record<string, unknown>;
            truncated: boolean;
            next_cursor: string | null;
            narrowing_hint: string | null;
            warnings: string[];
            provenance: components["schemas"]["Contract_common_9530994123d918d4"][];
        } & unknown;
        Contract_common_9530994123d918d4: {
            /** Format: uuid */
            artifactID: string;
            digest: string;
        };
        McpOutput_activate_policy: components["schemas"]["Contract_mcp_result"] & ({
            /** @constant */
            status: "ok";
            data: {
                policy_uid: string;
                /** Format: uuid */
                acceptance_id: string;
                /** @enum {unknown} */
                state: "active" | "pendingAudit";
                /** Format: date-time */
                expires_at: string;
                max_executions: number;
                replay: boolean;
                /** @description Recurring sharing of this acceptance (ADR-239): repeated collections will be shared with these recipients, at most max_captures captures, until not_after. */
                sharing?: {
                    /** @constant */
                    statement: "Repeated collections will be shared";
                    recipients: number;
                    max_captures: number;
                    /** Format: date-time */
                    not_after: string;
                };
            };
        } | {
            /** @constant */
            status: "error";
            data: {
                code: string;
                message: string;
                retryable: boolean;
                /** Format: uri */
                navigation_uri?: string;
                /** @enum {unknown} */
                responsible_role?: "maintainer" | "approver" | "administrator" | "none";
                retry_after_seconds?: number;
            };
        });
        McpInput_request_policy_grant: {
            policy_uid: string;
            idempotency_key: string;
            lifetime_seconds?: number;
            limits: {
                max_executions: number;
                max_collected_bytes: number;
                max_observed_bytes: number;
                /** @description Cumulative eligible entry and exit probe ceiling; zero or absent grants no argument observation. */
                max_observed_events?: number;
            };
            observation_limits?: {
                max_session_seconds: number;
                max_observed_bytes: number;
                max_bytes_per_second: number;
                max_concurrent_sessions: number;
                max_observed_events?: number;
            };
            policy_name: string;
        };
        McpOutput_request_policy_grant: components["schemas"]["Contract_mcp_result"] & ({
            /** @constant */
            status: "ok";
            data: {
                /** Format: uuid */
                grant_id: string;
                /** @enum {unknown} */
                phase: "Pending" | "Approved" | "Denied" | "Revoked" | "Expired" | "Exhausted";
                revision: number;
                /** @constant */
                kind: "policy";
                /** Format: uuid */
                capture_id?: string;
                execution_digest: string;
                review_digest: string;
                target: {
                    /** Format: uuid */
                    cluster_id: string;
                    namespace: string;
                    /** @enum {unknown} */
                    workload_kind: "Deployment" | "StatefulSet" | "Pod";
                    workload_name: string;
                    pod_name?: string;
                    namespace_uid?: string;
                    workload_uid?: string;
                };
                /** @enum {unknown} */
                data_class: "metadata" | "extract" | "raw";
                reasons: {
                    action_id: string;
                    /** @enum {unknown} */
                    code: "rawBytePredicate" | "rawPackets" | "httpHeaders" | "syscallArguments" | "liveProfile" | "recordingApprovalRequired" | "policyCollection";
                }[];
                observation_limits?: {
                    max_session_seconds: number;
                    max_observed_bytes: number;
                    max_bytes_per_second: number;
                    max_concurrent_sessions: number;
                    max_observed_events?: number;
                };
                requested_by: {
                    issuer: string;
                    subject: string;
                    client_id: string;
                };
                /** Format: date-time */
                requested_at: string;
                /** Format: date-time */
                review_until?: string;
                lifetime_seconds: number;
                decision?: {
                    /** @enum {unknown} */
                    decision: "approved" | "denied";
                    decided_by: {
                        issuer: string;
                        subject: string;
                        client_id: string;
                    };
                    /** Format: date-time */
                    decided_at: string;
                    reason: string;
                    authentication_context?: {
                        acr: string;
                        /** Format: date-time */
                        authenticated_at: string;
                    };
                };
                /** Format: date-time */
                not_after?: string;
                /** Format: date-time */
                revoked_at?: string;
                revoked_by?: {
                    issuer: string;
                    subject: string;
                    client_id: string;
                };
                can_decide: boolean;
                can_revoke: boolean;
                /** Format: uri */
                approval_navigation_uri: string;
                actions: ({
                    action_id: string;
                    /** @enum {unknown} */
                    kind: "packetCapture" | "syscallTrace" | "profile";
                    /** @enum {unknown} */
                    execution_mode: "ongoing" | "onTrigger";
                    before?: string;
                    after?: string;
                    filter?: string;
                    filter_digest?: string;
                    filter_instructions?: number;
                    max_bytes: number;
                    ring_max_bytes?: number;
                    ring_max_age?: string;
                    sensitive: ("rawBytePredicate" | "rawPackets" | "httpHeaders" | "syscallArguments" | "liveProfile" | "recordingApprovalRequired")[];
                    profile?: {
                        /** @constant */
                        runtime: "go";
                        /** @enum {unknown} */
                        type: "cpu" | "heap" | "allocs" | "goroutine" | "block" | "mutex" | "threadcreate" | "runtimeTrace";
                        /** @enum {unknown} */
                        mode: "snapshot" | "interval" | "cumulative" | "delta";
                        /** @constant */
                        source: "httpEndpoint";
                        duration?: string;
                        timeout: string;
                        force_gc: boolean;
                        source_ref: string;
                        source_name: string;
                        /** @enum {unknown} */
                        address_mode: "targetLoopback" | "podIP";
                        port?: number;
                        /** @constant */
                        path_policy: "go-pprof/v1";
                        endpoint_digest?: string;
                        /** @enum {unknown} */
                        source_kind?: "templateBinding" | "administratorProfile";
                        definition_digest?: string;
                        declared_port_name?: string;
                        minimum_port?: number;
                        maximum_port?: number;
                    } & (unknown | ({
                        /** @constant */
                        source_kind?: "templateBinding";
                    } | {
                        /** @constant */
                        source_kind?: "administratorProfile";
                    }));
                } & ({
                    /** @constant */
                    kind?: "profile";
                } | {
                    /** @enum {unknown} */
                    kind?: "packetCapture" | "syscallTrace";
                }))[];
                result_access?: {
                    action_ids: string[];
                    operations: ("download_artifact" | "get_logs" | "pcap_query" | "syscall_query")[];
                    max_artifacts: number;
                    max_bytes: number;
                    max_operations: number;
                    /** Format: date-time */
                    not_after: string;
                    artifacts_used: number;
                    bytes_used: number;
                    operations_used: number;
                };
                remaining_bytes?: number;
                remaining_executions?: number;
                remaining_observation_bytes?: number;
                /**
                 * Format: date-time
                 * @description Original passive preview expiry; bounds opening a new approval review, and also start for legacy previewDeadline plans.
                 */
                preview_deadline?: string;
                /**
                 * @description Manual preview/acceptance window, or the separately accepted team-policy authority bound by original request-anchored grant expiry.
                 * @enum {unknown}
                 */
                capture_deadline_rule: "previewDeadline" | "acceptanceWithinGrant" | "policyAuthority";
                /**
                 * @description Maximum window fixed once at acceptance, never beyond original approval expiry.
                 * @constant
                 */
                capture_window_seconds?: 300;
                /** @description Advisory current original requester/client collection eligibility under this exact approved grant. Submission rechecks all authority. */
                can_resume: boolean;
                policy?: {
                    uid: string;
                    executor: {
                        issuer: string;
                        subject: string;
                        client_id: string;
                    };
                    /** Format: date-time */
                    authority_issued_at: string;
                    /** Format: date-time */
                    authority_not_after: string;
                    max_executions: number;
                    executions_used: number;
                    max_collected_bytes: number;
                    max_observed_bytes: number;
                    collected_bytes_used: number;
                    observed_bytes_used: number;
                    /** @description Cumulative eligible entry and exit probe ceiling; zero or absent grants no argument observation. */
                    max_observed_events?: number;
                    /** @description Conservative charged event units, including uncertain observations. */
                    observed_events_used?: number;
                };
            } & (unknown & unknown & unknown & unknown);
        } | {
            /** @constant */
            status: "pending";
            data: {
                query_handle: string;
                retry_after_seconds: number;
            };
        } | {
            /** @constant */
            status: "error";
            data: {
                code: string;
                message: string;
                retryable: boolean;
                /** Format: uri */
                navigation_uri?: string;
                /** @enum {unknown} */
                responsible_role?: "maintainer" | "approver" | "administrator" | "none";
                retry_after_seconds?: number;
            };
        });
    };
    responses: never;
    parameters: never;
    requestBodies: never;
    headers: never;
    pathItems: never;
}
export type $defs = Record<string, never>;
export type operations = Record<string, never>;
