// Generated from canonical browser OpenAPI. Run npm run generate; do not edit.
export type paths = Record<string, never>;
export type webhooks = Record<string, never>;
export interface components {
    schemas: {
        McpInput_request_policy_grant: {
            policy_uid: string;
            idempotency_key: string;
            lifetime_seconds?: number;
            limits: {
                max_executions: number;
                max_collected_bytes: number;
                max_observed_bytes: number;
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
                /** Format: uuid */
                preview_id?: string;
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
                    code: "rawBytePredicate" | "recordingApprovalRequired";
                }[];
                observation_limits?: {
                    max_session_seconds: number;
                    max_observed_bytes: number;
                    max_bytes_per_second: number;
                    max_concurrent_sessions: number;
                };
                requested_by: {
                    issuer: string;
                    subject: string;
                    client_id: string;
                };
                /** Format: date-time */
                requested_at: string;
                /** Format: date-time */
                review_until: string;
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
                actions: {
                    action_id: string;
                    /** @enum {unknown} */
                    kind: "packetCapture" | "syscallTrace";
                    /** @enum {unknown} */
                    execution_mode: "ongoing" | "onTrigger";
                    before: string;
                    after: string;
                    filter?: string;
                    filter_digest?: string;
                    filter_instructions?: number;
                    max_bytes: number;
                    ring_max_bytes: number;
                    ring_max_age: string;
                    sensitive: ("rawBytePredicate" | "recordingApprovalRequired")[];
                }[];
                result_access?: {
                    action_ids: string[];
                    operations: "download_artifact"[];
                    client_ids: string[];
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
                /** @description Advisory original requester/client may recover a possibly accepted request after an approved decision. Never offered for pending or denied review; a missing acceptance closes the original intent. */
                can_resolve: boolean;
                /** @description Guidance only for the same requesting human on another OAuth client while this marked plan is Approved. It confers no authority or grant transfer. */
                resume_requires_original_client: boolean;
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
                };
            } & (unknown & unknown & unknown);
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
        McpInput_get_grant: {
            /** Format: uuid */
            grant_id: string;
        };
        McpOutput_get_grant: components["schemas"]["Contract_mcp_result"] & ({
            /** @constant */
            status: "ok";
            data: {
                /** Format: uuid */
                grant_id: string;
                /** @enum {unknown} */
                phase: "Pending" | "Approved" | "Denied" | "Revoked" | "Expired" | "Exhausted";
                revision: number;
                /** @enum {unknown} */
                kind: "adHocCapture" | "policy";
                /** Format: uuid */
                capture_id?: string;
                /** Format: uuid */
                preview_id?: string;
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
                    code: "rawBytePredicate" | "recordingApprovalRequired";
                }[];
                observation_limits?: {
                    max_session_seconds: number;
                    max_observed_bytes: number;
                    max_bytes_per_second: number;
                    max_concurrent_sessions: number;
                };
                requested_by: {
                    issuer: string;
                    subject: string;
                    client_id: string;
                };
                /** Format: date-time */
                requested_at: string;
                /** Format: date-time */
                review_until: string;
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
                actions: {
                    action_id: string;
                    /** @enum {unknown} */
                    kind: "packetCapture" | "syscallTrace";
                    /** @enum {unknown} */
                    execution_mode: "ongoing" | "onTrigger";
                    before: string;
                    after: string;
                    filter?: string;
                    filter_digest?: string;
                    filter_instructions?: number;
                    max_bytes: number;
                    ring_max_bytes: number;
                    ring_max_age: string;
                    sensitive: ("rawBytePredicate" | "recordingApprovalRequired")[];
                }[];
                result_access?: {
                    action_ids: string[];
                    operations: "download_artifact"[];
                    client_ids: string[];
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
                /** @description Advisory original requester/client may recover a possibly accepted request after an approved decision. Never offered for pending or denied review; a missing acceptance closes the original intent. */
                can_resolve: boolean;
                /** @description Guidance only for the same requesting human on another OAuth client while this marked plan is Approved. It confers no authority or grant transfer. */
                resume_requires_original_client: boolean;
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
                };
            } & (unknown & unknown & unknown);
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
        McpInput_list_reviews: {
            /** @enum {unknown} */
            view: "pending" | "requested";
            limit?: number;
        };
        McpOutput_list_reviews: components["schemas"]["Contract_mcp_result"] & ({
            /** @constant */
            status: "ok";
            data: {
                approvals: ({
                    /** Format: uuid */
                    grant_id: string;
                    /** @enum {unknown} */
                    phase: "Pending" | "Approved" | "Denied" | "Revoked" | "Expired" | "Exhausted";
                    revision: number;
                    /** @enum {unknown} */
                    kind: "adHocCapture" | "policy";
                    /** Format: uuid */
                    capture_id?: string;
                    /** Format: uuid */
                    preview_id?: string;
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
                        code: "rawBytePredicate" | "recordingApprovalRequired";
                    }[];
                    observation_limits?: {
                        max_session_seconds: number;
                        max_observed_bytes: number;
                        max_bytes_per_second: number;
                        max_concurrent_sessions: number;
                    };
                    requested_by: {
                        issuer: string;
                        subject: string;
                        client_id: string;
                    };
                    /** Format: date-time */
                    requested_at: string;
                    /** Format: date-time */
                    review_until: string;
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
                    };
                } & (unknown & unknown & unknown))[];
            };
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
        McpInput_decide_review: {
            /** Format: uuid */
            grant_id: string;
            /** @enum {unknown} */
            decision: "approve" | "deny";
            reason: string;
            idempotency_key: string;
        };
        McpOutput_decide_review: components["schemas"]["Contract_mcp_result"] & ({
            /** @constant */
            status: "ok";
            data: {
                /** Format: uuid */
                grant_id: string;
                /** @enum {unknown} */
                phase: "Approved" | "Denied" | "Expired";
                revision: number;
                /** Format: date-time */
                not_after?: string;
            };
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
        McpInput_revoke_grant: {
            /** Format: uuid */
            grant_id: string;
            expected_revision: number;
            idempotency_key: string;
        };
        McpOutput_revoke_grant: components["schemas"]["Contract_mcp_result"] & ({
            /** @constant */
            status: "ok";
            data: {
                /** Format: uuid */
                grant_id: string;
                /** @constant */
                phase: "Revoked";
                revision: number;
            };
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
