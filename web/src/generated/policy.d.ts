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
        McpInput_deactivate_policy: {
            policy_name: string;
            idempotency_key: string;
        };
        McpOutput_deactivate_policy: components["schemas"]["Contract_mcp_result"] & ({
            /** @constant */
            status: "ok";
            data: {
                policy_uid: string;
                /** Format: uuid */
                acceptance_id: string;
                /** @constant */
                state: "deactivated";
                replay: boolean;
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
        McpInput_get_policy_status: {
            policy_name: string;
        };
        McpOutput_get_policy_status: components["schemas"]["Contract_mcp_result"] & ({
            /** @constant */
            status: "ok";
            data: {
                policy_uid: string;
                /** Format: uuid */
                acceptance_id: string;
                /** @enum {unknown} */
                state: "active" | "deactivated" | "suspended" | "changed" | "expired" | "deleted";
                generation: number;
                /** Format: date-time */
                expires_at: string;
                executor: {
                    /** @constant */
                    kind: "policy";
                    policy_uid: string;
                };
                executions_spent: number;
                max_executions: number;
                watched_pods: number;
                occurrences: number;
                captured: number;
                recent: {
                    /** Format: uuid */
                    occurrence_id: string;
                    /** Format: uuid */
                    capture_id?: string;
                    /** @enum {unknown} */
                    outcome: "captured" | "refused" | "pending";
                    restarts?: number;
                    /** Format: date-time */
                    created_at: string;
                    /** @enum {unknown} */
                    detector: "exit" | "probe" | "alert" | "log" | "resource";
                    /** Format: date-time */
                    failed_at?: string;
                }[];
                suppressions: {
                    /** @enum {unknown} */
                    reason: "cooldown" | "budget" | "coalesced" | "capacity" | "authority" | "unavailable" | "overlong";
                    count: number;
                    /** Format: date-time */
                    first_at: string;
                    /** Format: date-time */
                    last_at: string;
                }[];
                /** @description The current DebugPolicy's detector configuration (no observed content). */
                detector?: {
                    /** @enum {unknown} */
                    kind: "exit" | "probe" | "alert" | "log" | "resource";
                    reasons?: ("CrashLoopBackOff" | "Error" | "OOMKilled")[];
                    exit_codes?: number[];
                    /** @enum {unknown} */
                    probe_type?: "Liveness" | "Readiness" | "Startup";
                    minimum_failures?: number;
                    window_seconds?: number;
                    /** @enum {unknown} */
                    match?: "literal" | "regexp";
                    json_field?: boolean;
                    /** @enum {unknown} */
                    metric?: "cpuCores" | "cpuQuotaRatio" | "memoryBytes" | "memoryLimitRatio";
                    /** @enum {unknown} */
                    operator?: "gt" | "gte" | "lt" | "lte";
                    threshold?: number;
                    sample_interval_seconds?: number;
                };
                /** @description Recurring sharing of the acceptance (ADR-239). stopped: a manager stopped future sharing (stop_future_sharing; already claimed captures still publish); policyChanged: the DebugPolicy changed after acceptance, activate the new revision to share again. Existing shares stay until they expire or are revoked (revoke_share with sharing_intent_id = acceptance_id and expected_revision = revision). */
                sharing?: {
                    /** @enum {unknown} */
                    state: "active" | "limitReached" | "expired" | "stopped" | "policyChanged" | "revoked";
                    recipients: number;
                    shared_captures: number;
                    max_captures: number;
                    /** Format: date-time */
                    not_after: string;
                    /** Format: date-time */
                    revoked_at?: string;
                    revision: number;
                    /** Format: date-time */
                    stopped_at?: string;
                };
                /** @description Conservative native-output reservations shared by this acceptance; uncertain spend remains charged. Not measured bytes. */
                collected_bytes_spent: number;
                /** @description Original accepted cumulative native-output ceiling, shared across grant replacements and controls. */
                max_collected_bytes: number;
                /** @description Conservative pre-filter observation charges shared by this acceptance, including uncertain legacy spend. Not collected output. */
                observed_bytes_spent: number;
                /** @description Original accepted cumulative pre-filter observation ceiling; zero permits no continuing acquisition. */
                max_observed_bytes: number;
                /**
                 * @description Accepted collection action; controls available approval commands, not acquisition authority.
                 * @enum {unknown}
                 */
                collection_kind: "podStatus" | "packetCapture";
                /**
                 * Format: uuid
                 * @description Grant named by the current attachment pointer; does not assert that its authority, budget or recorder readiness currently permits collection.
                 */
                attached_grant_id?: string;
                /** @description Server-derived ceiling in action-start units for the currently accepted policy grant plan. Policy executions remain a separate once-per-Save counter. */
                max_grant_starts?: number;
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
