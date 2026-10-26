// Generated from canonical browser OpenAPI. Run npm run generate; do not edit.
export type paths = Record<string, never>;
export type webhooks = Record<string, never>;
export interface components {
    schemas: {
        McpInput_activate_policy: {
            policy_name: string;
            idempotency_key: string;
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
                    restarts: number;
                    /** Format: date-time */
                    created_at: string;
                }[];
                suppressions: {
                    /** @enum {unknown} */
                    reason: "cooldown" | "budget" | "coalesced" | "capacity" | "authority" | "unavailable";
                    count: number;
                    /** Format: date-time */
                    first_at: string;
                    /** Format: date-time */
                    last_at: string;
                }[];
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
