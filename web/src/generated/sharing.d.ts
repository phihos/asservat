// Generated from canonical browser OpenAPI. Run npm run generate; do not edit.
export type paths = Record<string, never>;
export type webhooks = Record<string, never>;
export interface components {
    schemas: {
        Contract_common_9530994123d918d4: {
            /** Format: uuid */
            artifactID: string;
            digest: string;
        };
        Contract_common_0e44f1278c675a38: {
            /** @enum {string} */
            kind: "User" | "Group";
            /** Format: uri */
            issuer: string;
            id: string;
        };
        Contract_management_0d504ecd6bc8c0fd: {
            /** @constant */
            mode: "creator";
        } | {
            /** @constant */
            mode: "teams";
            teams: {
                /** @constant */
                kind: "Group";
                /** Format: uri */
                issuer: string;
                id: string;
            }[];
        };
        McpInput_create_share: {
            /** Format: uuid */
            case_id: string;
            artifacts: components["schemas"]["Contract_common_9530994123d918d4"][];
            recipients: components["schemas"]["Contract_common_0e44f1278c675a38"][];
            data_classes: ("metadata" | "extract" | "raw")[];
            operations: string[];
            /** Format: date-time */
            expires_at: string;
            reason: string;
            idempotency_key: string;
            management?: components["schemas"]["Contract_management_0d504ecd6bc8c0fd"];
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
        McpOutput_create_share: components["schemas"]["Contract_mcp_result"] & ({
            /** @constant */
            status: "ok";
            data: {
                /** Format: uuid */
                share_id: string;
                /** @enum {string} */
                phase: "Active" | "PendingApproval";
                /** Format: uri */
                navigation_uri?: string;
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
        McpInput_list_shares: {
            cursor?: string;
            limit?: number;
            /** @enum {string} */
            view: "owned" | "received" | "administration";
            /** @default false */
            include_intents: boolean;
        } & unknown;
        /** Format: uuid */
        Contract_common_2224a31324a0c811: string;
        /** Format: date-time */
        Contract_common_f06a67a70a2b97a5: string;
        McpOutput_list_shares: components["schemas"]["Contract_mcp_result"] & ({
            /** @constant */
            status: "ok";
            data: {
                shares: {
                    /** Format: uuid */
                    share_id: string;
                    /** Format: uuid */
                    case_id: string;
                    /** Format: uuid */
                    artifact_id?: string;
                    phase: string;
                    /** Format: date-time */
                    expires_at: string;
                    revision?: number;
                    created_by?: components["schemas"]["Contract_common_0e44f1278c675a38"];
                    managed_by?: components["schemas"]["Contract_common_0e44f1278c675a38"][];
                    origin?: {
                        sharingIntentID: components["schemas"]["Contract_common_2224a31324a0c811"];
                        captureUID: string;
                        selectionID: string;
                    };
                }[];
                intents?: {
                    sharing_intent_id: components["schemas"]["Contract_common_2224a31324a0c811"];
                    /** @enum {unknown} */
                    source_kind: "DebugCapture" | "DebugPolicy";
                    /** @enum {unknown} */
                    phase: "PendingApproval" | "Active" | "Draining" | "Completed" | "Suspended" | "Revoked" | "Expired" | "Denied";
                    expires_at: components["schemas"]["Contract_common_f06a67a70a2b97a5"];
                    registered_captures: number;
                    max_captures: number;
                }[];
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
        McpInput_revoke_share: {
            /** Format: uuid */
            share_id?: string;
            expected_revision: number;
            idempotency_key: string;
            sharing_intent_id?: components["schemas"]["Contract_common_2224a31324a0c811"];
        } & (unknown | unknown);
        McpOutput_revoke_share: components["schemas"]["Contract_mcp_result"] & ({
            /** @constant */
            status: "ok";
            data: {
                /** Format: uuid */
                share_id?: string;
                /** @constant */
                phase: "Revoked";
                revision: number;
                sharing_intent_id?: components["schemas"]["Contract_common_2224a31324a0c811"];
            } & (unknown | unknown);
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
        McpInput_transfer_share: {
            /** Format: uuid */
            share_id?: string;
            expected_revision: number;
            idempotency_key: string;
            sharing_intent_id?: components["schemas"]["Contract_common_2224a31324a0c811"];
            management: components["schemas"]["Contract_management_0d504ecd6bc8c0fd"];
        } & (unknown | unknown);
        McpOutput_transfer_share: components["schemas"]["Contract_mcp_result"] & ({
            /** @constant */
            status: "ok";
            data: {
                /** Format: uuid */
                share_id?: string;
                /** @enum {string} */
                phase: "Active" | "Suspended";
                revision: number;
                sharing_intent_id?: components["schemas"]["Contract_common_2224a31324a0c811"];
                managed_by: components["schemas"]["Contract_common_0e44f1278c675a38"][];
            } & (unknown | unknown);
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
        McpInput_stop_future_sharing: {
            sharing_intent_id: components["schemas"]["Contract_common_2224a31324a0c811"];
            expected_revision: number;
            idempotency_key: string;
        };
        McpOutput_stop_future_sharing: components["schemas"]["Contract_mcp_result"] & ({
            /** @constant */
            status: "ok";
            data: {
                sharing_intent_id: components["schemas"]["Contract_common_2224a31324a0c811"];
                /** @constant */
                state: "Stopped";
                revision: number;
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
