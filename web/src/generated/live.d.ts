// Generated from canonical browser OpenAPI. Run npm run generate; do not edit.
export type paths = Record<string, never>;
export type webhooks = Record<string, never>;
export interface components {
    schemas: {
        McpInput_list_live_sources: {
            cursor?: string;
            limit?: number;
            target_ref: {
                /** Format: uuid */
                cluster_id: string;
                namespace: string;
                /** @enum {unknown} */
                kind: "Deployment" | "StatefulSet" | "Pod";
                name: string;
            };
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
        Contract_live_watch_68ed420e6296d3d7: {
            sources: components["schemas"]["Contract_live_watch_0e1fb13609b49454"][];
        };
        Contract_live_watch_0e1fb13609b49454: {
            source_handle: string;
            /** Format: date-time */
            handle_expires_at: string;
            /** Format: uuid */
            source_session_id: string;
            workload_uid: string;
            pod_uid: string;
            action_id: string;
            /** @enum {unknown} */
            owner_kind: "policy" | "manualSession";
            owner_id: string;
            /** @enum {unknown} */
            state: "Warming" | "Ready" | "Degraded" | "Stopped" | "Unavailable";
            projections: components["schemas"]["Contract_live_watch_990f10221e26ab35"][];
            eligible: boolean;
            blocker_codes: string[];
            /** @enum {unknown} */
            save_via: "recordingSave" | "captureOutcome" | "unavailable";
            /** Format: date-time */
            lease_until: string;
        };
        /** @enum {unknown} */
        Contract_live_watch_990f10221e26ab35: "packetMetadata" | "httpHeaders" | "syscallMetadata";
        McpOutput_list_live_sources: components["schemas"]["Contract_mcp_result"] & ({
            /** @constant */
            status: "ok";
            data: components["schemas"]["Contract_live_watch_68ed420e6296d3d7"];
            /** @constant */
            data_class?: "metadata";
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
        Contract_live_watch_4ab053de92dad64a: {
            all: ({
                /** @constant */
                field: "protocol";
                /** @enum {unknown} */
                op: "eq" | "neq";
                value: string;
            } | {
                /** @constant */
                field: "peer_uid";
                /** @enum {unknown} */
                op: "eq" | "neq";
                value: string;
            } | {
                /** @constant */
                field: "method";
                /** @enum {unknown} */
                op: "eq" | "neq";
                value: string;
            } | {
                /** @constant */
                field: "syscall";
                /** @enum {unknown} */
                op: "eq" | "neq";
                value: string;
            } | {
                /** @constant */
                field: "port";
                /** @enum {unknown} */
                op: "eq" | "neq" | "gte" | "lte";
                value: number;
            } | {
                /** @constant */
                field: "status";
                /** @enum {unknown} */
                op: "eq" | "neq" | "gte" | "lte";
                value: number;
            } | {
                /** @constant */
                field: "pid";
                /** @enum {unknown} */
                op: "eq" | "neq" | "gte" | "lte";
                value: number;
            } | {
                /** @constant */
                field: "error";
                /** @enum {unknown} */
                op: "eq";
                value: boolean;
            } | {
                /** @constant */
                field: "remote_ip";
                /** @enum {unknown} */
                op: "eq" | "neq";
                value: string;
            })[];
        };
        McpInput_open_live_watch: {
            source_handles: string[];
            projection: components["schemas"]["Contract_live_watch_990f10221e26ab35"];
            display_filter?: components["schemas"]["Contract_live_watch_4ab053de92dad64a"];
            duration_seconds?: number;
            max_output_bytes?: number;
            idempotency_key: string;
        } & (unknown & unknown & unknown);
        Contract_live_watch_c46c0af02e1cfc16: {
            /** Format: uuid */
            watch_id: string;
            revision: number;
            /** @enum {unknown} */
            state: "Active" | "Paused" | "Closed" | "Expired" | "Exhausted" | "SourceEnded" | "AccessLost" | "Disconnected";
            source_session_ids: string[];
            projection: components["schemas"]["Contract_live_watch_990f10221e26ab35"];
            /** Format: date-time */
            accepted_at: string;
            /** Format: date-time */
            expires_at: string;
            /** Format: date-time */
            idle_expires_at: string;
            limits: components["schemas"]["Contract_live_watch_118dfa56ea0142d0"];
            cursor: string | null;
            handling: components["schemas"]["Contract_live_watch_06bb407a0e6104d6"];
        };
        Contract_live_watch_118dfa56ea0142d0: {
            duration_seconds: number;
            max_output_bytes: number;
            bytes_per_second: number;
            max_rows_per_batch: number;
            max_buffer_bytes: number;
            row_max_age_seconds: number;
            replay_seconds: number;
        };
        Contract_live_watch_06bb407a0e6104d6: {
            /** @constant */
            transient: true;
            /** @constant */
            may_contain_user_data: true;
            managed_row_max_age_seconds: number;
            /** @constant */
            raw_available_live: false;
            /** @constant */
            external_copies_recallable: false;
            /** @constant */
            save_semantics: "freshCurrentWindow";
        };
        McpOutput_open_live_watch: components["schemas"]["Contract_mcp_result"] & ({
            /** @constant */
            status: "ok";
            data: components["schemas"]["Contract_live_watch_c46c0af02e1cfc16"];
            /** @constant */
            data_class?: "metadata";
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
        McpInput_read_live_watch: {
            /** Format: uuid */
            watch_id: string;
            cursor: string;
            limit?: number;
            wait_ms?: number;
        };
        Contract_live_watch_e8308e53a77c994b: {
            /** Format: uuid */
            watch_id: string;
            revision: number;
            /** Format: uuid */
            batch_id: string;
            /** @enum {unknown} */
            state: "Active" | "Paused" | "Closed" | "Expired" | "Exhausted" | "SourceEnded" | "AccessLost" | "Disconnected";
            rows: components["schemas"]["Contract_live_watch_ff90f488760c877d"][];
            sources: components["schemas"]["Contract_live_watch_36ae48d944b9a767"][];
            gaps: components["schemas"]["Contract_live_watch_7016c6981d9b8d01"][];
            /** Format: date-time */
            interval_from: string;
            /** Format: date-time */
            interval_until: string;
            /** Format: date-time */
            received_at: string;
            output_bytes_spent: number;
            retry_after_ms: number;
            handling: components["schemas"]["Contract_live_watch_06bb407a0e6104d6"];
        };
        Contract_live_watch_ff90f488760c877d: {
            row_id: string;
            /** Format: uuid */
            source_session_id: string;
            source_sequence: number;
            /** Format: date-time */
            observed_at: string;
            /** Format: date-time */
            received_at: string;
            /** Format: date-time */
            expires_at: string;
            clock_uncertainty_ms: number;
            filter_generation: number;
            /** @constant */
            projection: "packetMetadata";
            pod_uid: string;
            fields: {
                /** @enum {unknown} */
                protocol: "TCP" | "UDP" | "ICMP" | "Other" | "Unknown";
                peer_uid: string | null;
                remote_ip: string;
                remote_port: number;
                /** @enum {unknown} */
                direction: "ingress" | "egress" | "unknown";
                wire_bytes: number;
                pid: number | null;
            };
        } | {
            row_id: string;
            /** Format: uuid */
            source_session_id: string;
            source_sequence: number;
            /** Format: date-time */
            observed_at: string;
            /** Format: date-time */
            received_at: string;
            /** Format: date-time */
            expires_at: string;
            clock_uncertainty_ms: number;
            filter_generation: number;
            /** @constant */
            projection: "httpHeaders";
            pod_uid: string;
            fields: {
                /** @enum {string} */
                method: "GET" | "HEAD" | "POST" | "PUT" | "DELETE" | "CONNECT" | "OPTIONS" | "TRACE" | "PATCH" | "OTHER";
                status: number | null;
                peer_uid: string | null;
                headers: {
                    /** @enum {string} */
                    name: "content-type" | "content-length";
                    value: string;
                }[];
                /** @enum {unknown} */
                pairing: "request" | "response" | "paired";
                duration_ms: number | null;
            };
        } | {
            row_id: string;
            /** Format: uuid */
            source_session_id: string;
            source_sequence: number;
            /** Format: date-time */
            observed_at: string;
            /** Format: date-time */
            received_at: string;
            /** Format: date-time */
            expires_at: string;
            clock_uncertainty_ms: number;
            filter_generation: number;
            /** @constant */
            projection: "syscallMetadata";
            pod_uid: string;
            fields: {
                pid: number;
                syscall: string;
                error: boolean;
                errno: number | null;
                duration_ns: number | null;
                paired: boolean;
            };
        };
        Contract_live_watch_36ae48d944b9a767: {
            /** Format: uuid */
            source_session_id: string;
            /** @enum {unknown} */
            state: "Warming" | "Ready" | "Degraded" | "Stopped" | "Unavailable";
            filter_generation: number;
            last_observed_at: string | null;
            /** @enum {unknown} */
            coverage: "observed" | "partial" | "unknown";
        };
        Contract_live_watch_7016c6981d9b8d01: {
            /** @enum {unknown} */
            reason: "sensorLoss" | "projectionSampled" | "subscriberOverflow" | "reconnect" | "filterChanged" | "paused" | "sourceEnded" | "clockUncertain" | "sourceUnavailable" | "bufferExpired" | "accessLost" | "unsupportedProtocol" | "filteredOut";
            source_session_id: string | null;
            count: number | null;
            /** Format: date-time */
            from: string;
            /** Format: date-time */
            until: string;
        };
        McpOutput_read_live_watch: components["schemas"]["Contract_mcp_result"] & ({
            /** @constant */
            status: "ok";
            data: components["schemas"]["Contract_live_watch_e8308e53a77c994b"];
            /** @constant */
            data_class?: "extract";
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
        McpInput_update_live_watch: {
            /** Format: uuid */
            watch_id: string;
            expected_revision: number;
            idempotency_key: string;
            /** @enum {unknown} */
            mode?: "Active" | "Paused";
            display_filter?: components["schemas"]["Contract_live_watch_4ab053de92dad64a"];
        } | unknown | unknown;
        McpOutput_update_live_watch: components["schemas"]["Contract_mcp_result"] & ({
            /** @constant */
            status: "ok";
            data: components["schemas"]["Contract_live_watch_c46c0af02e1cfc16"];
            /** @constant */
            data_class?: "metadata";
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
        McpInput_close_live_watch: {
            /** Format: uuid */
            watch_id: string;
            expected_revision: number;
            idempotency_key: string;
        };
        McpOutput_close_live_watch: components["schemas"]["Contract_mcp_result"] & ({
            /** @constant */
            status: "ok";
            data: components["schemas"]["Contract_live_watch_c46c0af02e1cfc16"];
            /** @constant */
            data_class?: "metadata";
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
