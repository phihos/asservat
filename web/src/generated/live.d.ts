// Generated from canonical browser OpenAPI. Run npm run generate; do not edit.
export type paths = Record<string, never>;
export type webhooks = Record<string, never>;
export interface components {
    schemas: {
        McpInput_list_recordings: {
            /** @description Policy name in the target namespace. */
            policy?: string;
            cursor?: string;
            limit?: number;
            target_ref: {
                /** @description Cluster name as configured in the hub (ADR-335 D4). */
                cluster: string;
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
        Contract_recording_save_5bb857fd69a5246d: {
            /** @constant */
            kind: "recordingPage";
            recordings: components["schemas"]["Contract_recording_save_29c99fc9ff508a4c"][];
            capture_enabled: boolean;
            /** Format: date-time */
            expires_at: string;
        };
        Contract_recording_save_29c99fc9ff508a4c: {
            /** @description Opaque, principal-bound handle for preview_capture(recording_handles) and watch_live(action=open, source_handles). */
            recording_handle: string;
            /** @enum {unknown} */
            owner_kind: "policy" | "manualSession";
            policy_name?: string;
            /**
             * Format: uuid
             * @description Manual-session source: the capture that owns it.
             */
            capture_id?: string;
            pod_name: string;
            action_id: string;
            /** @enum {unknown} */
            kind: "packetCapture" | "syscallTrace";
            /**
             * @description Shared source states (REQ-LIF-002).
             * @enum {unknown}
             */
            state: "Unavailable" | "Warming" | "Ready" | "Degraded" | "Stopped";
            /** @enum {unknown} */
            history: "Unknown" | "Full" | "Partial" | "None";
            maximum_before: components["schemas"]["Contract_common_76a8fd22c9ccd9dc"] | "0s";
            save_eligible: boolean;
            /** @enum {unknown} */
            save_via: "recordingSave" | "captureOutcome" | "unavailable";
            /** @description Live projections watch_live can open on this source; empty when live viewing is unavailable. */
            live_projections: components["schemas"]["Contract_live_watch_990f10221e26ab35"][];
            /** @description Actionable blocker codes, for example NotSaveEnabled, LiveViewDisabled or SourceStopped. */
            blockers: string[];
            incident_pod_cap: number;
            available_before_seconds?: number;
            /** Format: date-time */
            observed_at?: string;
            /**
             * Format: date-time
             * @description Source hard end; watches and saves end by then.
             */
            hard_end?: string;
            execution_authority?: components["schemas"]["Contract_policy_authority_12c1bf2df01fe57b"];
            /** @description Provenance only. */
            policy_uid?: string;
            /** @description Provenance only. */
            pod_uid?: string;
        } & (unknown & unknown);
        Contract_common_76a8fd22c9ccd9dc: string;
        /** @enum {unknown} */
        Contract_live_watch_990f10221e26ab35: "packetMetadata" | "httpHeaders" | "syscallMetadata";
        Contract_policy_authority_12c1bf2df01fe57b: {
            /** @constant */
            mode: "team";
            executor: components["schemas"]["Contract_common_864d4ca41d092930"];
            /** @constant */
            continuesAfterCreatorLeaves: true;
            notAfter: components["schemas"]["Contract_common_f06a67a70a2b97a5"];
            limits: {
                maxExecutions: number;
                maxBytes: number;
                maxObservedBytes: number;
                maxObservedEvents?: number;
            };
            /** @enum {unknown} */
            state: "Ready" | "DelegationRequired" | "Revoked" | "Expired" | "OwnerAssignmentChanged" | "ReapprovalRequired" | "Unavailable";
            reasonCodes: string[];
            ownerTeams: {
                /** @constant */
                kind: "Group";
                /** Format: uri */
                issuer: string;
                id: string;
            }[];
        };
        Contract_common_864d4ca41d092930: {
            /** Format: uri */
            issuer: string;
            subject: string;
            clientID: string;
            /** @enum {string} */
            identityType: "human" | "workload";
        };
        /** Format: date-time */
        Contract_common_f06a67a70a2b97a5: string;
        McpOutput_list_recordings: components["schemas"]["Contract_mcp_result"] & ({
            /** @constant */
            status: "ok";
            data: components["schemas"]["Contract_recording_save_5bb857fd69a5246d"];
            /** @constant */
            data_class?: "metadata";
        } | {
            /** @constant */
            status: "pending";
            data: {
                query_handle: string;
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
        McpInput_watch_live: {
            /**
             * @description Selects the action; each value has its own strict argument set.
             * @enum {unknown}
             */
            action: "open" | "read" | "update" | "close";
            /** @description recording_handle values from list_recordings rows that support the projection. */
            source_handles?: string[];
            projection?: components["schemas"]["Contract_live_watch_990f10221e26ab35"];
            display_filter?: components["schemas"]["Contract_live_watch_4ab053de92dad64a"];
            idempotency_key?: string;
            /** Format: uuid */
            watch_id?: string;
            cursor?: string;
            limit?: number;
            wait_ms?: number;
            expected_revision?: number;
            /** @enum {unknown} */
            mode?: "Active" | "Paused";
        } & (unknown & unknown & unknown & unknown);
        Contract_live_watch_c46c0af02e1cfc16: {
            /** Format: uuid */
            watch_id: string;
            revision: number;
            /** @enum {unknown} */
            state: "Active" | "Paused" | "Closed" | "Expired" | "SourceEnded" | "AccessLost" | "Disconnected";
            source_session_ids: string[];
            projection: components["schemas"]["Contract_live_watch_990f10221e26ab35"];
            /** Format: date-time */
            accepted_at: string;
            /**
             * Format: date-time
             * @description The watch closes if no read arrives and no browser stream is connected by then; every read or connected stream moves it to now + 10 minutes. There is no other lifetime limit; the source's hard end still ends the watch.
             */
            idle_expires_at: string;
            limits: components["schemas"]["Contract_live_watch_118dfa56ea0142d0"];
            cursor: string | null;
            handling: components["schemas"]["Contract_live_watch_06bb407a0e6104d6"];
            /**
             * Format: date-time
             * @description Earliest hard end of the selected sources; the watch ends then.
             */
            source_hard_end?: string;
        };
        /** @description Shipped defaults that administrators may only narrow (REQ-LIV-004); no lifetime or total output limit. */
        Contract_live_watch_118dfa56ea0142d0: {
            /** @description Per-watch rate; default derived from connector bandwidth and the hub-api memory request ÷ concurrent watches. */
            bytes_per_second: number;
            max_rows_per_batch: number;
            /** @description Per-watch transient buffer; bounds replay and rows awaiting a read. */
            max_buffer_bytes: number;
            replay_seconds: number;
        };
        Contract_live_watch_06bb407a0e6104d6: {
            /** @constant */
            transient: true;
            /** @constant */
            may_contain_user_data: true;
            /** @constant */
            raw_available_live: false;
            /** @constant */
            external_copies_recallable: false;
            /** @constant */
            save_semantics: "freshCurrentWindow";
        };
        Contract_live_watch_e8308e53a77c994b: {
            /** Format: uuid */
            watch_id: string;
            revision: number;
            /** Format: uuid */
            batch_id: string;
            /** @enum {unknown} */
            state: "Active" | "Paused" | "Closed" | "Expired" | "SourceEnded" | "AccessLost" | "Disconnected";
            rows: components["schemas"]["Contract_live_watch_ff90f488760c877d"][];
            sources: components["schemas"]["Contract_live_watch_36ae48d944b9a767"][];
            gaps: components["schemas"]["Contract_live_watch_7016c6981d9b8d01"][];
            /** Format: date-time */
            interval_from: string;
            /** Format: date-time */
            interval_until: string;
            /** Format: date-time */
            received_at: string;
            /** @description Aggregate bytes delivered so far; accounting only, not a cap. */
            output_bytes_spent: number;
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
            /**
             * Format: date-time
             * @description Source/content privacy deadline. Managed views clear the row by then or at watch close.
             */
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
            /**
             * Format: date-time
             * @description Source/content privacy deadline. Managed views clear the row by then or at watch close.
             */
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
            /**
             * Format: date-time
             * @description Source/content privacy deadline. Managed views clear the row by then or at watch close.
             */
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
        McpOutput_watch_live: components["schemas"]["Contract_mcp_result"] & ({
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
        } | {
            /** @constant */
            status: "ok";
            data: components["schemas"]["Contract_live_watch_e8308e53a77c994b"];
            /** @constant */
            data_class?: "extract";
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
