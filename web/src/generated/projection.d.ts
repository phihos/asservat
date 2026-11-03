// Generated from canonical browser OpenAPI. Run npm run generate; do not edit.
export type paths = Record<string, never>;
export type webhooks = Record<string, never>;
export interface components {
    schemas: {
        McpInput_get_file_excerpt: {
            /** Format: uuid */
            case_id: string;
            /** Format: uuid */
            artifact_id: string;
            line_start?: number;
            max_lines?: number;
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
        McpOutput_get_file_excerpt: components["schemas"]["Contract_mcp_result"] & ({
            /** @constant */
            status: "ok";
            data: {
                logical_path: string;
                line_start: number;
                lines: string[];
                /**
                 * Format: date-time
                 * @description Server time of this prepared query snapshot. This observation does not renew query or request authority. Together with query_expires_at it bounds managed-view lifetime independently of the client wall clock.
                 */
                query_observed_at: string;
                /**
                 * Format: date-time
                 * @description Original total query cutoff, irreversibly shortened by effective evidence access. A poll never extends it. Managed views clear by this cutoff or earlier on scope loss or closure; this cannot recall external copies. Distinct from the current request disclosure deadline.
                 */
                query_expires_at: string;
            };
        } | {
            /** @constant */
            status: "pending";
            data: {
                query_handle: string;
                retry_after_seconds: number;
                /**
                 * Format: date-time
                 * @description Server time of this prepared query snapshot. This observation does not renew query or request authority. Together with query_expires_at it bounds managed-view lifetime independently of the client wall clock.
                 */
                query_observed_at: string;
                /**
                 * Format: date-time
                 * @description Original total query cutoff, irreversibly shortened by effective evidence access. A poll never extends it. Managed views clear by this cutoff or earlier on scope loss or closure; this cannot recall external copies. Distinct from the current request disclosure deadline.
                 */
                query_expires_at: string;
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
        McpInput_get_profile_summary: {
            /** Format: uuid */
            case_id: string;
            /** Format: uuid */
            artifact_id: string;
            sample_type: string;
            top_n?: number;
        };
        McpOutput_get_profile_summary: components["schemas"]["Contract_mcp_result"] & ({
            /** @constant */
            status: "ok";
            data: {
                sample_type: string;
                unit: string;
                duration_seconds: number | null;
                total: number;
                top: {
                    function: string | null;
                    flat: number;
                    cumulative: number;
                    /** @description Flat divided by total for nonnegative samples with positive total; null for signed delta samples or a zero total. */
                    fraction: number | null;
                }[];
                /** @enum {string} */
                symbol_status: "complete" | "partial" | "missing";
                /**
                 * Format: date-time
                 * @description Server time of this prepared query snapshot. This observation does not renew query or request authority. Together with query_expires_at it bounds managed-view lifetime independently of the client wall clock.
                 */
                query_observed_at: string;
                /**
                 * Format: date-time
                 * @description Original total query cutoff, irreversibly shortened by effective evidence access. A poll never extends it. Managed views clear by this cutoff or earlier on scope loss or closure; this cannot recall external copies. Distinct from the current request disclosure deadline.
                 */
                query_expires_at: string;
            };
        } | {
            /** @constant */
            status: "pending";
            data: {
                query_handle: string;
                retry_after_seconds: number;
                /**
                 * Format: date-time
                 * @description Server time of this prepared query snapshot. This observation does not renew query or request authority. Together with query_expires_at it bounds managed-view lifetime independently of the client wall clock.
                 */
                query_observed_at: string;
                /**
                 * Format: date-time
                 * @description Original total query cutoff, irreversibly shortened by effective evidence access. A poll never extends it. Managed views clear by this cutoff or earlier on scope loss or closure; this cannot recall external copies. Distinct from the current request disclosure deadline.
                 */
                query_expires_at: string;
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
        McpInput_compare_profiles: {
            /** Format: uuid */
            case_id: string;
            /** Format: uuid */
            artifact_id: string;
            /** Format: uuid */
            baseline_case_id: string;
            /** Format: uuid */
            baseline_artifact_id: string;
            sample_type: string;
            /** @enum {string} */
            normalization: "none" | "perSecond";
            top_n?: number;
        };
        McpOutput_compare_profiles: components["schemas"]["Contract_mcp_result"] & ({
            /** @constant */
            status: "ok";
            data: {
                sample_type: string;
                unit: string;
                /** @enum {string} */
                normalization: "none" | "perSecond";
                /** @constant */
                comparable: true;
                rows: {
                    function: string | null;
                    baseline: number;
                    incident: number;
                    delta: number;
                }[];
                limitations: string[];
                /** @constant */
                aggregation: "cumulative";
                /** Format: uuid */
                case_id: string;
                /** Format: uuid */
                artifact_id: string;
                /** Format: uuid */
                baseline_case_id: string;
                /** Format: uuid */
                baseline_artifact_id: string;
                source_version: string;
                baseline_source_version: string;
                baseline: {
                    /** @enum {unknown} */
                    profile_type: "cpu" | "heap" | "allocs" | "goroutine" | "block" | "mutex" | "threadcreate";
                    /** @enum {unknown} */
                    mode: "snapshot" | "cumulative" | "delta" | "interval";
                    force_gc: boolean;
                    duration_seconds: number | null;
                    total: number;
                    period: {
                        type: string;
                        unit: string;
                        value: number;
                    } | null;
                    /** @enum {unknown} */
                    symbol_status: "complete" | "partial" | "missing";
                } & (unknown & unknown & unknown & unknown);
                incident: {
                    /** @enum {unknown} */
                    profile_type: "cpu" | "heap" | "allocs" | "goroutine" | "block" | "mutex" | "threadcreate";
                    /** @enum {unknown} */
                    mode: "snapshot" | "cumulative" | "delta" | "interval";
                    force_gc: boolean;
                    duration_seconds: number | null;
                    total: number;
                    period: {
                        type: string;
                        unit: string;
                        value: number;
                    } | null;
                    /** @enum {unknown} */
                    symbol_status: "complete" | "partial" | "missing";
                } & (unknown & unknown & unknown & unknown);
                /** @enum {unknown} */
                build_status: "same" | "different" | "unknown";
                /** @enum {unknown} */
                sampling_status: "same" | "different" | "unknown";
                /** @enum {unknown} */
                acquisition_status: "same" | "different";
                /**
                 * Format: date-time
                 * @description Server time of this prepared query snapshot. This observation does not renew query or request authority. Together with query_expires_at it bounds managed-view lifetime independently of the client wall clock.
                 */
                query_observed_at: string;
                /**
                 * Format: date-time
                 * @description Original total query cutoff, irreversibly shortened by effective evidence access. A poll never extends it. Managed views clear by this cutoff or earlier on scope loss or closure; this cannot recall external copies. Distinct from the current request disclosure deadline.
                 */
                query_expires_at: string;
            } & unknown;
            /** @constant */
            data_class?: "extract";
            provenance?: unknown[];
        } | {
            /** @constant */
            status: "pending";
            data: {
                query_handle: string;
                retry_after_seconds: number;
                /**
                 * Format: date-time
                 * @description Server time of this prepared query snapshot. This observation does not renew query or request authority. Together with query_expires_at it bounds managed-view lifetime independently of the client wall clock.
                 */
                query_observed_at: string;
                /**
                 * Format: date-time
                 * @description Original total query cutoff, irreversibly shortened by effective evidence access. A poll never extends it. Managed views clear by this cutoff or earlier on scope loss or closure; this cannot recall external copies. Distinct from the current request disclosure deadline.
                 */
                query_expires_at: string;
            };
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
            /** @constant */
            data_class?: "metadata";
        });
        McpInput_get_syscall_summary: {
            /** Format: uuid */
            case_id: string;
            /** Format: uuid */
            artifact_id: string;
            cursor?: string;
            limit?: number;
        };
        Contract_syscall_results_12c1bf2df01fe57b: {
            /** @constant */
            kind: "syscallSummary";
            rows: {
                syscall: string;
                count: number;
                errors: number;
                paired_count: number;
                total_duration_ns: number;
            }[];
            coverage: components["schemas"]["Contract_syscall_results_554f1345ab0637f1"];
            /**
             * Format: date-time
             * @description Server time of this prepared query snapshot. This observation does not renew query or request authority. Together with query_expires_at it bounds managed-view lifetime independently of the client wall clock.
             */
            query_observed_at?: string;
            /**
             * Format: date-time
             * @description Original total query cutoff, irreversibly shortened by effective evidence access. A poll never extends it. Managed views clear by this cutoff or earlier on scope loss or closure; this cannot recall external copies. Distinct from the current request disclosure deadline.
             */
            query_expires_at?: string;
        };
        Contract_syscall_results_554f1345ab0637f1: {
            dropped_events: number | null;
            unmatched_events: number;
            /** @description Whether acquisition output was truncated, when independently known; null means the retained source does not establish it. Pagination does not imply acquisition truncation. */
            truncated: boolean | null;
            gaps: string[];
            record_count?: number;
            unfinished_events?: number;
            unknown_events?: number;
        };
        McpOutput_get_syscall_summary: components["schemas"]["Contract_mcp_result"] & ({
            /** @constant */
            status: "ok";
            data: components["schemas"]["Contract_syscall_results_12c1bf2df01fe57b"];
            /** @constant */
            data_class?: "extract";
        } | {
            /** @constant */
            status: "pending";
            data: {
                query_handle: string;
                retry_after_seconds: number;
                /**
                 * Format: date-time
                 * @description Server time of this prepared query snapshot. This observation does not renew query or request authority. Together with query_expires_at it bounds managed-view lifetime independently of the client wall clock.
                 */
                query_observed_at?: string;
                /**
                 * Format: date-time
                 * @description Original total query cutoff, irreversibly shortened by effective evidence access. A poll never extends it. Managed views clear by this cutoff or earlier on scope loss or closure; this cannot recall external copies. Distinct from the current request disclosure deadline.
                 */
                query_expires_at?: string;
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
        McpInput_get_syscall_events: {
            /** Format: uuid */
            case_id: string;
            /** Format: uuid */
            artifact_id: string;
            cursor?: string;
            limit?: number;
            syscall_names?: string[];
            errors_only?: boolean;
        };
        Contract_syscall_results_64217b49b5760651: {
            /** @constant */
            kind: "syscallEvents";
            events: components["schemas"]["Contract_syscall_results_bc4d9514f0534d0a"][];
            coverage: components["schemas"]["Contract_syscall_results_554f1345ab0637f1"];
            /**
             * Format: date-time
             * @description Server time of this prepared query snapshot. This observation does not renew query or request authority. Together with query_expires_at it bounds managed-view lifetime independently of the client wall clock.
             */
            query_observed_at?: string;
            /**
             * Format: date-time
             * @description Original total query cutoff, irreversibly shortened by effective evidence access. A poll never extends it. Managed views clear by this cutoff or earlier on scope loss or closure; this cannot recall external copies. Distinct from the current request disclosure deadline.
             */
            query_expires_at?: string;
        };
        Contract_syscall_results_bc4d9514f0534d0a: {
            identity: {
                process_ref: string;
                thread_ref: string;
                pod_uid: string;
            };
            syscall: string;
            abi: string;
            /** Format: date-time */
            timestamp: string;
            duration_ns?: number;
            /** @enum {unknown} */
            outcome: "success" | "error" | "unfinished" | "unmatched" | "unknown";
            errno?: string;
        } & (unknown & unknown);
        McpOutput_get_syscall_events: components["schemas"]["Contract_mcp_result"] & ({
            /** @constant */
            status: "ok";
            data: components["schemas"]["Contract_syscall_results_64217b49b5760651"];
            /** @constant */
            data_class?: "extract";
        } | {
            /** @constant */
            status: "pending";
            data: {
                query_handle: string;
                retry_after_seconds: number;
                /**
                 * Format: date-time
                 * @description Server time of this prepared query snapshot. This observation does not renew query or request authority. Together with query_expires_at it bounds managed-view lifetime independently of the client wall clock.
                 */
                query_observed_at?: string;
                /**
                 * Format: date-time
                 * @description Original total query cutoff, irreversibly shortened by effective evidence access. A poll never extends it. Managed views clear by this cutoff or earlier on scope loss or closure; this cannot recall external copies. Distinct from the current request disclosure deadline.
                 */
                query_expires_at?: string;
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
        McpInput_get_query_result: {
            query_handle: string;
        };
        McpOutput_get_query_result: components["schemas"]["Contract_mcp_result"] & ({
            /** @constant */
            status: "ok";
            data: {
                query_handle: string;
                tool_name: string;
                result: Record<string, unknown>;
                /**
                 * Format: date-time
                 * @description Server time of this prepared query snapshot. This observation does not renew query or request authority. Together with query_expires_at it bounds managed-view lifetime independently of the client wall clock.
                 */
                query_observed_at: string;
                /**
                 * Format: date-time
                 * @description Original total query cutoff, irreversibly shortened by effective evidence access. A poll never extends it. Managed views clear by this cutoff or earlier on scope loss or closure; this cannot recall external copies. Distinct from the current request disclosure deadline.
                 */
                query_expires_at: string;
            };
        } | {
            /** @constant */
            status: "pending";
            data: {
                query_handle: string;
                retry_after_seconds: number;
                /**
                 * Format: date-time
                 * @description Server time of this prepared query snapshot. This observation does not renew query or request authority. Together with query_expires_at it bounds managed-view lifetime independently of the client wall clock.
                 */
                query_observed_at: string;
                /**
                 * Format: date-time
                 * @description Original total query cutoff, irreversibly shortened by effective evidence access. A poll never extends it. Managed views clear by this cutoff or earlier on scope loss or closure; this cannot recall external copies. Distinct from the current request disclosure deadline.
                 */
                query_expires_at: string;
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
