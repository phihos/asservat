// Generated from canonical browser OpenAPI. Run npm run generate; do not edit.
export type paths = Record<string, never>;
export type webhooks = Record<string, never>;
export interface components {
    schemas: {
        McpInput_get_extract: {
            /**
             * @description Selects the view; each value has its own strict argument set.
             * @enum {unknown}
             */
            view: "backtrace" | "runtimeSummary" | "profileSummary" | "syscallSummary" | "syscallEvents" | "pcapSummary" | "httpHeaders" | "zeekLog" | "fileExcerpt" | "logs" | "discovery";
            /** Format: uuid */
            case_id?: string;
            /** Format: uuid */
            artifact_id?: string;
            thread_id?: string;
            sample_type?: string;
            cursor?: string;
            limit?: number;
            syscall_names?: string[];
            errors_only?: boolean;
            fields?: string[];
            /** @enum {string} */
            stream?: "conn" | "dns" | "ssl" | "http" | "weird";
            line_start?: number;
            /**
             * Format: uuid
             * @description Optional. Current covering grants are reused automatically; the equivalent Kubernetes right on the workload (pods/exec) also suffices (ADR-335 D5). Name a grant only to select among several.
             */
            grant_id?: string;
            idempotency_key?: string;
            /** Format: uuid */
            capture_id?: string;
            /** @enum {unknown} */
            section?: "summary" | "processes" | "flows";
        } & (unknown & unknown & unknown & unknown & unknown & unknown & unknown & unknown & unknown & unknown & unknown);
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
             * @description Original total query cutoff, irreversibly shortened by effective evidence access. A status read never extends it. Managed views clear by this cutoff or earlier on scope loss or closure; this cannot recall external copies. Distinct from the current request disclosure deadline.
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
             * @description Original total query cutoff, irreversibly shortened by effective evidence access. A status read never extends it. Managed views clear by this cutoff or earlier on scope loss or closure; this cannot recall external copies. Distinct from the current request disclosure deadline.
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
        Contract_common_9cbf92fb972157c6: string;
        /** Format: date-time */
        Contract_common_f06a67a70a2b97a5: string;
        Contract_log_results_5bb857fd69a5246d: {
            /** @constant */
            kind: "logs";
            pod_uid: string;
            /** Format: date-time */
            window_start: string;
            /** Format: date-time */
            window_end: string;
            entries: components["schemas"]["Contract_log_results_d3f629e9c1ad4b52"][];
            coverage: {
                origins: number;
                complete_origins: number;
                partial_origins: number;
                unavailable_origins: number;
                unknown_timestamp_origins: number;
                gapped_origins: number;
                source_bytes: number;
                total_fragments: number;
            };
            /** Format: date-time */
            query_observed_at: string;
            /** Format: date-time */
            query_expires_at: string;
        };
        Contract_log_results_d3f629e9c1ad4b52: {
            origin: {
                origin_id: number;
                /** @enum {unknown} */
                container_kind: "regular" | "init" | "ephemeral";
                container_name: string;
                /** @enum {unknown} */
                source: "current" | "previous";
                /** @constant */
                stream: "combined";
                runtime_id: string | null;
                restart_count: number | null;
            };
            fragment: number;
            line: number;
            offset: number;
            line_offset: number;
            continuation: boolean;
            end_line: boolean;
            /** Format: date-time */
            source_time: string | null;
            text: string | null;
            bytes_base64: string | null;
        } & ({
            text?: string;
            bytes_base64?: null;
        } | {
            text?: null;
            bytes_base64?: string;
        });
        Contract_guidance_ab5389e8510e6fdf: {
            /** @constant */
            kind: "discoveryPage";
            /** Format: uuid */
            capture_id: string;
            source_artifact_ids: string[];
            /** Format: date-time */
            expires_at: string;
            /** @enum {unknown} */
            section: "summary" | "processes" | "flows";
            summary: components["schemas"]["Contract_guidance_12c1bf2df01fe57b"];
            processes?: components["schemas"]["Contract_guidance_1f2eaf917843690c"][];
            flows?: components["schemas"]["Contract_guidance_ec15ff08f2c4dc52"][];
            gaps: string[];
        } & (unknown & unknown);
        Contract_guidance_12c1bf2df01fe57b: {
            /** Format: date-time */
            started_at: string;
            /** Format: date-time */
            ended_at: string;
            observed_wire_bytes: number;
            retained_bytes: number;
            coverage: components["schemas"]["Contract_guidance_554f1345ab0637f1"];
            classifier_digest?: string;
            /** @enum {unknown} */
            capture_mode: "none" | "networkHeaders" | "rawPackets";
        };
        Contract_guidance_554f1345ab0637f1: {
            requested_pods: number;
            covered_pods: number;
            process_inventory_complete: boolean;
            traffic_complete: boolean;
            dropped_packets: number;
            /** @enum {unknown} */
            stop_reason: "completed" | "duration" | "outputLimit" | "observationLimit" | "impactLimit" | "cancelled" | "capabilityGap" | "targetGone";
        };
        Contract_guidance_1f2eaf917843690c: {
            process_ref: string;
            pod_uid: string;
            display_pid: number;
            executable_name?: string;
            executable_path?: string;
            /** @enum {unknown} */
            runtime: "native" | "go" | "dotnet" | "python" | "node" | "jvm" | "unknown";
            identity_basis: components["schemas"]["Contract_guidance_a88818a38198abf7"];
            parent_ref?: string;
            rss_bytes?: number;
            selector_candidate?: components["schemas"]["Contract_action_f252bcf961e0afcb"];
            build_ids?: string[];
            /** Format: date-time */
            observed_at: string;
        };
        Contract_guidance_a88818a38198abf7: {
            /** @enum {unknown} */
            confidence: "observed" | "inferred" | "ambiguous" | "unknown";
            reason: string;
        };
        Contract_action_f252bcf961e0afcb: {
            match: {
                executablePath?: string;
                executableName?: string;
                /** @enum {unknown} */
                runtime?: "native" | "go" | "dotnet" | "python" | "node" | "jvm";
                buildIDs?: string[];
            };
            includeDescendants: boolean;
            maxDepth: number;
            /** @constant */
            resolve: "atDispatch";
        };
        Contract_guidance_ec15ff08f2c4dc52: {
            flow_ref: string;
            pod_uid: string;
            /** @enum {unknown} */
            transport: "tcp" | "udp" | "icmp" | "other";
            peer_address: string;
            peer_port?: number;
            /** @enum {unknown} */
            direction: "ingress" | "egress" | "unknown";
            /** @enum {unknown} */
            protocol: "unknown" | "dns" | "http1" | "http2Cleartext" | "tls";
            protocol_basis: components["schemas"]["Contract_guidance_a88818a38198abf7"];
            peer_candidates: components["schemas"]["Contract_guidance_edd351d6a8502e69"][];
            peer_basis: components["schemas"]["Contract_guidance_a88818a38198abf7"];
            process_refs: string[];
            process_basis: components["schemas"]["Contract_guidance_a88818a38198abf7"];
            observation_point: string;
        };
        Contract_guidance_edd351d6a8502e69: {
            /** @enum {unknown} */
            kind: "Service" | "Deployment" | "StatefulSet" | "Pod";
            namespace: string;
            name: string;
            uid: string;
        };
        McpOutput_get_extract: components["schemas"]["Contract_mcp_result"] & ({
            /** @constant */
            status: "ok";
            data: {
                threads: {
                    thread_id: string;
                    frames: {
                        index: number;
                        function: string | null;
                        file?: string | null;
                        line?: number | null;
                        address?: string;
                    }[];
                }[];
                /** @enum {string} */
                symbol_status: "complete" | "partial" | "missing";
            };
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
        } | {
            /** @constant */
            status: "ok";
            data: {
                runtime: string;
                pack_version: string;
                metrics: {
                    name: string;
                    value: number | string | boolean;
                    unit?: string;
                }[];
            };
        } | {
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
                 * @description Original total query cutoff, irreversibly shortened by effective evidence access. A status read never extends it. Managed views clear by this cutoff or earlier on scope loss or closure; this cannot recall external copies. Distinct from the current request disclosure deadline.
                 */
                query_expires_at: string;
            };
        } | {
            /** @constant */
            status: "pending";
            data: {
                query_handle: string;
                revision: number;
                /**
                 * Format: date-time
                 * @description Server time of this prepared query snapshot. This observation does not renew query or request authority. Together with query_expires_at it bounds managed-view lifetime independently of the client wall clock.
                 */
                query_observed_at: string;
                /**
                 * Format: date-time
                 * @description Original total query cutoff, irreversibly shortened by effective evidence access. A status read never extends it. Managed views clear by this cutoff or earlier on scope loss or closure; this cannot recall external copies. Distinct from the current request disclosure deadline.
                 */
                query_expires_at: string;
            };
        } | {
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
                revision: number;
                /**
                 * Format: date-time
                 * @description Server time of this prepared query snapshot. This observation does not renew query or request authority. Together with query_expires_at it bounds managed-view lifetime independently of the client wall clock.
                 */
                query_observed_at?: string;
                /**
                 * Format: date-time
                 * @description Original total query cutoff, irreversibly shortened by effective evidence access. A status read never extends it. Managed views clear by this cutoff or earlier on scope loss or closure; this cannot recall external copies. Distinct from the current request disclosure deadline.
                 */
                query_expires_at?: string;
            };
        } | {
            /** @constant */
            status: "ok";
            data: components["schemas"]["Contract_syscall_results_64217b49b5760651"];
            /** @constant */
            data_class?: "extract";
        } | {
            /** @constant */
            status: "ok";
            data: {
                /** @enum {string} */
                capture_mode: "networkHeaders" | "rawPackets";
                /** @description Retained packet records in the authenticated saved file; this is not a count of unique network datagrams. */
                packets: number;
                /** @description Producer-reported exclusions with the exact meaning given by drop_reporting; null means unavailable. This is not measured network loss. */
                drops: number | null;
                /** @description Top100 directional numeric endpoint/protocol aggregates, ordered by record count descending then protocol/source/destination; never DNS, comments or payload. */
                conversations: {
                    source: string;
                    destination: string;
                    /** @enum {unknown} */
                    protocol: "TCP" | "UDP" | "ICMPv4" | "ICMPv6";
                    packets: number;
                }[];
                /** @enum {unknown} */
                drop_reporting: "captureExclusions" | "snapshotOutputLimit" | "unavailable";
                conversations_total: number;
                conversations_truncated: boolean;
                /**
                 * Format: date-time
                 * @description Server time of this prepared query snapshot. This observation does not renew query or request authority. Together with query_expires_at it bounds managed-view lifetime independently of the client wall clock.
                 */
                query_observed_at: string;
                /**
                 * Format: date-time
                 * @description Original total query cutoff, irreversibly shortened by effective evidence access. A status read never extends it. Managed views clear by this cutoff or earlier on scope loss or closure; this cannot recall external copies. Distinct from the current request disclosure deadline.
                 */
                query_expires_at: string;
                /** @description Saved raw packet records without usable complete headers. These records remain in packets but not conversations; this is not a drop or network-loss count. Required for rawPackets and omitted for networkHeaders. */
                unclassified_packets?: number;
            } & unknown;
        } | {
            /** @constant */
            status: "ok";
            data: {
                /** @constant */
                protocol: "http1";
                projection_digest: components["schemas"]["Contract_common_9cbf92fb972157c6"];
                records: {
                    timestamp: components["schemas"]["Contract_common_f06a67a70a2b97a5"];
                    /** @enum {unknown} */
                    method?: "GET" | "HEAD" | "POST" | "PUT" | "DELETE" | "CONNECT" | "OPTIONS" | "TRACE" | "PATCH" | "OTHER";
                    status?: number;
                    headers: {
                        name: string;
                        value: string;
                    }[];
                    partial: boolean;
                }[];
                dropped_flows: number;
                incomplete_flows: number;
                coverage_gaps: string[];
            };
            /** @constant */
            data_class?: "extract";
        } | {
            /** @constant */
            status: "ok";
            data: {
                fields: string[];
                rows: (string | number | boolean | null)[][];
            };
        } | {
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
                 * @description Original total query cutoff, irreversibly shortened by effective evidence access. A status read never extends it. Managed views clear by this cutoff or earlier on scope loss or closure; this cannot recall external copies. Distinct from the current request disclosure deadline.
                 */
                query_expires_at: string;
            };
        } | {
            /** @constant */
            status: "ok";
            data: components["schemas"]["Contract_log_results_5bb857fd69a5246d"];
            /** @constant */
            data_class?: "raw";
        } | {
            /** @constant */
            status: "ok";
            data: components["schemas"]["Contract_guidance_ab5389e8510e6fdf"];
            /** @constant */
            data_class?: "extract";
        });
        McpInput_query_artifact: {
            /**
             * @description Selects the operation; each value has its own strict argument set.
             * @enum {unknown}
             */
            operation: "packets" | "syscalls" | "memory" | "debugger";
            /** Format: uuid */
            case_id?: string;
            /** Format: uuid */
            artifact_id?: string;
            /**
             * Format: uuid
             * @description Optional. Current covering grants are reused automatically; the equivalent Kubernetes right on the workload (pods/exec) also suffices (ADR-335 D5). Name a grant only to select among several.
             */
            grant_id?: string;
            idempotency_key?: string;
            fields?: ("packet_index" | "packet_time" | "captured_length" | "wire_length" | "source_address" | "destination_address" | "source_port" | "destination_port" | "protocol" | "tcp_flags" | "tcp_seq" | "tcp_ack" | "tcp_window" | "icmp_type" | "icmp_code" | "frame_prefix_hex")[];
            /** @description tcpdump/libpcap packet filter under the acquisition rules (specs/packets.md REQ-NET-001): no name resolution; header-bound offsets need ordinary rights, payload offsets only match bytes a raw original saved. Omitted means no restriction. Not Wireshark display-filter syntax. */
            packet_filter?: string;
            /**
             * Format: date-time
             * @description Inclusive saved-packet timestamp bound; normalized to UTC. It does not establish clock accuracy.
             */
            start_time?: string;
            /**
             * Format: date-time
             * @description Exclusive saved-packet timestamp bound. Must be later than start_time when both are present.
             */
            end_time?: string;
            /** @description Only fully decoded TCP headers match (flags & mask) == value; value cannot contain bits outside mask. */
            tcp_flags?: {
                mask: number;
                value: number;
            };
            /** @description Raw-only actual saved-frame byte window. Offset plus length must not exceed 1500. Missing bytes remain unavailable; no padding or inferred payload start. */
            frame_prefix?: {
                offset: number;
                length: number;
            };
            cursor?: string;
            limit?: number;
            syscall_names?: string[];
            errors_only?: boolean;
            address?: string;
            /**
             * @description Bytes to read; at most 32 KiB per call (hex output fits the 96 KiB MCP result bound), default 8 KiB (fits the 24 KiB default target). Continue at the next address.
             * @default 8192
             */
            length: number;
            /** @enum {string} */
            command?: "backtrace" | "threads" | "registers" | "frame_variables" | "managed_stack" | "heap_statistics";
            thread_id?: string;
            frame?: number;
        } & (unknown & unknown & unknown & unknown);
        Contract_syscall_results_1ead5a3932d88272: {
            /** @constant */
            kind: "syscallQuery";
            events: components["schemas"]["Contract_syscall_results_2f5f2536b1f5a3d0"][];
            coverage: {
                dropped_events: number | null;
                unmatched_events: number;
                /** @description Whether acquisition output was truncated, when independently known; null means the retained source does not establish it. Pagination does not imply acquisition truncation. */
                truncated: boolean | null;
                gaps: string[];
                record_count: number;
                unfinished_events: number;
                unknown_events: number;
            };
            /**
             * Format: date-time
             * @description Server time of this prepared query snapshot. This observation does not renew query or request authority. Together with query_expires_at it bounds managed-view lifetime independently of the client wall clock.
             */
            query_observed_at: string;
            /**
             * Format: date-time
             * @description Original total query cutoff, irreversibly shortened by effective evidence access. A status read never extends it. Managed views clear by this cutoff or earlier on scope loss or closure; this cannot recall external copies. Distinct from the current request disclosure deadline.
             */
            query_expires_at: string;
        };
        Contract_syscall_results_2f5f2536b1f5a3d0: {
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
            arguments: {
                name: string;
                /** @description Verbatim recorded decimal scalar, canonical base64 bytes or unavailable:fault. A successful empty buffer is base64:. Current native verification imposes stricter ABI and recorded-byte limits; this schema ceiling authorizes no new acquisition. */
                value: string;
                truncated: boolean;
            }[];
        } & (unknown & unknown);
        McpOutput_query_artifact: components["schemas"]["Contract_mcp_result"] & (({
            /** @constant */
            status: "ok";
            data: {
                /** @enum {unknown} */
                capture_mode: "networkHeaders" | "rawPackets";
                fields: ("packet_index" | "packet_time" | "captured_length" | "wire_length" | "source_address" | "destination_address" | "source_port" | "destination_port" | "protocol" | "tcp_flags" | "tcp_seq" | "tcp_ack" | "tcp_window" | "icmp_type" | "icmp_code" | "frame_prefix_hex")[];
                /** @description Exactly one cell per selected field. Fixed field types, canonical values and null availability are independently validated; zero is not null. */
                rows: (string | number | null)[][];
                /** @description Captured bytes of saved records visited by this call, including nonmatches. */
                scanned_bytes: number;
                scanned_packets: number;
                row_limit_reached: boolean;
                scan_limit_reached: boolean;
                output_limit_reached: boolean;
                /**
                 * Format: date-time
                 * @description Server time of this prepared query snapshot. This observation does not renew query or request authority. Together with query_expires_at it bounds managed-view lifetime independently of the client wall clock.
                 */
                query_observed_at: string;
                /**
                 * Format: date-time
                 * @description Original total query cutoff, irreversibly shortened by effective evidence access. A status read never extends it. Managed views clear by this cutoff or earlier on scope loss or closure; this cannot recall external copies. Distinct from the current request disclosure deadline.
                 */
                query_expires_at: string;
            } & (unknown & unknown & unknown & unknown);
        } & unknown) | {
            /** @constant */
            status: "pending";
            data: {
                query_handle: string;
                revision: number;
                /**
                 * Format: date-time
                 * @description Server time of this prepared query snapshot. This observation does not renew query or request authority. Together with query_expires_at it bounds managed-view lifetime independently of the client wall clock.
                 */
                query_observed_at: string;
                /**
                 * Format: date-time
                 * @description Original total query cutoff, irreversibly shortened by effective evidence access. A status read never extends it. Managed views clear by this cutoff or earlier on scope loss or closure; this cannot recall external copies. Distinct from the current request disclosure deadline.
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
        } | {
            /** @constant */
            status: "ok";
            data: components["schemas"]["Contract_syscall_results_1ead5a3932d88272"];
            /** @constant */
            data_class?: "raw";
        } | {
            /** @constant */
            status: "ok";
            data: {
                address: string;
                /** @constant */
                encoding: "hex";
                value: string;
                bytes_returned: number;
            };
        } | {
            /** @constant */
            status: "pending";
            data: {
                query_handle: string;
                revision: number;
            };
        } | {
            /** @constant */
            status: "ok";
            data: {
                operation: string;
                columns: string[];
                rows: (string | number | boolean | null)[][];
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
            limit?: number;
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
                 * @description Original total query cutoff, irreversibly shortened by effective evidence access. A status read never extends it. Managed views clear by this cutoff or earlier on scope loss or closure; this cannot recall external copies. Distinct from the current request disclosure deadline.
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
                revision: number;
                /**
                 * Format: date-time
                 * @description Server time of this prepared query snapshot. This observation does not renew query or request authority. Together with query_expires_at it bounds managed-view lifetime independently of the client wall clock.
                 */
                query_observed_at: string;
                /**
                 * Format: date-time
                 * @description Original total query cutoff, irreversibly shortened by effective evidence access. A status read never extends it. Managed views clear by this cutoff or earlier on scope loss or closure; this cannot recall external copies. Distinct from the current request disclosure deadline.
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
        McpInput_get_query_result: {
            query_handle: string;
            /** @description Wait server-side until the state revision differs from this value or 30 seconds pass, then return the current state. Omit for an immediate read. Status reads are never charged. */
            after_revision?: number;
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
                 * @description Original total query cutoff, irreversibly shortened by effective evidence access. A status read never extends it. Managed views clear by this cutoff or earlier on scope loss or closure; this cannot recall external copies. Distinct from the current request disclosure deadline.
                 */
                query_expires_at: string;
            };
        } | {
            /** @constant */
            status: "pending";
            data: {
                query_handle: string;
                revision: number;
                /**
                 * Format: date-time
                 * @description Server time of this prepared query snapshot. This observation does not renew query or request authority. Together with query_expires_at it bounds managed-view lifetime independently of the client wall clock.
                 */
                query_observed_at: string;
                /**
                 * Format: date-time
                 * @description Original total query cutoff, irreversibly shortened by effective evidence access. A status read never extends it. Managed views clear by this cutoff or earlier on scope loss or closure; this cannot recall external copies. Distinct from the current request disclosure deadline.
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
