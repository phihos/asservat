// Generated from canonical browser OpenAPI. Run npm run generate; do not edit.
export type paths = Record<string, never>;
export type webhooks = Record<string, never>;
export interface components {
    schemas: {
        McpInput_list_diagnostics: {
            target_handle?: string;
            cursor?: string;
            limit?: number;
            target_ref?: {
                /** @description Cluster name as configured in the hub (ADR-335 D4). */
                cluster: string;
                namespace: string;
                /** @enum {unknown} */
                kind: "Deployment" | "StatefulSet" | "Pod";
                name: string;
            };
            /**
             * @description Optional row-kind filter.
             * @enum {unknown}
             */
            kind?: "preset" | "recipe" | "captureProfile" | "discovery";
            /** @enum {unknown} */
            catalog?: "builtin" | "organization" | "namespace";
            /**
             * @description Optional. Ranks applicable diagnostics for this goal as passive recommendations with rationale, gaps and proposed plans, optionally informed by existing discovery captures.
             * @enum {unknown}
             */
            goal?: "unknown" | "crash" | "memoryGrowth" | "highCPU" | "latency" | "hang" | "network" | "dns" | "probeFailure";
            discovery_capture_ids?: string[];
            preferences?: {
                history_seconds?: number;
                max_bytes?: number;
                /** @enum {unknown} */
                max_impact?: "observe" | "sensitiveRead" | "intrusive";
                max_ring_bytes?: number;
            };
            focus?: {
                process_refs?: string[];
                flow_refs?: string[];
            };
        } & (unknown | unknown);
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
        Contract_capture_composition_f1d3ea703d6af495: {
            /** @enum {unknown} */
            catalog: "builtin" | "organization" | "namespace";
            name: string;
            /** @description Optional; omitted, the hub resolves the current version and records it. */
            version?: string;
        };
        Contract_guidance_564bcb17d432827e: {
            /** @constant */
            kind: "diagnosticRecommendations";
            target_handle: string;
            /** @enum {unknown} */
            goal: "unknown" | "crash" | "memoryGrowth" | "highCPU" | "latency" | "hang" | "network" | "dns" | "probeFailure";
            catalog_digest: string;
            /** Format: date-time */
            expires_at: string;
            source_capture_ids: string[];
            recommendations: components["schemas"]["Contract_guidance_3832a95b9732184d"][];
            missing_observations: string[];
        };
        Contract_guidance_3832a95b9732184d: {
            diagnostic_handle: string;
            title: string;
            explanation: string;
            answers: string[];
            limitations: string[];
            basis: components["schemas"]["Contract_guidance_a88818a38198abf7"];
            evidence_kinds: string[];
            /** @enum {unknown} */
            impact: "observe" | "sensitiveRead" | "intrusive";
            max_bytes: number;
            max_process_starts: number;
            retention_seconds: number;
            approval_required: boolean;
            blockers: components["schemas"]["Contract_guidance_c8c053ecb8f17e88"][];
            process_selector?: components["schemas"]["Contract_action_f252bcf961e0afcb"];
            packet_parameters?: components["schemas"]["Contract_packet_capture"];
            ring_sizing?: components["schemas"]["Contract_guidance_11b6c98329eb1929"];
            process_batch?: components["schemas"]["Contract_action_e8308e53a77c994b"];
            process_match_count?: number;
            process_inventory_complete?: boolean;
        };
        Contract_guidance_a88818a38198abf7: {
            /** @enum {unknown} */
            confidence: "observed" | "inferred" | "ambiguous" | "unknown";
            reason: string;
        };
        Contract_guidance_c8c053ecb8f17e88: {
            code: string;
            message: string;
            /** @enum {unknown} */
            responsible_role: "maintainer" | "approver" | "administrator" | "none";
            retryable: boolean;
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
        /** Bounded packet action parameters */
        Contract_packet_capture: {
            profile: {
                /** @constant */
                kind: "networkHeaders";
            } | {
                /** @constant */
                kind: "httpHeaders";
                /** @constant */
                protocol: "http1";
                projectionRef: {
                    name: string;
                    version: string;
                };
                /**
                 * @description Common HTTP server header limits (nginx large_client_header_buffers 4 × 8 KiB) bound one request header block.
                 * @default 32768
                 */
                maxHeaderBytes: number;
                /**
                 * @description Per-target reassembly memory budget; per-flow reassembly is 2 × maxHeaderBytes, so tracked flows = maxReassemblyBytes ÷ (2 × maxHeaderBytes); the default 16 MiB is derived from the node collector memory limit together with the ring budget.
                 * @default 16777216
                 */
                maxReassemblyBytes: number;
            } | {
                /** @constant */
                kind: "rawPackets";
                snaplen: number;
                protocolSnaplen?: {
                    /** @enum {unknown} */
                    protocol: "tcp" | "udp" | "icmp";
                    bytes: number;
                }[];
            };
            before: string;
            after: string;
            /** @description No length cap on the text; the bound is the compiled classic BPF program, which must fit the kernel limit BPF_MAXINSNS (4096 instructions), checked at compile, and the enclosing Kubernetes object size. */
            filter?: string;
            /** @description In-memory ring; a saved window copies at most maxBytes. The collector memory formula (specs/packets.md REQ-NET-003) bounds all rings on a node. */
            ring: {
                maxAge: components["schemas"]["Contract_common_76a8fd22c9ccd9dc"];
                maxBytes: number;
                /** @description Segment count; segment size is maxBytes ÷ segments. At least 2 so the ring can rotate; evicting one segment drops 1/segments of history. */
                segments: number;
            };
            /** @description Peer generations are bounded only by the compiled program limit (BPF_MAXINSNS 4096). */
            peers: {
                entries: ({
                    cidrs: string[];
                } | {
                    podSelector: {
                        namespace: string;
                        matchLabels: {
                            [key: string]: string;
                        };
                    };
                } | {
                    resourceRef: {
                        /** @enum {unknown} */
                        kind: "Pod" | "Deployment" | "StatefulSet" | "Service";
                        namespace: string;
                        name: string;
                        /** @enum {unknown} */
                        serviceMode?: "backends" | "virtualIP" | "both";
                        readyOnly?: boolean;
                    } & unknown;
                })[];
                /** @enum {unknown} */
                protocol: "tcp" | "udp" | "icmp" | "any";
                ports?: number[];
                /** @enum {unknown} */
                resolution: "frozen" | "follow";
            };
        };
        Contract_common_76a8fd22c9ccd9dc: string;
        Contract_guidance_11b6c98329eb1929: {
            /** @enum {unknown} */
            basis: "measuredProjection" | "estimated";
            retained_bytes_per_second: number;
            history_seconds: number;
            burst_factor: number;
            segment_bytes: number;
            segments: number;
            ring_bytes: number;
            limitations: string[];
        };
        Contract_action_e8308e53a77c994b: {
            /** @description The default batch covers every resolved main process of the Pod, sidecars included; the batch is bounded by maxProcesses × maxBytesPerProcess ≤ the action maxBytes and by maxTotalStop. */
            maxProcesses: number;
            /** @description Bounded only by the action and capture byte budget. */
            maxBytesPerProcess: number;
            maxStopPerProcess: components["schemas"]["Contract_common_76a8fd22c9ccd9dc"];
            maxTotalStop: components["schemas"]["Contract_common_76a8fd22c9ccd9dc"];
            /** @constant */
            consistency: "sequential";
        };
        McpOutput_list_diagnostics: components["schemas"]["Contract_mcp_result"] & ({
            /** @constant */
            status: "ok";
            data: {
                diagnostics: (({
                    diagnostic_handle?: string;
                    name: string;
                    version: string;
                    description: string;
                    approval_required: boolean;
                    available: boolean;
                    blockers: {
                        code: string;
                        message: string;
                        /** @enum {unknown} */
                        responsible_role: "maintainer" | "approver" | "administrator" | "none";
                        retryable: boolean;
                    }[];
                    preset_ref?: {
                        /** @enum {unknown} */
                        name: "incident-context" | "pod-status";
                        /** @constant */
                        version: "v1";
                    };
                    /** @enum {unknown} */
                    kind: "preset" | "recipe" | "captureProfile" | "discovery";
                    profile_ref?: components["schemas"]["Contract_capture_composition_f1d3ea703d6af495"];
                    deprecated?: boolean;
                    display_name?: string;
                    execution_modes: ("onTrigger" | "ongoing")[];
                } & (unknown & unknown & unknown)) & (unknown | unknown | unknown))[];
            };
        } | {
            /** @constant */
            status: "ok";
            data: components["schemas"]["Contract_guidance_564bcb17d432827e"];
            /** @constant */
            data_class?: "extract";
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
        Contract_sharing_request_23966cae8e071ea3: {
            /** @description No count limit: recipients are bounded only by the request body byte limit (memory) (maintainer rule: limits need a reason). */
            recipients: components["schemas"]["Contract_common_0e44f1278c675a38"][];
            outputSelection?: {
                /** @constant */
                mode: "approvedExtracts";
            } | {
                /** @constant */
                mode: "explicit";
                outputs: ({
                    actionID: string;
                    /** @enum {unknown} */
                    dataClass: "metadata" | "extract" | "raw";
                    projectionRef?: {
                        name: string;
                        version: string;
                    };
                    operations?: ("list_cases" | "get_case" | "list_artifacts" | "get_extract" | "compare_profiles" | "get_query_result" | "read_memory" | "debugger_command" | "pcap_query" | "syscall_query" | "download_artifact")[];
                } & unknown)[];
            };
            notAfter?: components["schemas"]["Contract_common_f06a67a70a2b97a5"];
            reason?: string;
            management?: components["schemas"]["Contract_management_0d504ecd6bc8c0fd"];
        };
        Contract_common_0e44f1278c675a38: {
            /** @enum {string} */
            kind: "User" | "Group";
            /** Format: uri */
            issuer: string;
            id: string;
        };
        /** Format: date-time */
        Contract_common_f06a67a70a2b97a5: string;
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
        /** Flat bounded capture profile composition */
        Contract_capture_composition: {
            components: components["schemas"]["Contract_capture_composition_6b531f41803ddb7b"][];
            maxTotalBytes?: number;
            maxDuration?: components["schemas"]["Contract_common_76a8fd22c9ccd9dc"];
            $defs: {
                profileRef: {
                    /** @enum {unknown} */
                    catalog: "builtin" | "organization" | "namespace";
                    name: string;
                    /** @description Optional; omitted, the hub resolves the current version and records it. */
                    version?: string;
                };
                override: {
                    actionID: string;
                    /** @constant */
                    field: "packetPeers";
                    value: components["schemas"]["Contract_packet_capture_621ac6cb243f371c"];
                } | {
                    actionID: string;
                    /** @constant */
                    field: "packetFilter";
                    value: components["schemas"]["Contract_packet_capture_bd5424e783362da5"];
                } | {
                    actionID: string;
                    /** @constant */
                    field: "packetBefore";
                    value: components["schemas"]["Contract_packet_capture_3cabf6dd4f1621f2"];
                } | {
                    actionID: string;
                    /** @constant */
                    field: "packetAfter";
                    value: components["schemas"]["Contract_packet_capture_c29139839890e47d"];
                } | {
                    actionID: string;
                    /** @constant */
                    field: "packetRing";
                    value: components["schemas"]["Contract_packet_capture_8b1a78e06ce5adec"];
                } | {
                    actionID: string;
                    /** @constant */
                    field: "processSelector";
                    value: components["schemas"]["Contract_action_f252bcf961e0afcb"];
                } | {
                    actionID: string;
                    /** @constant */
                    field: "processBatch";
                    value: components["schemas"]["Contract_action_e8308e53a77c994b"];
                } | {
                    actionID: string;
                    /** @constant */
                    field: "profileDuration";
                    value: components["schemas"]["Contract_common_76a8fd22c9ccd9dc"];
                } | {
                    actionID: string;
                    /** @constant */
                    field: "syscallFilter";
                    value: components["schemas"]["Contract_syscall_trace_2f40cbbf2f8e105a"];
                } | {
                    actionID: string;
                    /** @constant */
                    field: "syscallMode";
                    value: components["schemas"]["Contract_syscall_trace_e845ec2a704c9e02"];
                } | {
                    actionID: string;
                    /** @constant */
                    field: "syscallBefore";
                    value: components["schemas"]["Contract_syscall_trace_3cabf6dd4f1621f2"];
                } | {
                    actionID: string;
                    /** @constant */
                    field: "syscallAfter";
                    value: components["schemas"]["Contract_syscall_trace_c29139839890e47d"];
                } | {
                    actionID: string;
                    /** @constant */
                    field: "syscallRing";
                    value: components["schemas"]["Contract_syscall_trace_8b1a78e06ce5adec"];
                } | {
                    actionID: string;
                    /** @constant */
                    field: "syscallArguments";
                    value: components["schemas"]["Contract_syscall_trace_1e2fcb79248fe77f"];
                } | {
                    actionID: string;
                    /** @constant */
                    field: "syscallRate";
                    value: components["schemas"]["Contract_syscall_trace_09825459ded300c7"];
                } | {
                    actionID: string;
                    /** @constant */
                    field: "filePath";
                    value: string;
                } | {
                    actionID: string;
                    /** @constant */
                    field: "commandArgv";
                    value: string[];
                } | {
                    actionID: string;
                    /** @constant */
                    field: "actionMaxBytes";
                    value: number;
                } | {
                    actionID: string;
                    /** @constant */
                    field: "actionTimeout";
                    value: components["schemas"]["Contract_common_76a8fd22c9ccd9dc"];
                } | {
                    actionID: string;
                    /** @constant */
                    field: "actionExecutionMode";
                    /** @enum {unknown} */
                    value: "onTrigger" | "ongoing";
                } | {
                    actionID: string;
                    /** @constant */
                    field: "logBefore";
                    value: string;
                } | {
                    actionID: string;
                    /** @constant */
                    field: "logAfter";
                    value: string;
                } | {
                    actionID: string;
                    /** @constant */
                    field: "logStream";
                    /** @enum {string} */
                    value: "both";
                };
                component: {
                    id: string;
                    profileRef: components["schemas"]["Contract_capture_composition_f1d3ea703d6af495"];
                    overrides?: components["schemas"]["Contract_capture_composition_e9eb2edd44ab3f11"][];
                };
                actionAlias: {
                    componentID: string;
                    localActionID: string;
                    actionID: string;
                    deduplicated: boolean;
                };
                /** @description Pinned resolved profile. A builtin definition is embedded in the release binary (ADR-243) and is identified by its definition digest alone; organization and namespace definitions name their source cluster, namespace and object. */
                resolvedProfile: {
                    componentID: string;
                    profileRef: components["schemas"]["Contract_capture_composition_f1d3ea703d6af495"];
                    sourceUID?: string;
                    definitionDigest: string;
                    /** Format: uuid */
                    sourceClusterID?: string;
                    sourceNamespaceUID?: string;
                } & unknown;
                provenance: {
                    authored: components["schemas"]["Contract_capture_composition"];
                    resolvedProfiles: components["schemas"]["Contract_capture_composition_d3d99d35a2742711"][];
                    actionMap: components["schemas"]["Contract_capture_composition_6256ac1ffa3775a5"][];
                };
            };
        };
        /** @description Peer generations are bounded only by the compiled program limit (BPF_MAXINSNS 4096). */
        Contract_packet_capture_621ac6cb243f371c: {
            entries: ({
                cidrs: string[];
            } | {
                podSelector: {
                    namespace: string;
                    matchLabels: {
                        [key: string]: string;
                    };
                };
            } | {
                resourceRef: {
                    /** @enum {unknown} */
                    kind: "Pod" | "Deployment" | "StatefulSet" | "Service";
                    namespace: string;
                    name: string;
                    /** @enum {unknown} */
                    serviceMode?: "backends" | "virtualIP" | "both";
                    readyOnly?: boolean;
                } & unknown;
            })[];
            /** @enum {unknown} */
            protocol: "tcp" | "udp" | "icmp" | "any";
            ports?: number[];
            /** @enum {unknown} */
            resolution: "frozen" | "follow";
        };
        /** @description No length cap on the text; the bound is the compiled classic BPF program, which must fit the kernel limit BPF_MAXINSNS (4096 instructions), checked at compile, and the enclosing Kubernetes object size. */
        Contract_packet_capture_bd5424e783362da5: string;
        Contract_packet_capture_3cabf6dd4f1621f2: string;
        Contract_packet_capture_c29139839890e47d: string;
        /** @description In-memory ring; a saved window copies at most maxBytes. The collector memory formula (specs/packets.md REQ-NET-003) bounds all rings on a node. */
        Contract_packet_capture_8b1a78e06ce5adec: {
            maxAge: components["schemas"]["Contract_common_76a8fd22c9ccd9dc"];
            maxBytes: number;
            /** @description Segment count; segment size is maxBytes ÷ segments. At least 2 so the ring can rotate; evicting one segment drops 1/segments of history. */
            segments: number;
        };
        Contract_syscall_trace_2f40cbbf2f8e105a: {
            /** @constant */
            mode: "all";
        } | {
            /** @constant */
            mode: "include";
            names: string[];
        };
        /** @enum {unknown} */
        Contract_syscall_trace_e845ec2a704c9e02: "metadata" | "arguments";
        Contract_syscall_trace_3cabf6dd4f1621f2: "0s" | components["schemas"]["Contract_common_76a8fd22c9ccd9dc"];
        Contract_syscall_trace_c29139839890e47d: "0s" | components["schemas"]["Contract_common_76a8fd22c9ccd9dc"];
        Contract_syscall_trace_8b1a78e06ce5adec: components["schemas"]["Contract_packet_capture_8b1a78e06ce5adec"];
        Contract_syscall_trace_1e2fcb79248fe77f: {
            maxBytesPerEvent: number;
            captureBuffers: boolean;
        };
        /** @description Reviewed observation rate; the shipped default is derived from measured per-node collector event throughput. With the ring, it bounds every trace; there is no lifetime event total (ADR-335 D6). */
        Contract_syscall_trace_09825459ded300c7: number;
        Contract_capture_composition_e9eb2edd44ab3f11: {
            actionID: string;
            /** @constant */
            field: "packetPeers";
            value: components["schemas"]["Contract_packet_capture_621ac6cb243f371c"];
        } | {
            actionID: string;
            /** @constant */
            field: "packetFilter";
            value: components["schemas"]["Contract_packet_capture_bd5424e783362da5"];
        } | {
            actionID: string;
            /** @constant */
            field: "packetBefore";
            value: components["schemas"]["Contract_packet_capture_3cabf6dd4f1621f2"];
        } | {
            actionID: string;
            /** @constant */
            field: "packetAfter";
            value: components["schemas"]["Contract_packet_capture_c29139839890e47d"];
        } | {
            actionID: string;
            /** @constant */
            field: "packetRing";
            value: components["schemas"]["Contract_packet_capture_8b1a78e06ce5adec"];
        } | {
            actionID: string;
            /** @constant */
            field: "processSelector";
            value: components["schemas"]["Contract_action_f252bcf961e0afcb"];
        } | {
            actionID: string;
            /** @constant */
            field: "processBatch";
            value: components["schemas"]["Contract_action_e8308e53a77c994b"];
        } | {
            actionID: string;
            /** @constant */
            field: "profileDuration";
            value: components["schemas"]["Contract_common_76a8fd22c9ccd9dc"];
        } | {
            actionID: string;
            /** @constant */
            field: "syscallFilter";
            value: components["schemas"]["Contract_syscall_trace_2f40cbbf2f8e105a"];
        } | {
            actionID: string;
            /** @constant */
            field: "syscallMode";
            value: components["schemas"]["Contract_syscall_trace_e845ec2a704c9e02"];
        } | {
            actionID: string;
            /** @constant */
            field: "syscallBefore";
            value: components["schemas"]["Contract_syscall_trace_3cabf6dd4f1621f2"];
        } | {
            actionID: string;
            /** @constant */
            field: "syscallAfter";
            value: components["schemas"]["Contract_syscall_trace_c29139839890e47d"];
        } | {
            actionID: string;
            /** @constant */
            field: "syscallRing";
            value: components["schemas"]["Contract_syscall_trace_8b1a78e06ce5adec"];
        } | {
            actionID: string;
            /** @constant */
            field: "syscallArguments";
            value: components["schemas"]["Contract_syscall_trace_1e2fcb79248fe77f"];
        } | {
            actionID: string;
            /** @constant */
            field: "syscallRate";
            value: components["schemas"]["Contract_syscall_trace_09825459ded300c7"];
        } | {
            actionID: string;
            /** @constant */
            field: "filePath";
            value: string;
        } | {
            actionID: string;
            /** @constant */
            field: "commandArgv";
            value: string[];
        } | {
            actionID: string;
            /** @constant */
            field: "actionMaxBytes";
            value: number;
        } | {
            actionID: string;
            /** @constant */
            field: "actionTimeout";
            value: components["schemas"]["Contract_common_76a8fd22c9ccd9dc"];
        } | {
            actionID: string;
            /** @constant */
            field: "actionExecutionMode";
            /** @enum {unknown} */
            value: "onTrigger" | "ongoing";
        } | {
            actionID: string;
            /** @constant */
            field: "logBefore";
            value: string;
        } | {
            actionID: string;
            /** @constant */
            field: "logAfter";
            value: string;
        } | {
            actionID: string;
            /** @constant */
            field: "logStream";
            /** @enum {string} */
            value: "both";
        };
        /** @description Pinned resolved profile. A builtin definition is embedded in the release binary (ADR-243) and is identified by its definition digest alone; organization and namespace definitions name their source cluster, namespace and object. */
        Contract_capture_composition_d3d99d35a2742711: {
            componentID: string;
            profileRef: components["schemas"]["Contract_capture_composition_f1d3ea703d6af495"];
            sourceUID?: string;
            definitionDigest: string;
            /** Format: uuid */
            sourceClusterID?: string;
            sourceNamespaceUID?: string;
        } & unknown;
        Contract_capture_composition_6256ac1ffa3775a5: {
            componentID: string;
            localActionID: string;
            actionID: string;
            deduplicated: boolean;
        };
        Contract_capture_composition_6b531f41803ddb7b: {
            id: string;
            profileRef: components["schemas"]["Contract_capture_composition_f1d3ea703d6af495"];
            overrides?: components["schemas"]["Contract_capture_composition_e9eb2edd44ab3f11"][];
        };
        /** @description Result access covers every OAuth client and browser session of the same human; clients carry the user's own evidence access (maintainer decision). */
        Contract_investigation_access_0d504ecd6bc8c0fd: {
            actionIds: string[];
            operations: ("debugger_command" | "download_artifact" | "get_logs" | "pcap_query" | "read_memory" | "syscall_query")[];
            maxArtifacts: number;
            maxBytes: number;
            maxOperations: number;
            /**
             * Format: date-time
             * @description Optional; defaults to the access end (AccessUntil) of the collected evidence, capped by the administrator maximum. No deadline restarts when an artifact arrives.
             */
            notAfter?: string;
        };
        McpInput_preview_capture: ({
            target_handle?: string;
            target_ref?: {
                /** @description Cluster name as configured in the hub (ADR-335 D4). */
                cluster: string;
                namespace: string;
                /** @enum {unknown} */
                kind: "Deployment" | "StatefulSet" | "Pod";
                name: string;
            };
            diagnostic_handle?: string;
            preset_ref?: {
                /** @enum {unknown} */
                name: "incident-context" | "pod-status";
                /** @constant */
                version: "v1";
            };
            reason?: string;
            sharing?: components["schemas"]["Contract_sharing_request_23966cae8e071ea3"];
            /** Format: uuid */
            history_capture_id?: string;
            /** Format: uuid */
            repeated_from_capture_id?: string;
            profile_composition?: components["schemas"]["Contract_capture_composition"];
            result_access?: components["schemas"]["Contract_investigation_access_0d504ecd6bc8c0fd"];
            /** @description Requested evidence-access lifetime in seconds. Omission uses the administrator default; effective access and managed deletion remain bounded by current retention policy and its deletion budget. History restoration preserves its original request; use a normal edited preview to change it. */
            requested_retention_seconds?: number;
            /**
             * @description Explicit manual selection when repeating a policy triggeringPod occurrence; the preview selects a current eligible Pod under the original workload identity.
             * @enum {unknown}
             */
            history_selection?: "currentEligiblePod";
            recording_handles?: string[];
            before?: components["schemas"]["Contract_common_76a8fd22c9ccd9dc"];
        } & (unknown & unknown)) & (((unknown | unknown) & (unknown | unknown | unknown)) | unknown | unknown);
        Contract_capture_composition_fea23abd809a781c: {
            authored: components["schemas"]["Contract_capture_composition"];
            resolvedProfiles: components["schemas"]["Contract_capture_composition_d3d99d35a2742711"][];
            actionMap: components["schemas"]["Contract_capture_composition_6256ac1ffa3775a5"][];
        };
        Contract_action_lifecycle_35910c4fba296505: {
            /** @constant */
            schemaVersion: "action-lifecycle/v1";
            /** @enum {unknown} */
            requestKind: "DebugCapture" | "DebugPolicy";
            actions: (({
                actionID: string;
                /** @enum {unknown} */
                kind: "kubernetesSnapshot" | "processSnapshot" | "fileRead" | "packetCapture" | "networkSnapshot" | "runtimeDiagnostic" | "kernelCore" | "liveCore" | "command" | "httpDiagnostic" | "artifactCollect" | "profile" | "syscallTrace";
                /** @constant */
                executionMode: "onTrigger";
                /** @constant */
                requestedBefore?: "0s";
                after?: string;
            } & unknown) | {
                actionID: string;
                /** @enum {unknown} */
                kind: "packetCapture" | "syscallTrace";
                /** @constant */
                executionMode: "ongoing";
                /** @enum {unknown} */
                activation: "policyArming" | "manualSession";
                requestedBefore: string;
                after: string;
            } | {
                actionID: string;
                /** @constant */
                kind: "logs";
                /** @constant */
                executionMode: "onTrigger";
                requestedBefore: string;
                after: string;
            })[];
            /** @enum {unknown} */
            ongoingPodScope: "allAuthorizedWithinObservationLimits" | "acceptedCapturePods" | "none";
        } & (unknown & unknown);
        Contract_capture_assessment_9c7f9709a5418f1b: {
            /** @constant */
            schemaVersion: "capture-assessment/v1";
            assessmentID: components["schemas"]["Contract_common_2224a31324a0c811"];
            planDigest: components["schemas"]["Contract_common_9cbf92fb972157c6"];
            /** Format: date-time */
            generatedAt: string;
            basis: {
                rulesDigest: components["schemas"]["Contract_common_9cbf92fb972157c6"];
                capabilityDigest: components["schemas"]["Contract_common_9cbf92fb972157c6"];
                metrics: {
                    /** @enum {unknown} */
                    state: "fresh" | "stale" | "unavailable";
                    /** Format: date-time */
                    observedAt?: string;
                } & unknown;
            };
            scope: {
                observationPods: number;
                incidentPods: number;
            };
            combinedImpact: components["schemas"]["Contract_capture_assessment_af46ae63614e2f28"];
            actions: {
                actionID: string;
                /** @enum {unknown} */
                executionMode: "onTrigger" | "ongoing";
                impact: components["schemas"]["Contract_capture_assessment_af46ae63614e2f28"];
                data: components["schemas"]["Contract_capture_assessment_eca2bc02f01833c6"];
                retention: components["schemas"]["Contract_capture_assessment_9d972ed356c3acb3"];
                quantities: components["schemas"]["Contract_capture_assessment_35deb14ea19cdb7b"][];
                /** @description For an existing-source save, identifies the selected source row whose incremental snapshot assessment this is. It conveys no acquisition authority. */
                recording_handle?: string;
            }[];
            combinedQuantities: components["schemas"]["Contract_capture_assessment_35deb14ea19cdb7b"][];
            interactions: {
                actionIDs: string[];
                /** @enum {unknown} */
                kind: "profilerConflict" | "measurementDistortion" | "sharedPressure" | "combinedCostUnknown";
                message: string;
                blocking: boolean;
            }[];
            alternatives: {
                actionIDs: string[];
                /** @enum {unknown} */
                change: "narrowScope" | "shortenWindow" | "lowerSampling" | "metadataOnly" | "fewerIncidentPods" | "serialize" | "removeAction" | "futureOnly";
                benefit: string;
                coverageLoss: string;
            }[];
            handlingCodes: ("minimizeCapture" | "restrictAccess" | "preferApprovedExtracts" | "reviewBeforeSharing" | "approvedClientsOnly" | "externalCopiesNotRecalled")[];
            handlingPolicyRef?: string;
        };
        /** Format: uuid */
        Contract_common_2224a31324a0c811: string;
        Contract_common_9cbf92fb972157c6: string;
        Contract_capture_assessment_af46ae63614e2f28: {
            /** @enum {unknown} */
            level: "low" | "moderate" | "high" | "unknown";
            hasUnknowns: boolean;
            effects: ("applicationPause" | "applicationCPU" | "applicationAllocation" | "forcedGC" | "nodeCPU" | "collectorMemory" | "storageIO" | "uploadContention" | "applicationMutation" | "diagnosticInterference")[];
            explanation: string;
        } & unknown;
        Contract_capture_assessment_eca2bc02f01833c6: {
            classification: components["schemas"]["Contract_privacy_common_cf52919b29fc225a"];
            /** @enum {unknown} */
            basis: "conservativeMechanism" | "protectedWorkload" | "reviewedTransform";
            assessmentRef?: string;
            retainedPossible: ("userContent" | "credentials" | "personalIdentifiers" | "networkAddresses" | "paths" | "profileLabels" | "unknownApplicationData")[];
            transientOnly: ("userContent" | "credentials" | "personalIdentifiers" | "networkAddresses" | "paths" | "profileLabels" | "unknownApplicationData")[];
            unknownContent: boolean;
        } & (unknown & unknown);
        /** @enum {string} */
        Contract_privacy_common_cf52919b29fc225a: "unknown" | "potentialPersonalData" | "personalData" | "specialCategoryPossible" | "verifiedNonPersonal";
        Contract_capture_assessment_9d972ed356c3acb3: {
            /**
             * @description submissionPreparation measures every newly accepted manual capture from preparation of its first admitted submission: waiting counts and accepted retries retain the original registration. firstAcquisitionOrEarlierSource is reserved for typed existing-source snapshots and measures from the original source acquisition or an earlier retained source, never preview creation.
             * @enum {unknown}
             */
            anchorRule: "firstAcquisitionOrEarlierSource" | "submissionPreparation";
            accessAgeSeconds: number;
            maximumAgeSeconds: number;
            deletionBudgetSeconds: number;
            policyDigests: components["schemas"]["Contract_common_9cbf92fb972157c6"][];
            /** @constant */
            automaticDeletion: true;
            /** @constant */
            managedCopiesOnly: true;
            /** @enum {unknown} */
            preservationException: "none" | "possible" | "active";
            deleteAgeSeconds: number;
        };
        Contract_capture_assessment_35deb14ea19cdb7b: {
            /** @enum {unknown} */
            dimension: "applicationPauseMs" | "applicationCpuMillicores" | "collectorMemoryBytes" | "outputBytes" | "uploadBytesPerSecond" | "applicationLatencyPercent" | "collectorStorageBytes";
            /** @enum {unknown} */
            phase: "whileArmed" | "perIncident";
            /** @enum {unknown} */
            scope: "perProcess" | "perObservationPod" | "perIncidentPod" | "perNode" | "wholePlan";
            /** @enum {unknown} */
            basis: "configuredLimit" | "modelEstimate" | "qualifiedMeasurement";
            lower: number;
            upper: number;
            sourceRef: string;
            /** Format: date-time */
            measuredAt?: string;
            environmentDigest?: components["schemas"]["Contract_common_9cbf92fb972157c6"];
            coverage: string;
        } & unknown;
        Contract_investigation_access_03804ffde11279ad: {
            actionIds: string[];
            operations: ("debugger_command" | "download_artifact" | "get_logs" | "pcap_query" | "read_memory" | "syscall_query")[];
            maxArtifacts: number;
            maxBytes: number;
            maxOperations: number;
            /** Format: date-time */
            notAfter: string;
            digest: string;
        };
        Contract_recording_save_9fa579a60a73e081: {
            /** @constant */
            kind: "recordingSavePreview";
            /** @constant */
            operation: "recordingSave";
            /** @description Digest of the resolved recording-save/v1 plan. Submit it as request_capture expected_plan_digest with the same preview request and an idempotency key. */
            plan_digest: components["schemas"]["Contract_common_9cbf92fb972157c6"];
            selected_recordings: components["schemas"]["Contract_recording_save_b717cd5d08e2c9d9"][];
            windows: {
                recording_handle: string;
                before: components["schemas"]["Contract_common_76a8fd22c9ccd9dc"];
                /** @constant */
                after: "0s";
            }[];
            capture_assessment: components["schemas"]["Contract_capture_assessment_9c7f9709a5418f1b"];
            /** @description Blocker codes; NoCurrentSource when a repeated save finds no matching running source (follow navigation_uri to list_recordings). */
            blockers: string[];
            /** Format: uri */
            navigation_uri: string;
            capture_enabled: boolean;
            incident_pod_cap: number;
        };
        Contract_recording_save_b717cd5d08e2c9d9: {
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
        /** @enum {unknown} */
        Contract_live_watch_990f10221e26ab35: "packetMetadata" | "httpHeaders" | "syscallMetadata";
        Contract_policy_authority_12c1bf2df01fe57b: {
            /** @constant */
            mode: "team";
            executor: components["schemas"]["Contract_common_864d4ca41d092930"];
            /** @constant */
            continuesAfterCreatorLeaves: true;
            /** @description Absent for an envelope without a lifetime ceiling (ADR-335 D6). */
            notAfter?: components["schemas"]["Contract_common_f06a67a70a2b97a5"];
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
            /** @description OIDC Core: sub is at most 255 ASCII characters. */
            subject: string;
            clientID: string;
            /** @enum {string} */
            identityType: "human" | "workload";
        };
        McpOutput_preview_capture: components["schemas"]["Contract_mcp_result"] & ({
            /** @constant */
            status: "ok";
            data: {
                /** @description Digest of the resolved plan: immutable target UIDs, dependencies and the normalized request. Submit it as request_capture expected_plan_digest. */
                plan_digest: string;
                execution_digest: string;
                pod_count: number;
                max_bytes: number;
                max_process_starts: number;
                approval_required: boolean;
                capture_enabled: boolean;
                blockers: {
                    code: string;
                    message: string;
                    /** @enum {unknown} */
                    responsible_role: "maintainer" | "approver" | "administrator" | "none";
                    retryable: boolean;
                }[];
                warnings: string[];
                /** Format: uri */
                navigation_uri: string;
                /** Format: uuid */
                repeated_from_capture_id?: string;
                profile_composition?: components["schemas"]["Contract_capture_composition_fea23abd809a781c"];
                lifecycle_plan: components["schemas"]["Contract_action_lifecycle_35910c4fba296505"];
                capture_assessment: components["schemas"]["Contract_capture_assessment_9c7f9709a5418f1b"] & {
                    actions?: unknown;
                };
                result_access?: components["schemas"]["Contract_investigation_access_03804ffde11279ad"];
                preset_ref?: {
                    /** @enum {unknown} */
                    name: "incident-context" | "pod-status";
                    /** @constant */
                    version: "v1";
                };
                target_ref?: {
                    /** Format: uuid */
                    cluster_id: string;
                    namespace: string;
                    /** @enum {unknown} */
                    kind: "Deployment" | "StatefulSet" | "Pod";
                    name: string;
                };
                selected_pods?: {
                    /** Format: uuid */
                    cluster_id: string;
                    namespace: string;
                    name: string;
                    uid: string;
                    workload: {
                        /** @enum {unknown} */
                        kind: "Deployment" | "StatefulSet" | "Pod";
                        name: string;
                        uid: string;
                    };
                }[];
                /**
                 * @description Selection for the fixed pod-status/v1 preset. This describes the reviewed pod, never ongoing monitoring coverage or authority to select a replacement.
                 * @enum {unknown}
                 */
                pod_selection?: "explicitPod" | "lexicalEligiblePod";
                /** @description Advisory follow-up access choices for this exact reviewed raw plan. Current authority, retained source and selected operations are checked again on submission. Absence grants no access. */
                result_access_actions?: {
                    action_id: string;
                    operations: ("download_artifact" | "get_logs" | "pcap_query" | "syscall_query")[];
                }[];
            } & unknown;
        } | {
            /** @constant */
            status: "ok";
            data: components["schemas"]["Contract_recording_save_9fa579a60a73e081"];
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
        }) & unknown;
        /** Asservat target v1 */
        Contract_target: ({
            /** @description Defaults to the object's own namespace; must equal it when given. */
            namespace?: string;
            workloadRef?: {
                /**
                 * @description Optional; derived from the kind.
                 * @enum {string}
                 */
                apiVersion?: "apps/v1" | "v1";
                /** @enum {string} */
                kind: "Deployment" | "StatefulSet" | "Pod";
                name: string;
                /** @description Optional pin with adoption: pinUID; otherwise provenance only. */
                uid?: string;
            } & unknown;
            podSelector?: {
                matchLabels: {
                    [key: string]: string;
                };
            };
            /**
             * @description Maximum pods collected per occurrence; never the monitoring coverage limit.
             * @default 1
             */
            maxPods: number;
            /**
             * @description Defaults to triggeringPod for policies and oldestReady for manual captures.
             * @enum {string}
             */
            selection?: "oldestReady" | "newest" | "allWithinLimit" | "lowestOrdinal" | "triggeringPod";
            ordinals?: number[];
            /**
             * @default followName
             * @enum {string}
             */
            adoption: "followName" | "pinUID";
        } & unknown) & (unknown | unknown);
        McpInput_request_capture: {
            /** @description Cluster name as configured in the hub (ADR-335 D4). */
            cluster?: string;
            target?: components["schemas"]["Contract_target"];
            /** @description EvidenceRecipe name; the hub records its digest (ADR-335 D4). */
            recipe?: string;
            reason?: string;
            idempotency_key: string;
            sharing?: components["schemas"]["Contract_sharing_request_23966cae8e071ea3"];
            result_access?: components["schemas"]["Contract_investigation_access_0d504ecd6bc8c0fd"];
            /** @description The preview_capture request that was reviewed (new capture, history repeat or recording save). Submission recomputes its plan. */
            preview?: ({
                target_handle?: string;
                target_ref?: {
                    /** @description Cluster name as configured in the hub (ADR-335 D4). */
                    cluster: string;
                    namespace: string;
                    /** @enum {unknown} */
                    kind: "Deployment" | "StatefulSet" | "Pod";
                    name: string;
                };
                diagnostic_handle?: string;
                preset_ref?: {
                    /** @enum {unknown} */
                    name: "incident-context" | "pod-status";
                    /** @constant */
                    version: "v1";
                };
                reason?: string;
                sharing?: components["schemas"]["Contract_sharing_request_23966cae8e071ea3"];
                /** Format: uuid */
                history_capture_id?: string;
                /** Format: uuid */
                repeated_from_capture_id?: string;
                profile_composition?: components["schemas"]["Contract_capture_composition"];
                result_access?: components["schemas"]["Contract_investigation_access_0d504ecd6bc8c0fd"];
                /** @description Requested evidence-access lifetime in seconds. Omission uses the administrator default; effective access and managed deletion remain bounded by current retention policy and its deletion budget. History restoration preserves its original request; use a normal edited preview to change it. */
                requested_retention_seconds?: number;
                /**
                 * @description Explicit manual selection when repeating a policy triggeringPod occurrence; the preview selects a current eligible Pod under the original workload identity.
                 * @enum {unknown}
                 */
                history_selection?: "currentEligiblePod";
                recording_handles?: string[];
                before?: components["schemas"]["Contract_common_76a8fd22c9ccd9dc"];
            } & (unknown & unknown)) & (((unknown | unknown) & (unknown | unknown | unknown)) | unknown | unknown);
            /** @description plan_digest of the reviewed preview. A different recomputed plan returns ReviewChanged with the differences; nothing is accepted. */
            expected_plan_digest?: string;
            /** @description Optional provenance pin: refuse when the named recipe's digest differs. */
            recipe_digest?: string;
        } & (unknown | unknown);
        McpOutput_request_capture: components["schemas"]["Contract_mcp_result"] & ({
            /** @constant */
            status: "ok";
            data: {
                /** Format: uuid */
                capture_id: string;
                phase: string;
                sharing_intent_id?: components["schemas"]["Contract_common_2224a31324a0c811"];
                /** Format: uri */
                sharing_navigation_uri?: string;
                /** Format: uri */
                navigation_uri: string;
                /** Format: uuid */
                repeated_from_capture_id?: string;
                /** @enum {unknown} */
                operation?: "collect" | "recordingSave";
                /** @enum {unknown} */
                history_state?: "available" | "unavailable";
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
        });
        McpInput_get_capture: {
            /** Format: uuid */
            capture_id: string;
            /**
             * @description status (default) reads progress; settings reads the retained immutable parameter snapshot for review/editing: no old grants, secrets, reason or sharing. Settings above the 96 KiB MCP result bound return SettingsTooLarge with browser navigation; repeat by reference still works.
             * @enum {unknown}
             */
            view?: "status" | "settings";
            /** @description Wait server-side until the state revision differs from this value or 30 seconds pass, then return the current state. Omit for an immediate read. Status reads are never charged. */
            after_revision?: number;
        };
        Contract_investigation_access_0b2b78f874cf920d: {
            /** @enum {unknown} */
            state: "NotRequested" | "AwaitingReview" | "WaitingForArtifacts" | "Ready" | "Partial" | "Expired" | "Revoked" | "Unavailable";
            scopeDigest?: string;
            grantIDs?: string[];
            reason?: string;
        };
        Contract_capture_history_6f7c512573a1694c: {
            /** @constant */
            kind: "captureSettings";
            /** Format: uuid */
            capture_id: string;
            /** Format: uuid */
            cluster_id: string;
            /** @description Configured name of the cluster (ADR-335 D4) that a repeat addresses; absent when that cluster is no longer configured. */
            cluster?: string;
            namespace_uid: string;
            /** Format: date-time */
            accepted_at: string;
            /** Format: date-time */
            expires_at: string;
            settings_digest: string;
            original_execution_digest: string;
            settings: components["schemas"]["Contract_capture_history_69de8902a1418e08"];
            /** Format: uri */
            navigation_uri: string;
        };
        Contract_capture_history_69de8902a1418e08: {
            target: components["schemas"]["Contract_target"];
            recipe_spec: components["schemas"]["Contract_recipe_ad816c81a7733f89"];
            dependency_pins: components["schemas"]["Contract_collection_scope_d82f582d45541458"];
            requested_retention?: components["schemas"]["Contract_common_76a8fd22c9ccd9dc"];
            profile_composition?: components["schemas"]["Contract_capture_composition_fea23abd809a781c"];
            original_effective_retention?: components["schemas"]["Contract_common_76a8fd22c9ccd9dc"];
        };
        Contract_recipe_ad816c81a7733f89: {
            description: string;
            actions: components["schemas"]["Contract_action"][];
            maxTotalBytes: number;
            maxDuration: string;
            endpointBindings?: {
                name: string;
                templateRef: string;
                /** @enum {string} */
                addressMode: "targetLoopback" | "podIP";
                portName: string;
            }[];
        };
        /** Asservat action v1 */
        Contract_action: {
            $defs: {
                processSelector: {
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
                batch: {
                    /** @description The default batch covers every resolved main process of the Pod, sidecars included; the batch is bounded by maxProcesses × maxBytesPerProcess ≤ the action maxBytes and by maxTotalStop. */
                    maxProcesses: number;
                    /** @description Bounded only by the action and capture byte budget. */
                    maxBytesPerProcess: number;
                    maxStopPerProcess: components["schemas"]["Contract_common_76a8fd22c9ccd9dc"];
                    maxTotalStop: components["schemas"]["Contract_common_76a8fd22c9ccd9dc"];
                    /** @constant */
                    consistency: "sequential";
                };
            };
        } & ({
            id: string;
            /** @constant */
            kind: "kubernetesSnapshot";
            parameters: {
                include: ("pod" | "workload" | "events" | "endpoints" | "rollout")[];
            };
            dependsOn?: string[];
            required: boolean;
            /** @enum {string} */
            impact: "observe" | "sensitiveRead" | "intrusive";
            limits: components["schemas"]["Contract_common_118dfa56ea0142d0"];
            /**
             * @default onTrigger
             * @constant
             */
            executionMode: "onTrigger";
        } | {
            id: string;
            /** @constant */
            kind: "logs";
            parameters: {
                before: string;
                after: string;
                /** @enum {string} */
                stream: "stdout" | "stderr" | "both";
            };
            dependsOn?: string[];
            required: boolean;
            /** @enum {string} */
            impact: "observe" | "sensitiveRead" | "intrusive";
            limits: components["schemas"]["Contract_common_118dfa56ea0142d0"];
            /**
             * @default onTrigger
             * @constant
             */
            executionMode: "onTrigger";
        } | {
            id: string;
            /** @constant */
            kind: "processSnapshot";
            parameters: {
                include: ("status" | "limits" | "maps" | "smaps_rollup" | "threads" | "fdMetadata" | "cgroups" | "identity")[];
            };
            dependsOn?: string[];
            required: boolean;
            /** @enum {string} */
            impact: "observe" | "sensitiveRead" | "intrusive";
            limits: components["schemas"]["Contract_common_118dfa56ea0142d0"];
            /**
             * @default onTrigger
             * @constant
             */
            executionMode: "onTrigger";
        } | {
            id: string;
            /** @constant */
            kind: "fileRead";
            parameters: {
                /** @enum {string} */
                namespace: "podRoots" | "targetProc" | "runtimeOutput";
                path: string;
                /** @enum {string} */
                process: "podMainProcesses" | "allPodProcesses";
            };
            dependsOn?: string[];
            required: boolean;
            /** @enum {string} */
            impact: "observe" | "sensitiveRead" | "intrusive";
            limits: components["schemas"]["Contract_common_118dfa56ea0142d0"];
            /**
             * @default onTrigger
             * @constant
             */
            executionMode: "onTrigger";
        } | ({
            id: string;
            /** @constant */
            kind: "packetCapture";
            parameters: components["schemas"]["Contract_packet_capture"];
            dependsOn?: string[];
            required: boolean;
            /** @enum {string} */
            impact: "observe" | "sensitiveRead" | "intrusive";
            limits: components["schemas"]["Contract_common_118dfa56ea0142d0"];
            /**
             * @default ongoing
             * @enum {unknown}
             */
            executionMode: "onTrigger" | "ongoing";
        } & (unknown & unknown)) | {
            id: string;
            /** @constant */
            kind: "networkSnapshot";
            parameters: {
                include: ("addresses" | "routes" | "sockets" | "counters" | "socketOwners")[];
            };
            dependsOn?: string[];
            required: boolean;
            /** @enum {string} */
            impact: "observe" | "sensitiveRead" | "intrusive";
            limits: components["schemas"]["Contract_common_118dfa56ea0142d0"];
            /**
             * @default onTrigger
             * @constant
             */
            executionMode: "onTrigger";
        } | {
            id: string;
            /** @constant */
            kind: "runtimeDiagnostic";
            parameters: {
                /** @enum {string} */
                runtime: "native" | "go" | "dotnet" | "python" | "node" | "jvm" | "cuda";
                /** @enum {string} */
                operation: "stacks" | "report" | "heap" | "counters" | "trace" | "gpuDump";
                profileRef?: string;
            };
            dependsOn?: string[];
            required: boolean;
            /** @constant */
            impact: "intrusive";
            limits: components["schemas"]["Contract_common_118dfa56ea0142d0"];
            /**
             * @default onTrigger
             * @constant
             */
            executionMode: "onTrigger";
        } | {
            id: string;
            /** @constant */
            kind: "kernelCore";
            parameters: {
                profileRef: string;
            };
            dependsOn?: string[];
            required: boolean;
            /** @enum {string} */
            impact: "observe" | "sensitiveRead" | "intrusive";
            limits: components["schemas"]["Contract_common_118dfa56ea0142d0"];
            /**
             * @default onTrigger
             * @constant
             */
            executionMode: "onTrigger";
        } | {
            id: string;
            /** @constant */
            kind: "liveCore";
            parameters: {
                profileRef: string;
                /** @enum {string} */
                process: "podMainProcesses" | "selectedPID" | "matchedProcesses";
                processIdentity?: {
                    podUID: string;
                    nodeBootID: components["schemas"]["Contract_common_2224a31324a0c811"];
                    hostPID: number;
                    startTimeTicks: number;
                };
                processSelector?: components["schemas"]["Contract_action_f252bcf961e0afcb"];
                batch?: components["schemas"]["Contract_action_e8308e53a77c994b"];
            } & (unknown & unknown);
            dependsOn?: string[];
            required: boolean;
            /** @constant */
            impact: "intrusive";
            limits: components["schemas"]["Contract_common_118dfa56ea0142d0"];
            /**
             * @default onTrigger
             * @constant
             */
            executionMode: "onTrigger";
        } | {
            id: string;
            /** @constant */
            kind: "command";
            parameters: {
                argv: string[];
                /** @description Linux PATH_MAX (4096 bytes). */
                workingDirectory: string;
                environmentNames?: string[];
                /** @enum {string} */
                adapter: "podsExec" | "qualifiedRuntime";
            };
            dependsOn?: string[];
            required: boolean;
            /** @constant */
            impact: "intrusive";
            limits: components["schemas"]["Contract_common_118dfa56ea0142d0"];
            /**
             * @default onTrigger
             * @constant
             */
            executionMode: "onTrigger";
        } | {
            id: string;
            /** @constant */
            kind: "httpDiagnostic";
            parameters: {
                endpointRef: string;
                path: string;
                /** @constant */
                method: "GET";
            };
            dependsOn?: string[];
            required: boolean;
            /** @enum {string} */
            impact: "observe" | "sensitiveRead" | "intrusive";
            limits: components["schemas"]["Contract_common_118dfa56ea0142d0"];
            /**
             * @default onTrigger
             * @constant
             */
            executionMode: "onTrigger";
        } | {
            id: string;
            /** @constant */
            kind: "artifactCollect";
            parameters: {
                path: string;
                /** @enum {string} */
                format: "elf-core" | "dotnet-dump" | "hprof" | "node-report" | "cuda-core" | "text";
                settleFor: string;
            };
            dependsOn?: string[];
            required: boolean;
            /** @enum {string} */
            impact: "observe" | "sensitiveRead" | "intrusive";
            limits: components["schemas"]["Contract_common_118dfa56ea0142d0"];
            /**
             * @default onTrigger
             * @constant
             */
            executionMode: "onTrigger";
        } | {
            id: string;
            /** @constant */
            kind: "profile";
            parameters: {
                /** @enum {unknown} */
                runtime: "go" | "dotnet" | "jvm" | "node" | "python" | "native" | "any";
                /** @enum {unknown} */
                type: "cpu" | "heap" | "allocs" | "goroutine" | "block" | "mutex" | "threadcreate" | "offCpu" | "wall" | "lock" | "events" | "runtimeTrace";
                source: {
                    /** @enum {unknown} */
                    kind: "httpEndpoint" | "runtimeSocket" | "runtimeFile" | "nativeAttach" | "gadget" | "ebpfSampler";
                    profileRef?: string;
                } & unknown;
                duration?: components["schemas"]["Contract_common_76a8fd22c9ccd9dc"];
                /** @description Bounded by the node's kernel.perf_event_max_sample_rate, which the kernel lowers itself under load. */
                frequencyHz?: number;
                forceGC: boolean;
                /** @enum {unknown} */
                mode: "snapshot" | "cumulative" | "delta" | "interval";
            } & (unknown & unknown & unknown & unknown & unknown);
            dependsOn?: string[];
            required: boolean;
            /**
             * @description observe for pprof GETs and the eBPF sampler; intrusive for forced GC, sampling changes, traces and attached profilers (ADR-335 D5).
             * @enum {string}
             */
            impact: "observe" | "intrusive";
            limits: components["schemas"]["Contract_common_118dfa56ea0142d0"];
            /**
             * @default onTrigger
             * @constant
             */
            executionMode: "onTrigger";
        } | ({
            id: string;
            /** @constant */
            kind: "syscallTrace";
            parameters: components["schemas"]["Contract_syscall_trace"];
            dependsOn?: string[];
            required: boolean;
            /** @enum {string} */
            impact: "observe" | "sensitiveRead" | "intrusive";
            limits: components["schemas"]["Contract_common_118dfa56ea0142d0"];
            /**
             * @default ongoing
             * @enum {unknown}
             */
            executionMode: "onTrigger" | "ongoing";
        } & (unknown & unknown)));
        Contract_common_118dfa56ea0142d0: {
            maxBytes: number;
            timeout: string;
        };
        /** Bounded pod-wide syscall acquisition parameters */
        Contract_syscall_trace: {
            /** @constant */
            processes: "allPodProcesses";
            /** @enum {unknown} */
            mode: "metadata" | "arguments";
            before: "0s" | components["schemas"]["Contract_common_76a8fd22c9ccd9dc"];
            after: "0s" | components["schemas"]["Contract_common_76a8fd22c9ccd9dc"];
            syscalls: {
                /** @constant */
                mode: "all";
            } | {
                /** @constant */
                mode: "include";
                names: string[];
            };
            /** @enum {unknown} */
            result: "all" | "errors";
            ring: components["schemas"]["Contract_packet_capture_8b1a78e06ce5adec"];
            /** @description Reviewed observation rate; the shipped default is derived from measured per-node collector event throughput. With the ring, it bounds every trace; there is no lifetime event total (ADR-335 D6). */
            maxEventsPerSecond: number;
            /** @description Sizes the eBPF per-thread map (memory per tracked thread); derived from the collector map memory budget. */
            maxTrackedThreads: number;
            arguments?: {
                maxBytesPerEvent: number;
                captureBuffers: boolean;
            };
        } & unknown;
        Contract_collection_scope_d82f582d45541458: {
            /** @enum {unknown} */
            role: "recipe" | "collectionCeiling" | "retention" | "endpointTemplate" | "runtimePack" | "preset" | "projection" | "approvalPolicy" | "captureProfile" | "collector";
            digest: string;
            /** @description Source object of an organization or namespace captureProfile dependency. A release-embedded builtin profile (ADR-243) has none; its profileComposition provenance names the builtin catalog. */
            source?: components["schemas"]["Contract_collection_scope_4ad7f6b328929f94"];
        }[];
        Contract_collection_scope_4ad7f6b328929f94: {
            /** Format: uuid */
            clusterID: string;
            namespaceUID: string;
            resourceUID: string;
        };
        Contract_recording_save_f55cbe756b7a0883: {
            /** @constant */
            kind: "recordingSaveSettings";
            /** @constant */
            operation: "recordingSave";
            /** Format: uuid */
            capture_id: string;
            /** Format: uuid */
            cluster_id: string;
            /** @description Configured name of the cluster (ADR-335 D4) that a repeat addresses; absent when that cluster is no longer configured. */
            cluster?: string;
            namespace_uid: string;
            /** Format: date-time */
            accepted_at: string;
            /** Format: date-time */
            expires_at: string;
            settings_digest: components["schemas"]["Contract_common_9cbf92fb972157c6"];
            original_execution_digest: components["schemas"]["Contract_common_9cbf92fb972157c6"];
            settings: {
                target: components["schemas"]["Contract_target"];
                policy: {
                    /** Format: uuid */
                    clusterID: string;
                    namespaceUID: string;
                    policyUID: string;
                    executionDigest: components["schemas"]["Contract_common_9cbf92fb972157c6"];
                };
                action_windows: {
                    actionID: string;
                    before: components["schemas"]["Contract_common_76a8fd22c9ccd9dc"];
                }[];
            };
            /** Format: uri */
            navigation_uri: string;
        };
        McpOutput_get_capture: components["schemas"]["Contract_mcp_result"] & ({
            /** @constant */
            status: "ok";
            data: {
                /** Format: uuid */
                capture_id: string;
                revision: number;
                /** @enum {unknown} */
                phase: "Pending" | "AwaitingApproval" | "Armed" | "Running" | "Succeeded" | "Partial" | "Failed" | "Cancelled" | "Indeterminate";
                actions: {
                    action_id: string;
                    /** @enum {unknown} */
                    phase: "Pending" | "WaitingApproval" | "Queued" | "Running" | "Finalizing" | "Succeeded" | "Partial" | "Skipped" | "Denied" | "TimedOut" | "Failed" | "TargetGone" | "Unsupported" | "Indeterminate" | "Cancelled";
                    /** @description Bounded stable action reason. Failed Go profile acquisition reports ProfileUnavailable when the endpoint is unavailable or disabled, or ProfilerBusy for an existing conflicting profiling session that Asservat did not stop. Other existing reason strings retain their current meaning; a reason never authorizes retry or replacement. */
                    reason_code?: string;
                    /**
                     * Format: uuid
                     * @description Exact child identity within this parent save. It is not a separate navigation or retry target.
                     */
                    action_instance_id?: string;
                    pod_uid?: string;
                    pod_name?: string;
                }[];
                /** Format: uuid */
                case_id?: string;
                /** Format: uri */
                navigation_uri: string;
                /** Format: uri */
                approval_navigation_uri?: string;
                /** Format: uuid */
                grant_id?: string;
                can_cancel: boolean;
                blockers: {
                    code: string;
                    message: string;
                    /** @enum {unknown} */
                    responsible_role: "maintainer" | "approver" | "administrator" | "none";
                    retryable: boolean;
                }[];
                /** Format: uuid */
                repeated_from_capture_id?: string;
                /** @enum {unknown} */
                operation?: "collect" | "recordingSave";
                result_access?: components["schemas"]["Contract_investigation_access_0b2b78f874cf920d"];
                /** @description Capture-time sharing status, reported separately from collection progress. Present only when the request included sharing. Shared names the concrete share; SharingUnavailable means the result was not shared (collection outcome is unaffected). */
                sharing?: {
                    /** @enum {unknown} */
                    state: "Pending" | "Shared" | "SharingUnavailable";
                    /** Format: uuid */
                    share_id?: string;
                };
                /** @enum {unknown} */
                history_state?: "available" | "unavailable";
                cancellation_requested?: boolean;
                /** @description Authorized parent Save reason, preserved verbatim; never restored on repeat. */
                reason?: string;
                /**
                 * @description Omitted when no reason was supplied. Unavailable descriptive metadata does not block capture status.
                 * @enum {unknown}
                 */
                reason_state?: "available" | "unavailable";
            } & (unknown & unknown);
        } | {
            /** @constant */
            status: "ok";
            data: components["schemas"]["Contract_capture_history_6f7c512573a1694c"] | components["schemas"]["Contract_recording_save_f55cbe756b7a0883"];
            /** @constant */
            data_class?: "extract";
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
        McpInput_cancel_capture: {
            /** Format: uuid */
            capture_id: string;
            expected_revision: number;
            idempotency_key: string;
        };
        McpOutput_cancel_capture: components["schemas"]["Contract_mcp_result"] & ({
            /** @constant */
            status: "ok";
            data: {
                /** Format: uuid */
                capture_id: string;
                /** @enum {unknown} */
                phase: "Pending" | "AwaitingApproval" | "Armed" | "Running" | "Succeeded" | "Partial" | "Failed" | "Cancelled" | "Indeterminate";
                revision: number;
                cancellation_requested: boolean;
                /** Format: uri */
                navigation_uri: string;
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
        });
        McpInput_list_capture_history: {
            target_handle?: string;
            target_ref?: {
                /** @description Cluster name as configured in the hub (ADR-335 D4). */
                cluster: string;
                namespace: string;
                /** @enum {unknown} */
                kind: "Deployment" | "StatefulSet" | "Pod";
                name: string;
            };
            /** @description Cluster name as configured in the hub (ADR-335 D4). */
            cluster?: string;
            target?: components["schemas"]["Contract_target"];
            /** @enum {unknown} */
            origin?: "manual" | "policy" | "discovery" | "all";
            cursor?: string;
            limit?: number;
        } & (unknown | unknown | unknown);
        Contract_capture_history_5bb857fd69a5246d: {
            /** @constant */
            kind: "captureHistoryPage";
            history: components["schemas"]["Contract_capture_history_d3f629e9c1ad4b52"][];
            /** @constant */
            ordering: "acceptedAtDescCaptureIDDesc";
        };
        Contract_capture_history_d3f629e9c1ad4b52: {
            /** Format: uuid */
            capture_id: string;
            /** @enum {unknown} */
            origin: "manual" | "policy" | "discovery";
            /** Format: date-time */
            accepted_at: string;
            /** Format: date-time */
            summary_expires_at: string;
            /** @enum {unknown} */
            phase: "Pending" | "AwaitingApproval" | "Armed" | "Running" | "Succeeded" | "Partial" | "Failed" | "Cancelled" | "Indeterminate";
            action_kinds: ("kubernetesSnapshot" | "logs" | "processSnapshot" | "fileRead" | "packetCapture" | "networkSnapshot" | "runtimeDiagnostic" | "kernelCore" | "liveCore" | "command" | "httpDiagnostic" | "artifactCollect" | "profile" | "syscallTrace")[];
            /** @enum {unknown} */
            evidence_state: "pending" | "available" | "partial" | "expired" | "unavailable";
            /** @enum {unknown} */
            repeat_state: "available" | "requiresSelection" | "parametersExpired" | "parametersUnavailable" | "targetUnavailable";
            /** Format: date-time */
            settings_expires_at?: string;
            /** Format: uuid */
            repeated_from_capture_id?: string;
            /** Format: uri */
            navigation_uri: string;
            /** @enum {unknown} */
            operation?: "collect" | "recordingSave";
            requester?: {
                /** Format: uri */
                issuer: string;
                subject_id: string;
                /** @enum {unknown} */
                identity_type: "human" | "service" | "policy";
            };
        } & (unknown & unknown);
        McpOutput_list_capture_history: components["schemas"]["Contract_mcp_result"] & ({
            /** @constant */
            status: "ok";
            data: components["schemas"]["Contract_capture_history_5bb857fd69a5246d"];
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
        McpInput_get_capture_profile: {
            target_handle?: string;
            profile_ref: components["schemas"]["Contract_capture_composition_f1d3ea703d6af495"];
            target_ref?: {
                /** @description Cluster name as configured in the hub (ADR-335 D4). */
                cluster: string;
                namespace: string;
                /** @enum {unknown} */
                kind: "Deployment" | "StatefulSet" | "Pod";
                name: string;
            };
        } & (unknown | unknown);
        Contract_capture_profile_657e00232a612262: {
            displayName: string;
            description: string;
            recipe: components["schemas"]["Contract_recipe_ad816c81a7733f89"];
            editableFields: {
                actionID: string;
                /** @enum {unknown} */
                field: "packetPeers" | "packetFilter" | "packetBefore" | "packetAfter" | "packetRing" | "processSelector" | "processBatch" | "profileDuration" | "syscallFilter" | "syscallMode" | "syscallBefore" | "syscallAfter" | "syscallRing" | "syscallArguments" | "syscallRate" | "filePath" | "commandArgv" | "actionMaxBytes" | "actionTimeout" | "actionExecutionMode" | "logBefore" | "logAfter" | "logStream";
                label: string;
                description?: string;
            }[];
        };
        McpOutput_get_capture_profile: components["schemas"]["Contract_mcp_result"] & ({
            /** @constant */
            status: "ok";
            data: {
                profile_ref: components["schemas"]["Contract_capture_composition_f1d3ea703d6af495"];
                definition_digest: string;
                definition: components["schemas"]["Contract_capture_profile_657e00232a612262"];
            };
            /** @constant */
            data_class?: "extract";
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
    };
    responses: never;
    parameters: never;
    requestBodies: never;
    headers: never;
    pathItems: never;
}
export type $defs = Record<string, never>;
export type operations = Record<string, never>;
