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
                /** Format: uuid */
                cluster_id: string;
                namespace: string;
                /** @enum {unknown} */
                kind: "Deployment" | "StatefulSet" | "Pod";
                name: string;
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
                } & unknown) & (unknown | unknown))[];
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
        Contract_sharing_request_23966cae8e071ea3: {
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
                    operations?: ("get_case" | "list_artifacts" | "get_timeline" | "get_backtrace" | "get_runtime_summary" | "get_profile_summary" | "get_pcap_summary" | "get_zeek_log" | "get_file_excerpt" | "get_logs" | "read_memory" | "debugger_command" | "pcap_query" | "list_cases" | "find_similar_cases" | "compare_profiles" | "get_query_result" | "get_http_headers" | "syscall_query" | "get_syscall_summary" | "get_syscall_events" | "download_artifact")[];
                } & unknown)[];
            };
            notAfter?: components["schemas"]["Contract_common_f06a67a70a2b97a5"];
            /** @default 64 */
            maxArtifactsPerCapture: number;
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
            maxTotalBytes: number;
            maxDuration: components["schemas"]["Contract_common_76a8fd22c9ccd9dc"];
            $defs: {
                profileRef: {
                    /** @enum {unknown} */
                    catalog: "builtin" | "organization" | "namespace";
                    name: string;
                    version: string;
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
                    field: "syscallMaxEvents";
                    value: components["schemas"]["Contract_syscall_trace_7af1b59de58e9115"];
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
                resolvedProfile: {
                    componentID: string;
                    profileRef: components["schemas"]["Contract_capture_composition_f1d3ea703d6af495"];
                    sourceUID: string;
                    definitionDigest: string;
                    /** Format: uuid */
                    sourceClusterID: string;
                    sourceNamespaceUID: string;
                };
                provenance: {
                    authored: components["schemas"]["Contract_capture_composition"];
                    resolvedProfiles: components["schemas"]["Contract_capture_composition_d3d99d35a2742711"][];
                    actionMap: components["schemas"]["Contract_capture_composition_6256ac1ffa3775a5"][];
                };
            };
        };
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
            maxEndpoints: number;
            maxStaleness: components["schemas"]["Contract_common_76a8fd22c9ccd9dc"];
        };
        Contract_common_76a8fd22c9ccd9dc: string;
        Contract_packet_capture_bd5424e783362da5: string;
        Contract_packet_capture_3cabf6dd4f1621f2: string;
        Contract_packet_capture_c29139839890e47d: string;
        Contract_packet_capture_8b1a78e06ce5adec: {
            maxAge: components["schemas"]["Contract_common_76a8fd22c9ccd9dc"];
            maxBytes: number;
            segmentBytes: number;
            maxSegments: number;
            /** @enum {unknown} */
            medium: "memory" | "encryptedDisk";
            storageProfileRef?: string;
        } & unknown;
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
        Contract_action_e8308e53a77c994b: {
            maxProcesses: number;
            maxBytesPerProcess: number;
            maxStopPerProcess: components["schemas"]["Contract_common_76a8fd22c9ccd9dc"];
            maxTotalStop: components["schemas"]["Contract_common_76a8fd22c9ccd9dc"];
            /** @constant */
            consistency: "sequential";
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
        Contract_syscall_trace_7af1b59de58e9115: number;
        Contract_syscall_trace_09825459ded300c7: number;
        Contract_capture_composition_f1d3ea703d6af495: {
            /** @enum {unknown} */
            catalog: "builtin" | "organization" | "namespace";
            name: string;
            version: string;
        };
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
            field: "syscallMaxEvents";
            value: components["schemas"]["Contract_syscall_trace_7af1b59de58e9115"];
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
        };
        Contract_capture_composition_d3d99d35a2742711: {
            componentID: string;
            profileRef: components["schemas"]["Contract_capture_composition_f1d3ea703d6af495"];
            sourceUID: string;
            definitionDigest: string;
            /** Format: uuid */
            sourceClusterID: string;
            sourceNamespaceUID: string;
        };
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
        Contract_investigation_access_0d504ecd6bc8c0fd: {
            actionIds: string[];
            operations: ("read_memory" | "debugger_command" | "pcap_query" | "syscall_query" | "download_artifact")[];
            clientIDs: string[];
            maxArtifacts: number;
            maxBytes: number;
            maxOperations: number;
            /** Format: date-time */
            notAfter: string;
        };
        McpInput_preview_capture: {
            target_handle?: string;
            target_ref?: {
                /** Format: uuid */
                cluster_id: string;
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
        } & (((unknown | unknown) & (unknown | unknown | unknown)) | unknown);
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
                kind: "kubernetesSnapshot" | "logs" | "processSnapshot" | "fileRead" | "packetCapture" | "networkSnapshot" | "runtimeDiagnostic" | "kernelCore" | "liveCore" | "command" | "httpDiagnostic" | "artifactCollect" | "profile" | "syscallTrace";
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
            /** Format: date-time */
            validUntil: string;
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
             * @description submissionPreparation measures from preparation of the first admitted submission: waiting counts and accepted retries retain the original registration. firstAcquisitionOrEarlierSource measures from acquisition or an earlier retained source.
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
            operations: ("read_memory" | "debugger_command" | "pcap_query" | "syscall_query" | "download_artifact")[];
            clientIDs: string[];
            maxArtifacts: number;
            maxBytes: number;
            maxOperations: number;
            /** Format: date-time */
            notAfter: string;
            digest: string;
        };
        McpOutput_preview_capture: components["schemas"]["Contract_mcp_result"] & ({
            /** @constant */
            status: "ok";
            data: {
                /** Format: uuid */
                preview_id: string;
                /** Format: date-time */
                expires_at: string;
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
                capture_assessment: components["schemas"]["Contract_capture_assessment_9c7f9709a5418f1b"];
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
            } & unknown;
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
        }) & unknown;
        /** Asservat target v1 */
        Contract_target: ({
            namespace: string;
            workloadRef?: {
                /** @enum {string} */
                apiVersion: "apps/v1" | "v1";
                /** @enum {string} */
                kind: "Deployment" | "StatefulSet" | "Pod";
                name: string;
                uid?: string;
            } & unknown;
            podSelector?: {
                matchLabels: {
                    [key: string]: string;
                };
            };
            /** @description Maximum pods collected per occurrence; never the monitoring coverage limit. */
            maxPods: number;
            /** @enum {string} */
            selection: "oldestReady" | "newest" | "allWithinLimit" | "lowestOrdinal" | "triggeringPod";
            ordinals?: number[];
            /** @enum {string} */
            adoption: "pinUID" | "followApprovedReplacement";
        } & unknown) & (unknown | unknown);
        McpInput_request_capture: {
            /** Format: uuid */
            cluster_id?: string;
            target?: components["schemas"]["Contract_target"];
            recipe_digest?: string;
            reason?: string;
            idempotency_key: string;
            sharing?: components["schemas"]["Contract_sharing_request_23966cae8e071ea3"];
            /** Format: uuid */
            preview_id?: string;
            result_access?: components["schemas"]["Contract_investigation_access_0d504ecd6bc8c0fd"];
            /**
             * @description Explicitly continue acquisition for an already accepted original preview and request key using current permissions. Omission preserves passive accepted replay. This cannot admit a missing request, create another attempt, renew a start interval, or retry uncertain key preparation.
             * @constant
             */
            continue_acquisition?: true;
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
        McpInput_resolve_capture_request: {
            /** Format: uuid */
            preview_id: string;
            idempotency_key: string;
        };
        McpOutput_resolve_capture_request: components["schemas"]["Contract_mcp_result"] & ({
            /** @constant */
            status: "ok";
            data: {
                /** Format: uuid */
                capture_id: string;
                /** @constant */
                phase: "Accepted";
                /** Format: uri */
                navigation_uri: string;
                /** @constant */
                operation: "collect";
                /** @constant */
                state: "accepted";
            } | {
                /** @constant */
                state: "closed";
            };
            /** @constant */
            data_class?: "metadata";
            /** @constant */
            truncated?: false;
            next_cursor?: null;
            narrowing_hint?: null;
            warnings?: unknown[];
            provenance?: unknown[];
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
        };
        Contract_investigation_access_0b2b78f874cf920d: {
            /** @enum {unknown} */
            state: "NotRequested" | "AwaitingReview" | "WaitingForArtifacts" | "Ready" | "Partial" | "Expired" | "Revoked" | "Unavailable";
            scopeDigest?: string;
            grantIDs?: string[];
            reason?: string;
        };
        McpOutput_get_capture: components["schemas"]["Contract_mcp_result"] & ({
            /** @constant */
            status: "ok";
            data: {
                /** Format: uuid */
                capture_id: string;
                revision: number;
                /** @enum {unknown} */
                phase: "Pending" | "Validating" | "AwaitingApproval" | "Armed" | "Queued" | "Running" | "Finalizing" | "Succeeded" | "Partial" | "Failed" | "Cancelled" | "Indeterminate";
                actions: {
                    action_id: string;
                    /** @enum {unknown} */
                    phase: "Pending" | "WaitingApproval" | "Queued" | "Running" | "Finalizing" | "Succeeded" | "Partial" | "Skipped" | "Denied" | "TimedOut" | "Failed" | "TargetGone" | "Unsupported" | "Indeterminate";
                    reason_code?: string;
                }[];
                /** Format: uuid */
                case_id?: string;
                /** Format: uri */
                navigation_uri: string;
                /** Format: uri */
                approval_navigation_uri?: string;
                /** Format: uuid */
                grant_id?: string;
                retry_after_seconds?: number;
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
