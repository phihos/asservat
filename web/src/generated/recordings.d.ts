// Generated from canonical browser OpenAPI. Run npm run generate; do not edit.
export type paths = Record<string, never>;
export type webhooks = Record<string, never>;
export interface components {
    schemas: {
        McpInput_list_recordings: {
            policy_uid?: string;
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
        Contract_recording_save_5bb857fd69a5246d: {
            /** @constant */
            kind: "recordingPage";
            recordings: components["schemas"]["Contract_recording_save_b717cd5d08e2c9d9"][];
            capture_enabled: boolean;
            /** Format: date-time */
            expires_at: string;
        };
        Contract_recording_save_b717cd5d08e2c9d9: {
            recording_handle?: string;
            policy_uid: string;
            policy_name?: string;
            pod_uid: string;
            pod_name: string;
            action_id: string;
            /** @enum {unknown} */
            kind: "packetCapture" | "syscallTrace";
            /** @enum {unknown} */
            state: "Unknown" | "Ready" | "Armed" | "Warming" | "Degraded" | "Stopped" | "Expired" | "Unavailable";
            /** @enum {unknown} */
            history: "Unknown" | "Full" | "Partial" | "None";
            maximum_before: components["schemas"]["Contract_common_76a8fd22c9ccd9dc"] | "0s";
            save_eligible: boolean;
            blockers: string[];
            incident_pod_cap: number;
            /** Format: date-time */
            handle_expires_at?: string;
            available_before_seconds?: number;
            /** Format: date-time */
            observed_at?: string;
            execution_authority?: components["schemas"]["Contract_policy_authority_12c1bf2df01fe57b"];
        } & unknown;
        Contract_common_76a8fd22c9ccd9dc: string;
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
        McpInput_preview_recording_save: {
            recording_handles: string[];
            before?: components["schemas"]["Contract_common_76a8fd22c9ccd9dc"];
            /** @description Optional Unicode scalars preserved verbatim; omit when absent. Empty is invalid. Repeat does not restore it. */
            reason?: string;
            sharing?: components["schemas"]["Contract_sharing_request_23966cae8e071ea3"];
            /** Format: uuid */
            repeated_from_capture_id?: string;
        };
        Contract_recording_save_9fa579a60a73e081: {
            /** @constant */
            kind: "recordingSavePreview";
            /** @constant */
            operation: "recordingSave";
            /** Format: uuid */
            preview_id: string;
            /** Format: uuid */
            capture_id: string;
            /** Format: date-time */
            expires_at: string;
            save_scope_digest: components["schemas"]["Contract_common_9cbf92fb972157c6"];
            selected_recordings: components["schemas"]["Contract_recording_save_b717cd5d08e2c9d9"][];
            windows: {
                recording_handle: string;
                before: components["schemas"]["Contract_common_76a8fd22c9ccd9dc"];
                /** @constant */
                after: "0s";
            }[];
            capture_assessment: components["schemas"]["Contract_capture_assessment_9c7f9709a5418f1b"];
            blockers: string[];
            /** Format: uri */
            navigation_uri: string;
            capture_enabled: boolean;
            incident_pod_cap: number;
        };
        Contract_common_9cbf92fb972157c6: string;
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
        McpOutput_preview_recording_save: components["schemas"]["Contract_mcp_result"] & ({
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
