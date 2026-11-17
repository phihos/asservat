// Generated from canonical browser OpenAPI. Run npm run generate; do not edit.
export type paths = Record<string, never>;
export type webhooks = Record<string, never>;
export interface components {
    schemas: {
        McpInput_get_case: {
            /** Format: uuid */
            case_id: string;
            /** @description Continues the timeline. */
            cursor?: string;
            /** @description Timeline events per page. */
            limit?: number;
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
        Contract_capture_assessment_896e91b8fce79799: {
            classification: components["schemas"]["Contract_privacy_common_cf52919b29fc225a"];
            mayContain: ("userContent" | "credentials" | "personalIdentifiers" | "networkAddresses" | "paths" | "profileLabels" | "unknownApplicationData")[];
            /** Format: date-time */
            expiresAt: string;
            /** Format: date-time */
            deleteBy: string;
            /** @enum {unknown} */
            deletionState: "pending" | "verified" | "overdue" | "restrictedPreservation";
            /** @constant */
            automaticDeletion: true;
            /** @constant */
            managedCopiesOnly: true;
            /** @constant */
            externalCopiesRecallable: false;
            handlingCodes: ("minimizeCapture" | "restrictAccess" | "preferApprovedExtracts" | "reviewBeforeSharing" | "approvedClientsOnly" | "externalCopiesNotRecalled")[];
            preservationException: boolean;
            /** Format: date-time */
            asOf: string;
            handlingPolicyRef?: string;
        } & unknown;
        /** @enum {string} */
        Contract_privacy_common_cf52919b29fc225a: "unknown" | "potentialPersonalData" | "personalData" | "specialCategoryPossible" | "verifiedNonPersonal";
        McpOutput_get_case: components["schemas"]["Contract_mcp_result"] & ({
            /** @constant */
            status: "ok";
            data: {
                case: {
                    /** Format: uuid */
                    case_id: string;
                    title?: string;
                    status: string;
                    /** @enum {string} */
                    access: "ordinary" | "shared";
                    /** Format: date-time */
                    updated_at?: string;
                    /** Format: uuid */
                    cluster_id?: string;
                };
                /** @description First 100 artifacts (page size); list_artifacts pages through all of them. */
                artifacts: ({
                    /** Format: uuid */
                    artifact_id: string;
                    /** @description Immutable verified artifact version. For the current pod-status artifact this is SHA-256 of the existing serialized verified ciphertext copy receipts, not the native file checksum. The prepared download supplies the native SHA-256 separately. */
                    digest: string;
                    kind: string;
                    /** @enum {string} */
                    data_class: "metadata" | "extract" | "raw";
                    completeness: string;
                    /** Format: date-time */
                    expires_at: string;
                    handling_notice: components["schemas"]["Contract_capture_assessment_896e91b8fce79799"];
                    /** @description Verified native format, when supplied; used to choose a compatible saved-evidence view. It grants no download or analysis authority. */
                    native_format?: string;
                    verified_native_bytes?: number;
                    target?: {
                        /** Format: uuid */
                        cluster_id: string;
                        namespace_uid: string;
                        workload_uid: string;
                        pod_uid: string;
                        namespace?: string;
                        /** @enum {unknown} */
                        workload_kind?: "Deployment" | "StatefulSet";
                        workload_name?: string;
                        pod_name?: string;
                    };
                    /** @description Accepted request parameters and authenticated HTTP acquisition timing, not the sample interval or cumulative history. Legacy timing, clock uncertainty and serving-process attribution may be unknown. */
                    profile_acquisition?: {
                        /** @enum {string} */
                        requested_type: "cpu" | "heap" | "allocs" | "goroutine" | "block" | "mutex" | "threadcreate" | "runtimeTrace";
                        /** @enum {string} */
                        mode: "interval" | "snapshot" | "cumulative" | "delta";
                        requested_duration_ms: number | null;
                        force_gc: boolean;
                        /** @constant */
                        execution_mode: "onTrigger";
                        /** Format: date-time */
                        started_at: string | null;
                        /** Format: date-time */
                        completed_at: string | null;
                        clock_uncertainty_ms: null;
                        /** @constant */
                        process_attribution: "unknown";
                        /** @constant */
                        window_kind: "httpAcquisition";
                        /** @constant */
                        timestamp_precision: "microsecond";
                    } & (({
                        /** @enum {unknown} */
                        requested_type?: "cpu";
                        /** @constant */
                        mode?: "interval";
                        requested_duration_ms?: number;
                        /** @constant */
                        force_gc?: false;
                    } | {
                        /** @enum {unknown} */
                        requested_type?: "runtimeTrace";
                        /** @constant */
                        mode?: "interval";
                        requested_duration_ms?: number;
                        /** @constant */
                        force_gc?: false;
                    } | {
                        /** @enum {unknown} */
                        requested_type?: "heap";
                        /** @constant */
                        mode?: "snapshot";
                        requested_duration_ms?: null;
                    } | {
                        /** @enum {unknown} */
                        requested_type?: "goroutine";
                        /** @constant */
                        mode?: "snapshot";
                        requested_duration_ms?: null;
                        /** @constant */
                        force_gc?: false;
                    } | {
                        /** @enum {unknown} */
                        requested_type?: "allocs" | "block" | "mutex" | "threadcreate";
                        /** @constant */
                        mode?: "cumulative";
                        requested_duration_ms?: null;
                        /** @constant */
                        force_gc?: false;
                    } | {
                        /** @enum {unknown} */
                        requested_type?: "heap" | "allocs" | "goroutine" | "block" | "mutex" | "threadcreate";
                        /** @constant */
                        mode?: "delta";
                        requested_duration_ms?: number;
                        /** @constant */
                        force_gc?: false;
                    }) & ({
                        started_at?: null;
                        completed_at?: null;
                    } | {
                        started_at?: string;
                        completed_at?: string;
                    }));
                } & unknown)[];
                timeline: {
                    /** Format: date-time */
                    time: string;
                    kind: string;
                    summary: string;
                    clock_uncertainty_ms?: number;
                }[];
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
        McpInput_download_artifact: {
            /**
             * @description Selects the action; each value has its own strict argument set.
             * @enum {unknown}
             */
            action: "prepare" | "status" | "cancel";
            /** Format: uuid */
            artifact_id?: string;
            idempotency_key?: string;
            /**
             * @description Core artifacts only: bundle (default) is the debugger-ready tar with executable, libraries, debug files and gdb.cmd/dlv.sh; file is the bare core. Ignored for other kinds.
             * @default bundle
             * @enum {unknown}
             */
            representation: "bundle" | "file";
            /** Format: uuid */
            download_id?: string;
            /** @description Wait server-side until the state revision differs from this value or 30 seconds pass, then return the current state. Omit for an immediate read. Status reads are never charged. */
            after_revision?: number;
        } & (unknown & unknown & unknown);
        /** @description Current authorized transfer status. Prepare returns Ready with the catalog's verified metadata in the same request. Ready carries content_path and browser_url; terminal states carry neither. Completed records the server transfer outcome, not local file persistence. Status reads never decrypt a file. */
        Contract_artifact_download_0b2b78f874cf920d: {
            /** Format: uuid */
            download_id: string;
            /** Format: uuid */
            artifact_id: string;
            /**
             * @description An interrupted connection leaves the session Ready; resume with HTTP Range until access_until. Completed, Failed and Cancelled are terminal.
             * @enum {unknown}
             */
            state: "Ready" | "Completed" | "Failed" | "Cancelled";
            /** @description Changes whenever the session state or transfer generation changes; pass it as after_revision to wait for the next change. */
            revision: number;
            /** @description <workload>-<pod>-<time>.<ext> from recorded provenance (core bundle: .core.tar). */
            filename?: string;
            native_format?: string;
            /** @description Verified size from the catalog; present in every status while the caller may read the artifact's metadata. */
            size_bytes: number;
            /** @description Verified full-file SHA-256 from the catalog; present in every status. */
            sha256: string;
            content_path?: string;
            emitted_bytes: number;
            /** @constant */
            local_copy_managed: false;
            handling_notice: string;
            coverage_notice?: string;
            /** @description Strong opaque native-representation version; use with If-Match when resuming. */
            etag?: string;
            /** @enum {unknown} */
            failure_reason?: "Expired" | "Denied" | "Integrity" | "Deleted" | "Unavailable";
            /** @enum {unknown} */
            representation?: "bundle" | "file";
            /** @description Console page that downloads this session in the signed-in browser of the same human without another consent or approval. */
            browser_url?: string;
            /**
             * Format: date-time
             * @description AccessUntil: the artifact's access end (retention, share or grant end), never extended by status reads. Resumes are allowed until then; the caller's token lifetime does not shorten a started response (ADR-312).
             */
            access_until: string;
        } & (unknown & unknown);
        /** @description A minimal receipt for stopping the original caller/client download, even after evidence access is lost. AlreadyTerminal hides the finer prior state. No artifact or native metadata. The audit row is written in the same transaction (ADR-330 D6). */
        Contract_artifact_download_b566de55874898e7: {
            /** Format: uuid */
            download_id: string;
            /** @enum {unknown} */
            state: "Cancelled" | "AlreadyTerminal";
        };
        McpOutput_download_artifact: components["schemas"]["Contract_mcp_result"] & ({
            /** @constant */
            status: "ok";
            data: components["schemas"]["Contract_artifact_download_0b2b78f874cf920d"] | components["schemas"]["Contract_artifact_download_b566de55874898e7"];
        } | {
            /** @constant */
            status: "error";
            data: {
                /** @description RawApprovalRequired is returned only for a fresh preparation whose ordinary access checks passed but neither the equivalent Kubernetes right nor a current grant covers the raw file; navigation_uri opens the prefilled review. Other failures must not open approval. */
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
