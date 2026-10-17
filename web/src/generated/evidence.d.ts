// Generated from canonical browser OpenAPI. Run npm run generate; do not edit.
export type paths = Record<string, never>;
export type webhooks = Record<string, never>;
export interface components {
    schemas: {
        McpInput_get_case: {
            /** Format: uuid */
            case_id: string;
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
            deletionState: "scheduled" | "inProgress" | "verified" | "overdue" | "unknown" | "restrictedPreservation";
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
                artifacts: {
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
                }[];
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
        McpInput_prepare_artifact_download: {
            /** Format: uuid */
            artifact_id: string;
            /** Format: uuid */
            grant_id?: string;
            idempotency_key: string;
        };
        /** @description Current authorized transfer status. Completed records the server transfer outcome, not local file persistence. Terminal status may omit native file metadata and remains readable after the transfer deadline while current evidence metadata authority permits it. Any included native metadata is the complete verified group; status reads never prepare or decrypt a file. */
        Contract_artifact_download_0b2b78f874cf920d: {
            /** Format: uuid */
            download_id: string;
            /** Format: uuid */
            artifact_id: string;
            /** @enum {unknown} */
            state: "Preparing" | "Ready" | "Streaming" | "Completed" | "Interrupted" | "Cancelled" | "Expired" | "Denied" | "Failed";
            filename?: string;
            native_format?: string;
            size_bytes?: number;
            sha256?: string;
            content_path?: string;
            /**
             * Format: date-time
             * @description Effective transfer deadline, no later than the original session deadline or current managed evidence access expiry. A past deadline is valid for terminal status and never renews preparation, transfer or resume authority.
             */
            expires_at: string;
            /** Format: date-time */
            managed_read_until: string;
            emitted_bytes: number;
            resume_available: boolean;
            /** @constant */
            local_copy_managed: false;
            handling_notice: string;
            coverage_notice?: string;
            /** @description Strong opaque native-representation version; use with If-Match when resuming. */
            etag?: string;
            /**
             * @description Only an acknowledged Preparing response to the explicit preparation operation permits bounded automatic continuation with the original key and deadline. Passive status never supplies this instruction.
             * @constant
             */
            continue_preparation?: true;
        } & (unknown & unknown & unknown & unknown);
        McpOutput_prepare_artifact_download: components["schemas"]["Contract_mcp_result"] & ({
            /** @constant */
            status: "ok";
            data: components["schemas"]["Contract_artifact_download_0b2b78f874cf920d"];
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
        McpInput_get_artifact_download: {
            /** Format: uuid */
            download_id: string;
        };
        McpOutput_get_artifact_download: components["schemas"]["Contract_mcp_result"] & ({
            /** @constant */
            status: "ok";
            data: components["schemas"]["Contract_artifact_download_0b2b78f874cf920d"] & unknown;
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
        McpInput_cancel_artifact_download: {
            /** Format: uuid */
            download_id: string;
            idempotency_key: string;
        };
        /** @description A minimal receipt for stopping the original caller/client download, even after evidence access is lost. AlreadyTerminal intentionally hides the finer prior state. No artifact or native metadata. Pending/overdue audit never reverses the enforced stop. */
        Contract_artifact_download_b566de55874898e7: {
            /** Format: uuid */
            download_id: string;
            /** @enum {unknown} */
            state: "Cancelled" | "AlreadyTerminal";
            /** @enum {unknown} */
            audit_state: "pending" | "recorded" | "overdue";
        };
        McpOutput_cancel_artifact_download: components["schemas"]["Contract_mcp_result"] & ({
            /** @constant */
            status: "ok";
            data: (components["schemas"]["Contract_artifact_download_0b2b78f874cf920d"] & unknown) | components["schemas"]["Contract_artifact_download_b566de55874898e7"];
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
