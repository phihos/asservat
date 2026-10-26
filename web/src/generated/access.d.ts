// Generated from canonical browser OpenAPI. Run npm run generate; do not edit.
export type paths = Record<string, never>;
export type webhooks = Record<string, never>;
export interface components {
    schemas: {
        McpInput_explain_access: {
            target_ref: {
                /** Format: uuid */
                cluster_id: string;
                namespace: string;
                /** @enum {unknown} */
                kind: "Deployment" | "StatefulSet" | "Pod";
                name: string;
            };
            /** @enum {unknown} */
            operation: "capture" | "read" | "download";
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
        McpOutput_explain_access: components["schemas"]["Contract_mcp_result"] & ({
            /** @constant */
            status: "ok";
            data: {
                /** @enum {unknown} */
                decision: "Allow" | "Deny" | "Indeterminate";
                /** @enum {unknown} */
                operation: "capture" | "read" | "download";
                /** @enum {unknown} */
                unmet?: "NoMatchingAllow" | "ExplicitDeny" | "ClientScopeMissing" | "PermissionObservationStale" | "IdentityUnavailable" | "AudienceOverflow" | "ServiceUnavailable";
                /** @enum {unknown} */
                missing_scope?: "evidence:read" | "evidence:capture" | "evidence:download";
                required_roles: ("evidence-reader" | "workload-maintainer" | "evidence-owner" | "action-approver")[];
                message: string;
                target?: {
                    /** Format: uuid */
                    cluster_id: string;
                    namespace_uid: string;
                    workload_uid: string;
                    pod_uid: string;
                };
                assignments: {
                    /** @enum {unknown} */
                    effect: "allow" | "deny";
                    /** Format: uuid */
                    assignment_id: string;
                    /** @enum {unknown} */
                    role: "evidence-reader" | "workload-maintainer" | "evidence-owner" | "action-approver";
                    /** @enum {unknown} */
                    subject_kind: "User" | "Group" | "Workload";
                    /** @enum {unknown} */
                    basis_kind: "AccessBinding" | "PermissionSource";
                    basis_uid: string;
                    revision: string;
                }[];
                assignments_total: number;
                /** Format: date-time */
                valid_until?: string;
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
