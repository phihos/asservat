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
