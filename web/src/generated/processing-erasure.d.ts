// Generated from canonical browser OpenAPI. Run npm run generate; do not edit.
export type paths = Record<string, never>;
export type webhooks = Record<string, never>;
export interface components {
    schemas: {
        McpInput_get_processing_erasure: {
            /** Format: uuid */
            request_id: string;
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
        Contract_processing_erasure: {
            /** Format: uuid */
            request_id: string;
            /** Format: uuid */
            artifact_id: string;
            /** Format: date-time */
            accepted_at: string;
            /** Format: date-time */
            access_until: string;
            /** Format: date-time */
            delete_by: string;
            /** Format: date-time */
            effective_delete_by: string;
            /** @enum {unknown} */
            audit_state: "pending" | "acknowledged";
            /** @enum {unknown} */
            deletion_state: "pending" | "overdue" | "deleted";
            /** Format: date-time */
            deleted_at?: string;
        };
        McpOutput_get_processing_erasure: components["schemas"]["Contract_mcp_result"] & ({
            /** @constant */
            status: "ok";
            data: components["schemas"]["Contract_processing_erasure"];
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
