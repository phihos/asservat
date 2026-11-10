// Generated from canonical browser OpenAPI. Run npm run generate; do not edit.
export type paths = Record<string, never>;
export type webhooks = Record<string, never>;
export interface components {
    schemas: {
        Contract_processing_discovery_f0d7c9129b200d3a: {
            /** Format: uuid */
            artifact_id: string;
        };
        Contract_processing_discovery_b5f2f60104c78f25: {
            /** Format: uuid */
            artifact_id: string;
            /** Format: date-time */
            anchor_at: string;
        };
        Contract_processing_discovery_0f29f5ee20b5e9ef: {
            /** Format: uuid */
            case_id: string;
            purpose_ref?: string;
            /** @default 12 */
            limit: number;
            after?: components["schemas"]["Contract_processing_discovery_f0d7c9129b200d3a"];
        };
        Contract_processing_discovery_a36954fff1bd9148: {
            /** Format: uuid */
            cluster_id: string;
            namespace_uid: string;
            workload_uid: string;
            /** Format: date-time */
            acquired_from: string;
            /** Format: date-time */
            acquired_until: string;
            purpose_ref?: string;
            /** @default 12 */
            limit: number;
            after?: components["schemas"]["Contract_processing_discovery_b5f2f60104c78f25"];
        };
        McpInput_search_processing_evidence: {
            /** Format: uuid */
            case_id?: string;
            purpose_ref?: string;
            /** @default 12 */
            limit: number;
            after?: components["schemas"]["Contract_processing_discovery_f0d7c9129b200d3a"] | components["schemas"]["Contract_processing_discovery_b5f2f60104c78f25"];
            /** Format: uuid */
            cluster_id?: string;
            namespace_uid?: string;
            workload_uid?: string;
            /** Format: date-time */
            acquired_from?: string;
            /** Format: date-time */
            acquired_until?: string;
        } & (components["schemas"]["Contract_processing_discovery_0f29f5ee20b5e9ef"] | components["schemas"]["Contract_processing_discovery_a36954fff1bd9148"]);
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
        Contract_processing_discovery_7d55ed8323bb4714: {
            candidates: components["schemas"]["Contract_processing_discovery_689e5103cc02f819"][];
            next?: components["schemas"]["Contract_processing_discovery_f0d7c9129b200d3a"] | components["schemas"]["Contract_processing_discovery_b5f2f60104c78f25"];
        };
        Contract_processing_discovery_689e5103cc02f819: {
            /** Format: uuid */
            artifact_id: string;
            /** Format: uuid */
            capture_id: string;
            /** Format: uuid */
            case_id: string;
            /** Format: uuid */
            cluster_id: string;
            namespace_uid: string;
            workload_uid: string;
            purpose_ref: string;
            native_type: string;
            /** @enum {unknown} */
            data_class: "metadata" | "raw" | "extract";
            /** @enum {unknown} */
            origin: "capture" | "derived";
            /** Format: date-time */
            anchor_at: string;
            /** Format: date-time */
            expires_at: string;
            /** Format: date-time */
            delete_by: string;
            /** @enum {unknown} */
            custody_state: "stored_unpublished" | "deleting";
            parents: string[];
        };
        McpOutput_search_processing_evidence: components["schemas"]["Contract_mcp_result"] & ({
            /** @constant */
            status: "ok";
            data: components["schemas"]["Contract_processing_discovery_7d55ed8323bb4714"];
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
