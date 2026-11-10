// Generated from canonical browser OpenAPI. Run npm run generate; do not edit.
export type paths = Record<string, never>;
export type webhooks = Record<string, never>;
export interface components {
    schemas: {
        McpInput_get_live_capacity: {
            /** Format: uuid */
            cluster_id: string;
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
        Contract_live_capacity: {
            active_viewers: number;
            /** Format: uuid */
            cluster_id: string;
            /** Format: date-time */
            observed_at: string;
            /** Format: date-time */
            fresh_until: string;
            message: string;
            nodes: number;
            rates_unavailable: number;
            rates_complete: boolean;
            live?: {
                cohorts: number;
                scan_events: number;
                scan_bytes: number;
                scan_cpu_nanos: number;
                delivered_rows: number;
                delivered_bytes: number;
                refused_admissions: number;
                lost_events: number;
                dropped_rows: number;
                pending_rows: number;
            };
            rates: {
                scan_events_per_second: number;
                scan_bytes_per_second: number;
                scan_cpu_nanos_per_second: number;
                delivered_rows_per_second: number;
                delivered_bytes_per_second: number;
                refused_admissions_per_second: number;
                lost_events_per_second: number;
                dropped_rows_per_second: number;
            };
        };
        McpOutput_get_live_capacity: components["schemas"]["Contract_mcp_result"] & ({
            /** @constant */
            status: "ok";
            data: components["schemas"]["Contract_live_capacity"];
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
