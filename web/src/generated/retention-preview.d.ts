// Generated from canonical browser OpenAPI. Run npm run generate; do not edit.
export type paths = Record<string, never>;
export type webhooks = Record<string, never>;
export interface components {
    schemas: {
        Contract_retention_policy_ad816c81a7733f89: {
            scope: {
                clusterIDs?: components["schemas"]["Contract_common_2224a31324a0c811"][];
                namespaceSelector?: {
                    matchLabels: {
                        [key: string]: string;
                    };
                };
                workloadSelector?: {
                    matchLabels: {
                        [key: string]: string;
                    };
                };
            };
            purposeRef: string;
            defaults: {
                evidenceSeconds: number;
                caseMetadataSeconds: number;
                auditMetadataSeconds: number;
            };
            maxima: {
                evidenceSeconds: number;
                caseMetadataSeconds: number;
                auditMetadataSeconds: number;
            };
            rules: {
                name: string;
                privacyClasses?: ("unknown" | "potentialPersonalData" | "personalData" | "specialCategoryPossible" | "verifiedNonPersonal")[];
                evidenceTypes?: ("coreDump" | "heapDump" | "packetCapture" | "logs" | "files" | "profile" | "commandOutput" | "context" | "other" | "syscallTrace")[];
                maxAgeSeconds: number;
            }[];
            deletionBudgetSeconds: number;
            /** @enum {string} */
            legalExceptions: "disabled" | "reviewed";
        };
        /** Format: uuid */
        Contract_common_2224a31324a0c811: string;
        McpInput_preview_retention_change: {
            changes: ({
                /** @constant */
                action: "create";
                /** Format: uuid */
                source_cluster_id?: string;
                spec: components["schemas"]["Contract_retention_policy_ad816c81a7733f89"];
            } | {
                /** @constant */
                action: "update";
                /** Format: uuid */
                source_cluster_id?: string;
                uid: string;
                spec: components["schemas"]["Contract_retention_policy_ad816c81a7733f89"];
            } | {
                /** @constant */
                action: "delete";
                /** Format: uuid */
                source_cluster_id?: string;
                uid: string;
            })[];
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
        McpOutput_preview_retention_change: components["schemas"]["Contract_mcp_result"] & ({
            /** @constant */
            status: "ok";
            data: {
                complete: boolean;
                message: string;
                /** Format: date-time */
                observed_at: string;
                artifacts_scanned: number;
                scan_limited: boolean;
                affected_total: number;
                read_closed_total: number;
                deletion_due_total: number;
                unknown_total: number;
                /** Format: date-time */
                earliest_expires_at?: string;
                /** Format: date-time */
                earliest_delete_by?: string;
                baseline_changed: boolean;
                groups: {
                    /** Format: uuid */
                    cluster_id: string;
                    /** @enum {unknown} */
                    privacy_class: "unknown" | "potentialPersonalData" | "personalData" | "specialCategoryPossible" | "verifiedNonPersonal";
                    /** @enum {unknown} */
                    evidence_type: "coreDump" | "heapDump" | "packetCapture" | "syscallTrace" | "logs" | "files" | "profile" | "commandOutput" | "context" | "other";
                    scanned: number;
                    affected: number;
                    read_closed: number;
                    deletion_due: number;
                    unknown: number;
                    /** Format: date-time */
                    earliest_expires_at?: string;
                    /** Format: date-time */
                    earliest_delete_by?: string;
                }[];
                groups_total: number;
                incomplete_clusters: {
                    /** Format: uuid */
                    cluster_id: string;
                    /** @enum {unknown} */
                    reason: "SourceUnavailable";
                }[];
                incomplete_total: number;
                not_evaluated: {
                    /** @enum {unknown} */
                    action: "create" | "update" | "delete";
                    /** Format: uuid */
                    source_cluster_id?: string;
                    uid?: string;
                    /** @enum {unknown} */
                    reason: "UnknownObject" | "SourceAmbiguous";
                }[];
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
