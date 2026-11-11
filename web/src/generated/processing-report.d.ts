// Generated from canonical browser OpenAPI. Run npm run generate; do not edit.
export type paths = Record<string, never>;
export type webhooks = Record<string, never>;
export interface components {
    schemas: {
        Contract_processing_report_0677dae4fbb0d75c: {
            /**
             * @default artifacts
             * @constant
             */
            section: "artifacts";
            /** @default 3 */
            limit: number;
            /** Format: date-time */
            created_before?: string;
            policy_digest?: string;
            after?: components["schemas"]["Contract_processing_report_b73fb784fca02133"];
        } | {
            /** @constant */
            section: "shares";
            /** @default 3 */
            limit: number;
            /** Format: date-time */
            created_before?: string;
            policy_digest?: string;
            after?: components["schemas"]["Contract_processing_report_08f46acf8da767bb"];
        } | {
            /** @constant */
            section: "downloads";
            /** @default 3 */
            limit: number;
            /** Format: date-time */
            created_before?: string;
            policy_digest?: string;
            after?: components["schemas"]["Contract_processing_report_96f24dc2296992e0"];
        } | {
            /** @constant */
            section: "operations";
            /** @default 3 */
            limit: number;
            /** Format: date-time */
            created_before?: string;
            policy_digest?: string;
            after?: components["schemas"]["Contract_processing_report_54d594a8354c9969"];
        } | {
            /** @constant */
            section: "rules";
            /** @default 3 */
            limit: number;
            /** Format: date-time */
            created_before?: string;
            policy_digest?: string;
            after?: components["schemas"]["Contract_processing_report_96f24dc2296992e0"];
        } | {
            /** @constant */
            section: "paths";
            /** @default 3 */
            limit: number;
            /** Format: date-time */
            created_before?: string;
            policy_digest?: string;
            after?: components["schemas"]["Contract_processing_report_96f24dc2296992e0"];
        } | {
            /** @constant */
            section: "processors";
            /** @default 3 */
            limit: number;
            /** Format: date-time */
            created_before?: string;
            policy_digest?: string;
            after?: components["schemas"]["Contract_processing_report_23bd1b72c07989c7"];
        };
        Contract_processing_report_b73fb784fca02133: {
            /** Format: uuid */
            id: string;
            /** Format: uuid */
            cluster_id: string;
            /** Format: uuid */
            attempt_id: string;
        };
        Contract_processing_report_08f46acf8da767bb: {
            /** Format: uuid */
            id: string;
            /** Format: date-time */
            created_at: string;
            ordinal: number;
        };
        Contract_processing_report_96f24dc2296992e0: {
            /** Format: uuid */
            id: string;
        };
        Contract_processing_report_54d594a8354c9969: {
            /** Format: uuid */
            id: string;
            ordinal?: number;
        };
        Contract_processing_report_23bd1b72c07989c7: {
            id: string;
        };
        McpInput_get_processing_report: {
            section?: unknown;
            limit?: unknown;
            after?: unknown;
            created_before?: unknown;
            policy_digest?: unknown;
        } & components["schemas"]["Contract_processing_report_0677dae4fbb0d75c"];
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
        Contract_processing_report_7d55ed8323bb4714: {
            /** @constant */
            schema_version: "processing-report/v1";
            /** Format: uuid */
            root_id: string;
            /** Format: uuid */
            installation_id: string;
            /** @enum {unknown} */
            section: "artifacts" | "shares" | "downloads" | "operations" | "rules" | "paths" | "processors";
            /** Format: date-time */
            selection_created_before: string;
            policy_revision: components["schemas"]["Contract_processing_report_619a5171607803a6"];
            records: unknown[];
            next?: components["schemas"]["Contract_processing_report_030af8db8ac2f04d"];
            /** Format: date-time */
            observed_at: string;
            /** Format: date-time */
            valid_until: string;
            /** @enum {unknown} */
            processor_declarations: "supplied" | "unsupplied";
            /** @constant */
            coverage: [
                "retained metadata observations",
                "unknown client receipt",
                "legal exceptions disabled",
                "recorded lineage"
            ];
        } & ({
            /** @constant */
            section: "artifacts";
            records: components["schemas"]["Contract_processing_report_a78339eba4cbfeea"][];
            next: components["schemas"]["Contract_processing_report_030af8db8ac2f04d"] & ({
                /** @constant */
                section?: "artifacts";
            } | {
                /** @constant */
                section?: "shares";
            });
        } | {
            /** @constant */
            section: "shares";
            records: components["schemas"]["Contract_processing_report_64ee37806ed7dd7a"][];
            next: components["schemas"]["Contract_processing_report_030af8db8ac2f04d"] & ({
                /** @constant */
                section?: "shares";
            } | {
                /** @constant */
                section?: "downloads";
            });
        } | {
            /** @constant */
            section: "downloads";
            records: components["schemas"]["Contract_processing_report_b1f8f1b7d4b56231"][];
            next: components["schemas"]["Contract_processing_report_030af8db8ac2f04d"] & ({
                /** @constant */
                section?: "downloads";
            } | {
                /** @constant */
                section?: "operations";
            });
        } | {
            /** @constant */
            section: "operations";
            records: components["schemas"]["Contract_processing_report_51fb8d504c211c56"][];
            next: components["schemas"]["Contract_processing_report_030af8db8ac2f04d"] & ({
                /** @constant */
                section?: "operations";
            } | {
                /** @constant */
                section?: "rules";
            });
        } | {
            /** @constant */
            section: "rules";
            records: components["schemas"]["Contract_processing_report_5a3a6a0832c5c9c2"][];
            next: components["schemas"]["Contract_processing_report_030af8db8ac2f04d"] & ({
                /** @constant */
                section?: "rules";
            } | {
                /** @constant */
                section?: "paths";
            });
        } | {
            /** @constant */
            section: "paths";
            records: components["schemas"]["Contract_processing_report_0571407f104add70"][];
            next: components["schemas"]["Contract_processing_report_030af8db8ac2f04d"] & ({
                /** @constant */
                section?: "paths";
            } | {
                /** @constant */
                section?: "processors";
            });
        } | {
            /** @constant */
            section: "processors";
            records: components["schemas"]["Contract_processing_report_8682db2167529de2"][];
            next?: components["schemas"]["Contract_processing_report_030af8db8ac2f04d"] & {
                /** @constant */
                section?: "processors";
            };
        });
        Contract_processing_report_619a5171607803a6: {
            uid: string;
            generation: number;
            digest: string;
        };
        Contract_processing_report_030af8db8ac2f04d: components["schemas"]["Contract_processing_report_0677dae4fbb0d75c"];
        Contract_processing_report_a78339eba4cbfeea: {
            /** Format: date-time */
            visible_until: string;
            artifact: components["schemas"]["Contract_processing_report_0f91bbdc8ec9e8d0"];
        };
        Contract_processing_report_0f91bbdc8ec9e8d0: {
            /** Format: uuid */
            artifact_id: string;
            /** Format: uuid */
            capture_id: string;
            /** Format: uuid */
            case_id: string;
            /** Format: uuid */
            cluster_id: string;
            /** Format: uuid */
            attempt_id: string;
            namespace_uid: string;
            workload_uid: string;
            /** Format: uuid */
            store_id: string;
            purpose_ref: string;
            native_type: string;
            /** @enum {unknown} */
            data_class: "metadata" | "extract" | "raw";
            /** @constant */
            privacy_class: "potentialPersonalData";
            /** @enum {unknown} */
            origin: "capture" | "derived";
            parents: string[];
            /** Format: date-time */
            anchor_at: string;
            /** Format: date-time */
            original_expires_at: string;
            /** Format: date-time */
            original_delete_by: string;
            /** Format: date-time */
            expires_at: string;
            /** Format: date-time */
            delete_by: string;
            /** @enum {unknown} */
            custody_state: "stored_unpublished" | "deleting" | "deleted";
            /** Format: date-time */
            deleted_at?: string;
            /** @enum {unknown} */
            deletion_state: "retained" | "pending" | "overdue" | "deleted";
        } & (unknown & unknown);
        Contract_processing_report_64ee37806ed7dd7a: {
            /** Format: date-time */
            visible_until: string;
            share: components["schemas"]["Contract_processing_report_13931d83e4959180"];
        };
        Contract_processing_report_13931d83e4959180: {
            /** Format: uuid */
            share_id: string;
            /** Format: uuid */
            artifact_id: string;
            /** @enum {unknown} */
            recipient_kind: "User" | "Group";
            recipient_issuer: string;
            recipient_id: string;
            ordinal: number;
            /** Format: date-time */
            created_at: string;
            /** Format: date-time */
            expires_at: string;
            /** Format: date-time */
            revoked_at?: string;
            /** @enum {unknown} */
            state: "recorded" | "expired" | "revoked";
        };
        Contract_processing_report_b1f8f1b7d4b56231: {
            /** Format: date-time */
            visible_until: string;
            download: components["schemas"]["Contract_processing_report_2a7d4d7f18737293"];
        };
        Contract_processing_report_2a7d4d7f18737293: {
            /** Format: uuid */
            download_id: string;
            /** Format: uuid */
            artifact_id: string;
            issuer: string;
            subject: string;
            client_id: string;
            /** @enum {unknown} */
            principal_kind: "human" | "workload";
            /** @enum {unknown} */
            state: "Preparing" | "Ready" | "Streaming" | "Interrupted" | "Completed" | "Cancelled" | "Expired" | "Denied" | "Failed";
            /** Format: date-time */
            created_at: string;
            /** Format: date-time */
            deadline: string;
            emitted_bytes: number;
            /** @constant */
            client_receipt: "unknown";
        };
        Contract_processing_report_51fb8d504c211c56: {
            /** Format: date-time */
            visible_until: string;
            operation: components["schemas"]["Contract_processing_report_40e2eb0ca8309cb6"];
        };
        Contract_processing_report_40e2eb0ca8309cb6: {
            /** Format: uuid */
            operation_id: string;
            /** Format: uuid */
            artifact_id?: string;
            ordinal: number;
            name: string;
            issuer: string;
            subject: string;
            client_id: string;
            /** @enum {unknown} */
            principal_kind: "human" | "workload";
            /** Format: date-time */
            created_at: string;
            intent_acknowledged: boolean;
            outcome_acknowledged: boolean;
            /** @enum {unknown} */
            status: "unknown" | "success" | "denied" | "invalid" | "unavailable" | "interrupted";
            output_bytes?: number;
            /** @constant */
            client_receipt: "unknown";
            /** @enum {unknown} */
            lane: "normal" | "resolution" | "processing";
        } & (unknown & unknown);
        Contract_processing_report_5a3a6a0832c5c9c2: {
            /** Format: date-time */
            visible_until: string;
            rule: components["schemas"]["Contract_processing_report_ebfbfb6e2ab36705"];
        };
        Contract_processing_report_ebfbfb6e2ab36705: {
            /** Format: date-time */
            created_at?: string;
            /** Format: uuid */
            id: string;
            revision: number;
            /** @enum {unknown} */
            state: "reserved" | "restricted" | "released";
            scope: components["schemas"]["Contract_processing_report_30a5a965212655cf"];
            /** Format: date-time */
            administration_until: string;
            /** Format: date-time */
            retire_by: string;
        };
        Contract_processing_report_30a5a965212655cf: {
            /** @constant */
            kind: "artifact";
            location: components["schemas"]["Contract_processing_report_d464378d42c6b8f9"];
        } | {
            /** @constant */
            kind: "workloadInterval";
            /** Format: uuid */
            cluster_id: string;
            namespace_uid: string;
            workload_uid: string;
            /** Format: date-time */
            acquired_from: string;
            /** Format: date-time */
            acquired_until: string;
        };
        Contract_processing_report_d464378d42c6b8f9: {
            /** Format: uuid */
            cluster_id: string;
            /** Format: uuid */
            artifact_id: string;
            /** Format: uuid */
            attempt_id: string;
        };
        Contract_processing_report_0571407f104add70: {
            /** Format: date-time */
            visible_until: string;
            path: components["schemas"]["Contract_processing_report_7f5536acd65504f4"];
        };
        Contract_processing_report_7f5536acd65504f4: {
            /** Format: uuid */
            id: string;
            /** Format: uuid */
            target_cluster_id: string;
            /** Format: uuid */
            store_id: string;
            storage_region: string;
            /** Format: uuid */
            acquisition_cluster_id: string;
            acquisition_region: string;
            /** Format: uuid */
            connector_cluster_id: string;
            connector_region: string;
            /** Format: uuid */
            hub_cluster_id: string;
            hub_region: string;
        };
        Contract_processing_report_8682db2167529de2: {
            /** Format: date-time */
            visible_until: string;
            processor: components["schemas"]["Contract_processing_report_94b3f589d61e2ceb"];
        };
        Contract_processing_report_94b3f589d61e2ceb: {
            id: string;
            name: string;
            activities: string[];
            regions: string[];
        };
        McpOutput_get_processing_report: components["schemas"]["Contract_mcp_result"] & ({
            /** @constant */
            status: "ok";
            data: components["schemas"]["Contract_processing_report_7d55ed8323bb4714"];
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
        Contract_processing_report_663acbd20e298c4f: {
            /** @constant */
            format: "asservat-processing-inventory/v1";
            part: number;
            /** Format: date-time */
            selection_created_before: string;
            policy_revision: components["schemas"]["Contract_processing_report_619a5171607803a6"];
            pages: (components["schemas"]["Contract_processing_report_a1c00165337ee333"] & {
                /** @constant */
                status?: "ok";
            })[];
            next?: components["schemas"]["Contract_processing_report_0677dae4fbb0d75c"];
            complete: boolean;
        };
        Contract_processing_report_a1c00165337ee333: components["schemas"]["Contract_mcp_result"] & ({
            /** @constant */
            status: "ok";
            data: components["schemas"]["Contract_processing_report_7d55ed8323bb4714"];
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
        ProcessingReportExport: components["schemas"]["Contract_processing_report_663acbd20e298c4f"];
    };
    responses: never;
    parameters: never;
    requestBodies: never;
    headers: never;
    pathItems: never;
}
export type $defs = Record<string, never>;
export type operations = Record<string, never>;
