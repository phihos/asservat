// Generated from canonical browser OpenAPI. Run npm run generate; do not edit.
export type paths = Record<string, never>;
export type webhooks = Record<string, never>;
export interface components {
    schemas: {
        Contract_access_binding_ad816c81a7733f89: {
            /** @enum {string} */
            effect: "Allow" | "Deny";
            subjects: components["schemas"]["Contract_permission_common_3ecc34f302c77f66"][];
            roles: components["schemas"]["Contract_permission_common_4158ef06eeec0fc1"][];
            scope: components["schemas"]["Contract_permission_common_5df8ba27f204b8b8"];
            /** Format: date-time */
            notAfter?: string;
            reason: string;
            automation?: components["schemas"]["Contract_policy_authority_82c5ee701fbfe76f"];
        } & unknown;
        Contract_permission_common_3ecc34f302c77f66: {
            /** @enum {string} */
            kind: "User" | "Group" | "Workload";
            /** Format: uri */
            issuer: string;
            id: string;
        };
        /** @enum {string} */
        Contract_permission_common_4158ef06eeec0fc1: "evidence-reader" | "workload-maintainer" | "evidence-owner" | "action-approver";
        Contract_permission_common_5df8ba27f204b8b8: {
            /** Format: uuid */
            clusterID: string;
            namespaceRef: components["schemas"]["Contract_permission_common_94881780cf4467f4"];
            workloads?: components["schemas"]["Contract_permission_common_a7eab82de91b4ad7"][];
        };
        Contract_permission_common_94881780cf4467f4: {
            name: string;
            uid: string;
        };
        Contract_permission_common_a7eab82de91b4ad7: {
            /** @enum {string} */
            kind: "Deployment" | "StatefulSet";
            name: string;
            uid: string;
        };
        Contract_policy_authority_82c5ee701fbfe76f: {
            allowedActions: ("kubernetesSnapshot" | "logs" | "processSnapshot" | "fileRead" | "packetCapture" | "networkSnapshot" | "runtimeDiagnostic" | "kernelCore" | "liveCore" | "command" | "httpDiagnostic" | "artifactCollect" | "profile" | "syscallTrace")[];
            maxLifetimeSeconds: number;
            maxExecutions: number;
            maxBytes: number;
            maxObservedBytes: number;
        };
        Contract_permission_source_ad816c81a7733f89: {
            enabled: boolean;
            /** Format: uuid */
            clusterID: string;
            /** @enum {string} */
            type: "namespaceMetadata" | "workloadMetadata" | "kubernetesExec" | "kubernetesAccessReview";
            namespaceSelector: components["schemas"]["Contract_permission_common_f38038cf755001e7"];
            excludedNamespaces: string[];
            role: components["schemas"]["Contract_permission_common_4158ef06eeec0fc1"];
            maxDecisionAgeSeconds: number;
            maxNamespaces: number;
            protection?: components["schemas"]["Contract_permission_common_75520915533164b6"];
            metadataMapping?: components["schemas"]["Contract_permission_common_f75e769ddd84f0e8"];
            workloadSelector?: components["schemas"]["Contract_permission_common_f38038cf755001e7"];
            identityMappingRef?: string;
            admissionParity?: {
                /** @enum {string} */
                mode: "noAdditionalRestrictions" | "qualifiedAdapter";
                reviewRef: string;
                adapterRef?: string;
            } & unknown;
            accessReview?: {
                /** @enum {string} */
                check: "namespaceCaptureCreate" | "workloadGet" | "workloadPatch" | "workloadUpdate";
            };
        } & (unknown & unknown & unknown & unknown);
        Contract_permission_common_f38038cf755001e7: {
            matchLabels: {
                [key: string]: string;
            };
        };
        Contract_permission_common_75520915533164b6: {
            /** @enum {string} */
            mode: "administratorManaged" | "admissionEnforced";
            reviewRef: string;
            guardRef?: string;
        } & unknown;
        Contract_permission_common_f75e769ddd84f0e8: {
            /** @enum {string} */
            field: "annotation" | "label";
            key: string;
            /** @enum {string} */
            mode: "groupID" | "valueMap";
            /** Format: uri */
            issuer: string;
            values?: {
                [key: string]: string[];
            };
        } & unknown;
        McpInput_preview_access_change: {
            changes: ({
                /** @constant */
                action: "create";
                /** @constant */
                kind: "AccessBinding";
                spec: components["schemas"]["Contract_access_binding_ad816c81a7733f89"];
            } | {
                /** @constant */
                action: "update";
                /** @constant */
                kind: "AccessBinding";
                uid: string;
                spec: components["schemas"]["Contract_access_binding_ad816c81a7733f89"];
            } | {
                /** @constant */
                action: "create";
                /** @constant */
                kind: "PermissionSource";
                spec: components["schemas"]["Contract_permission_source_ad816c81a7733f89"];
            } | {
                /** @constant */
                action: "update";
                /** @constant */
                kind: "PermissionSource";
                uid: string;
                spec: components["schemas"]["Contract_permission_source_ad816c81a7733f89"];
            } | {
                /** @constant */
                action: "delete";
                /** @enum {unknown} */
                kind: "AccessBinding" | "PermissionSource";
                uid: string;
            })[];
            cursor?: string;
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
        McpOutput_preview_access_change: components["schemas"]["Contract_mcp_result"] & ({
            /** @constant */
            status: "ok";
            data: {
                complete: boolean;
                message: string;
                targets_evaluated: number;
                /** Format: date-time */
                fresh_until?: string;
                deltas_total: number;
                unavailable_total: number;
                listed_rows: number;
                page_offset: number;
                unavailable: {
                    /** Format: uuid */
                    cluster_id: string;
                    namespace_uid: string;
                    workload_uid: string;
                    other_workloads: boolean;
                    /** @constant */
                    decision: "Indeterminate";
                    /** @enum {unknown} */
                    unmet: "PermissionObservationStale" | "ServiceUnavailable" | "ClusterUnavailable";
                }[];
                deltas: {
                    /** Format: uuid */
                    cluster_id: string;
                    namespace_uid: string;
                    workload_uid: string;
                    other_workloads: boolean;
                    subject: components["schemas"]["Contract_permission_common_3ecc34f302c77f66"];
                    /** @enum {unknown} */
                    operation: "capture" | "read" | "download";
                    /** @enum {unknown} */
                    before: "Allow" | "Deny" | "Indeterminate";
                    /** @enum {unknown} */
                    after: "Allow" | "Deny" | "Indeterminate";
                    /** @enum {unknown} */
                    before_unmet?: "NoMatchingAllow" | "ExplicitDeny" | "PermissionObservationStale" | "AudienceOverflow" | "ServiceUnavailable";
                    /** @enum {unknown} */
                    after_unmet?: "NoMatchingAllow" | "ExplicitDeny" | "PermissionObservationStale" | "AudienceOverflow" | "ServiceUnavailable";
                    before_basis: {
                        /** @enum {unknown} */
                        effect: "allow" | "deny";
                        role: components["schemas"]["Contract_permission_common_4158ef06eeec0fc1"];
                        /** @enum {unknown} */
                        subject_kind: "User" | "Group" | "Workload";
                        /** @enum {unknown} */
                        basis_kind: "AccessBinding" | "PermissionSource";
                        basis_uid: string;
                        revision: string;
                        proposed: boolean;
                    }[];
                    after_basis: {
                        /** @enum {unknown} */
                        effect: "allow" | "deny";
                        role: components["schemas"]["Contract_permission_common_4158ef06eeec0fc1"];
                        /** @enum {unknown} */
                        subject_kind: "User" | "Group" | "Workload";
                        /** @enum {unknown} */
                        basis_kind: "AccessBinding" | "PermissionSource";
                        basis_uid: string;
                        revision: string;
                        proposed: boolean;
                    }[];
                    /** Format: date-time */
                    after_valid_until?: string;
                }[];
                not_evaluated: {
                    /** @enum {unknown} */
                    action: "create" | "update";
                    /** @constant */
                    kind: "PermissionSource";
                    uid?: string;
                    /** @constant */
                    decision: "Indeterminate";
                    /** @constant */
                    reason: "InheritanceNotAccepted";
                }[];
                unmatched: {
                    /** @enum {unknown} */
                    kind: "AccessBinding" | "PermissionSource";
                    uid: string;
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
