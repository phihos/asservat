// Generated from canonical browser OpenAPI. Run npm run generate; do not edit.
export type paths = Record<string, never>;
export type webhooks = Record<string, never>;
export interface components {
    schemas: {
        /** @description Lists are not capped: the Kubernetes object size limit (about 1.5 MiB) bounds them; roles are bounded by their enum and uniqueItems. */
        Contract_access_binding_ad816c81a7733f89: {
            /** @enum {string} */
            effect: "Allow" | "Deny";
            subjects: components["schemas"]["Contract_permission_common_29c9711e543c29dd"][];
            roles: components["schemas"]["Contract_permission_common_4158ef06eeec0fc1"][];
            workloads?: components["schemas"]["Contract_permission_common_a7eab82de91b4ad7"][];
            /** Format: date-time */
            notAfter?: string;
            /** @description Optional. */
            reason?: string;
            automation?: components["schemas"]["Contract_policy_authority_82c5ee701fbfe76f"];
        } & unknown;
        /** @description Authored subject (ADR-335 D4): a user by username, a group by the name the provider emits (for example /payments) or a workload identity. issuer defaults to the installation's issuer. */
        Contract_permission_common_29c9711e543c29dd: {
            /** @enum {string} */
            kind: "User" | "Group" | "Workload";
            /** @description Compared literally with the verified issuer. PostgreSQL permission assignments store up to 2048 UTF-8 bytes. */
            issuer?: string;
            /** @description PostgreSQL permission assignments store up to 256 UTF-8 bytes. */
            id: string;
        };
        /** @enum {string} */
        Contract_permission_common_4158ef06eeec0fc1: "evidence-reader" | "workload-maintainer" | "evidence-owner" | "action-approver";
        /** @description Workload by kind and name; a recreated workload of the same name keeps its access. Optional uid pins one instance. */
        Contract_permission_common_a7eab82de91b4ad7: {
            /** @enum {string} */
            kind: "Deployment" | "StatefulSet";
            /** @description Kubernetes object name (DNS subdomain). */
            name: string;
            /** @description Kubernetes UID (a UUID; 64 characters leaves room for its textual forms). */
            uid?: string;
        };
        /** @description Automation envelope on an AccessBinding (ADR-335 D6). Only allowedActions is required; an omitted lifetime is unbounded. Bytes are bounded by the installation's capacity and rate limits, not a lifetime budget. Intrusive actions still need an expiring policy grant. */
        Contract_policy_authority_82c5ee701fbfe76f: {
            allowedActions: ("kubernetesSnapshot" | "logs" | "processSnapshot" | "fileRead" | "packetCapture" | "networkSnapshot" | "runtimeDiagnostic" | "kernelCore" | "liveCore" | "command" | "httpDiagnostic" | "artifactCollect" | "profile" | "syscallTrace")[];
            maxLifetimeSeconds?: number;
        };
        Contract_permission_common_94881780cf4467f4: {
            /** @description Kubernetes namespace name (DNS label). */
            name: string;
            /** @description Kubernetes UID (a UUID; 64 characters leaves room for its textual forms). */
            uid: string;
        };
        Contract_permission_source_ad816c81a7733f89: {
            enabled: boolean;
            /** @description Name of the cluster the source derives access in (ADR-335 D4). */
            cluster: string;
            /** @enum {string} */
            type: "namespaceMetadata" | "workloadMetadata" | "kubernetesExec" | "kubernetesAccessReview";
            namespaceSelector?: components["schemas"]["Contract_permission_common_f38038cf755001e7"];
            /** @description Namespace names (DNS label, 63 characters). Not capped: the Kubernetes object size limit (about 1.5 MiB in etcd) bounds this list. */
            excludedNamespaces?: string[];
            role: components["schemas"]["Contract_permission_common_4158ef06eeec0fc1"];
            protection?: components["schemas"]["Contract_permission_common_75520915533164b6"];
            metadataMapping?: components["schemas"]["Contract_permission_common_f75e769ddd84f0e8"];
            workloadSelector?: components["schemas"]["Contract_permission_common_f38038cf755001e7"];
            identityMappingRef?: string;
            admissionParity?: {
                /** @enum {string} */
                mode: "noAdditionalRestrictions" | "qualifiedAdapter";
                reviewRef?: string;
                adapterRef?: string;
            } & unknown;
            accessReview?: {
                /** @enum {string} */
                check: "namespaceCaptureCreate" | "workloadGet" | "workloadPatch" | "workloadUpdate";
            };
        } & (unknown & unknown & unknown & unknown);
        Contract_permission_common_f38038cf755001e7: {
            /** @description Label values are at most 63 characters (Kubernetes label syntax). Not capped: the Kubernetes object size limit (about 1.5 MiB in etcd) bounds this list. */
            matchLabels: {
                [key: string]: string;
            };
        };
        /** @description administratorManaged: the source itself is the administrator's statement. admissionEnforced: the Helm-rendered label ValidatingAdmissionPolicy protects the keys. reviewRef and guardRef are optional notes. */
        Contract_permission_common_75520915533164b6: {
            /** @enum {string} */
            mode: "administratorManaged" | "admissionEnforced";
            reviewRef?: string;
            guardRef?: string;
        };
        Contract_permission_common_f75e769ddd84f0e8: {
            /** @enum {string} */
            field: "annotation" | "label";
            /** @description Kubernetes label or annotation key (at most 253 characters). */
            key: string;
            /** @enum {string} */
            mode: "groupName" | "valueMap";
            /**
             * Format: uri
             * @description Defaults to the installation's issuer.
             */
            issuer?: string;
            values?: {
                [key: string]: string[];
            };
            /** @description groupName mode: prepended to the value (label values cannot contain /). */
            prefix?: string;
        } & unknown;
        McpInput_preview_access_change: {
            changes: ({
                /** @constant */
                action: "create";
                /** @constant */
                kind: "AccessBinding";
                spec: components["schemas"]["Contract_access_binding_ad816c81a7733f89"];
                /** Format: uuid */
                clusterID: string;
                namespace: components["schemas"]["Contract_permission_common_94881780cf4467f4"];
            } | {
                /** @constant */
                action: "update";
                /** @constant */
                kind: "AccessBinding";
                uid: string;
                spec: components["schemas"]["Contract_access_binding_ad816c81a7733f89"];
                /** Format: uuid */
                clusterID: string;
                namespace: components["schemas"]["Contract_permission_common_94881780cf4467f4"];
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
        Contract_permission_common_3ecc34f302c77f66: {
            /** @enum {string} */
            kind: "User" | "Group" | "Workload";
            /** Format: uri */
            issuer: string;
            id: string;
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
                    unmet: "ClusterNotObserved" | "ServiceUnavailable" | "ClusterUnavailable";
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
                    before_unmet?: "NoMatchingAllow" | "ExplicitDeny" | "ClusterNotObserved" | "ServiceUnavailable" | "DecisionTimeSource";
                    /** @enum {unknown} */
                    after_unmet?: "NoMatchingAllow" | "ExplicitDeny" | "ClusterNotObserved" | "ServiceUnavailable" | "DecisionTimeSource";
                    before_basis: {
                        /** @enum {unknown} */
                        effect: "allow" | "deny";
                        role: components["schemas"]["Contract_permission_common_4158ef06eeec0fc1"];
                        /** @enum {unknown} */
                        subject_kind: "User" | "Group" | "Workload";
                        /** @enum {unknown} */
                        basis_kind: "AccessBinding" | "ClusterAccessBinding" | "PermissionSource";
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
                        basis_kind: "AccessBinding" | "ClusterAccessBinding" | "PermissionSource";
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
                    /** @enum {unknown} */
                    reason: "MetadataUnavailable" | "MetadataNotObserved" | "DecisionTimeSource";
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
