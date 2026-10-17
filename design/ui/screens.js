window.ASSERVAT_SCREENS = [
  {
    "id": "overview",
    "surface_id": "UI-001",
    "title": "Overview",
    "group": "Investigate",
    "personas": [
      "maintainer",
      "admin"
    ],
    "entity": "Overview",
    "purpose": "What needs attention and where evidence is already available",
    "route": "#/overview",
    "states": [
      "normal",
      "loading",
      "empty",
      "denied",
      "expired",
      "offline",
      "quota"
    ]
  },
  {
    "id": "workloads",
    "surface_id": "UI-002",
    "title": "Workloads",
    "group": "Investigate",
    "personas": [
      "maintainer",
      "admin"
    ],
    "entity": "WorkloadProjection",
    "purpose": "Find an authorized workload and see monitoring coverage",
    "route": "#/workloads",
    "states": [
      "normal",
      "loading",
      "empty",
      "denied",
      "expired",
      "offline",
      "quota"
    ]
  },
  {
    "id": "workload",
    "surface_id": "UI-003",
    "title": "checkout-api",
    "group": "Investigate",
    "personas": [
      "maintainer",
      "admin"
    ],
    "entity": "WorkloadProjection",
    "purpose": "Understand the selected workload, coverage and recent incidents",
    "route": "#/workload",
    "states": [
      "normal",
      "loading",
      "empty",
      "denied",
      "expired",
      "offline",
      "quota"
    ]
  },
  {
    "id": "capture-goal",
    "surface_id": "UI-004",
    "title": "What are you investigating?",
    "group": "Collect",
    "personas": [
      "maintainer",
      "admin"
    ],
    "entity": "Capture",
    "purpose": "Select a target and diagnostic goal",
    "route": "#/capture-goal",
    "states": [
      "normal",
      "loading",
      "empty",
      "denied",
      "expired",
      "offline",
      "quota"
    ]
  },
  {
    "id": "capture-compose",
    "surface_id": "UI-005",
    "title": "Choose evidence",
    "group": "Collect",
    "personas": [
      "maintainer",
      "admin"
    ],
    "entity": "RecipeDefinition",
    "purpose": "Compose shipped and team profiles with bounded custom actions",
    "route": "#/capture-compose",
    "states": [
      "normal",
      "loading",
      "empty",
      "denied",
      "expired",
      "offline",
      "quota"
    ]
  },
  {
    "id": "capture-processes",
    "surface_id": "UI-006",
    "title": "Choose processes",
    "group": "Collect",
    "personas": [
      "maintainer",
      "admin"
    ],
    "entity": "ResolvedTarget",
    "purpose": "Choose reload-safe logical selectors and bounded process batches",
    "route": "#/capture-processes",
    "states": [
      "normal",
      "loading",
      "empty",
      "denied",
      "expired",
      "offline",
      "quota"
    ]
  },
  {
    "id": "capture-network",
    "surface_id": "UI-007",
    "title": "Choose network evidence",
    "group": "Collect",
    "personas": [
      "maintainer",
      "admin"
    ],
    "entity": "SourceSession",
    "purpose": "Choose representation, dynamic peers, filters and ring limits",
    "route": "#/capture-network",
    "states": [
      "normal",
      "loading",
      "empty",
      "denied",
      "expired",
      "offline",
      "quota"
    ]
  },
  {
    "id": "capture-review",
    "surface_id": "UI-008",
    "title": "Review collection",
    "group": "Collect",
    "personas": [
      "maintainer",
      "admin"
    ],
    "entity": "AcceptedScope",
    "purpose": "Understand impact, permissions, sensitive data and effective retention",
    "route": "#/capture-review",
    "states": [
      "normal",
      "loading",
      "empty",
      "denied",
      "expired",
      "offline",
      "quota"
    ]
  },
  {
    "id": "captures",
    "surface_id": "UI-009",
    "title": "Captures",
    "group": "Collect",
    "personas": [
      "maintainer",
      "admin"
    ],
    "entity": "Capture",
    "purpose": "Find ongoing and completed requests without losing partial results",
    "route": "#/captures",
    "states": [
      "normal",
      "loading",
      "empty",
      "denied",
      "expired",
      "offline",
      "quota"
    ]
  },
  {
    "id": "capture-progress",
    "surface_id": "UI-010",
    "title": "Capture C-1042",
    "group": "Collect",
    "personas": [
      "maintainer",
      "admin"
    ],
    "entity": "Capture",
    "purpose": "Follow independent actions, approvals and available evidence",
    "route": "#/capture-progress",
    "states": [
      "normal",
      "loading",
      "empty",
      "denied",
      "expired",
      "offline",
      "quota"
    ]
  },
  {
    "id": "history",
    "surface_id": "UI-011",
    "title": "Capture history",
    "group": "Collect",
    "personas": [
      "maintainer",
      "admin"
    ],
    "entity": "CaptureHistory",
    "purpose": "Repeat settings with current permissions and fresh source selection",
    "route": "#/history",
    "states": [
      "normal",
      "loading",
      "empty",
      "denied",
      "expired",
      "offline",
      "quota"
    ]
  },
  {
    "id": "recordings",
    "surface_id": "UI-012",
    "title": "Existing recordings",
    "group": "Collect",
    "personas": [
      "maintainer",
      "admin"
    ],
    "entity": "SourceSession",
    "purpose": "See current history coverage and snapshot eligibility",
    "route": "#/recordings",
    "states": [
      "normal",
      "loading",
      "empty",
      "denied",
      "expired",
      "offline",
      "quota"
    ]
  },
  {
    "id": "recording-save",
    "surface_id": "UI-013",
    "title": "Save existing recordings now",
    "group": "Collect",
    "personas": [
      "maintainer",
      "admin"
    ],
    "entity": "SourceSnapshot",
    "purpose": "Preserve a bounded lookback without another recorder or dump",
    "route": "#/recording-save",
    "states": [
      "normal",
      "loading",
      "empty",
      "denied",
      "expired",
      "offline",
      "quota"
    ]
  },
  {
    "id": "policies",
    "surface_id": "UI-014",
    "title": "Monitoring policies",
    "group": "Monitor",
    "personas": [
      "maintainer",
      "admin"
    ],
    "entity": "DebugPolicy",
    "purpose": "Find coverage gaps, approvals and suppressed incidents",
    "route": "#/policies",
    "states": [
      "normal",
      "loading",
      "empty",
      "denied",
      "expired",
      "offline",
      "quota"
    ]
  },
  {
    "id": "policy",
    "surface_id": "UI-015",
    "title": "Checkout failures",
    "group": "Monitor",
    "personas": [
      "maintainer",
      "admin"
    ],
    "entity": "PolicyActivation",
    "purpose": "Explain why a policy did or did not capture",
    "route": "#/policy",
    "states": [
      "normal",
      "loading",
      "empty",
      "denied",
      "expired",
      "offline",
      "quota"
    ]
  },
  {
    "id": "policy-editor",
    "surface_id": "UI-016",
    "title": "Edit monitoring policy",
    "group": "Monitor",
    "personas": [
      "maintainer",
      "admin"
    ],
    "entity": "DebugPolicy",
    "purpose": "Compose bounded triggers and ongoing versus on-trigger evidence",
    "route": "#/policy-editor",
    "states": [
      "normal",
      "loading",
      "empty",
      "denied",
      "expired",
      "offline",
      "quota"
    ]
  },
  {
    "id": "policy-review",
    "surface_id": "UI-017",
    "title": "Review policy change",
    "group": "Monitor",
    "personas": [
      "maintainer",
      "admin"
    ],
    "entity": "AcceptedScope",
    "purpose": "Compare execution scope and approval impact before Kubernetes submission",
    "route": "#/policy-review",
    "states": [
      "normal",
      "loading",
      "empty",
      "denied",
      "expired",
      "offline",
      "quota"
    ]
  },
  {
    "id": "profiles",
    "surface_id": "UI-018",
    "title": "Capture profiles",
    "group": "Monitor",
    "personas": [
      "maintainer",
      "admin"
    ],
    "entity": "CaptureProfile",
    "purpose": "Discover immutable reusable building blocks",
    "route": "#/profiles",
    "states": [
      "normal",
      "loading",
      "empty",
      "denied",
      "expired",
      "offline",
      "quota"
    ]
  },
  {
    "id": "profile",
    "surface_id": "UI-019",
    "title": "HTTP request headers",
    "group": "Monitor",
    "personas": [
      "maintainer",
      "admin"
    ],
    "entity": "CaptureProfile",
    "purpose": "Inspect version, editable fields, prerequisites and privacy",
    "route": "#/profile",
    "states": [
      "normal",
      "loading",
      "empty",
      "denied",
      "expired",
      "offline",
      "quota"
    ]
  },
  {
    "id": "profile-editor",
    "surface_id": "UI-020",
    "title": "Publish a profile version",
    "group": "Monitor",
    "personas": [
      "maintainer",
      "admin"
    ],
    "entity": "CaptureProfile",
    "purpose": "Publish data-only bounded settings without in-place version edits",
    "route": "#/profile-editor",
    "states": [
      "normal",
      "loading",
      "empty",
      "denied",
      "expired",
      "offline",
      "quota"
    ]
  },
  {
    "id": "cases",
    "surface_id": "UI-021",
    "title": "Cases",
    "group": "Investigate",
    "personas": [
      "maintainer",
      "admin"
    ],
    "entity": "Case",
    "purpose": "Find related incidents and available evidence",
    "route": "#/cases",
    "states": [
      "normal",
      "loading",
      "empty",
      "denied",
      "expired",
      "offline",
      "quota"
    ]
  },
  {
    "id": "case",
    "surface_id": "UI-022",
    "title": "Checkout latency after rollout",
    "group": "Investigate",
    "personas": [
      "maintainer",
      "admin"
    ],
    "entity": "Case",
    "purpose": "Read incident timeline and independent evidence outcomes",
    "route": "#/case",
    "states": [
      "normal",
      "loading",
      "empty",
      "denied",
      "expired",
      "offline",
      "quota"
    ]
  },
  {
    "id": "artifact-summary",
    "surface_id": "UI-023",
    "title": "Evidence details",
    "group": "Investigate",
    "personas": [
      "maintainer",
      "admin"
    ],
    "entity": "Artifact",
    "purpose": "See collection identity, completeness, access and deletion deadlines",
    "route": "#/artifact-summary",
    "states": [
      "normal",
      "loading",
      "empty",
      "denied",
      "expired",
      "offline",
      "quota"
    ]
  },
  {
    "id": "artifact-logs",
    "surface_id": "UI-024",
    "title": "Logs",
    "group": "Investigate",
    "personas": [
      "maintainer",
      "admin"
    ],
    "entity": "Artifact",
    "purpose": "Read bounded redacted log excerpts with gaps",
    "route": "#/artifact-logs",
    "states": [
      "normal",
      "loading",
      "empty",
      "denied",
      "expired",
      "offline",
      "quota"
    ]
  },
  {
    "id": "artifact-files",
    "surface_id": "UI-025",
    "title": "Files and pod context",
    "group": "Investigate",
    "personas": [
      "maintainer",
      "admin"
    ],
    "entity": "Artifact",
    "purpose": "Inspect approved pseudo-file and Kubernetes snapshots",
    "route": "#/artifact-files",
    "states": [
      "normal",
      "loading",
      "empty",
      "denied",
      "expired",
      "offline",
      "quota"
    ]
  },
  {
    "id": "artifact-core",
    "surface_id": "UI-026",
    "title": "Stacks and memory",
    "group": "Investigate",
    "personas": [
      "maintainer",
      "admin"
    ],
    "entity": "AnalysisRun",
    "purpose": "Inspect symbol-aware stacks and request separate raw operations",
    "route": "#/artifact-core",
    "states": [
      "normal",
      "loading",
      "empty",
      "denied",
      "expired",
      "offline",
      "quota"
    ]
  },
  {
    "id": "artifact-packets",
    "surface_id": "UI-027",
    "title": "Network evidence",
    "group": "Investigate",
    "personas": [
      "maintainer",
      "admin"
    ],
    "entity": "Artifact",
    "purpose": "Compare peers, HTTP fields and actual capture/filter coverage",
    "route": "#/artifact-packets",
    "states": [
      "normal",
      "loading",
      "empty",
      "denied",
      "expired",
      "offline",
      "quota"
    ]
  },
  {
    "id": "artifact-syscalls",
    "surface_id": "UI-028",
    "title": "Syscall activity",
    "group": "Investigate",
    "personas": [
      "maintainer",
      "admin"
    ],
    "entity": "Artifact",
    "purpose": "Inspect syscall metadata, losses and separately approved arguments",
    "route": "#/artifact-syscalls",
    "states": [
      "normal",
      "loading",
      "empty",
      "denied",
      "expired",
      "offline",
      "quota"
    ]
  },
  {
    "id": "artifact-profile",
    "surface_id": "UI-029",
    "title": "Runtime profile",
    "group": "Investigate",
    "personas": [
      "maintainer",
      "admin"
    ],
    "entity": "Artifact",
    "purpose": "Understand units, sampling and hotspots",
    "route": "#/artifact-profile",
    "states": [
      "normal",
      "loading",
      "empty",
      "denied",
      "expired",
      "offline",
      "quota"
    ]
  },
  {
    "id": "profile-compare",
    "surface_id": "UI-030",
    "title": "Compare profiles",
    "group": "Investigate",
    "personas": [
      "maintainer",
      "admin"
    ],
    "entity": "AnalysisRun",
    "purpose": "Choose an authorized compatible baseline and normalization",
    "route": "#/profile-compare",
    "states": [
      "normal",
      "loading",
      "empty",
      "denied",
      "expired",
      "offline",
      "quota"
    ]
  },
  {
    "id": "raw-access",
    "surface_id": "UI-031",
    "title": "Request raw access",
    "group": "Investigate",
    "personas": [
      "maintainer",
      "recipient",
      "admin"
    ],
    "entity": "AccessGrant",
    "purpose": "Request bounded raw queries or native download of exact existing artifacts",
    "route": "#/raw-access",
    "states": [
      "normal",
      "loading",
      "empty",
      "denied",
      "expired",
      "offline",
      "quota"
    ]
  },
  {
    "id": "analysis-job",
    "surface_id": "UI-032",
    "title": "Analysis progress",
    "group": "Investigate",
    "personas": [
      "maintainer",
      "admin"
    ],
    "entity": "AnalysisRun",
    "purpose": "Understand scratch, symbols, isolated analysis and publication failures",
    "route": "#/analysis-job",
    "states": [
      "normal",
      "loading",
      "empty",
      "denied",
      "expired",
      "offline",
      "quota"
    ]
  },
  {
    "id": "share-compose",
    "surface_id": "UI-033",
    "title": "Share evidence",
    "group": "Share",
    "personas": [
      "maintainer",
      "admin"
    ],
    "entity": "EvidenceShare",
    "purpose": "Choose concrete outputs, recipients, owner teams and expiry",
    "route": "#/share-compose",
    "states": [
      "normal",
      "loading",
      "empty",
      "denied",
      "expired",
      "offline",
      "quota"
    ]
  },
  {
    "id": "shares",
    "surface_id": "UI-034",
    "title": "Sharing you manage",
    "group": "Share",
    "personas": [
      "maintainer",
      "admin"
    ],
    "entity": "SharingIntent",
    "purpose": "Manage snapshot shares and bounded future sharing separately",
    "route": "#/shares",
    "states": [
      "normal",
      "loading",
      "empty",
      "denied",
      "expired",
      "offline",
      "quota"
    ]
  },
  {
    "id": "share-detail",
    "surface_id": "UI-035",
    "title": "Incident response share",
    "group": "Share",
    "personas": [
      "maintainer",
      "admin"
    ],
    "entity": "EvidenceShare",
    "purpose": "Preview recipient access and revoke without changing collection",
    "route": "#/share-detail",
    "states": [
      "normal",
      "loading",
      "empty",
      "denied",
      "expired",
      "offline",
      "quota"
    ]
  },
  {
    "id": "shared",
    "surface_id": "UI-036",
    "title": "Shared with me",
    "group": "Share",
    "personas": [
      "recipient",
      "maintainer",
      "admin"
    ],
    "entity": "EvidenceShare",
    "purpose": "Discover only explicitly shared evidence",
    "route": "#/shared",
    "states": [
      "normal",
      "loading",
      "empty",
      "denied",
      "expired",
      "offline",
      "quota"
    ]
  },
  {
    "id": "shared-case",
    "surface_id": "UI-037",
    "title": "Shared checkout evidence",
    "group": "Share",
    "personas": [
      "recipient",
      "maintainer",
      "admin"
    ],
    "entity": "Case",
    "purpose": "Investigate a recipient projection without hidden artifacts or live inventory",
    "route": "#/shared-case",
    "states": [
      "normal",
      "loading",
      "empty",
      "denied",
      "expired",
      "offline",
      "quota"
    ]
  },
  {
    "id": "approvals",
    "surface_id": "UI-038",
    "title": "Approvals",
    "group": "Review",
    "personas": [
      "approver",
      "maintainer",
      "admin"
    ],
    "entity": "AccessGrant",
    "purpose": "Separate requests to review from own pending requests",
    "route": "#/approvals",
    "states": [
      "normal",
      "loading",
      "empty",
      "denied",
      "expired",
      "offline",
      "quota"
    ]
  },
  {
    "id": "approval",
    "surface_id": "UI-039",
    "title": "Review request",
    "group": "Review",
    "personas": [
      "approver",
      "admin"
    ],
    "entity": "AccessGrant",
    "purpose": "Review frozen target, impact, budget and expiry with independent identity",
    "route": "#/approval",
    "states": [
      "normal",
      "loading",
      "empty",
      "denied",
      "expired",
      "offline",
      "quota"
    ]
  },
  {
    "id": "agent",
    "surface_id": "UI-040",
    "title": "Connect your agent",
    "group": "Account",
    "personas": [
      "maintainer",
      "recipient",
      "admin"
    ],
    "entity": "Principal",
    "purpose": "Connect an external MCP client and hand off an authorized case reference",
    "route": "#/agent",
    "states": [
      "normal",
      "loading",
      "empty",
      "denied",
      "expired",
      "offline",
      "quota"
    ]
  },
  {
    "id": "access",
    "surface_id": "UI-041",
    "title": "Your access",
    "group": "Account",
    "personas": [
      "maintainer",
      "recipient",
      "approver",
      "admin"
    ],
    "entity": "AccessDecision",
    "purpose": "Explain effective rights and missing prerequisites",
    "route": "#/access",
    "states": [
      "normal",
      "loading",
      "empty",
      "denied",
      "expired",
      "offline",
      "quota"
    ]
  },
  {
    "id": "admin",
    "surface_id": "UI-042",
    "title": "Administration",
    "group": "Operate",
    "personas": [
      "admin"
    ],
    "entity": "InstallationProfile",
    "purpose": "See infrastructure readiness independently from evidence availability",
    "route": "#/admin",
    "states": [
      "normal",
      "loading",
      "empty",
      "denied",
      "expired",
      "offline",
      "quota"
    ]
  },
  {
    "id": "clusters",
    "surface_id": "UI-043",
    "title": "Clusters",
    "group": "Operate",
    "personas": [
      "admin"
    ],
    "entity": "ClusterRegistration",
    "purpose": "See connectivity, enrollment and capability coverage by region",
    "route": "#/clusters",
    "states": [
      "normal",
      "loading",
      "empty",
      "denied",
      "expired",
      "offline",
      "quota"
    ]
  },
  {
    "id": "cluster",
    "surface_id": "UI-044",
    "title": "eu-production",
    "group": "Operate",
    "personas": [
      "admin"
    ],
    "entity": "ClusterRegistration",
    "purpose": "Inspect node pools, local ceilings and bounded disconnected authority",
    "route": "#/cluster",
    "states": [
      "normal",
      "loading",
      "empty",
      "denied",
      "expired",
      "offline",
      "quota"
    ]
  },
  {
    "id": "enroll",
    "surface_id": "UI-045",
    "title": "Enroll a cluster",
    "group": "Operate",
    "personas": [
      "admin"
    ],
    "entity": "ClusterRegistration",
    "purpose": "Prepare a short-lived bootstrap credential and bounded installation bundle",
    "route": "#/enroll",
    "states": [
      "normal",
      "loading",
      "empty",
      "denied",
      "expired",
      "offline",
      "quota"
    ]
  },
  {
    "id": "capabilities",
    "surface_id": "UI-046",
    "title": "Capability report",
    "group": "Operate",
    "personas": [
      "admin"
    ],
    "entity": "CapabilityReport",
    "purpose": "Separate configured, inspected and actively verified capability",
    "route": "#/capabilities",
    "states": [
      "normal",
      "loading",
      "empty",
      "denied",
      "expired",
      "offline",
      "quota"
    ]
  },
  {
    "id": "permissions",
    "surface_id": "UI-047",
    "title": "Permission sources",
    "group": "Operate",
    "personas": [
      "admin"
    ],
    "entity": "PermissionSource",
    "purpose": "Inspect trusted namespace, workload and exec inheritance",
    "route": "#/permissions",
    "states": [
      "normal",
      "loading",
      "empty",
      "denied",
      "expired",
      "offline",
      "quota"
    ]
  },
  {
    "id": "permission-preview",
    "surface_id": "UI-048",
    "title": "Preview permission configuration",
    "group": "Operate",
    "personas": [
      "admin"
    ],
    "entity": "PermissionSource",
    "purpose": "Preview a Kubernetes configuration change without another CRUD API",
    "route": "#/permission-preview",
    "states": [
      "normal",
      "loading",
      "empty",
      "denied",
      "expired",
      "offline",
      "quota"
    ]
  },
  {
    "id": "retention",
    "surface_id": "UI-049",
    "title": "Retention policies",
    "group": "Operate",
    "personas": [
      "admin"
    ],
    "entity": "EvidenceRetentionPolicy",
    "purpose": "Inspect inherited maximum ages and managed-copy constraints",
    "route": "#/retention",
    "states": [
      "normal",
      "loading",
      "empty",
      "denied",
      "expired",
      "offline",
      "quota"
    ]
  },
  {
    "id": "retention-preview",
    "surface_id": "UI-050",
    "title": "Preview retention changes",
    "group": "Operate",
    "personas": [
      "admin"
    ],
    "entity": "EvidenceRetentionPolicy",
    "purpose": "See affected deadlines and incompatible backups before applying configuration",
    "route": "#/retention-preview",
    "states": [
      "normal",
      "loading",
      "empty",
      "denied",
      "expired",
      "offline",
      "quota"
    ]
  },
  {
    "id": "deletion",
    "surface_id": "UI-051",
    "title": "Evidence deletion",
    "group": "Operate",
    "personas": [
      "admin"
    ],
    "entity": "ArtifactCopy",
    "purpose": "Track inaccessible, pending, overdue and verified copies separately",
    "route": "#/deletion",
    "states": [
      "normal",
      "loading",
      "empty",
      "denied",
      "expired",
      "offline",
      "quota"
    ]
  },
  {
    "id": "deletion-detail",
    "surface_id": "UI-052",
    "title": "Deletion overdue",
    "group": "Operate",
    "personas": [
      "admin"
    ],
    "entity": "DeletionWork",
    "purpose": "Resolve a failed object-version cleanup without claiming deletion",
    "route": "#/deletion-detail",
    "states": [
      "normal",
      "loading",
      "empty",
      "denied",
      "expired",
      "offline",
      "quota"
    ]
  },
  {
    "id": "capacity",
    "surface_id": "UI-053",
    "title": "Capacity and fairness",
    "group": "Operate",
    "personas": [
      "admin"
    ],
    "entity": "CapacityAccount",
    "purpose": "Inspect protected workload allocations, shared burst and upload contention",
    "route": "#/capacity",
    "states": [
      "normal",
      "loading",
      "empty",
      "denied",
      "expired",
      "offline",
      "quota"
    ]
  },
  {
    "id": "integrations",
    "surface_id": "UI-054",
    "title": "Integrations",
    "group": "Operate",
    "personas": [
      "admin"
    ],
    "entity": "InstallationProfile",
    "purpose": "Inspect IdP, storage, keys, symbols, alert receivers and event destinations",
    "route": "#/integrations",
    "states": [
      "normal",
      "loading",
      "empty",
      "denied",
      "expired",
      "offline",
      "quota"
    ]
  },
  {
    "id": "audit",
    "surface_id": "UI-055",
    "title": "Audit activity",
    "group": "Operate",
    "personas": [
      "admin"
    ],
    "entity": "AuditReference",
    "purpose": "Inspect content-minimized decisions with authorized correlations",
    "route": "#/audit",
    "states": [
      "normal",
      "loading",
      "empty",
      "denied",
      "expired",
      "offline",
      "quota"
    ]
  },
  {
    "id": "install",
    "surface_id": "UI-056",
    "title": "Installation readiness",
    "group": "Operate",
    "personas": [
      "admin"
    ],
    "entity": "InstallationProfile",
    "purpose": "Configure reusable prerequisites and distinguish missing analysis scratch",
    "route": "#/install",
    "states": [
      "normal",
      "loading",
      "empty",
      "denied",
      "expired",
      "offline",
      "quota"
    ]
  },
  {
    "id": "upgrade",
    "surface_id": "UI-057",
    "title": "Upgrade preflight",
    "group": "Operate",
    "personas": [
      "admin"
    ],
    "entity": "CapabilityReport",
    "purpose": "Inspect compatibility, mirrored assets and changed capability qualification",
    "route": "#/upgrade",
    "states": [
      "normal",
      "loading",
      "empty",
      "denied",
      "expired",
      "offline",
      "quota"
    ]
  },
  {
    "id": "privacy-request",
    "surface_id": "UI-058",
    "title": "Evidence privacy action",
    "group": "Operate",
    "personas": [
      "admin"
    ],
    "entity": "PrivacyDecision",
    "purpose": "Request scoped early erasure or restricted processing with exact consequences",
    "route": "#/privacy-request",
    "states": [
      "normal",
      "loading",
      "empty",
      "denied",
      "expired",
      "offline",
      "quota"
    ]
  },
  {
    "id": "signin",
    "surface_id": "UI-059",
    "title": "Sign in to Asservat",
    "group": "Account",
    "personas": [
      "maintainer",
      "recipient",
      "approver",
      "admin"
    ],
    "entity": "Principal",
    "purpose": "Use the installation identity provider with safe return navigation",
    "route": "#/signin",
    "states": [
      "normal",
      "loading",
      "empty",
      "denied",
      "expired",
      "offline",
      "quota"
    ]
  },
  {
    "id": "help",
    "surface_id": "UI-060",
    "title": "Help and shortcuts",
    "group": "Account",
    "personas": [
      "maintainer",
      "recipient",
      "approver",
      "admin"
    ],
    "entity": "InterfaceHelp",
    "purpose": "Find workflow guidance and accessible navigation without embedded AI",
    "route": "#/help",
    "states": [
      "normal",
      "loading",
      "empty",
      "denied",
      "expired",
      "offline",
      "quota"
    ]
  },
  {
    "id": "live-sources",
    "surface_id": "UI-061",
    "title": "Live sources",
    "entity": "SourceSession",
    "purpose": "Choose existing authorized packet or syscall projections without starting collection",
    "route": "#/live-sources",
    "group": "Collect",
    "personas": [
      "maintainer",
      "admin"
    ],
    "states": [
      "normal",
      "loading",
      "empty",
      "denied",
      "expired",
      "offline",
      "quota"
    ]
  },
  {
    "id": "live-watch",
    "surface_id": "UI-062",
    "title": "Watch live",
    "entity": "LiveWatch",
    "purpose": "Observe bounded approved rows with independent filters, pause, gaps and expiry",
    "route": "#/live-watch",
    "group": "Collect",
    "personas": [
      "maintainer",
      "admin"
    ],
    "states": [
      "normal",
      "loading",
      "empty",
      "denied",
      "expired",
      "offline",
      "quota"
    ]
  },
  {
    "id": "artifact-download",
    "surface_id": "UI-063",
    "title": "Download evidence",
    "group": "Investigate",
    "personas": [
      "maintainer",
      "recipient",
      "admin"
    ],
    "entity": "ArtifactDownload",
    "purpose": "Download any authorized native artifact for local tools with coverage, grant reuse, resume and external-copy handling",
    "route": "#/artifact-download",
    "states": [
      "normal",
      "loading",
      "empty",
      "denied",
      "expired",
      "offline",
      "quota"
    ]
  }
];
