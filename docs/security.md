# Security and privacy design

Read with [authorization and sharing](../specs/authorization.md) and [evidence lifecycle](../specs/evidence.md) and [privacy controls](../specs/privacy.md).

Native download of every gathered artifact and saved derivative is supported under [REQ-DLD-001–004](../specs/artifact-downloads.md). Managed encryption protects storage; authenticated HTTPS delivers readable native files to authorized local tools. Explicit raw-download grants, current artifact access, transfer budgets and audit apply. The scoped regional downloader and relays join the plaintext-handling boundary; no managed plaintext scratch/cache or unwrap credentials at the hub. Local files are outside automatic deletion and cannot be recalled. A controlled disclosure is not a claim that the recipient's machine is trusted for future storage or execution.

## Trust model

The node collector can observe and affect opted-in processes using host privileges. A fully compromised collector/node can forge observations or access plaintext before encryption. Encryption and signed manifests protect transport/storage and attest origin; they cannot establish truth against that host. Cluster administrators, KMS administrators and root-capable infrastructure operators are part of the trusted computing base. No "zero trust" or forensic nonrepudiation claim is made.

An installation serves one organization across its enrolled clusters. Its administrators manage identity-provider trust, user/group eligibility and workload permissions; unrelated organizations use separate installations. Application users, workload-controlled files/logs, packet contents, registry image layers, debugger scripts, webhook inputs, and external agent clients are untrusted. Shared recipients are authenticated but may lack any workload entitlement. They receive only explicit evidence rights.

## Threats and controls

| Threat | Control | Verification |
| --- | --- | --- |
| Confused deputy: user CRD makes privileged collector inspect a neighbor | Local namespace ceiling, target UID binding, independent grant validation, no generic CRI proxy | SC-TGT-003, SC-AUT-002 |
| PID/name/IP reuse redirects a dump/read | Process identity tuple, pinned descriptors, immediate revalidation, peer filter generations | SC-TGT-002, SC-TGT-004 |
| Path/symlink race escapes container | Kernel path confinement, separate proc adapter, restricted file types and blocking-worker limits | SC-ACT-002 |
| Command runs with host privileges | Runtime exec or qualified credential/cgroup/seccomp adapter; no inherited secrets or shell interpolation | SC-ACT-003 |
| Packet "headers" leak payload | Explicit parser/sanitizer, fail closed for unsupported layouts, test secret markers | SC-ACT-004 |
| Grant race or retry repeats a pause/dump | SQL transactions and local CAS reservations, idempotent operation IDs, fencing, conservative spend, indeterminate outcome | SC-AUT-004 |
| Shared view leaks neighbor metadata | Organization identity eligibility, explicit artifact snapshot, authorized result projection before counts/pagination | SC-SHR-001, SC-SHR-002 |
| Future sharing expands silently | Source/plan/projection pinning, finite capture/artifact limits, complete lineage checks, per-selection raw review | SC-SHR-004 through SC-SHR-006 |
| Revoked instruction recreated by late worker or GitOps replay | Parent revision checked before delivery, terminal revocation, child tombstones and conservative recovery | SC-SHR-007 |
| Revoked share/cursor still works | Authoritative revision checks at result delivery, current group evidence, bounded permit TTL | SC-SHR-003 |
| Malicious evidence executes analyzer code | Trusted tools, disabled auto-load/plugins, offline isolated Jobs and strict resource limits | SC-EVD-005 |
| Parser escape reaches storage/KMS | Separate acquisition/publication identities and Jobs; no credentials in analyzer | SC-EVD-005 |
| Evidence instructs external AI to exfiltrate | Explicit untrusted-content framing; no server execution or URL following; client remains responsible | SC-MCP-004 |
| Metadata or OAuth URL used for SSRF | Configured issuer/endpoint allowlists, no arbitrary discovery URLs, redirect/address checks | SC-MCP-001, SC-EVT-001 |
| Ownership metadata or exec inheritance expands scope | Protected source configuration/metadata, exact SAR subjects, admission-parity qualification, retained audiences and bounded freshness | SC-PER-003, SC-PER-004, SC-PER-008 |
| CRD/GitOps submission impersonates a powerful actor | Authenticated submission envelope, protected status, actor/executor mapping and current target checks | SC-PER-007 |
| Stolen token replays against another service/cluster | Issuer/audience/client and cluster authorization checks, mTLS identities, short expiries | SC-AUT-001, SC-FED-001 |
| S3 tampering or incomplete object accepted | AEAD, explicit checksums, conditional commit, manifest chain, optional Object Lock | SC-EVD-001, SC-EVD-002 |
| Retention bypass via backups/derived data/holds | Administrator maxima, inherited deadlines, managed-copy inventory, separate access/deletion deadlines, restore gate and explicit legal-exception policy | SC-PRV-002/003/004/005 |
| Collector or noisy workload exhausts shared resources | Cross-policy/workload rate limits, reservations before acquisition, fair transfer, protected storage, bounded queues, impact breakers and helper qualification | SC-CAP-001 through SC-CAP-006 |

## Service authority

- Hub query service reads catalog, active grants/shares and audit-write endpoint. It cannot read workload Secrets, run pods/exec or issue node commands directly.
- Hub grant/sharing service alone mutates grant/share/SharingIntent authoritative status; controllers cannot impersonate a human approver. Browser actions authenticate users; Kubernetes workload users have neither a grant/share CRD endpoint nor SQL credentials.
- Local controller reads permitted workload metadata and creates Asservat analysis Jobs only in its namespace. It cannot create arbitrary privileged workload pods from user-supplied templates.
- Node collector gets narrowly scoped wrap/upload credentials and the necessary local process privileges. Collection recipes cannot select arbitrary credential profiles or external destinations.
- Acquisition workers get one-artifact, short-duration decrypt/read grants. Analyzer Jobs receive no token/KMS role. Publisher workers can write outputs, not decrypt arbitrary evidence.
- Retention worker has deletion privileges isolated from ingestion and query paths. Hold changes require explicit retention-admin authority; holding evidence does not grant reading it.

Roles are implemented through Kubernetes RBAC, SQL service roles, service identity, bucket/KMS policies and application checks together. A namespace label alone does not grant evidence access. Group/owner mappings come from protected AccessBindings or configured trusted sources. Namespace annotations are permitted where their writers are trusted administrators; mutable workload/pod labels do not establish authority without the required guards. See [permission management](../specs/permissions.md).

## Sharing policy

Extract sharing is enabled only for authorized evidence owners and identities admitted by the organization's identity policy. Owner authority means the configured evidence-owner role for that case, not simply the user who happened to trigger collection. Received shares cannot be delegated onward. Raw sharing adds approver review, followed by recipient-specific raw query grants. Approval, sharing and retention purposes are separate records. Collection-time instructions pin an immutable creator and personal/team management, exact source plan, bounded recipients/output projections and expiry before collection. Policy instructions additionally require explicit future-capture opt-in and a finite count. Publication requires committed evidence and complete matching lineage; independent raw-sharing approval may cover these bounded future outputs but never manufactures a recipient raw-query grant. Revoking a parent intent or selection approval denies dependent child reads before asynchronous cleanup, and individual child revocation prevents automatic recreation. Stops/policy deletion only drain registration; the UI distinguishes them from revocation.

Personal shares suspend on loss of the creator's authority. Team-managed shares continue while a pinned managing assignment remains valid and the retained scope remains authorized; creator departure alone is not suspension. Loss of every valid manager suspends dependent access. Explicit administrator recovery/transfer cannot reset limits or expose historical evidence without authorization. Group membership freshness defaults to five minutes. Individual revocation and share revision changes take effect on the next operation without that group-cache delay. Never suggest that revocation retracts a response already delivered to a human/model.

## Data handling

Maintain a field inventory: raw core/heap/packet/file/log data; projected extracts; content-free operational metadata; identity/audit metadata. Minimize each separately. Redaction is best-effort and versioned. Hashes of sensitive low-entropy values may still leak information; use keyed audit digests and protect plaintext content hashes inside encrypted manifests.

Operators choose lawful purpose, access groups, finite retention maxima and storage/disclosure region. The [privacy review](research/privacy-retention.md) maps GDPR guidance to concrete controls, responsibilities and remaining feasibility gates. Unknown user-data presence is treated conservatively; access class is not proof of anonymity. Documentation must support records of processing, access reviews, incident handling and an assessment of whether a DPIA is required. Product defaults are not compliance certification or legal advice. Relevant EU obligations include purpose/storage limitation, security of processing, and impact assessment where applicable. [GDPR Articles 5, 32 and 35](https://eur-lex.europa.eu/eli/reg/2016/679/oj/eng).

Neither test fixtures nor bug reports may contain production evidence. Synthetic packet markers, fake secrets and generated crashes are required. Security logs use opaque identifiers and no payloads. The product displays the registered external AI-client disclosure boundary and configured handling policy before raw approval; Asservat cannot enforce the downstream model provider's retention policy.

## Added state and packet boundaries

SQL is now authoritative hub state. Restrict credentials to runtime/migration/backup roles, require TLS and qualified primary fencing, and deny authorization from stale replicas/projections. An outbox commit is not durable object audit; new sensitive dispatch/disclosure waits for that audit. Restore must not resurrect revoked grants/shares or consumed permits. See [persistence](../specs/persistence.md).

Managing teams are stable issuer-scoped owner assignments, separate from immutable creators and recipients. Current membership, retained access and authority are rechecked; management cannot make an unseen historical core readable or permit self-approval. A source outage suspends affected authority without manufacturing a broader fallback.

Pcap expressions intersect mandatory target/peer filters. Payload-sensitive predicates need sensitive authority. HTTP parsing consumes untrusted input within hard CPU/state limits and drops unknown framing rather than retaining raw fallback. Bodies/credentials must be absent from retained HTTP evidence; TLS plaintext requires a separate future approved mechanism. Qualification tests cover malformed streams, IP reuse, map update races and stalls.

Whole-pod scope is now explicit (ADR-028). No container-level confidentiality/permission claim is made; internal container/process provenance prevents target reuse and distinguishes sources. Partial-container exec rights cannot be widened through inheritance. Logical process selectors are bounded approved templates: resolve before the batch, pin each attempt and never follow PID reuse. PodNetwork does not authorize hostNetwork traffic outside a qualified attribution mechanism. Sensitive observation sessions charge inspected wire bytes independently of retained snapshots; backup/index expiry follows REQ-PRV-008.

## Profile publication and syscall isolation

A published profile is reusable configuration, never a grant. Protected catalog locations, immutable versions, authenticated Kubernetes writers and current target/definition checks prevent namespace shadowing and stale-definition execution. Literal field overrides cannot inject arbitrary patches, change impact labels or execute a template. Combined actions receive the ordinary scope/approval checks and quotas. Syscall metadata must avoid user-memory reads at acquisition; sensitive arguments use bounded pre-read event/byte reservations and independent raw-analysis/share approval. Follow [capture profiles](../specs/capture-profiles.md) and [syscalls](../specs/syscalls.md).

## Assessment disclosure boundaries

[Impact and data notices](../specs/capture-assessment.md) use reviewed mechanism rules and already authorized context; they never inspect user data opportunistically to declare it safe. Publisher text cannot suppress warnings. Shared-artifact notices exclude hidden parents and targets. Automatic deletion notices distinguish access denial, cleanup and verified removal, and never promise recall of external-agent disclosures. Warning acknowledgment cannot replace a grant, current authority or collection ceiling.
