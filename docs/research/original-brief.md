# Asservat: design brief

## Overview

This brief is the hand-off for planning and building **Asservat**, an open-source debug evidence collector for Kubernetes. It triggers and collects core dumps and packet captures for arbitrary workloads, pre-analyses them, and exposes the results to humans and to AI agents through standard protocols. You are expected to plan the work, run the investigations listed below, and then implement it phase by phase.

The collector **collects evidence and nothing else**. It runs no LLM and no agent harness, and it writes to no ticket, chat or wiki system. Agent platforms and humans read its evidence through an MCP server and decide what to do with it. This separation is a core design principle: it keeps the collector small, auditable and usable with any agent stack. Do not build agent features into it.

*Asservat* is the German legal term for an item of evidence held in custody. The name states the project's role: Asservat secures evidence, seals it, controls and logs every access to it, and never delivers the verdict. Use these identifiers:

| Identifier | Value |
| --- | --- |
| Project, binary, Helm chart and container image name | `asservat` |
| Kubernetes API group | `asservat.io`, for example `debugcaptures.asservat.io` |
| CloudEvents type prefix | `io.asservat.` |
| Evidence URI scheme | `asservat://` |

!!! note
    On 2026-10-09 `asservat.io` had no DNS records, which suggests it is still unregistered. Register it, and run a trademark check, before the first CRD or event type is published. API groups and event types are hard to rename later.

## Why it exists

Kubernetes has no built-in way to collect core dumps or packet captures, and the existing options fall short:

- `kernel.core_pattern` is a node-global, non-namespaced kernel setting. Every solution needs a privileged node component, and that component is the only place where collection policy can be enforced.
- The established open-source core-dump handler for Kubernetes has had no release since late 2024. Newer handlers are single-author experiments.
- `kubectl debug` with tcpdump or gdb requires capabilities that Pod Security `baseline` forbids, so workload namespaces would have to be relaxed.
- Several capture tools phone home or depend on licence keys:
  - a widely used capture CRD project embeds a telemetry key in its published images;
  - a popular traffic analyser uses expiring licence keys;
  - an eBPF TLS-capture tool checks for updates with no opt-out.
- No existing tool hands dumps and captures to AI agents in a controlled way, with data classes, approvals and audit.

## Design principles

These principles are binding for every component and every dependency:

- **No call-home.** No telemetry, usage statistics, update checks or crash reporting to any third party, and no opt-out flags that default to on. Verify every component with egress blocked.
- **No licence keys or vendor control planes.** Every dependency must be open source with no kill-switch: no online licence checks, no expiring licence files, no required SaaS.
- **Air-gap capable.** Every image and chart can be mirrored into a private OCI registry, and nothing needs internet access at runtime, including symbol lookup.
- **Evidence is sensitive.** Core dumps and packet captures contain user data and secrets. Encrypt them before they leave the node, give access only through bounded, audited operations, and keep them for a short time by default.
- **Managed-Kubernetes friendly.** Work on clusters where nodes are vendor-managed and replaced on upgrade, the CNI is fixed (including managed Cilium), and there is no SSH access to nodes.
- **Workload namespaces stay `restricted`.** Only the collector's own namespace is privileged.
- **Pluggable backends** for object storage, key management and identity, with one well-supported default each.
- **Standard interfaces only:** MCP for agents, CloudEvents for notifications, OIDC/OAuth for identity, Kubernetes CRDs and RBAC for requests.

!!! warning
    Develop and test with synthetic crashes and synthetic traffic only. Never use real production evidence in tests, CI logs or bug reports.

For every dependency, record its licence, maintainer base, call-home behaviour and the settings that disable it, in the implementation plan.

## Scope

| In scope | Out of scope |
| --- | --- |
| Crash-triggered and on-demand core dumps for C/C++, Go, Rust, .NET, Python (including CUDA processes), Node.js and JVM workloads | LLMs, agent harnesses, prompts |
| Packet captures for pods, header-only by default | Posting findings to tickets, chat or wikis |
| Pre-analysis into compact, structured extracts | Error-tracking dashboards |
| An MCP server for agents, with data classes, grants and audit | Cluster provisioning |
| An approval page for raw access | A general-purpose UI beyond approvals and case browsing |
| CloudEvents notifications for new cases | |

## Architecture

The collector has nine components. Build only what the table marks as build.

| # | Component | Build or reuse | Runs as |
| --- | --- | --- | --- |
| 1 | Node crash agent and on-demand dump executor | Build | Privileged DaemonSet |
| 2 | Capture engine | Reuse Inspektor Gadget, driven by component 3 | Inspektor Gadget DaemonSet |
| 3 | Controller and trigger router (`DebugCapture` CRD) | Build | Deployment |
| 4 | Evidence store | Reuse S3-compatible object storage; build the manifest and encryption | External |
| 5 | Symbol and source mapping | Reuse debuginfod and symbol stores | External or optional Deployment |
| 6 | Analysis sandbox | Build; Kubernetes Jobs created by component 3 | Job per artefact |
| 7 | MCP server | Build | Deployment |
| 8 | Grant store and approval page | Build | Part of component 7, or a Deployment next to it |
| 9 | Case events | Build, small | Part of component 3 |

**Default language: Go** for components 1, 3, 6 (orchestration), 7, 8 and 9. It has client-go and controller-runtime, a Tier 1 MCP SDK, the CloudEvents SDK and a Vault-compatible client. Propose another language only with a reason, for example Rust for the core pipe helper.

**Minimal hard dependencies:** Kubernetes, an S3-compatible bucket, a key-management backend, and an OIDC provider for the MCP server and the approval page. Workflow engines such as Argo Workflows or Argo Events are integrations, not dependencies: they can consume the CloudEvents or create `DebugCapture` resources.

### 1. Node crash agent

The kernel ignores `RLIMIT_CORE` for piped `core_pattern` handlers, and common container runtimes run with an unlimited core limit. The handler is therefore where policy is enforced.

Requirements:

- **Pattern:** set a piped `core_pattern` on every node and re-apply it after every boot. Expose a health check and a metric that fail when the pattern drifts, because node images and other agents may overwrite it. Support pipe mode everywhere. The socket mode needs kernel 6.17+ and is optional where available.
- **Opt-in and deny-list:** collect only from namespaces that carry an opt-in label. Support a deny-list for key-handling workloads such as secret stores, key-management services, identity providers and certificate managers. Document `PR_SET_DUMPABLE=0` as a second line for those.
- **Enrich before the process is reaped:**
  - resolve the pod and container from `/proc/%P/cgroup` (lookup by hostname breaks for `hostNetwork` pods);
  - record the image digest from the container status;
  - record the ELF build-IDs, signal and executable;
  - record the `org.opencontainers.image.revision` label where present.
- **Signature and rate limit:** compute a crash signature from build-ID, signal and top frames. Rate-limit per signature, so a CrashLoopBackOff does not become a dump storm.
- **Stream, never buffer:** core → zstd → AEAD encryption → multipart upload. Node replacement destroys anything buffered on node disk. Enforce a size cap per configurable runtime class.
- **Encrypt on the node:**
  - get a per-artefact data key from the key-management backend;
  - upload with a credential that can write but not read;
  - store the wrapped key and the plaintext and ciphertext SHA-256 in the manifest.
- **Announce:** write a JSON manifest next to the artefact, and emit a Kubernetes Event.
- **On-demand dumps:** the same agent executes approved on-demand dumps against the target's host PID: `gcore`, `dotnet-dump collect` through the diagnostic port, `jcmd`, `py-spy dump --native` or `pystack remote`, and CUDA user-triggered dumps. A live dump pauses the process, so every on-demand dump needs a grant (component 8).

Runtime recipes:

| Runtime | On crash | On demand | Pre-analysis (component 6) |
| --- | --- | --- | --- |
| C/C++, Rust | Kernel core through the agent | `gcore` | `gdb -batch` all-thread backtraces with symbols, signal, registers |
| Go | Kernel core with `GOTRACEBACK=crash` | `gcore` | `gdb` or Delve core analysis |
| .NET | Kernel core; optionally the runtime's own minidump settings | `dotnet-dump collect` | `dotnet-dump analyze` (SOS): `clrstack -all`, `dumpheap -stat` |
| Python, including CUDA | CUDA GPU dump with the skip-memory options; host core shaped by `coredump_filter`; `PYTHONFAULTHANDLER` | `py-spy dump --native`, `pystack remote`, CUDA user-triggered dump | `pystack core`, `cuda-gdb` |
| Node.js | `--report-on-fatalerror`; `--abort-on-uncaught-exception` for a core | `--heapsnapshot-signal` | Report JSON |
| JVM | `-XX:+HeapDumpOnOutOfMemoryError`, hs_err file | `jcmd Thread.print`, `GC.heap_dump` | Eclipse MAT headless |

!!! note
    A full core of a GPU inference server can be hundreds of GiB. The kernel keeps the process alive until the pipe helper finishes, so liveness probes and restarts interact with dump time. Measure this before you set default size caps and timeouts.

### 2. Capture engine

Recent Cilium versions no longer ship a pcap recorder, and Hubble gives flow metadata only. Packets therefore come from Inspektor Gadget's `tcpdump` gadget, which writes pcap-ng with node, pod, container and label metadata. Inspektor Gadget is Apache-2.0 and a CNCF project.

- Capture in the pod's network namespace or on its host-side veth. With node-to-node encryption (WireGuard, IPsec), only there is the traffic plaintext and unique.
- Run a pinned, signature-verified gadget allow-list from a configurable registry, with pulls of anything else disabled.
- Never expose Inspektor Gadget directly. It has node-wide visibility, and its client-side filters are not a security boundary. Only component 3 drives it.
- Inspektor Gadget has no upload, so component 3 streams its output through the same encrypt-and-upload path as cores.
- **Two modes:**
  - **Header-only** (default): a ring buffer with a short snaplen (default 96 bytes for TLS, 60 for cleartext HTTP/2), frozen and uploaded when a trigger fires.
  - **Payload** (snaplen 0): only under a grant. Decrypting application TLS through key logging or Inspektor Gadget's `trace_ssl` gadget needs a separate grant.
- Optionally collect Hubble flows as context when the cluster runs Cilium with Hubble.

### 3. Controller and trigger router

The controller owns a namespaced `DebugCapture` resource in the `asservat.io` API group (core, live dump, pcap), so Kubernetes RBAC decides who may request evidence.

- **Spec:** target (pod or selector), kind, mode, duration, byte limit, filter, reason and case reference.
- **Status:** phase, artefact references and errors.
- **Admission caps:** ship a ValidatingAdmissionPolicy that limits duration, size, snaplen and target namespaces.
- **Built-in triggers:**
  - an Alertmanager-compatible webhook receiver;
  - a watch on container exits with codes 134 and 139 and on OOMKilled;
  - the crash agent's Kubernetes Events;
  - manually created resources.
- **Cases:** open one case per (cluster, workload, signature) and append recurrences.
- **Analysis:** create one sandbox Job (component 6) per artefact.

### 4. Evidence store

- **Storage:** any S3-compatible bucket. Treat the bucket's own server-side encryption as defence in depth only, because artefacts are already encrypted on the node.
- **Key management:** pluggable. The first backend is Vault-compatible Transit (OpenBao or HashiCorp Vault). Design the interface so that cloud KMS services or a local key file can be added.
- **Manifest per artefact:** case ID, cluster, namespace, pod, container, node, image digest, build-IDs, source revision, signal or trigger, alert fingerprint, signature, sizes, hashes, wrapped key reference, data classes available and retention.
- **Retention:** short by default (72 hours, configurable) through bucket lifecycle rules, with a per-case legal hold. Deleting the key version crypto-shreds every copy.
- **Locality:** document that evidence should be stored and analysed in the cluster or environment where it was collected.
- **Provenance** (phase 3): sign each manifest as an in-toto statement with cosign, using a key held in the key-management backend and no public transparency-log upload.

### 5. Symbol and source mapping

- Support a self-hosted elfutils debuginfod for native code and a private symbol store for .NET portable PDBs.
- Never default to public symbol servers. Override `DEBUGINFOD_URLS` and the .NET symbol server explicitly, so lookups work air-gapped.
- The analysis sandbox runs from the crashed container's image digest, so binaries, libraries, the .NET DAC and the Python interpreter match exactly.

### 6. Analysis sandbox

A Kubernetes Job per artefact runs the pre-analysis from the recipe table:

- no network (default-deny NetworkPolicy);
- non-root;
- only the one artefact mounted;
- decryption through a key-management role that only the sandbox holds.

For captures it produces limited `tshark -T json` output, `-z` conversation and expert statistics, and Zeek JSON logs. The outputs are the **extract** data class. Run a secret and high-entropy redaction pass over them, store them encrypted like the artefacts, and record them in the case.

When a case's extracts are ready, emit `case.analysis.completed` (component 9).

### 7. MCP server

Agents, and any other MCP client, read evidence only through this server.

- **Protocol:** MCP **2026-07-28** over Streamable HTTP, with a fallback for 2025-11-25 clients. The new revision is stateless, so cross-call state (cursors, debugger sessions, grant IDs) is a server-minted handle passed as a tool argument. Validate the handle against the caller's `sub` and `azp` on every call.
- **Tools first:** every capability is a tool with an `outputSchema`, because agent clients support tools far better than resources. Resource links (`asservat://case/<id>/…`) are optional mirrors. Do not use Sampling, Roots, Logging or Dynamic Client Registration; all are deprecated.
- **Tool groups:**

  | Group | Tools |
  | --- | --- |
  | Discovery | `list_cases`, `get_case` (manifest and available data classes), `find_similar_cases(signature)` |
  | Extract (default) | `get_backtrace`, `get_runtime_summary`, `get_pcap_summary`, `get_zeek_log` |
  | Raw (grant required) | `request_raw_access`, `get_grant`, `read_memory` (byte cap), `debugger_command` (allow-listed commands such as `bt`, `frame variable`, `clrstack`, `dumpheap -stat`), `pcap_query` (display filter, `max_packets`, field projection) |
  | Disabled by default | `request_capture` |

- **Result contract:** every result carries a `data_class` field and `{truncated, next_cursor, narrowing_hint}`. Keep default responses to about 5,000–8,000 tokens.
- **No raw bytes:** raw bytes never leave as files or presigned URLs. Raw access is always a bounded query executed in an analysis sandbox.
- **No model:** the server runs no model, so similarity search is deterministic (signature match, label filters, full-text over extracts).
- **Authorization:** any OIDC provider acts as the OAuth authorization server.
  - The server publishes RFC 9728 protected-resource metadata and validates the token audience strictly. Support identity providers that set the audience through a mapper, because RFC 8707 resource indicators are not yet universal.
  - Support pre-registered clients, including workload identities such as projected ServiceAccount tokens.
  - `evidence:read` is advertised and covers discovery and extract tools.
  - `evidence:raw` is never advertised; request it through a `403 insufficient_scope` challenge.
- **Grants:** a scope alone never authorizes a raw call. The call must also match an active grant with these fields: `grant_id`, `case_id`, `artefact_digest`, `operations`, `requester_sub`, `requester_azp`, `approver_sub`, `reason`, `not_after`, `max_bytes`.
- **Audit:** write one append-only record per `tools/call`. It holds `sub`, `azp`, the tool, an argument hash, `case_id`, `data_class`, `grant_id`, the result size and SHA-256, the decision and `traceparent`.
- **SDKs:** pin MCP SDK versions and track their security advisories.

### 8. Grant store and approval page

Raw reads, payload captures and on-demand live dumps all go through the same flow:

1. `request_raw_access` creates a pending grant and emits `grant.requested`.
2. A second person opens the approval page and approves. The page signs in through the OIDC provider with step-up authentication. It enforces that:
   - the approver is not the requester;
   - the approver belongs to a configurable approver group;
   - the grant expires within a configurable window (default 8 hours).
3. The grant is stored authoritatively here. The requester polls `get_grant`.

Do not implement approval through MCP elicitation, because the spec requires the requester to complete it, and do not rely on agent platforms' tool-approval features. Ship defaults that suit strict environments and document how to adjust them.

### 9. Case events

The collector notifies consumers with content-free CloudEvents 1.0, POSTed to configurable webhook URLs and signed with Standard Webhooks headers.

- **Types:**
  - `io.asservat.case.opened.v1`;
  - `io.asservat.case.recurred.v1`, rate-limited per case;
  - `io.asservat.case.analysis.completed.v1`;
  - `io.asservat.grant.requested.v1`.
- **Envelope:** `source` plus `id` is unique per event, `subject` carries the crash signature, and `dataref` points to `asservat://case/<id>`.
- **Data:** only identifiers (case ID, cluster, namespace, workload, image digest, source revision, alert fingerprint, occurrence count, available data classes). Never evidence content.
- **Tracing:** propagate W3C `traceparent` in the event and in MCP `_meta`.

The collector holds no write credential for any ticket, chat or wiki system.

## Phases

| Phase | Delivers | Exit criterion |
| --- | --- | --- |
| 0 | Investigations below, implementation plan, project decisions (licence, governance), registration of `asservat.io` and a trademark check | Maintainers have reviewed the plan |
| 1 | Capture engine integration; header-only capture rings frozen on trigger; evidence store with node-side encryption and manifests; pcap pre-analysis; MCP server with discovery and extract tools; case events. No `core_pattern` changes yet | A test alert produces a case and a CloudEvent, and a generic MCP client lists the case and reads its pcap summary |
| 2 | Crash agent with `core_pattern`; symbol lookup; C/C++, Go and .NET pre-analysis; grant store and approval page; on-demand `gcore` and `dotnet-dump` under a grant | A deliberate SIGSEGV yields an encrypted core, a symbolised backtrace through `get_backtrace` and a case event; an on-demand dump runs only after approval |
| 3 | Python and CUDA recipes, the host-core size policy, JVM and Node.js recipes; payload captures and TLS key logging under grants; raw tools; signed manifests | Each runtime has a passing crash test; raw tools are refused without a grant |
| 4 | Air-gap hardening and packaging: mirror manifests, offline install docs, egress-blocked CI test | Install and crash tests pass with all egress blocked |

## Investigations for phase 0

Run these before you fix the design; each answer can change it. Use kind and k3s plus at least two managed Kubernetes services whose nodes are vendor-managed. Ask the maintainers before you create paid cloud resources.

1. **`core_pattern` on managed nodes.**
   - Read the default pattern (distribution crash reporters such as apport often drop container cores), `kernel.yama.ptrace_scope`, the container runtime's core limit and the kernel version per node image.
   - Set a piped pattern from a privileged DaemonSet outside `kube-system`.
   - Verify that the setting holds across reboot, node-pool upgrade and automatic node replacement, and measure the window between boot and DaemonSet readiness.
2. **Inspektor Gadget with managed CNIs:** run the `tcpdump` gadget against pods on Cilium (with kube-proxy replacement and WireGuard) and on at least one other CNI; check interface names and socket-level load balancing.
3. **CUDA core dumps** on at least one GPU node type with a vendor-managed driver: enable them on exception, then open the dump with `cuda-gdb`.
4. **Large cores:** time streaming a core of 100+ GiB through zstd and encryption to object storage, and observe probe and restart behaviour meanwhile.
5. **OIDC providers:** test Keycloak and at least one other provider. Cover workload-identity client authentication, the audience mapping, and step-up authentication for the approval page.
6. **MCP SDK:** whether the Go SDK serves 2026-07-28 and 2025-11-25 clients from one endpoint.
7. **Symbols:** how common base images and build setups ship debug info (DWARF, separate debug files, .NET PDBs), and what the documentation must ask users to change.

## Decided and open

**Decided. Do not reopen without the maintainers:**
- the name is Asservat, with the identifiers listed in the overview;
- the collector runs no LLM and writes to no external system except the evidence store and event webhooks;
- MCP with tools first is the agent interface;
- events are content-free CloudEvents;
- artefacts are encrypted on the node;
- Inspektor Gadget captures packets;
- the project builds its own crash agent;
- raw access needs a second person through the approval page;
- workload namespaces stay `restricted`;
- there is no call-home of any kind.

**Open. Propose in the plan:**
- the licence (Apache-2.0 suggested, to match the Kubernetes ecosystem);
- the `DebugCapture` schema;
- the manifest schema and bucket layout;
- the default size caps per runtime class;
- the Helm chart structure;
- the repository layout and CI;
- the documentation of data-protection obligations for operators, such as guidance for impact assessments and retention.

## How to work

- **Plan first.** Start with a written implementation plan, covering:
  - components and repository layout;
  - the dependency list with licence and call-home review;
  - test strategy;
  - investigation results;
  - risks.

  Wait for the maintainers' review before phase 1.
- **Test first.** Write tests first where feasible. Reproduce every bug with a failing test before you fix it. Run tests and linters before every pull or merge request.
- **Test without egress.** Keep an end-to-end test suite that runs on kind with egress blocked, so that "no call-home" and "air-gap capable" stay true.
- **Ask first** before anything outward-facing or hard to reverse: paid cloud resources, public releases, registry pushes, changes to protected branches.
