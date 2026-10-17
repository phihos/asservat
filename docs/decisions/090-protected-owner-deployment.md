# ADR-090 — Protected owner deployment inputs and rotating credentials

Date: 2026-10-11. Status: selected for implementation under continuing maintainer authorization. Requirements: REQ-DEP-003, REQ-DEP-005, REQ-FED-001, REQ-DLD-003; part of TASK-02/07/11 and S-01/S-02.

## Problem

ADR-088 supplies the owner runtime, but programmatic dependencies alone cannot start an installed process. Ordinary Kubernetes projections rotate credentials using symlinks; holding an earlier token indefinitely or accepting an ambient kubeconfig/SQL DSN would bypass protected installation inputs. Opening a FIFO before checking its file type can also block startup or renewal indefinitely.

## Decision

Add a private, versioned deployment document at `/run/asservat/hub/deployment.json`, with fixed separate credential filenames. The installation owns this read-only projection and supplies the Pod UID through the Downward API. The document pins provider endpoints/public CA roots, installation/control namespace/configuration source, workload protection and finite resource limits. It cannot contain credentials, arbitrary paths, callbacks or permission grants. The installer produces it; developers have no new setup or approval. Schemas and the exact file table are in [the deployment contract](../architecture/owner-deployment.md).

`bootstrap.NewOwnerDeployment` builds five independent SQL pools, current accepted owner configuration, native Kubernetes proof/protection/discovery, encrypted owner audit, separate OpenBao server/client signing, the multi-cluster read facet, worker trust catalog and existing runtime/router. Reject duplicate SQL role names. Scope each provider credential to its existing purpose. Constructor success is neither configuration acceptance nor recovery acceptance. This process has no configuration-acceptance or recovery-write credential, and no artifact unwrap credential.

Use the shared C-21 mounted-file reader with confined relative symlinks, nonblocking open, bounded regular-file reads and rejection of group/world-writable files. Open each file afresh; support Kubernetes AtomicWriter replacement without permitting symlink escape. Missing or malformed current credentials never fall back to ambient or previously cached credentials. Qualified local projection storage remains required; a stuck remote filesystem is not made interruptible by a Go context.

Read Kubernetes/OpenBao tokens and S3 credentials per provider request. Refresh SQL passwords before each new connection while retaining the initially selected username; changing the role or pinned provider topology requires a process restart. Existing SQL sessions retain their finite pool lifetime and current database privileges. Rotating a password is not immediate cancellation of an already authenticated session. Do not claim reliable Go/SDK secret zeroization.

Reopen the public worker-control bundle every second; validate changed bytes before publishing a complete atomic catalog. An empty valid bundle removes all worker trust. A missing or invalid bundle stops this owner subsystem and joins its runtime work. ADR-089's catalog replacement itself still preserves its prior snapshot on invalid input; the loader does not continue serving while reporting that invalid input as a successful refresh. Missing individual documents in a valid bundle deny only the affected workers. Whole-bundle failure is an installation fault, visible as process failure; another healthy replica may continue. This conservative initial failure behavior can later become a scoped health state only with explicit current-input and delivery semantics.

Add the `asservat hub-api` entry point without configuration flags. It currently serves only the private owner enrollment subsystem, using the existing mutual-TLS protocol and accepted port. Public browser, MCP, federation ingress and evidence-transfer routes remain unavailable. The Helm chart remains a configuration foundation until protected provisioning, source/recovery reconciliation and native in-Pod operation are qualified. The executable name does not imply a complete hub.

## Validation and limits

Reproduce FIFO blocking before the fix. Test projection rotation/loss/escape, closed JSON, explicit TLS and endpoint selection, rejection of ambient credentials, SQL role continuity and storage credential loss. Run the loader against real scoped PostgreSQL, Kubernetes proof/admission, S3 and OpenBao providers, with explicit fixture-only source/recovery refresh. Verify pre-Ready identity, token loss/recovery and joined failure shutdown. Actual results belong in [implementation progress](../implementation-progress.md).

No new dependency, SQL migration, public administration API, user permission or evidence format is introduced. Public provider configuration changes require restart. Automatic mount provisioning/control synchronization, production credential issuance/revocation, native in-Pod routing, whole-hub readiness, local-key backend deployment and the full investigation workflow remain required.
