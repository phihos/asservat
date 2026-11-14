# Download reader deployment

Implements REQ-DLD-003, REQ-DEP-003 and REQ-CAP-003 under
[ADR-330](../decisions/330-event-driven-system-design.md) D3/D4. C-14 owns the
reader's behavior inside `ArtifactDownload`; C-21 supplies the Kubernetes, SQL
and object-store adapters. Supersedes the per-download Job dispatch of ADR-069
and the worker attestation of ADR-068.

## Workload

Native downloads and stored-evidence queries are served by a long-running
`download-worker` Deployment in each region's Asservat namespace (in combined
mode, a container of the hub Deployment). The Helm chart renders it. It is
scaled by replica count or a HorizontalPodAutoscaler; no Kubernetes object is
created per download or query.

The Pod runs under Pod Security `restricted`: non-root UID/GID 65532,
RuntimeDefault seccomp, no added capabilities, no privilege escalation,
read-only root filesystem, CPU/memory requests equal to limits and a small
ephemeral-storage limit. It mounts its configuration ConfigMap, the read-only
object-store credential for evidence and one audience-bound projected
ServiceAccount token. It has no host namespaces, no automatic API token and no
Kubernetes API permissions.

Each replica serves at most a configured number of concurrent streams
(set in the reader configuration). A request beyond the free capacity of all
replicas is refused with a retryable busy status; it does not queue a paid
operation.

## Identity

The reader is the only workload besides the key service that obtains plaintext
data keys. The hub, connector and collectors stay wrap-only.

- At connect, the reader presents its projected token (audience
  `asservat-download-reader`) to the connector of its cluster. The connector
  checks it once with TokenReview and requires the expected ServiceAccount.
  The connection is then mutually authenticated TLS with certificates from
  the installation CA; nothing is re-verified per stream.
- The reader authenticates to the key service with the same installation-CA
  client certificate. The key service unwraps artifact keys only for the
  `download-reader` role, and the reader requests keys only for operations the
  hub assigned to it; see
  [local key service](local-key-service.md).
- Configuration comes from the mounted ConfigMap and Secret and is trusted
  (ADR-328). The reader does not read or compare its own Pod, Job, namespace,
  PriorityClass or spec.

## Lifecycle

A reader replica ending (rollout, eviction, node loss) resets its open
streams. The hub records each affected download as interrupted with the bytes
actually delivered and releases its charges; the client resumes with
`Range`/`If-Range` under a new authorization
([native download retry](native-download-retry.md)). No termination proof,
retirement step or orphan cleanup exists because no per-request object exists.

Rollouts use the Deployment's ordinary `maxUnavailable`/`maxSurge`; a stopping
replica stops accepting streams and finishes open ones within
`terminationGracePeriodSeconds`.
