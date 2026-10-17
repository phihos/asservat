# Acquisition worker startup and supervision

[ADR-073](../decisions/073-worker-startup.md) composes the credential phase of A-ACQUIRE using the existing [worker credential channel](worker-credential-channel.md), [protected configuration](worker-configuration.md) and [dispatch](download-worker-dispatch.md). C-20 owns wire shapes, C-21 owns trust/token/crypto adapters, C-14 owns supervision and C-24 owns original identity/period values. `cmd/asservat` selects the role and `internal/bootstrap` chooses concrete adapters. The executable does not import Kubernetes or SQL clients just to read its fixed projected files.

## Inputs and trust

The private immutable ConfigMap contains exactly one key, `worker.json`, at `/run/asservat/control/worker.json`. Its closed [schema](../../specs/contracts/worker-control.schema.json) requires format, installation/cluster UUIDs, one HTTPS endpoint and distinct server/issuer root arrays. Endpoint paths, userinfo, query strings and fragments are rejected. Each root set has one to four unique DER CA certificates, each at most 16 KiB, with a combined 32 KiB bound and 64 KiB JSON bound. Every configured root must have a valid current lifetime. There is no system-root or stale-root fallback. Historical certificate retirement and operational CA rotation still require qualification.

`WorkerControlDigest` hashes the exact ConfigMap data representation after strict validation. Whitespace changes require a new digest; semantic parsing cannot conceal a changed source. Dispatch checks the actual immutable ConfigMap UID/digest, installation/cluster and current roots under the existing current protected profile. Startup independently checks the mounted file bytes and roots. The root parser is not administrator admission or a protected endpoint provisioning system.

The exact Job argument vector starts with `download-worker`, followed by these required flag/value pairs: `--installation`, `--cluster`, `--dispatch`, `--session`, `--created-at`, `--until`, `--control-sha256`, `--control`, `--token`. Timestamps use canonical UTC RFC3339Nano and the digest is lowercase SHA-256. Duplicate/unknown/alternative flags, missing pins and caller-selected paths fail. The only environment entry is `ASSERVAT_WORKER_POD_UID`, from downward API `metadata.uid`. The dedicated token remains at `/run/asservat/identity/token`; it is reread for enrollment and never passed as an argument or logged. The Pod UID and arguments are identity inputs, not proof: the independent control path still verifies the actual Pod/token and admitted SQL identity.

Before key creation, Linux startup disables this process's core dumping and verifies the result. Failure stops startup. Non-Linux startup is unavailable. No privileged operation, host sysctl change, shell, debugger, root key, default service-account token or secret in the ConfigMap is needed. The Job remains non-root with Pod Security restricted, fixed image/configuration, read-only root filesystem and dropped capabilities.

## Finite lifecycle

Initial enrollment has at most thirty seconds, intersected with the original worker end. Each enrollment phase permits at most eight attempts with 1/2/4/8-second capped backoff and 0–500 ms jitter, all inside that phase's original deadline. Provider signing attempts remain independently controlled by the durable issuance ledger; these HTTP retries cannot reset that ledger. Deployment-wide request admission is still required.

The supervisor renews one minute before each anchored twenty-minute certificate end, retaining the same process key. A renewed credential must advance expiry without exceeding the original worker end; the final shortened certificate waits only to its own expiry. An eight-hour worker has at most twenty-four certificate periods. Cancellation, exhausted attempts and original expiry close the client and disable retained signers. Initial failure cannot leave a successful-looking idle worker. The native v2 extension below joins its connection lifetime with this supervisor.

Notifications to an optional readiness channel are nonblocking; nil, full or unconsumed channels cannot delay expiry. The executable uses one buffered slot and one process-owned status reporter. Legacy v1 emits only `worker credentials established; native transfer unavailable`; explicit native v2 emits `worker credentials established`. A blocked stdout may hold that reporter until process exit but cannot delay credential shutdown; no goroutine is created per notification. This is diagnostic output, not a persisted success receipt or evidence authorization. SIGTERM/SIGINT initiate cancellation; original expiry or startup failure returns a sanitized failure without raw provider details.

## Upgrade-safe cleanup

Historical cleanup verifies the original exact Job UID/spec digest and Pod UID/owner/spec digest from the stored worker. It does not compare the historical object with today's generated startup template. New launches and bindings still check the current template. This permits cleanup after rollout without accepting an old template for new work. This covers application-template changes with the same admitted API representation; Kubernetes upgrade/defaulting compatibility still needs its own qualification.

The initial termination proof requires exactly the pinned Pod and known container termination. A replaced, additional, missing or uncertain Pod blocks release; a dedicated orphan reconciliation path remains required. Persist the original termination proof before deleting, delete with the exact UID precondition, and confirm both Job and labeled-Pod absence before releasing capacity. Cleanup does not renew identity, permits or current configuration.

## Verification and remaining scope

Focused tests cover closed startup/configuration parsing, exact immutable-byte binding, CA bounds/expiry, full original renewal periods, final short periods, bounded retries, cancellation and an unconsumed readiness channel. A separate child process reads back zero core limits and dumpability without crashing or changing the parent's limits. Historical-template tests verify that the original pinned object is cleanable but cannot be newly bound, and reject changed identities/specs.

The owned Kubernetes fixture now builds the actual `cmd/asservat` executable into a digest-pinned restricted Job, consumes its mounted configuration and projected token, and issues its process-generated CSR through the actual private TLS handler and OpenBao client. A separate fixture-only executable reads the token for an independent proof test, sends SIGTERM, and supplies a bounded TLS-byte relay in an owned container. The relay reaches a private host Unix socket without a published host port or firewall change; TLS still terminates at the checked handler. None of these helpers is a product command or the native evidence relay. Dispatch registry and signing permit/audit are explicitly synthetic inputs. A fixed diagnostic from the Pod establishes that its own client installed the returned credential. Actual runs and source/cleanup reports belong in [implementation progress](../implementation-progress.md); fixture construction alone is not a passing result.

Still required: protected issuer/endpoint initialization and rotation, active browser/MCP-to-connector request-owner routing, current work delivery, artifact/byte relay, connection shutdown, orphan cleanup, local CA, full packaging and end-to-end native download. No public route, successful empty transfer, enabled collector or Helm runtime deployment is added by this credential-phase executable.

## Explicit native worker startup extension

The native exchange requires `asservat-worker-control/v2` and the matching
`asservat-worker-configuration/v2`. Legacy v1 remains credential-only; mixed
versions, missing native settings and credential projections on v1 reject.
The native object pins the exact HTTPS HTTP/2 exchange path, separate exchange,
object-store and key-service roots, configured store UUID/bucket/region, artifact
key scope and immutable storage-credential Secret name/UID. All five trust sets
share the original combined 32 KiB DER limit; the full document remains 64 KiB.
Every root remains current, and exact-byte control changes require a new accepted
profile and dispatch. These settings contain no source objects or work permits.

The acquisition Job additionally mounts only `credentials.json`, read-only mode
0440, from the accepted immutable Opaque Secret at
`/run/asservat/native-store/credentials.json`. Configuration observation and
Job/proof checks reject a missing, mutable, deleting or replaced Secret. The
accepted profile and control pins must agree. The worker reads the bounded closed
file through the existing confined projection reader; it cannot select a path,
endpoint or fallback through environment variables. It gets only scoped read-only
object-store credentials and its own acquisition certificate. Object storage and
key service use separate pinned TLS transports without proxy or redirect; the
object store never receives that process certificate. No wrapping root, SQL
credential or user session enters this worker.

Installation must provision and protect the original credential Secret before
accepting its profile, enforce its read-only backend scope and grant only named
Secret reads to the configuration/dispatch observers. An observed UID alone does
not establish that initial provisioning or backend IAM policy. Replacement uses
a new accepted profile and dispatch; no secret payload hash is persisted in SQL,
audit or the public configuration. Legacy profile JSON omits the new fields,
retaining its exact existing serialized representation.

The public CSR-key digest accessor identifies only the process's original key;
it is neither an enrollment proof nor effect authority. The v2 runtime joins
credential renewal, one original regional result owner and every opened
conversation. It starts native work only after credentials are established.
Each connection rereads the projected token and uses a new cryptographic nonce.
The hub must positively close the exact original SQL operation before producing final Done. The worker’s one-second scheduling delay is not proof of that closure; failed or unknown close/final delivery remains uncertain.

Only an exact authenticated NoCommand or positively Joined result permits the
next connection, with one-second backoff, the original worker end and a 32,768
conversation ceiling. An unknown reply or lost acknowledgement stops the worker;
no automatic command replay is introduced. Cancellation or failure of either
child joins both before the regional owner and dependencies close. Tests that
hold either child's cleanup require the supervisor to remain blocked until both
have actually returned. These component tests do not qualify protected producer
composition or an installed native download.

The native storage projection may contain a canonical UTC `expiresAt`. Temporary
`sessionToken` credentials require it; startup must reject a credential that
does not cover the original admitted worker lifetime. No in-place credential
refresh, unknown-expiry assumption or provider fallback is permitted. These
inputs are checked before process enrollment and again before native reads. A
new accepted credential identity and dispatch are required for rotation.
The finite five-second S3/key HTTP helper is distinct from the live I-13 HTTP/2
transport; using it for the native conversation would impose an invalid lifetime.

Native v2 requires at least 64 MiB configured memory; v1 retains its existing
16 MiB floor. This is a provisional input minimum for the bounded transfer
buffers, not a measured peak-RSS or workload-impact guarantee. Deployed worst-case
command/manifest and slow-consumer memory qualification remains required.

The selected v2 native fixture now passes with the actual compiled worker in a
Restricted Pod. It verifies the immutable credential projection, process-owned
certificate, two separate current mTLS/Pod-token idle exchanges with distinct
32-byte nonces, and positive termination/foreground retirement. It found and
corrected UUID wire incompatibility and an incorrect comparison between the
server observation deadline and earlier client setup start. Both independent
five-second bounds and the original worker lifetime remain enforced. The fixture
has an explicitly empty synthetic command registry and unused storage credentials;
it does not qualify native evidence delivery, timed renewal or provider provisioning.
Actual failures, corrections, source hashes and cleanup are recorded in
[implementation progress](../implementation-progress.md).
