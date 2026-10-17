# Protected owner deployment

[ADR-090](../decisions/090-protected-owner-deployment.md) makes the [owner runtime](owner-startup.md) constructible from installation-managed files. `internal/bootstrap` owns composition; C-21 owns bounded file/provider adapters. C-04's accepted configuration and credential lifecycle, C-08's audit and C-14's worker authority retain their existing owners. No public permission interface or new domain entity is added.

## Installation inputs

`asservat hub-api` accepts no additional flags. It reads `/run/asservat/hub`, with `ASSERVAT_HUB_POD_UID` supplied by the Downward API. The installation must protect the Pod template, mounts and sources against non-administrator replacement and mount them read-only. The file reader checks confinement/type/size/mode; it does not prove Kubernetes admission or protect an administrator-writable directory by itself. Native workload and accepted source checks provide the separate authority boundary.

| Fixed filename | Purpose and limit |
| --- | --- |
| `deployment.json` | Public [owner-deployment schema](../../specs/contracts/owner-deployment.schema.json), at most 256 KiB; installation, hub cluster, permission root, namespace/source UID, native admission pins, explicit provider endpoints/roots and resource ceilings. |
| `worker-controls.json` | Public [worker-trust bundle](../../specs/contracts/owner-worker-trust.schema.json), at most 16 MiB encoded JSON, at most 256 exact base64 control documents, each at most 64 KiB decoded. Reuses immutable installation-produced worker control bytes and their existing digests. |
| `sql-enrollment.json` | [SQL credential shape](../../specs/contracts/owner-credentials.schema.json), at most 16 KiB; existing owner enrollment/attempt/signing-spend ledger role. |
| `sql-audit.json` | Same shape; exact owner audit acknowledgement role. |
| `sql-activation.json` | Same shape; owner certificate activation role. |
| `sql-registry.json` | Same shape; current accepted owner configuration and active certificate read role. |
| `sql-routing.json` | Same shape; installation/root-bound current worker and locator read role. |
| `kube-observer.token` | At most 16 KiB; scoped namespace/workload/admission/discovery reads and TokenReview. No mutation or source-acceptance role. |
| `kube-probe.token` | At most 16 KiB; independently scoped native protection dry-run probe identity. |
| `owner-pod.token` | At most 16 KiB; projected current bound token with the existing owner enrollment audience. Never use an ordinary API token as a replacement. |
| `audit-storage.json` | [Storage credential shape](../../specs/contracts/owner-credentials.schema.json), at most 32 KiB; explicit owner-audit bucket access only. Empty session token is explicit. |
| `audit-wrap.token`, `audit-unwrap.token` | Each at most 16 KiB; separate credentials for the fixed owner-audit Transit encrypt/decrypt paths. These cannot unwrap evidence. |
| `owner-server-sign.token`, `owner-client-sign.token` | Each at most 16 KiB; separate credentials for the fixed purpose-specific owner PKI roles. |

Token files contain the exact token without a trailing newline. Credential documents use closed JSON with exact field names; unknown/duplicate/aliased/missing fields fail. Every root list contains 1–4 DER CA certificates under existing size/lifetime checks. Provider topology, SQL usernames, workload guard pins and initial owner pool remain fixed for the process. The bundle and credential projections may rotate. Installation must coordinate rollouts; this is not another administrator-maintained trust list.

## Connections, authority and rotation

[ADR-147](../decisions/147-standard-owner-provider-authentication.md) selects
standard Kubernetes authentication for sustained external owner key-service
credentials. Its closed [provider profile](../../specs/contracts/owner-provider-auth.schema.json)
and generated four-purpose recipes now have component tests. Actual provider
login, renewal, original credential expiry through response closure and installed
selection remain pending. This standalone profile is deliberately not a
recognized OwnerDeployment field yet: the legacy loader rejects it instead of
silently using mounted token files. Integrate its producer, protected selection
and mixed-profile rejection together before changing this file table. The
independent local-key profile remains supported by the design.

No provider endpoint or credential path is chosen by a request. Use explicit trusted HTTPS for API/S3/OpenBao, explicit verified PostgreSQL TLS with no plaintext fallback, no ambient proxy or provider token, no kubeconfig and no default AWS credential chain. PostgreSQL bootstrap rejects `PG*` environment variables instead of allowing pgx service/passfile/options defaults; installation should disable unrelated service-link injection. Passwords are assigned to typed connection fields, never a logged secret-bearing DSN. Provider CA rotations/topology changes require a protected process rollout.

SQL pool limits are 1–4 connections per purpose, five distinct usernames, no minimum warm connections, five-minute maximum lifetime plus at most thirty seconds jitter, and thirty-second idle expiry. Password reads occur before every new connection and reject username replacement. Existing database sessions are not instantly revoked by removing a credential file; current SQL authority and privileges remain independently enforced. Immediate incident response must revoke the relevant role/session or stop the process.

Kubernetes and OpenBao transports read the current token before each HTTP request. Storage uses an explicit uncached mounted credential provider. Failed reads return sanitized errors before provider transmission; no earlier secret is reused. Temporary owned byte buffers are cleared where possible, but libraries and Go strings can retain copies. Core dumping is suppressed for this process before secrets or private keys are loaded.

Construction has an original thirty-second budget and closes partially constructed dependencies on failure. It reads current audited owner configuration/recovery from the registry role, then builds native workload proof, routes, purpose-specific audited signing and existing runtime credentials. Accepted pool/source and original roots remain authoritative. There is no source acceptance, fixture identity, automatic recovery clearing or broad raw-evidence decryption role in this wiring.

The private receiver accepts 1–64 connections and 1–16 concurrent requests, with concurrency no greater than connections. The worker router uses the same concurrency ceiling. Those limits do not establish installation-wide KMS or storage capacity. Existing purpose-specific operation deadlines and authorization checks continue to apply.

## Lifetime and incomplete integration

The owner runtime still owns enrollment renewal, private listening, current readiness and live forwarding. The loader watches the protected public worker bundle at one-second intervals; unchanged bytes avoid reparsing but do not avoid reopening the file. Changed valid bytes atomically replace the catalog. Invalid/missing whole-bundle input cancels the subsystem; an omitted individual profile in a valid bundle denies that profile. This does not change ADR-089's invalid-replacement semantics or make the catalog an acceptance source.

Run and Close serialize admission. Close cancels its root, disables owned credentials/forwarding, joins the admitted runtime and router work, then closes SQL pools and owned idle transports. The router join includes registration, delivery and already admitted locator/claim/release SQL calls; new wrapper calls are denied during shutdown. An unissued restrictive release stays occupied until its original lease expiry. Active operations retain their original cancellation/deadline bounds; an uncooperative dependency still requires process termination. Run releases its lifetime registration before invoking shared cleanup, so concurrent Close cannot make it wait on itself. The installation owns the mount root; programmatic callers keep it open through shutdown. A rejected listener remains caller-owned. The [component regression record](../../test/results/owner-deployment-join-integration.json) distinguishes actual original failures from the controlled router wait reversal.

The native fixture runs this loader outside the protected pause Pod using actual Kubernetes proof, distinct SQL grants, encrypted S3 audit and scoped OpenBao issuance. It supplies initial trust, mount delivery and serial source/recovery freshness explicitly. That is provider composition evidence, not native in-Pod deployment, production credential provisioning or a complete service. Whole-hub health, automatic source/recovery reconciliation, installation-generated projections, connector ingress, native evidence bytes and public UI/MCP flows remain pending. Helm must not enable collection on the strength of these component checks.

## Independent configuration probes

[ADR-092](../decisions/092-independent-source-admission-probes.md) adds the required private `configurationProbes` array: at most eight unique `{configMap, serviceAccount}` pairs, both exact same-namespace Kubernetes names; `[]` permits none. The loader includes this list in its expected workload policy and protection digest. Only explicitly true dry-run ConfigMap UPDATE can pass the namespace guard for those pairs. Source protection still independently denies the probe. Real writes and other requests remain blocked even when the source guard disappears. The installer generates this projection; no developer configuration or approval is required.

## Bounded scheduling permission

[ADR-093](../decisions/093-bounded-hub-scheduling-permission.md) adds the required private `schedulingLeases` array with at most four distinct `{lease, serviceAccount}` pairs in the same namespace; `[]` grants none. The loader validates exact names, copies them into the expected workload policy and includes them in its protection digest. Only UPDATE of those named coordination Leases can pass admission. Runtime remains unable to create/delete/adopt a replacement, and no source/credential/recovery authority follows from scheduling. Installer generation and restart/requalification rules match other protected deployment inputs.

The active audit store requires a nonempty, non-`null` immutable version for every recognized owner input format, including the original static-provider observation path. The configuration worker applies the same requirement to owner configuration audit, and capture cleanup uses separate version-required writer and independent verifier stores. Input formats and original projection bytes remain unchanged; an older format cannot select version-optional active audit behavior. Missing-version acknowledgements and retained current-authority receipts fail closed, with physical versions still charged and inventoried for independent cleanup. Generic native evidence download retains its separate store behavior.
