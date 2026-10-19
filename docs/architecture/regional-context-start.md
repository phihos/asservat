# Regional API context start

ADR-135 connects the existing hub `ContextAcceptedStart` port to a region over a retained connector-originated HTTP/2 exchange. Since [ADR-171](../decisions/171-hub-run-context-execution.md) the hub runs `APIContextRunner` itself and the region answers only cluster-local operations. This is a private first-profile component. It does not enable public collection or supply missing installer authority.

## Ownership and flow

`bootstrap.RegionalAPIContextStart` reads the exact accepted API work with current identity/recovery, checks the protected capability, reserves a cluster capture slot and signs only the existing reference. It has no collector, evidence-key or evidence-reader dependency. `contextstart.Router` attaches that request to a current standby on the same hub process. Historical request replay stays passive; explicit fresh-current continuation uses the original key/preview/capture and exact acknowledged SQL52 read.

`mtls.ContextStartClient` opens one fixed-path POST to a currently accepted owner route using process-owned connector client keys. One actual TLS1.3 socket is handed to Go's standard HTTP/2 transport. There is no redirect, compression, rewindable body or uncertain POST retry. `ContextStartIngress` verifies the actual TLS chain, current exact connector leaf/process/source and local hub owner. Independently supplied executor pins are checked against the Hello; Hello does not supply collection authority.

`contextstart.ServeRegionalOperations` waits passively for the first work frame under the original standby residency. Only after receipt does it acquire a fresh exact peer proof and verify the disjoint signed API work. It then answers the hub runner's operations (resolve Pod, read process, prepare/ready/consume start, prepare output, acquire context, complete stored) only for that exact work, in order. Plaintext and data keys stay in the region; only acquisition instants and copy receipts cross. No key preparation follows an old or uncertain execution preparation. The regional result contains only a finite disposition, not native bytes or raw errors. Publication still requires the separate existing verification/audit/catalog path.

The work type is `asservat-api-context-work+jws`, fixed Ed25519. Work binds the exact capture/attempt, human actor/client, target, scope/expectation/minimized-intent/budget digests, capability and projection, actual connector leaf and connector/API/hub process identities. Groups and scopes never leave the hub. No public token/cookie is forwarded. A dedicated verify-only trust ConfigMap uses current recovery plus its own independent native enforcement proof. Existing node work bytes and trust purpose remain unchanged.

## Original bounds and resource ceilings

| Item | Bound |
| --- | --- |
| Standby residence | Original 30 seconds; no human authority |
| Setup, peer proof, work and operations | At most original 5 seconds; minimum of all contributing observations |
| Complete discovered owner set | 16; oversized/incomplete list is unavailable |
| Whole hub standby budget | At most 64, independently reserved per cluster |
| Whole hub capture budget | At most 16, independently reserved per cluster |
| Regional owner conversations | At most 16, one per exact owner/process |
| Work / signed work | 8 KiB canonical / 16 KiB JWS |
| Operation request/reply | 32 KiB canonical each |
| Whole exchange | 36 frames, 2 MiB, at most 16 sequential operations |
| Connector API settings | 16 KiB, at most 16 exact input references |

JSON encoding disables HTML escaping before canonicalization. Actual maximum-string encoding is tested, including quotes, backslashes and Unicode. The settings bound was corrected after the maximum legal 16-input test failed at 8 KiB. This changes only the new private settings format.

Work and independently current peer/trust observations may overlap without having identical ends. Verification takes their minimum; it does not reject a valid shorter proof or renew it. Every blocking read/sign/write retains that minimum. The stream owns a single bounded EOF reader, one queued frame and one decoder frame. Socket/pipe callbacks cancel and join before release. Stream termination cancels the hub runner and the regional operation contexts, including a blocked operation. A late positive backend result cannot authorize a reply after cancellation.

Standby and capture reservations count closing owners until joined completion. Each discovered owner has an independent thirty-second conversation with at least one second before a fresh empty standby; after a TLS refusal (a registered owner process the hub no longer serves) the next attempt to that owner waits thirty seconds, so its setup proofs do not contend with the live owner's opening. A hub target query that finds no idle standby waits for the next registration only within its own original deadline, keeping 2.5 seconds for the query and the caller. A retry never carries a capture or signed work from a prior connection. SQL52/ADR134 determine whether an explicit current continuation can proceed; transport failure is not proof of non-admission or no effect.

The installed regional supervisor reports failed candidate observation, an empty
candidate set, failed connection setup and failed exchange service using fixed
private labels and the existing exponentially suppressed logger. Optional nested
steps are explicitly allowlisted; error text, target identity and credentials are
excluded. Omitting the reporter preserves the same operation, retry and deadline
behavior. A capacity standby is a separate protocol and does not establish that
a context-start standby is available for preview target resolution.

## Work transport observation

[ADR-163](../decisions/163-original-work-transport-observation-lease.md) bounds repeated frame traffic with one complete receiver observation owned by the actual stream. The hub obtains it at work Send; the region obtains it only after the passive work frame arrives. Setup and standby observations cannot supply this lease. Its original start, earliest observation/caller expiry and exact root/exchange/challenge/leaf/process channel remain fixed. There is no renewal or replacement lease for that accepted work.

Correctly ordered operation frames reuse that transport observation. The hub runner still performs its complete current identity, permission, target, recovery and capability checks, and each regional operation its own current local check. The stream validates direction and phase: one work, paired operation requests/replies, one result, one receipt. Unexpected work, unsolicited replies, a result while an operation is pending, premature receipts or frames after receipt close it.

A regional result Send and hub result Receive each perform a full current receiver check after preceding blocking work, bounded by the initial lease and matching its exact channel. The result check can only shorten the retained interval. The terminal receipt must fit the resulting original bounds. Negative/late final reads never fall back to the initial observation.

A retained expiry callback cancels the stream between frames as well as during I/O. Original cancellation, EOF and known transport/peer failures close it permanently, with all readers, producers and callbacks joined. Remote changes not otherwise observed can remain unknown during operation-frame traffic until the original lease expires, at most five seconds; this is bounded freshness, not instantaneous distributed revocation. An application denial creates no effects and its finite unavailable disposition still needs a final full peer proof. No application authority reader uses the transport cache.

The bare-Pod native fixture's original identity-frame graph required seventeen full process observations for seven identity round trips, which a 20-token bucket at 20 QPS could not complete within five seconds. The lease reduced that to two transport observations; ADR-171 then removed the identity frames. Current application checks remain additional.

## Protected connector API process

`ConnectorAPIExecutionProtection` composes the concrete connector attester, owned credentials, namespace guard and separate immutable API settings. It checks current online Pod-bound TokenReview, SSR account/Pod identity, live Deployment/ReplicaSet/Pod chain, current original CSR/leaf registration and all exact settings/input pins. A new independent API process epoch is generated once; it is not the connector epoch and cannot follow a replacement connector process silently.

One concrete protection instance coalesces a single positively completed process proof. Reuse retains the original observation start and earliest end, including the original TokenReview and independent admission-denial intervals. It performs current process credential/source/registration, SSR account/Pod identity, namespace/account, exact guard policy/binding, immutable settings, full workload digest and approved input metadata checks before returning. These later reads can shorten the interval; they cannot create a new denial proof or renew it. An error or known change invalidates the snapshot and any in-flight publication generation. A cancelled waiter cannot detach the original producer; cancellation, expiry or invalidation prevents a late positive producer from entering the cache. There is no background refresh or general Kubernetes client cache.

The concrete executor also implements `mtls.ContextStartProcessReader`. Its
combined read returns the connector observation already checked inside that
complete native proof, only for the identical process-owned credentials
instance. The transport need not make a second outer connector observation
before the same proof. Both results retain their original starts and earliest
expiry; returned CSR/profile buffers are copies. The transport validates both
identities and the exact expected channel after the read. Other process readers
keep the separate connector/process checks. This removes one duplicate per
local read; it neither caches a whole connection setup nor removes its later
owner, source or executor checks. Whole installed opening timing remains
unqualified.

After expiry, a new independent invocation may perform the full proof again under its own original caller bound. Existing preparation, binding and request deadlines remain fixed. [ADR-163](../decisions/163-original-work-transport-observation-lease.md) separately selects an exchange-owned transport observation lease, described below. Source-reader reuse remains unimplemented; neither mechanism qualifies the installed HTTP/2 path or removes current effect checks inside the production credential source.

The accepted template is the API-returned defaulted Deployment template. Comparison retains every PodSpec/security/mount/token field and template label/annotation. It normalizes only the deprecated service-account alias and Pod-only zero priority/default preemption/default service-links scalars. It removes exactly the qualified ReplicaSet controller hash and actual node assignment for comparison. Both 300-second not-ready/unreachable tolerations are explicit. Automount is false; the projected service-account token is explicit and dynamic, with its entire specification pinned. Init/ephemeral/sidecar injection, different mounts, privilege, image or arguments fail closed.

ConfigMap/Secret metadata reads bind exact UID and resourceVersion. Settings cannot include their own future UID/RV: those are independent constructor pins plus a current exact immutable source read. Changes to SQL/provider input revisions require an accepted new configuration/rollout; they do not silently refresh a running profile.

PartialObjectMetadata limits returned data, not Kubernetes privileges. `dedicatedToAPI` is an immutable installer-owned whole-object approval required for Secret references and forbidden for ConfigMap references. The installer must construct role-owned dedicated objects and independently accept those exact names/UIDs. Mounting one file does not establish ownership of other keys. Native grants permit GET on only these whole approved objects; unrelated GET and namespace LIST must fail. No payload hash is used, and the reader does not fetch Secret payloads. A metadata reader with broader credentials would be an unqualified composition.

The optional owner policy branch admits exact capacity-account CREATE on the main CapacityReservation and exact capacity/execution-account UPDATE on its status subresource. It grants no RBAC and no main UPDATE, deletion, Secret/token/input mutation or arbitrary CRD privilege. Independently pinned StartAdmission enforces the original immutable binding, Ready and one StartCommitted transition. Legacy bare-Pod and omitted owner-capability bytes are unchanged.

## SQL and components

`OwnerEnrollments.ReadContextStartOwners` reuses the existing current owner read facet. It locks recovery before owner configuration, reads at most seventeen candidates, rejects overflow and returns no addresses or certificates. Only audited enrolled server-purpose processes with a current activated certificate are candidates. Exact route/TLS checks remain mandatory. The query adds no schema, role, durable row or authority producer.

C-20 owns closed wire DTOs and `internal/transport/contextstart`. C-21 owns the existing adapter/bootstrap composition. Application/domain imports remain inward; adapters never import transport handlers in production. The bootstrap connections supervisor owns joined shutdown, not a new durable queue.

## Qualification and remaining work

Focused races exercise actual loopback TLS1.3/HTTP2 with process-owned keys: hub-run operations end to end, owner cancellation joined with a blocked operation, original-work expiry rejecting a late operation result, and EOF joining a blocked operation. (Before ADR-171 these covered seven identity round trips.) Sources/registries/routes/API process in those tests are explicitly synthetic. Separate stream races cover passive first wait, shorter peer expiry interrupting a blocked body pipe, finite bidirectional frames and blocked operation cancellation. Signed-work tests include wrong purpose/profile/process, closed encoding, maximum strings and retention of the original trust/peer deadline. The earlier overlap condition and settings-size defect both have preserved failing-before evidence.

`TestConnectorAPIProcessWithRealKubernetes` now passes the complete local-start sequence under [ADR-173](../decisions/173-work-scoped-process-observation.md) ([run 6](../../test/results/connector-api-timing-6/result.json): 2.57 s of the original 5 s, with a cold 71-call process proof). It covers real guarded Deployment/Pod defaulting, TokenReview/SSR, source/input pins, named Secret grants and both local status transitions. Its accepted connector source, CA/registry and first preparation claim are explicit fixture inputs. Earlier runs exhausted PrepareStart or ReadyStart because every start check re-proved the whole process; those failures are retained. Actual API/QPS cost must fit the existing five-second intervals; whole-test duration is not evidence of a particular authority timeout.

The native public journey (adr171-journey-2) passes the whole signed exchange with hub-run execution, regional capture/storage, publication and native download on the bare-Pod executor; see ADR-171. Pending qualification: the connector-Deployment executor's local start below, and failure/unknown partitions across those components. No deadline or client QPS limit is enlarged.

Missing production inputs remain dedicated work-signing key/sign-only hub credential, verify-only regional trust, exact connector API profile/input ownership/RBAC, protected installed composition and regional command startup. Existing initial installation does not yet provision those inputs. The first installed context investigation remains unavailable until these producers and the combined runtime path are implemented and qualified.
