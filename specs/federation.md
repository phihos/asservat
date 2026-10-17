# Federation and events

## REQ-FED-001 — Enrollment and trust

A cluster MUST enroll through a one-use, short-expiry administrator-issued bootstrap credential and receive a cluster UUID and short-lived mTLS identity from the installation. The connector initiates outbound connections to a configured hub. No arbitrary callback URL, inbound node service exposure or hub-stored cluster-admin kubeconfig is required.

Cluster enrollment/credential revocations and heartbeat summaries are SQL runtime state, with protected declarative trust configuration in Kubernetes. Certificates issued under the installation's configured trust bind cluster and connector identity, rotate before expiry, and can be revoked. Local cluster configuration pins hub trust and a maximum collection policy. Hub commands are signed, versioned, expiry-bound and independently checked against that local ceiling. Node identities bind Kubernetes node UID and boot epoch; joining a new node does not inherit an old node's work.

The initial connector enrollment implementation preserves the original bootstrap/key on retries, durably audits the claim before signing, and caps provider calls at two nonrefundable attempts of at most five seconds each. Issued identities have a fixed expiry thirty minutes after the original claim. Unknown signing outcomes do not become peer authority. Signed results require an exact durable encrypted audit and a current atomic peer registration before delivery; retry cannot re-enable revoked registration or extend any deadline. See the [activation contract](../docs/architecture/enrollment-activation.md). [Protected fleet administration](../docs/architecture/fleet-administration.md) assigns enrollment separately from workload access. [Credential delivery](../docs/architecture/bootstrap-channel.md) uses a configured secret-channel profile, returns no secret in operation results and cannot activate a slot before issuance audit. These refinements do not qualify production enrollment merely by being specified. Automatic connector restart recovery MUST use the per-profile rotating cluster enrollment credential of [ADR-168](../docs/decisions/168-rotating-cluster-enrollment-credential.md): a protected workload-cluster Secret key whose exporter-bound possession proof admits only that profile's process enrollment and renewal, with finite configurable validity and rotation, fork fencing and revocation. Outbound-only connectivity is preserved; the hub never stores the private key, a cluster kubeconfig or a reusable bearer. The regional process supplies native lifecycle observations, its protected source and leaf-registration lookups as delegated proof over one presentation-authenticated conversation ([ADR-169](../docs/decisions/169-delegated-regional-lifecycle-channel.md)); every SQL, signing and audit effect stays a hub duty in the separate federation compartment ([ADR-170](../docs/decisions/170-federation-compartment.md)). Regional Pods MUST NOT receive hub SQL, signing or audit credentials.

For the optional fresh-install observation-bootstrap profile, the original protected owner Service UID and issuer scope derive one common TLS verification name alongside each server leaf's existing exact process name. Before dialing the installed reachable endpoint, the consumer MUST retain a finite current independently accepted owner candidate set. Standard TLS hostname/root verification, membership of the actual leaf in that set and exact current SQL activation/configuration MUST precede peer-proof exchange. Only the producer's own scoped source/guard/route facts may pass before full proof; workload metadata and effects require the complete current proof. Original deadlines are never restarted at receipt. Existing exact-owner/public/effect routes MUST reject common-SNI connections, including requests that substitute an exact-owner HTTP Host. Omitted capability preserves the legacy profile; this is not a rolling upgrade or protection against a compromised authorized cluster-local observer. See [ADR144](../docs/decisions/144-cluster-local-observations.md).

[ADR-155](../docs/decisions/155-unchanged-fleet-persistence-contention.md) permits only a classified failed persistence of an independently observed unchanged positive fleet source to retain its previous original SQL expiry without an additional suspension. Under [ADR-161](../docs/decisions/161-fleet-observation-separation.md), classification MUST require the fixed producer's exact authority-row lock abort before any mutation, rollback, and complete current source/row/semantic-version/database-incarnation comparison before and after blocking work. Table/observation-row failures and unknown commit outcomes MUST NOT select this exception. It MUST remain unavailable and MUST invalidate scheduling notices, create no write/success hint and never refresh a selected proof. Source-read errors, new/changed/suspended/recovery state, expiry, failed confirmation and uncertain commits MUST retain ordinary fencing. The next observation MUST be independently selected under normal cadence; no timeout, role, lock or retry bound changes follow.

### SC-FED-001

Given an enrollment token used once or a connector from another cluster, when registration/work polling is attempted, then replay/identity substitution is rejected. A hub request cannot widen a locally denied namespace.

Fresh installed-owner startup MAY perform its first complete native preflight
before the retained recovery lock under [ADR-158](../docs/decisions/158-owner-startup-critical-sections.md).
It MUST bind the exact preflight source identity/revision under current recovery
and activation locks, recheck current native and accepted configuration after
blocking work, and retain the original earliest deadline through effects and
independent final checking. Preflight MUST NOT allocate attempts or use credentials
for effects. Reading the original private journal still requires its preceding
short current accepted/recovery check. No later observation can renew the call.

For fresh owner projection only, [ADR-159](../docs/decisions/159-owner-projection-split-preflight.md)
permits completing the first native bracket across bridge acquisition. Its
pre-lock prefix MUST NOT constitute a completed proof or authorize effects.
Current post-wait comparisons and a separate positive accepted-owner SQL read
MUST precede first private-journal selection under the bridge. The original root
UID MUST already be pinned; a valid version of that same UID may be selected
at this later first read, and its full version/state MUST bind subsequent checks.
No unread earlier version is a baseline. Original source observation dates and
all earlier deadlines MUST remain binding. Complete current checking after the
claim and role locks, and independent final checking, MUST remain mandatory.
This refinement grants no replacement attempt, root repair or authority renewal.

[ADR-162](../docs/decisions/162-owner-projection-read-only-finalization.md) MUST
separate each fixed fresh provider-backed owner projection/launch effect from
mandatory read-only finalization; alternate fresh-provider entry points MUST NOT
bypass it. The actual legacy layout remains separate. Execution MUST preserve current postclaim and
postlock checks, original claim/effect deadlines and spent identities, and return
only an unverified transition. The same-live-root pending record MUST block all
further effects until independently current verification succeeds. Finalization
MUST use its own at-most-five-second observation inside the original caller/root
lifetime, retain exact semantic identities and known target UIDs, and perform no
persistent mutation, receipt write, replay or replacement. Expired effect handles
MUST remain closed; unknown CREATEs without original UID pins MUST remain
unverified. Stored receipts alone MUST NOT supply current authority or restart
continuation. Current runtime admission remains independent of installer success.
The pending result MUST pin SQL59 semantic version from the locked execution
authority read and compare it under finalization locks. Current matching values
MUST NOT hide intervening SQL suspension, repeated fencing or semantic ABA;
unchanged positive renewal MUST NOT extend the original effect deadline.
The first execution MUST retain original live role-root creation lineage; reading
an existing private journal MUST NOT substitute for it. New controllers MUST NOT
adopt existing projection/launch progress. Later execution MUST require the
original process-local verified predecessor, checked after serialization waits.
No restart/resume producer or durable global ownership guarantee is implied.

Fleet freshness MUST bind the exact semantic authority version and accepted
database incarnation. An unchanged positive observation MAY update a separate
record while consumers retain semantic SHARE locks; restrictive changes MUST
remain serialized against effects. The original SQL basis MUST precede native
source reading and preserve its deadline. Missing/mismatched observations MUST
fail closed; ordinary observation MUST NOT seed activation or clear recovery.
A delayed failure MUST NOT affect a newer semantic root or newer observation.

## REQ-FED-002 — Durable outbound work and compatibility

Use authenticated HTTPS long polling for control work and bounded event/result upload. Internal payloads use versioned JSON contracts; this is an implementation protocol, not a new external agent interface. The hub stores active work in its SQL outbox; connectors store active execution state locally in Kubernetes; immutable outcomes live in object storage.

Each work item binds `workID`, `operationID`, cluster UUID, target/plan digests, authorizing grant/reservation, expiry and attempt. Delivery is at least once. Work transitions are `Queued → Leased → Accepted → Running → terminal`; lease expiry enables reconciliation, not blind re-execution. Intrusive work that may have started remains `Indeterminate` until proved otherwise. Bounded result references survive connector reconnects.

Support hub/connector N and N-1 minor compatibility within the same API major, with capability negotiation. Unknown required actions/fields fail explicitly. Policy generation acknowledgements and last heartbeat are visible. Default heartbeat 15 seconds, offline after 60 seconds; these are tunable operational values.

### SC-FED-002

Given duplicate leased work after a network break, when a connector resumes, then it returns the prior operation state and does not rerun the intrusive action. An older connector rejects an unknown required recipe capability.

## REQ-FED-003 — Locality and partial availability

Each storage/analysis profile MUST declare its region/locality boundary. Raw artifacts and decryption remain local by default. The hub may broker only currently authorized bounded query results and permitted metadata. A hub database outage denies new central authorizations/disclosures; local prepaid execution and deletion retain their existing limits. A disconnected cluster remains visible with stale-data indicators; the hub cannot claim fresh capability, completed collection or a current query from it.

Metadata events MAY queue in bounded local storage/Kubernetes references; full evidence never enters CRD status. Hub and local APIs apply backpressure, bounded queues and explicit drop/gap counters. Intrusive grants obey the permit expiry rules in [authorization](authorization.md). Local capacity slices must also be prepaid/fenced under [capacity isolation](capacity.md); reconnection or lease expiry cannot mint another copy of an uncertain upload reservation.

### SC-FED-003

Given a hub outage during collection, when regional S3/KMS and local control remain healthy, then already authorized local evidence is committed and later synchronized. A remote raw query reports `ClusterOffline`, and expired permits cannot start new dumps.

## REQ-EVT-001 — Content-free CloudEvents

Emit CloudEvents 1.0 structured JSON over configured HTTPS webhooks. Event types include:

```text
io.asservat.case.opened.v1
io.asservat.case.recurred.v1
io.asservat.case.analysis.completed.v1
io.asservat.capture.partial.v1
io.asservat.grant.requested.v1
io.asservat.grant.revoked.v1
io.asservat.share.created.v1
io.asservat.share.revoked.v1
io.asservat.evidence.expired.v1
```

`source` identifies the producing hub/cluster, `id` is stable across retries, and `subject` is an opaque case/signature/grant/share identifier. `dataref` is an authenticated `asservat://case/<id>` reference for a case event, or `asservat://grant/<id>`, `asservat://share/<id>` or `asservat://capture/<id>` for a transition without a case yet. Propagate `traceparent`. Data contains only an administrator-approved identifier allowlist. Default external payloads omit namespace/workload names, arbitrary labels, reasons, usernames and matched text; these can disclose information even without raw evidence.

Sign exact request bytes with Standard Webhooks `webhook-id`, `webhook-timestamp`, `webhook-signature` headers and operator-managed rotating secrets. Enforce recipient-specific cluster/workload event scope, destination allowlist, HTTPS, bounded DNS resolution/redirect behavior and SSRF restrictions. Do not accept a webhook URL from a capture request. [CloudEvents](https://github.com/cloudevents/spec/blob/main/cloudevents/spec.md), [dataref extension](https://github.com/cloudevents/spec/blob/main/cloudevents/extensions/dataref.md), [Standard Webhooks](https://github.com/standard-webhooks/standard-webhooks/blob/main/spec/standard-webhooks.md).

### SC-EVT-001

Given a case containing a token in its log/filename/reason, when events are delivered, then that content is absent from the payload and headers. Retries preserve the CloudEvent ID and verify with the rotated webhook key.

## REQ-EVT-002 — Delivery outbox

Events MUST be durable SQL outbox entries committed with their hub case/grant/share transition; local producers keep bounded fenced delivery records. Work-claim leases, deduplication, audit gates and recovery follow [persistence](persistence.md). Deliver at least once with exponential backoff/jitter, maximum 24 hours by default, then dead-letter an opaque reference for operator replay. Rate-limit recurrence events without losing aggregate counts. Consumers deduplicate by `(source,id)`. A failed webhook does not roll back evidence collection or grant revocation. Avoid promising exactly-once delivery.

### SC-EVT-002

Given a receiver that acknowledges then drops its connection before the sender sees the response, when Asservat retries, then the event ID is unchanged. Evidence remains committed and the outbox accurately reports the uncertain delivery.

The [internal interfaces](../docs/architecture/interfaces.md) refine these rules into negotiated hub/connector and collector-initiated local protocols, strict purpose-bound control DTOs and separate transient live exchange. Work/start/receipt identities and effect fencing follow [REQ-ARC-003/004](implementation-architecture.md); protocol acceptance is not proof of action start or evidence commit.
