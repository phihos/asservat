# Public context operation audit

This staged C-08/C-20 slice adds real encrypted intent/result components and SQL
capacity; it enables no public collection, metadata or Helm runtime. It covers
list_diagnostics, preview_capture, request_capture, resolve_capture_request,
get_capture and get_case only. C-08 owns audit persistence; C-20 keeps canonical
input/output projection and invokes the existing C-09/C-16 services.

## One request identity and original authority interval

`presentation.AuditedOperations` creates one server UUID and passes an
`OperationCall` with a private request ID into the already composed presentation.
The inner envelope uses that same ID. Callers cannot supply it through JSON.
Existing unaudited `Call`, `NewInvestigationHandler` and `NewContextHandler`
constructors remain component/test compatibility paths only. Enabled runtime
composition must use `NewAuditedInvestigationHandler` and
`NewAuditedContextHandler`, which bind the same concrete audited instance to
callbacks and ingress rejection handling. None is mounted by this increment.

A normalized typed input is MACed with a separate purpose domain from invalid
bounded input and exact output bytes. Neither raw input, provider credentials,
groups, free text reasons, namespace names nor command strings enter the journal.
Identity principal and opaque authorized result references are minimized audit
facts; they are not current authority. Error outcomes never echo submitted case,
artifact or capture IDs. Successful output references come only from the already
authorized projected result. The MAC of the <=24 KiB application envelope is
distinct from a native artifact checksum and from MCP's duplicated outer wrapper.

The wrapper caps its complete caller interval at five seconds and floors SQL
bounds to microsecond precision without extending them. It checks current exact
principal/policy/groups/scopes after intent acknowledgement and again after
outcome acknowledgement. Metadata's earlier original deadline remains binding.
If audit finishes too late, the result is withheld. Audit-only finishing may
retain a bounded original 30-second write interval after caller cancellation;
it cannot redispatch, reauthorize, send late bytes or claim client receipt.

## Authenticated ingress and one audit owner

Schema-invalid inputs, missing read scope and unsupported invocations are proven
pre-dispatch rejections. They use the existing `invalid_operation` name and normal
pool, even when a caller asked for `resolve_capture_request`. The requested name,
closed invalid/denied category and bounded input are covered only by the keyed
`invalid-input/v1` digest. They are not new plaintext journal fields. An invalid
UTF-8 name is framed as bytes rather than silently normalized to replacement
characters. Accepted resolution input retains its original resolution lane;
errors after business dispatch never become pre-dispatch rejections.

`RejectBeforeDispatch` returns only the original response deadline after intent,
outcome and final current-identity checks. It grants no evidence access. Browser
and MCP preserve it through the final identity read and the socket write deadline.
A late acknowledgement cannot renew it. The shared `Call` also carries that bound
on acknowledged error returns, without a response body or audit-authority flag.

The pinned MCP SDK's receiving middleware handles unknown tools and unsupported
continuation input. Its parameter/header decoder can fail before that middleware;
a bounded outer response catches those failures. One request-owned CAS decides
whether the callback or the rejection path owns the audit. A late callback cannot
dispatch after rejection/closure. Both protocol revisions use the original HTTP
context even where SDK cancellation behavior differs. Tool calls require a scalar
non-null request ID; notifications and invalid IDs cannot execute mutations.

SDK error text is never parsed for policy and is never forwarded from pre-callback
rejections: it can contain submitted parameters. Fixed error messages preserve a
valid JSON-RPC ID without exposing raw diagnostics. Middleware uses a bounded
copy of the original frame for the keyed digest, avoiding loss of unknown fields
or JSON re-encoding expansion; request closure clears that copy. Successful
handshake, discovery, list and ping traffic is not an application operation.

Unauthenticated/CSRF failures, oversized inputs, exhausted admission and audit
unavailability increment fixed saturating process-local counters. They create no
invented principal or unbounded individual audit record. Unsupported content
encoding/type rejected before reading browser input records a closed rejection
marker, not a claim to have hashed an unread body. Durable security/exhaustion
recording is still required. An admitted operation still needs both independent
audit acknowledgements before its response may escape.

## Immutable provider work

`audit.OperationAuditor` reserves a minimized intent, claims the first create,
then requires independent encrypted receipt acknowledgement. It freezes an
outcome before its separately claimed create and acknowledgement. An unknown
COMMIT never returns Fresh, and only an acknowledged first claim permits a PUT.
After a lost provider reply, exact GET/decrypt verification is the sole retry.
No phase UUID is replaced, and receipt replay creates no new logical object.

`OperationAuditObjects` reuses `sealControlAudit` and `verifyControlAudit` through
closed operation-specific formats. Intent plaintext is at most 8 KiB, outcome
16 KiB and either ciphertext 64 KiB. Only Tink keysets reach the wrapping service.
Each normal complete audit takes two wraps, two unwraps, two PUTs and two GETs;
lookup recovery adds a GET/unwrap and no wrap/PUT. Independently acknowledged
receipts precede response delivery. The journal is never treated as object audit.

The installed provider layout obtains the audit-store credential once for each
finite intent/outcome create or lookup. As in the owner-enrollment adapter, the
bootstrap wrapper owns a private static-credential store only for that operation.
The earliest original caller, write, five-second observation and accepted-source
deadline bounds sealing, signed PUT, pinned GET, response-body closure and
verification. SDK credential expiry alone cannot cancel an already signed
request. No credential cache crosses operations; a later outcome or replay gets
its own current observation without replacing the original operation dates.
Normal public audit and capture-intent publication share this composition.
Their SQL claims, acknowledgement, recovery and final request-identity checks
remain independent and mandatory. Completed object receipts are historical
facts, never authority for later SQL work or evidence disclosure.

Other installed audit families still use the shared per-SDK credential adapter:
bootstrap issue objects (`bootstrap/public_fleet.go`), and download stop,
dispatch, enrollment, window and session objects (`bootstrap/public_downloads.go`).
Equivalent operation-owned deadline composition remains required there; this
change does not qualify those families or the whole installed investigation.

Known scope/target denials and unsupported inputs retain their private typed
classification through the nondisclosing public error envelope. The audit does
not interpret the public `NotAvailable` code as proof of a denial: provider
failures use that same projection. A prepared application error envelope retains its exact keyed digest and size.
Errors rejected before an application envelope exists instead MAC the closed
`operation-error/v1` decision and retain zero output bytes; that is not a claim
about the HTTP problem response or JSON-RPC error wrapper. Private classifications
are never wire fields.

A proven rejection before business dispatch records no effect **from this
invocation**. It does not prove that an earlier invocation with the same business
key was never accepted. Once a mutation service was dispatched, an error,
denial, conflict or timeout retains unknown effects unless an authorized accepted
receipt or durable closed disposition establishes the result. Unknown capture
commits are recorded as unknown effects. Existing C-09 replay
and resolve-or-close keep the original preview/request identity; audit never
executes an operation from an outbox. Client receipt is always unknown. A result
hash proves the prepared result's identity, not that a person received it.

## Finite backing and role separation

Schema 40 adds `operation_audit_pool`, `operation_audit_account` and
`operation_audit`. A normal and a resolution pool each has a finite account count
and records-per-account. A new account atomically consumes one configured slot;
its record allowance is already backed by that pool. Maximum objects are twice
accounts times records-per-account, and maximum ciphertext bytes multiply that
by 64 KiB. Runtime cannot increase those limits or reduce retained charges.
Accounts are keyed by a stable issuer/subject/kind HMAC excluding client ID.
A separate rotatable audit MAC key controls input/output digests. Neither key is
a wrapping root, session/CSRF credential or identity-provider token.

Configuration is a private protected facet with revision CAS. It can renew its
finite interval or adjust backed ceilings while preserving accounts and spend.
An indexed check rejects a new per-account ceiling below retained charge. Stable
account-key replacement cannot invent new accounts; qualified mapping/rotation
remains separate from ordinary audit MAC rotation. Current accepted database
incarnation is locked before new journal work, and the original issuer epoch is
pinned through phase completion. Recovery-blocked SQL cannot authorize new writes. A new reservation retains the
original backing expiry through its final SQL check, including account-lock waits
inside the charging trigger; exact replay does not renew or reserve backing.

Normal and resolution coordinators are separately composed with their own SQL
pools and provider clients. Their process concurrency/rate limits are separate;
active per-principal maps disappear only after joined work finishes and are
bounded by those slots. The existing resolve operation alone can use resolution
capacity in this slice. Invalid resolve requests cannot consume it. The shared
HTTP admission slots still precede lane selection, so separate audit backing does
not establish whole-ingress resolution availability during saturated long normal
HTTP requests; front-door admission isolation remains unqualified. Future download cancellation must use its separately protected stop-authority
path and reserved audit resources. It cannot be routed through this read-scope
gate by silently broadening the wrapper. There is no caller-selected priority.

The journal role cannot acknowledge receipts; the acknowledgement role cannot
create operations, outcomes or write attempts. Neither can configure backing or
mutate accounts. Trigger functions have fixed search paths and no PUBLIC execute,
charges and receipts are monotonic, and no record/account DELETE is implemented.
Audit charges are independent from workload evidence/control allocation spend.

## Qualification and unfinished enablement

Focused tests exercise unknown creates/claims/acknowledgements, provider error
minimization, MAC/domain separation, rotation with unchanged account identity,
canonical input normalization, one shared request ID, audit-before-effects,
withholding on output audit failure, current identity revocation, cancellation,
original deadline expiry and protected resolution during normal concurrency
exhaustion. The ingress regression fails against the original wrapper because
invalid-schema and missing-read-scope resolve calls both spend the resolution
pool. Focused race tests cover the corrected lane, strict browser/real TLS MCP
composition across both revisions, SDK failures before callbacks, missing/null/
object IDs, original HTTP cancellation, one CAS owner, audit failure, fixed bounded
counters and final-read/socket deadline preservation. Their journal receipts are
explicit test-only fixtures, not SQL/object authority. Tink tests count the actual wrap/unwrap calls with local synthetic
keys; they are not provider latency qualification.

The existing selected `TestContextAdmissionWithRealServices` contains actual
SQL/S3 subtests for bounded account creation/spend, separate resolution backing,
role/immutability checks, exact lookup after a lost response and lock wait expiry.
`TestOperationAuditWithRealProviders` runs under the existing full context fixture
and measures six actual OpenBao/S3 audit pairs, exact call counts and elapsed p50/
maximum. Compile-only/skipped tests are not passing external qualification.
Parent-owned fixture reports determine actual provider/native results.

Before enablement, complete protected MAC/backing provisioning and source
acceptance; retain durable bounded security/exhaustion evidence for invalid
authentication, oversized pre-admission inputs and overload floods (these are not
individually audited application operations); qualify positive writer quiescence, deletion
checkpoints, cleanup and budget restoration; and supply bounded interrupted-audit
reconciliation. A process dying without a frozen outcome currently leaves a
charged pending record. The fixed write interval is not a refund or permission
to invent a terminal result. The runtime stays disabled until these are resolved.

The schema deliberately does not provide general audit query/export, public
operator configuration, background retry of business operations or collection
permission. It does not turn ADR-111's artifact writer receipt into audit cleanup
authority. See [ADR-110](../decisions/110-bounded-public-operation-audit.md).
