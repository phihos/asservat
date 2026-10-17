# First deployed context investigation: integration plan

2026-10-12. This map began at the SQL49/ADR131 checkpoint. SQL52 capture-intent
lifecycle, the [capability/submission checkpoint](../architecture/context-capability.md)
and ADR134 explicit continuation are now integrated;
[implementation progress](../implementation-progress.md) records actual
verification. Regional transport and installed public composition remain work
in progress. The original package outline below is retained as an integration
checklist; its implemented parts do not prove a deployed flow.

## Immediate implementation package

The protected API pod-status capability reader and request-to-runner bridge
are integrated. The capability reader's native Kubernetes guard/source case
now passes, including independent denial and exact source/image/recovery
binding; accepted recovery and image qualification remain fixture inputs.
SQL52 now passes its real SQL/object-storage lifecycle cases. The explicit
fresh same-key continuation now passes its native regional runner fixture,
including original encrypted intent, one acquisition and independently verified
publication/read after target deletion. Installed regional transport is next;
the fixture still supplies human, capability, retention and bootstrap authority.
Keep `CollectionEnabled=false` in installed public
composition until the complete path below is qualified. This is connection of
existing C09/C08/C11 services, not a new dispatch framework, queue, or authority.

The admission-only `ContextInvestigation.Request` returns an accepted SQL
registration. The integrated submission coordinator adds exact acknowledged
intent lookup, atomically backed persistence and request-owned start. The
installed regional connection is still missing.
The existing runner requires the current original human request at acquisition;
the UI then polls `get_capture`, which correctly cannot start collection. Simply
mounting existing HTTP/MCP handlers would therefore accept work that never runs.

### Proposed files and concrete changes

1. **Protected capability**
   - Add `internal/contracts/context_capability.go` and its closed canonical
     schema under `specs/contracts/`, using the existing offline-schema workflow.
   - Add `internal/adapters/kubernetes/context_capability.go` and tests. Implement
     both existing consumer ports named `ContextCapability`, rather than adding
     a new service interface or a fallback capability constant.
   - Reuse installation-owned ConfigMap administration/protection and independent
     denial machinery. Pin source namespace/name/UID, policy/binding identities,
     root/installation/cluster and accepted recovery epoch in protected startup.
     Public requests provide none of those pins.
   - The closed first profile is `ContextAPIExecution`, the existing pod-status
     projection/version, exact qualified collector image digest and revision.
     Match the configured cluster to the independently resolved target. Bind the
     same collector/projection tuple in preview and execution. Disabled, stale,
     replaced, malformed or unqualified configurations deny.
   - Preserve the earliest current guard/source deadline (at most five seconds
     for this adapter), including after final reads. The domain's 30-second
     structural ceiling is not permission to renew a five-second observation.
   - No SQL migration is inherently needed for this immutable installed profile.
     Changing the qualified collector tuple invalidates reviewed scopes; do not
     silently adopt a replacement UID or turn a source observation into rollout
     acceptance. Subsequent mutable rollout support is separate.

2. **Exact accepted intent before acquisition**
   - Extend `internal/application/audit/capture.go`,
     `internal/adapters/postgres/capture_intent.go` and
     `migrations/queries/capture.sql` with a purpose-specific exact-capture intent
     read/publish operation, retaining separate audit writer/ack credentials.
   - The existing global `PendingCaptureIntents LIMIT 2` publisher is useful for
     bounded reconciliation but is not a request bridge: unrelated older rows
     can consume the page. Never drain arbitrary work to reach this request.
   - Reuse immutable encrypted intent bytes, receipt matching and original audit
     deadlines. Unknown audit writes remain exact-object reconciliation, not a
     renewed write permit. The runner itself requires `IntentAudited`.

3. **Still-live submission bridge**
   - Add a narrow consumer-owned start port and coordinator alongside
     `internal/application/capture/context_investigation.go`, with meaningful
     implementation in the composition/adapters layer; do not introduce a
     forbidden direct C09-to-C11 import or an empty interface-only package.
   - Reuse `internal/application/execution/api_context.go` unchanged where
     possible. A concrete composed bridge calls exact intent audit, then
     `APIContextRunner.Execute(ctx, current, accepted.CaptureID)` with the same
     request-owned current identity and cancellation. Never serialize the
     `CurrentIdentity`, enqueue its observed groups, use `Background`, or start
     after the caller's original authority interval expires.
   - Apply the bridge after first admission. Historical accepted replay remains
     passive, including when its preview or target has disappeared. Add a
     separate explicit fresh-current same-key continuation before enabling the
     public workflow, so lost/late initial replies do not strand accepted work.
     Durable execution/start rows decide whether any work may start; continuation
     cannot create new IDs, a replacement Pod, keys, a new start interval or
     another execution. Resolve/get/progress remain read-only.
   - Preserve the accepted receipt when the admission committed. A downstream
     failure must not be reported as proof of non-admission. Final metadata
     delivery still requires its original `MetadataValidUntil`; a late reply
     yields the existing uncertain-outcome recovery, not a refreshed deadline.
   - Cancellation after possible start stays spent. Joined producer completion
     and the recorded result, not an HTTP success or memory-only boolean,
     control later publication. A capture is Succeeded only after existing
     independent verification/audit/catalog publication.
   - Do not opportunistically run the regional collector with hub credentials.
     The first bridge package can qualify this composition in the existing real
     regional-process fixture. Installed hub-to-regional invocation additionally
     needs a purpose-specific authenticated, request-owned start connection; no
     current private download/native handler implements API capture dispatch.
     Keep that connection explicit in the next runtime package, retaining the
     existing regional role boundary and current identity checks.

4. **Focused qualification sources**
   - New capability adapter/unit tests; add a real API case to the existing
     native protection fixture proving exact source/guard/cluster/image binding.
   - New shared request bridge tests, plus extend
     `test/integration/api_execution_native_test.go` to enter through actual
     C09 preview/request and exact intent audit instead of directly invoking
     admission and runner as unrelated test steps.
   - Use actual separately credentialed SQL facets, actual API target/process,
     and real S3/OpenBao. Explicitly label remaining fixture-installed permission,
     retention, capability/bootstrap roots until their real producers are used.
   - Add a failing-before assertion that an accepted request calls the concrete
     runner and reaches encrypted stored output, followed by actual publication.
     Preserve separately tested raw status, audit and metadata deadlines.

### Acceptance cases for this package

- A normal preview/request yields the same original capture through intent
  audit, exact API acquisition and verified publication; one actual acquisition.
- Unrelated pending intent rows cannot prevent selection of this exact intent.
- Concurrent same-key submissions, lost admission reply, audited-intent replay
  and unknown start never create a second capture/attempt or recollect.
- Permission/capability/recovery revocation or changed source/target between
  preview, audit and start prevents acquisition; no stale observation fallback.
- Cancellation or the shorter original deadline expiring during blocked audit,
  SQL, target/protection reads or local start prevents the next effect. Final
  metadata delivery never outlives its original authority.
- A positively stored result can be independently published after the target
  disappears; publication cannot reacquire from a replacement Pod.
- `get_capture`, `resolve_capture_request`, status refresh and reload cannot
  trigger acquisition. Unsupported profiles remain unavailable.
- Production composition lacks no-op capability/process/permission/recovery
  ports. Runtime enablement remains false until installed-role tests pass.

The timing boundary needs measurement in that real composition: admission,
exact intent audit and acquisition must fit the original short live interval.
Do not extend authority to make a slow pipeline pass. If acknowledged work needs
another current submission, specify an explicit same-key continuation contract
and visible pending state before adding an automatic UI/MCP loop; the current
accepted response contains no continuation instruction. This is an engineering
decision within existing semantics, not a reason to ask the user to weaken
authorization or approve a second investigation.

## Production inputs: implemented mechanisms versus missing provisioning

| Input | Concrete existing mechanism | Still required for installed first path |
| --- | --- | --- |
| Root/schema/recovery | ADR130 schema loader and ADR129/131 original installer/historical path; four fixed bootstrap commands and setup-free replay now qualified in an actual Restricted Pod; `fleet_current_trust` fence | Finish official Helm composition and positive managed credential-copy cleanup. Fixture supplies initial administrator/upstream services, not SQL activation. First-install Activated does not qualify later recovery. |
| Human identity/browser | `BrowserSessions`, protected browser settings and SQL session/refresh backing, Keycloak adapter; request-owned identities and `LiveReader` | Protected public deployment, exact browser and MCP client/resource audience settings, original SQL/key roles and session/refresh supervision. No directory service account or stale-group queue. |
| Permissions | Kubernetes permission guard/source, audited explicit-binding reconciliation, SQL `Permissions`, evaluator and complete denies | Provision protected source/review pins and role credentials; run real source reconciliation. Start with existing explicit bindings; do not invent permissive defaults or demand all inheritance modes first. |
| Retention | Protected reviews/source/journal, accepted topology, SQL checkpoints/catch-up/readiness, effective-date guards | Install accepted policies/topology/source and continuous followers; no fixture resolution used as production policy. |
| Capture capability | Concrete protected `ContextCapabilitySource` implements both existing consumer ports with the same immutable collector/projection tuple | Installer-created pinned qualified source, installed consumers and actual API/composed acquisition qualification. The reader cannot qualify its own image or enable collection. |
| Storage/quota | `ContextStorageReader`, `BindContextStorage`, custody pools/allocations and control-capacity backing | Protected accepted configuration producer, per-workload selection and refresh; do not derive capacity from requested bytes or default an allocation. |
| Regional execution | `APIExecutionProtection`, `NewAPIExecutionProcess`, API targets/collector, local capacity CAS, SQL execution ledger and positive writer protocol | Protected process/Pod/image/API credentials, actual regional command/start listener and caller-owned connection; not a fixture-only process assertion. |
| Publication | SQL facets, actual `APIContextPublicationGate`, full manifest verification, encrypted verification audit and catalog publication | Independently credentialed regional verification/finalization owner and bounded work selection; no hub unwrap root. |
| Download privacy | SQL50 `CurrentDownloadEnvironment`, `DownloadEnvironmentSource`, `ProcessingReads/Configuration/Decisions` | Provision exact protected path/client/region policy and bounded processing backing/init acceptance; compose every download/key/native gate. Missing lineage is not allow. |
| Audit/deletion | Healthy public-operation lifecycle, positive context writer/deletion checkpoint and separate Stop lifecycle | Accepted measured backing/backup policy, purpose credentials and actual supervisors. Window-audit cleanup and unknown/restart reconciliation are not automatically solved by the operation-audit protocol. |

## Following packages that complete the developer flow

1. **Installed shared public composition.** Extend the fixed protected bootstrap
   pattern with a closed public/context deployment projection and real role
   constructors. `internal/bootstrap/hub_api.go` currently starts only private
   owner services. Compose `console.New`, `browser.SessionHandler`,
   `presentation.NewContextOperations`, case/progress services,
   `NewInvestigationOperations`, `NewHealthyAuditedOperations`,
   `browser.NewAuditedDownloadInvestigationHandler`, and
   `mcp.NewAuditedContextHandler`. Reuse the existing console design and canonical
   API/MCP schemas. No unaudited fallback or SDK/browser-session substitution.
   Keep process privileges separated; a loader does not justify merging all
   purpose SQL credentials and evidence unwrap into the public hub.

2. **Actual download runtime and allocation reader.** Implement the existing
   `ContextDownloadPlans` and `ContextDownloadRuntime` ports in
   `internal/application/evidence/context_download_control.go`; searches found
   no non-test implementation. Use accepted exact-workload allocation backing,
   `DownloadDispatcher.EnsureCurrent`, real worker enrollment/native startup,
   `ContextDownloadResultOwner`, `NativeAttachment`, and the actual
   `OwnerRuntime.RegisterNativeExchange`. Check is passive; Read never decrypts
   or dispatches; Continue uses the original worker/session and current explicit
   prepare request. Existing prepared metadata must survive status reads without
   another decrypt. A lost worker/result cannot silently create replacement
   work. Compose the real Stop service and current SQL50 environment.

3. **Authenticated native GET.** Add a request-owned content handler in
   `internal/transport/browser/` (shared authenticated-client logic may be a
   focused helper) and mount `/api/v1/downloads/{id}/content`. It does not exist
   today, although `presentation/context_download.go` advertises that path.
   Reuse `NewBrowserLiveReader`/`NewBearerLiveReader`, exact current session/scope,
   `DownloadResponseTransfer`, `NewRemoteContextSource` and
   `HTTPDownloadResponseFactory`. Existing HTTP types are sinks, not routes.
   Select/validate Range and conditionals before accounting; preserve response
   windows, current short leases, cancellation and after-header abort. No S3
   redirect, signed public URL, hub raw decrypt or bytes inside MCP JSON.

4. **One actual user journey, then chart enablement.** Start intended installed
   commands with the protected inputs, actual Keycloak identity, explicit real
   permission/retention configuration, actual deployment/Pod and role-separated
   SQL/S3/key services. Exercise built console and authenticated MCP against the
   same shared backend: preview → request → published progress → case → prepare
   → authenticated native bytes; compare the actual native SHA/length. Repeat
   with permission loss, target deletion, response loss, Range and active Stop.
   Verify role denial and cleanup, not merely synthetic transport DTOs. Only
   then enable the qualified profile in Helm; it currently rejects runtime.

## User-visible boundaries to keep explicit

The first complete slice is ordinary API pod-status metadata (at most 4096 native
bytes). It is not packet capture, coredump, logs, pprof, live watch, sharing or raw
approval implementation. Subsequent enabled mechanisms must include their native
download. The first UI must expose only real supported diagnostics; neither
accepted work nor an audit/SQL row means evidence is available. The download UI
already explains unmanaged local copies and uses the verified native filename;
retain that flow without adding debugger-specific restrictions.

Existing architecture documents contain historical pending statements now
superseded by code: the API publication gate and public operation audit exist;
SQL50 adds a real environment reader; connector49 adds identity components.
Update the narrow relevant rows at integration rather than treating old text as
evidence that those mechanisms must be rebuilt. Their deployment/provisioning
and exact combined qualification still remain distinct.
