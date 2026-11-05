# Product implementation status

Status checked on **2026-11-05** against merged main through [PR167](https://github.com/phihos/asservat/pull/167), merge `897fd783`. Its complete tree matches the reviewed and installed-tested `b6e2c084`. [Qualification evidence](../test/results/raw-packet-summary-native-41960249012/README.md) records the actual exits,4,212 source hashes, MCP/React/native-file parity and cleanup. Other rows retain their named evidence scopes; [implementation progress](implementation-progress.md) preserves the detailed history.

**There is no supported homelab release yet.** Several packaged operator/developer workflows have installed evidence. That evidence applies to the named environments and inputs; it does not complete the accepted first-release scope or qualify sustained production operation. Component, built-browser and installed evidence remain distinct.

No overall completion percentage or calendar ETA is established. Earlier estimates lacked a consistent scope/effort baseline and are withdrawn.

## Evidence levels

- **Designed:** accepted behavior/contracts exist; prototypes and mechanism spikes
  are distinguished from product implementation.
- **Component implemented:** concrete product code has relevant unit or component
  tests; its installed dependencies may be absent.
- **Integrated:** components communicate in a fixture. Any synthetic identity,
  installation, permission or capacity inputs remain explicit.
- **Native-tested:** the named boundary passed against real APIs/providers/SQL/TLS,
  containers or the built browser. This may still use synthetic authority inputs.
- **Installed workflow:** the intended operator/developer completes the named flow
  with packaged product services and supported inputs.
- **Production-qualified:** the applicable failure, privacy, operational, scale,
  compatibility and usability exits pass for the advertised support profile.

These levels are evidence categories, not equal amounts of remaining work. A native
component test is not an installed workflow. Shared foundations count once across
the features that depend on them.

## Capability baseline

| Developer or operator outcome | Established evidence | Work still required |
| --- | --- | --- |
| Bootstrap with Helm | Packaged reference workflows install/resume the protected runtime continuation and its hub, console/MCP, regional, key and publication services. Recent profile workflows use the actual installer. [Evidence](../test/results/profile-auth-native-41926293863/README.md). | Supported release artifacts and complete operational lifecycle. Direct `runtime.enabled: true` remains rejected; use the documented [bootstrap continuation](installation/helm.md). |
| Sign in through browser/MCP | Keycloak browser sessions, MCP identity and reviewer step-up are implemented and exercised in installed workflows. [Evidence](../test/results/profile-auth-native-41926293863/README.md). | Broader identity-provider/session lifecycle qualification and the internal-user alternative. |
| Request and browse workload context | Installed browser/MCP pod-status capture, encrypted publication, case lookup and approved inspection exist. [Ledger](implementation-progress.md). | Reconnect import and Partial states; generalized context acquisition. Pod-status remains a narrow diagnostic, not a file/log/command adapter. |
| Download, Stop and deliberately retry | Authenticated native transfer, Range/resume, bounded renewal, Stop, revocation and expiry have named installed evidence. Go profiles also cover Running→Stop→Cancelled and explicit busy/unavailable refusal without acquisition retry. [Ledger](implementation-progress.md), [refusal record](../test/results/profile-refusals-native-41795338953/provenance.json). | Sustained availability and cross-type/maximum-size interruption and recovery qualification. |
| Download every evidence type for local tools | Installed PCAPNG, syscall recordings, pprof and Go trace downloads preserve original bytes; named workflows open them with local tools. [Heap](../test/results/heap-browser-native-41891716697/README.md), [trace](../test/results/runtime-trace-native-41912395184/README.md), [ledger](implementation-progress.md). | Cores, exact debugger companions, remaining derivatives and large-artifact matrices. Earlier 2GiB feasibility is separate prototype evidence. |
| Automatic suspicious-event collection | Existing trigger implementations include restart/probe, Alertmanager, log and resource signals. Installed workflows cover automatic snapshots from ongoing packet/syscall sources and finite policy-triggered Go CPU profiles. [Ledger](implementation-progress.md#installed-automatic-incident-snapshot-from-an-ongoing-packet-source), [policy profile](../test/results/policy-profile-native-41771221394/provenance.json). | Broader trigger/collector combinations, capture-storm/scale qualification and unsupported metric/log selectors. |
| Files, logs, processes and commands | Designed; pod-status is the implemented narrow exception. [Scope](product.md). | Confined whole-pod adapters, bounded execution, partial/error handling, native output and platform qualification. |
| Packet/syscall rings, save and live watch | Ongoing header-packet and syscall-metadata sources, incident snapshots, manual Save and fresh-selection repeat are implemented. Named installed packet Save/incident flows passed. Raw packet acquisition/download, HTTP-header projection, frozen peer verification and encrypted-disk rings have merged implementations with separately scoped evidence. [Ledger](implementation-progress.md#installed-ongoing-packet--save-focus-first-full-pass), [ring qualification](implementation-progress.md#encrypted-disk-ring-on-a-real-node). | Live viewer delivery, broader grouped/argument/peer paths and full CNI/node matrices. Cilium and ring evidence cover named configurations; collectors remain disposable-test-host only. |
| Inspect saved syscall recordings | Console/MCP approved metadata-only summaries and filtered/paged events work for saved metadata and argument traces. PR150's two native Go fixtures passed with native parity and SQL/key/worker closure. [Ledger](implementation-progress.md). | The argument outer job reached its wall-clock limit despite successful Go/cleanup; do not call that workflow green. Arbitrary `syscall_query` and broader kernel/resource matrices remain open. |
| Runtime profiles and offline analysis | Installed manual/policy CPU, heap React inspection, pprof summaries/comparison, Go trace native/local tooling and fresh history Repeat have named evidence. TLS and private Authorization endpoints are installed-qualified for the reference CPU workflows through PR164. [Auth](../test/results/profile-auth-native-41926293863/README.md), [TLS](../test/results/profile-tls-native-41916430295/README.md), [trace](../test/results/runtime-trace-native-41912395184/README.md). Saved metadata and raw packet fixed summaries passed MCP, actual React and same-original native/tshark parity in [PR165](../test/results/saved-packet-summary-native-41945434872/README.md) and [PR167](../test/results/raw-packet-summary-native-41960249012/README.md). Raw remains raw; its fixed numeric summary grants no raw-content query or download rights. | Other modes/runtimes, eBPF packs, core analysis, arbitrary raw `pcap_query` and all-maxima qualification. Accepted-heavy comparison proves one input shape under the measured 384MiB/500m worker, not every maximum. [Resource evidence](../test/results/profile-heavy-native-41863091784/README.md). Bounded Go analysis uses ADR286; native tools retain the encrypted-scratch/Job boundary. Named packet resource checks are separate from installed maximum-shape/sustained operation; focused PR167 did not run second-workload/replay checks. |
| Core dumps and compatible debugger workflows | Disposable-VM helper/crash/local-debugger feasibility exists. [Scope](product.md). | Product helper lifecycle, prepaid crash path, process selection, exact companions, large native downloads and supported node/runtime qualification. |
| Combined approval and evidence sharing | Independent collection/result-access approvals, reviewer step-up, sharing/recipient/manager controls and bounded policy sharing are implemented. Named raw packet, syscall and profile workflows exercise separate collection/disclosure grants and retained spend. [Ledger](implementation-progress.md), [policy profile proof](../test/results/policy-profile-native-41771221394/provenance.json). | Complete cross-feature sharing/raw-grant qualification. Download approval does not implement arbitrary raw query approval or remove current entitlement checks. |
| Capture profiles, guidance, history and repeat | Builtin/organization/namespace versioned catalogs, flat composition, typed edits, combined review, plan diff and Save as profile are merged. Named context, recording Save and Go profile workflows cover immutable history/settings and fresh Repeat; the former blanket recording-history gap is superseded. [Console implementation](implementation-progress.md#console-plan-diff-and-save-as-profile), [trace/history proof](../test/results/runtime-trace-native-41912395184/README.md). | Broader profile/action/composition and guidance coverage; a successful named Repeat does not establish continuous availability or every history source. |
| Permission/privacy administration | Explicit/inherited rights, explanations, team/share controls, retention impact, revocation/deletion and conservative failed-cleanup accounting are implemented with named installed/component evidence. [Ledger](implementation-progress.md). | Processing release, overdue/admin reporting, browser-session cleanup, managed-copy/backup lifetime closure, complete operational and upgrade-role qualification. |
| Incident notification and recurrence investigation | Trigger-to-case and bounded case/navigation foundations exist; Go profile acquisition timing is displayed as a verified HTTP-fetch window, with unknown process/clock attribution. [Ledger](implementation-progress.md), [timing contract](decisions/297-verified-profile-acquisition-metadata.md). | Complete incident grouping, notification delivery, findings and recurrence investigation. Acquisition timing is not a full incident timeline or proof of common process identity. |
| Small deployment alternatives | Local wrapping/signing/key-service components exist. [Scope](product.md), [installation](installation/helm.md). | Installed internal accounts, local PKI lifecycle, bundled PostgreSQL/pgBackRest/evidence store and provider lifecycle qualification. |
| Recover, upgrade and operate production | Protected bootstrap, database-incarnation fencing, selected schema/image upgrades and accepted-history accounting/rollback have real fixture evidence. [History/upgrade proof](../test/results/accepted-history-capacity-local/README.md), [ledger](implementation-progress.md). | Supported backup/restore, failover/partition/version-skew profiles, sustained operation, distributable verified artifacts and production acceptance. A selected upgrade fixture is not complete operational qualification. |

The 17 groups describe capabilities, not a completion score. Earlier failures are retained in the ledger and original reports; later successes supersede only the exact boundaries they exercise. No complete S-02/S-04/S-05 or whole-specification exit is asserted here.

## Homelab trial status

A source-built, context-only developer experiment can use an ordinary owned
homelab Kubernetes cluster without a node collector or disposable-node marker.
It requires external PostgreSQL, S3-compatible storage, OpenBao and Keycloak;
matching source-built, digest-pinned images accessible to the cluster; and the
[documented installer setup](installation/helm.md#optional-initial-bootstrap-checkpoint),
including separate credentials, identity and permission configuration, delegation
where needed and regional enrollment. Private-registry credentials are needed
only when used.

The default Helm install starts no services. The documented
`bootstrap.enabled: true` with `bootstrap.continuation.enabled: true` runs the
runtime continuation while `runtime.enabled` remains `false`.
`runtime.enabled: true` is still rejected. This is a developer experiment;
internal users, the bundled small-deployment profile and a supported release
remain unfinished.

Packet/syscall collectors remain
[disposable-test-host only](installation/helm.md#node-collector-test-hosts-only).
Keep them off ordinary homelab nodes. Named recording Save, history/settings,
Repeat and profile workflows now have later installed passes; the older blanket
recording-history failure descriptions are superseded at those boundaries.
Sustained availability and wider environments remain unqualified.
[Implementation progress](implementation-progress.md) retains failed campaigns
and subsequent corrections with their tested boundaries.

## Next product milestone and forecasting basis

S-02's established context path and remaining acceptance work provide the
baseline: use an installed hub to select
an authorized workload in either of two clusters, preview/request context through
browser and MCP, collect and publish encrypted evidence, inspect/download it, then
verify denial on expiry/revocation and deletion of managed copies. Authority and
capacity must come from product-provisioned accepted sources, not fixture seeding.

Native107 (2026-10-24, [record](../test/results/resumed-c62e02ac-native107/README.md))
passes the named core S-02 journey in two workload clusters through one hub: browser and MCP
preview/request/inspection/download with reply parity, duplicate and conflicting idempotency,
Range resume, catalog minimization, an unrelated principal refused exactly as for absent
objects, Stop, Deny revocation, expiry refusal, a failed cleanup that retains its charges and
verified deletion; the second cluster completes capture, publication and native download.
Still not installed-qualified, against the
[S-02 exit](architecture/implementation-slices.md#s-02-exit-in-detail):

- hub disconnect/reconnect importing a committed result (documented limitation, ADR-223:
  a lost regional completion reply is not imported and the collection is never repeated);
- object/KMS failure states in the installed run: object-store failure reports
  `Indeterminate`/`StorageOutcomeUnconfirmed` and exhausted capacity `CapacityUnavailable`
  (component tests); a key-service failure before the start stays Pending until the deadline
  marks it Indeterminate.

A lost target is installed-qualified in [native109](../test/results/resumed-c62e02ac-native109/README.md):
a request for a deleted reviewed Pod returns `TargetGone`; a started capture records
`TargetGone` or `Denied` ([ADR-225](decisions/225-context-capture-failure-causes.md)).

Future forecasts must use bounded deliverables with explicit implementation,
integration and qualification work; account for dependencies and shared foundations;
and compare estimates with measured delivery of similar completed workflows.
Report scope changes and uncertainty explicitly. Until that baseline supports a
forecast, report completed outcomes, current failures and the next acceptance test.
